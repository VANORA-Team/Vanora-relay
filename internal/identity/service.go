package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultChallengeLifetime is the default lifetime of a login challenge.
	DefaultChallengeLifetime = 5 * time.Minute
	// MaxChallengeLifetime caps the lifetime of a login challenge.
	MaxChallengeLifetime = 10 * time.Minute
	// DefaultLeaseLifetime is the default lifetime of a liveness lease.
	DefaultLeaseLifetime = 45 * time.Second

	maxRequestBodySize = 16 << 10

	// leaseNonceRetention is how long a used lease nonce is remembered. It is
	// at least as long as a lease plus clock skew, so replaying a lease request
	// can never extend a client's grace window.
	leaseNonceRetention = MaxLeaseLifetime + clockSkew
	// maxLeaseNonces bounds the replay cache.
	maxLeaseNonces = 8192
)

// Config configures the independent identity service.
type Config struct {
	// OIDCIssuer is the exact issuer URL of the external identity provider.
	OIDCIssuer string
	// OIDCClientID is the public native client registered with the provider.
	OIDCClientID string
	// OIDCClientSecret is optional and only needed for a confidential client.
	OIDCClientSecret string
	// OIDCRedirectURI is the registered callback the native client receives.
	OIDCRedirectURI string
	// OIDCScopes defaults to ["openid", "offline_access"]. "openid" is always
	// added; "offline_access" is added unless DisableRefresh is set.
	OIDCScopes []string
	// DisableRefresh suppresses the automatic offline_access request. Without
	// offline_access the provider returns no refresh token, enrollment has no
	// refresh handle, and unattended renewal is impossible.
	DisableRefresh bool

	// Signer holds the authority signing key. Required.
	Signer *Signer
	// ChallengeTTL defaults to DefaultChallengeLifetime.
	ChallengeTTL time.Duration
	// LeaseTTL defaults to DefaultLeaseLifetime and is capped at
	// MaxLeaseLifetime.
	LeaseTTL time.Duration

	HTTPClient *http.Client
	// Now supplies the service clock. Defaults to time.Now.
	Now func() time.Time
	// Logger is optional; failures are logged without tokens or codes.
	Logger *slog.Logger
}

// Server is the identity service HTTP handler. It holds no per-user
// authorization state; every certificate is a time-bounded bearer of the
// verified owner and endpoint key.
type Server struct {
	signer          *Signer
	oidc            *oidcProvider
	challenges      *challengeStore
	nonces          *leaseNonceCache
	renewalNonces   *leaseNonceCache
	challengeTTL    time.Duration
	leaseTTL        time.Duration
	refreshDisabled bool
	now             func() time.Time
	logger          *slog.Logger
	handler         http.Handler
}

// NewServer validates the configuration and returns the HTTP service.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Signer == nil {
		return nil, fmt.Errorf("identity: signer is required")
	}
	provider, err := newOIDCProvider(cfg)
	if err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	challengeTTL := cfg.ChallengeTTL
	if challengeTTL == 0 {
		challengeTTL = DefaultChallengeLifetime
	}
	if challengeTTL < 0 || challengeTTL > MaxChallengeLifetime {
		return nil, fmt.Errorf("identity: challenge ttl must be in (0, %s]", MaxChallengeLifetime)
	}
	leaseTTL := cfg.LeaseTTL
	if leaseTTL == 0 {
		leaseTTL = DefaultLeaseLifetime
	}
	if leaseTTL < 0 || leaseTTL > MaxLeaseLifetime {
		return nil, fmt.Errorf("identity: lease ttl must be in (0, %s]", MaxLeaseLifetime)
	}
	s := &Server{
		signer:          cfg.Signer,
		oidc:            provider,
		challenges:      newChallengeStore(maxOutstandingChallenges),
		nonces:          newLeaseNonceCache(maxLeaseNonces),
		renewalNonces:   newLeaseNonceCache(maxLeaseNonces),
		challengeTTL:    challengeTTL,
		leaseTTL:        leaseTTL,
		refreshDisabled: cfg.DisableRefresh,
		now:             now,
		logger:          cfg.Logger,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/identity/challenges", postOnly(s.handleChallenges))
	mux.HandleFunc("/v1/identity/enroll", postOnly(s.handleEnroll))
	mux.HandleFunc("/v1/identity/lease", postOnly(s.handleLease))
	mux.HandleFunc("/v1/identity/renew", postOnly(s.handleRenew))
	mux.HandleFunc("/readyz", getOnly(s.handleReady))
	mux.HandleFunc("/healthz", getOnly(s.handleHealth))
	s.handler = mux
	return s, nil
}

// Handler returns the HTTP handler for the identity service.
func (s *Server) Handler() http.Handler {
	return s.handler
}

type challengeRequest struct {
	Purpose   string `json:"purpose"`
	PublicKey string `json:"public_key"`
}

type challengeResponse struct {
	ChallengeID         string `json:"challenge_id"`
	Nonce               string `json:"nonce"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	AuthorizationURL    string `json:"authorization_url"`
	ExpiresAt           int64  `json:"expires_at"`
}

type enrollRequest struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
	State       string `json:"state"`
	Signature   string `json:"signature"`
}

type enrollResponse struct {
	Certificate  string `json:"certificate"`
	DeviceID     string `json:"device_id"`
	RemoteUserID string `json:"remote_user_id"`
	ExpiresAt    int64  `json:"expires_at"`
	// RefreshHandle lets the endpoint renew its certificate without another
	// browser sign-in. It is opaque, encrypted to the authority, and empty
	// when the provider returned no refresh token.
	RefreshHandle string `json:"refresh_handle,omitempty"`
	Renewable     bool   `json:"renewable"`
}

type renewRequest struct {
	RefreshHandle string `json:"refresh_handle"`
	Nonce         string `json:"nonce"`
	Signature     string `json:"signature"`
}

type renewResponse struct {
	Certificate   string `json:"certificate"`
	RefreshHandle string `json:"refresh_handle"`
	DeviceID      string `json:"device_id"`
	RemoteUserID  string `json:"remote_user_id"`
	ExpiresAt     int64  `json:"expires_at"`
}

type leaseRequest struct {
	Certificate string `json:"certificate"`
	Nonce       string `json:"nonce"`
	Signature   string `json:"signature"`
}

type leaseResponse struct {
	Lease        string `json:"lease"`
	DeviceID     string `json:"device_id"`
	RemoteUserID string `json:"remote_user_id"`
	IssuedAt     int64  `json:"issued_at"`
	ExpiresAt    int64  `json:"expires_at"`
}

// ProofMessage returns the exact bytes a client must sign with its endpoint
// key to prove possession of the key registered with a challenge.
func ProofMessage(challengeID, nonce, purpose string, publicKey ed25519.PublicKey) []byte {
	return []byte("vanora-identity-proof-v1\n" +
		challengeID + "\n" +
		nonce + "\n" +
		purpose + "\n" +
		base64.RawURLEncoding.EncodeToString(publicKey))
}

// LeaseProofMessage returns the exact bytes an endpoint must sign with its
// certificate key to request a liveness lease. The certificate is bound via
// its SHA-256 so the signature stays small.
func LeaseProofMessage(nonce, certificate string) []byte {
	sum := sha256.Sum256([]byte(certificate))
	return []byte("vanora-identity-lease-v1\n" +
		nonce + "\n" +
		base64.RawURLEncoding.EncodeToString(sum[:]))
}

func (s *Server) handleChallenges(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	purpose := strings.ToLower(strings.TrimSpace(req.Purpose))
	if purpose == "" {
		purpose = "enroll"
	}
	if purpose != "enroll" && purpose != "renew" {
		writeError(w, http.StatusBadRequest, "invalid_purpose")
		return
	}
	publicKey, err := decodePublicKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_public_key")
		return
	}

	_, metadata, err := s.oidc.load(r.Context())
	if err != nil {
		s.logFailure("challenge discovery failed", err)
		writeError(w, http.StatusServiceUnavailable, "provider_unavailable")
		return
	}
	id, err := newSecret()
	if err != nil {
		s.logFailure("challenge id generation failed", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	nonce, err := newSecret()
	if err != nil {
		s.logFailure("challenge nonce generation failed", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	state, err := newSecret()
	if err != nil {
		s.logFailure("challenge state generation failed", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	codeVerifier, err := newSecret()
	if err != nil {
		s.logFailure("challenge verifier generation failed", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	now := s.now().UTC()
	ch := &challenge{
		id:           id,
		nonce:        nonce,
		state:        state,
		codeVerifier: codeVerifier,
		purpose:      purpose,
		publicKey:    publicKey,
		expires:      now.Add(s.challengeTTL),
	}
	s.challenges.add(ch, now)

	authorizationURL := s.oidc.authorizationURL(metadata, ch)
	if authorizationURL == "" {
		writeError(w, http.StatusServiceUnavailable, "provider_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, challengeResponse{
		ChallengeID:         id,
		Nonce:               nonce,
		State:               state,
		CodeChallenge:       pkceChallenge(codeVerifier),
		CodeChallengeMethod: "S256",
		AuthorizationURL:    authorizationURL,
		ExpiresAt:           ch.expires.Unix(),
	})
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if !validSecretValue(req.ChallengeID) || !validSecretValue(req.State) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(req.Code) == 0 || len(req.Code) > 4096 {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	now := s.now().UTC()
	ch, err := s.challenges.get(req.ChallengeID, now)
	if err != nil {
		writeError(w, http.StatusBadRequest, "challenge_invalid")
		return
	}
	if subtle.ConstantTimeCompare([]byte(ch.state), []byte(req.State)) != 1 {
		writeError(w, http.StatusBadRequest, "challenge_invalid")
		return
	}
	signature, err := decodeSegment(req.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		writeError(w, http.StatusBadRequest, "proof_invalid")
		return
	}
	if !ed25519.Verify(ch.publicKey, ProofMessage(ch.id, ch.nonce, ch.purpose, ch.publicKey), signature) {
		writeError(w, http.StatusBadRequest, "proof_invalid")
		return
	}
	// Consume the challenge only after the proof succeeds, so a bogus request
	// cannot burn a legitimate client's challenge. take is atomic: exactly one
	// request can win, which also makes the OIDC code single use here.
	if _, err := s.challenges.take(req.ChallengeID, now); err != nil {
		writeError(w, http.StatusBadRequest, "challenge_invalid")
		return
	}

	provider, metadata, err := s.oidc.load(r.Context())
	if err != nil {
		s.logFailure("enrollment discovery failed", err)
		writeError(w, http.StatusServiceUnavailable, "provider_unavailable")
		return
	}
	tokens, err := s.oidc.exchangeCode(r.Context(), metadata.TokenEndpoint, req.Code, ch.codeVerifier)
	if err != nil {
		s.logFailure("authorization code exchange failed", err)
		if errors.Is(err, ErrCodeRejected) {
			writeError(w, http.StatusUnauthorized, "code_rejected")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "provider_unavailable")
		return
	}
	subject, err := s.oidc.verifyIDToken(r.Context(), provider, tokens.IDToken, ch.nonce)
	if err != nil {
		s.logFailure("ID token verification failed", err)
		writeError(w, http.StatusUnauthorized, "identity_verification_failed")
		return
	}

	deviceID, err := s.signer.DeviceID(s.oidc.issuer, subject, ch.publicKey)
	if err != nil {
		s.logFailure("device id derivation failed", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	certificate, err := s.signer.Issue(s.oidc.issuer, subject, ch.publicKey, now)
	if err != nil {
		s.logFailure("certificate issuance failed", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	response := enrollResponse{
		Certificate:  certificate,
		DeviceID:     deviceID,
		RemoteUserID: RemoteUserID(s.oidc.issuer, subject),
		ExpiresAt:    now.Add(s.signer.CertificateTTL()).Unix(),
	}
	if !s.refreshDisabled && tokens.RefreshToken != "" {
		handle, err := s.signer.sealRefresh(s.oidc.issuer, subject, ch.publicKey, tokens.RefreshToken, now)
		if err != nil {
			s.logFailure("refresh handle seal failed", err)
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		response.RefreshHandle = handle
		response.Renewable = true
	}
	writeJSON(w, http.StatusOK, response)
}

// handleRenew exchanges a provider refresh token carried inside an opaque
// handle for a new certificate, after proving possession of the same endpoint
// key. It never contacts the browser: the provider rejects disabled or revoked
// accounts and the refreshed ID token must still carry the same issuer and
// subject.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	var req renewRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(req.RefreshHandle) == 0 || len(req.RefreshHandle) > maxRefreshHandleSize || !validNonce(req.Nonce) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if s.refreshDisabled {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	now := s.now().UTC()
	grant, publicKey, err := s.signer.openRefresh(req.RefreshHandle, now)
	if err != nil || grant.Issuer != s.oidc.issuer {
		// A handle sealed under a different issuer is stale configuration, not
		// a login for the currently configured provider.
		writeError(w, http.StatusBadRequest, "invalid_refresh_handle")
		return
	}
	signature, err := decodeSegment(req.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		writeError(w, http.StatusBadRequest, "proof_invalid")
		return
	}
	if !ed25519.Verify(publicKey, RenewProofMessage(req.Nonce, req.RefreshHandle), signature) {
		writeError(w, http.StatusUnauthorized, "proof_invalid")
		return
	}
	if !s.renewalNonces.claim(grant.DeviceID, req.Nonce, now) {
		writeError(w, http.StatusConflict, "nonce_reused")
		return
	}

	provider, metadata, err := s.oidc.load(r.Context())
	if err != nil {
		s.logFailure("renewal discovery failed", err)
		writeError(w, http.StatusServiceUnavailable, "provider_unavailable")
		return
	}
	tokens, err := s.oidc.refresh(r.Context(), metadata.TokenEndpoint, grant.RefreshToken)
	if err != nil {
		s.logFailure("refresh token exchange failed", err)
		if errors.Is(err, ErrCodeRejected) {
			writeError(w, http.StatusUnauthorized, "refresh_rejected")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "provider_unavailable")
		return
	}
	// A refresh ID token has no OIDC nonce, so only issuer, audience, expiry,
	// signature and subject are checked; the subject must match the handle.
	subject, err := s.oidc.verifyIDToken(r.Context(), provider, tokens.IDToken, "")
	if err != nil || subject != grant.Subject {
		s.logFailure("refresh ID token verification failed", err)
		writeError(w, http.StatusUnauthorized, "identity_verification_failed")
		return
	}
	deviceID, err := s.signer.DeviceID(grant.Issuer, subject, publicKey)
	if err != nil || deviceID != grant.DeviceID {
		s.logFailure("refresh device binding failed", err)
		writeError(w, http.StatusUnauthorized, "identity_verification_failed")
		return
	}
	certificate, err := s.signer.Issue(grant.Issuer, subject, publicKey, now)
	if err != nil {
		s.logFailure("renewal certificate issuance failed", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	refreshToken := tokens.RefreshToken
	if refreshToken == "" {
		refreshToken = grant.RefreshToken
	}
	handle, err := s.signer.sealRefresh(grant.Issuer, subject, publicKey, refreshToken, now)
	if err != nil {
		s.logFailure("renewal handle seal failed", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, renewResponse{
		Certificate:   certificate,
		RefreshHandle: handle,
		DeviceID:      deviceID,
		RemoteUserID:  RemoteUserID(grant.Issuer, subject),
		ExpiresAt:     now.Add(s.signer.CertificateTTL()).Unix(),
	})
}

func (s *Server) handleLease(w http.ResponseWriter, r *http.Request) {
	var req leaseRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.Certificate == "" || len(req.Certificate) > maxCertificateSize || !validNonce(req.Nonce) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	now := s.now().UTC()
	principal, err := VerifyCertificate(req.Certificate, s.signer.PublicKey(), now)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_certificate")
		return
	}
	signature, err := decodeSegment(req.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		writeError(w, http.StatusBadRequest, "proof_invalid")
		return
	}
	if !ed25519.Verify(principal.PublicKey, LeaseProofMessage(req.Nonce, req.Certificate), signature) {
		writeError(w, http.StatusUnauthorized, "proof_invalid")
		return
	}
	// A lease claims liveness now, so the authority itself must be able to
	// validate and sign right now. Cached readiness never exceeds 5 seconds.
	if err := s.oidc.Ready(r.Context()); err != nil {
		s.logFailure("lease readiness check failed", err)
		writeError(w, http.StatusServiceUnavailable, "provider_unavailable")
		return
	}
	if !s.nonces.claim(principal.DeviceID, req.Nonce, now) {
		writeError(w, http.StatusConflict, "nonce_reused")
		return
	}
	lease, expires, err := s.signer.IssueLease(principal, req.Certificate, req.Nonce, now, s.leaseTTL)
	if err != nil {
		s.logFailure("lease issuance failed", err)
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, leaseResponse{
		Lease:        lease,
		DeviceID:     principal.DeviceID,
		RemoteUserID: principal.RemoteUserID(),
		IssuedAt:     now.Unix(),
		ExpiresAt:    expires.Unix(),
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), oidcRequestTimeout)
	defer cancel()
	if err := s.oidc.Ready(ctx); err != nil {
		s.logFailure("readiness probe failed", err)
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unready",
			"reason": "identity_provider_unreachable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ready",
		"issuer": s.oidc.issuer,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) logFailure(message string, err error) {
	if s.logger == nil {
		return
	}
	s.logger.Warn(message, "error", err)
}

// leaseNonceCache remembers lease nonces so a replayed request cannot mint a
// fresh lease and silently extend a client's grace window.
type leaseNonceCache struct {
	mu    sync.Mutex
	items map[string]time.Time
	max   int
}

func newLeaseNonceCache(max int) *leaseNonceCache {
	if max <= 0 {
		max = maxLeaseNonces
	}
	return &leaseNonceCache{items: make(map[string]time.Time, max/8+1), max: max}
}

func (c *leaseNonceCache) claim(deviceID, nonce string, now time.Time) bool {
	key := deviceID + "\x00" + nonce
	c.mu.Lock()
	defer c.mu.Unlock()
	for existing, expiry := range c.items {
		if !expiry.After(now) {
			delete(c.items, existing)
		}
	}
	if expiry, ok := c.items[key]; ok && expiry.After(now) {
		return false
	}
	if len(c.items) >= c.max {
		for existing := range c.items {
			delete(c.items, existing)
			break
		}
	}
	c.items[key] = now.Add(leaseNonceRetention)
	return true
}

// decodeJSON reads a single bounded JSON object and rejects unknown fields and
// trailing data.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("unexpected trailing data")
	}
	return nil
}

func decodePublicKey(raw string) (ed25519.PublicKey, error) {
	if len(raw) < 40 || len(raw) > 64 {
		return nil, fmt.Errorf("invalid public key length")
	}
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		if key, err := encoding.DecodeString(raw); err == nil && len(key) == ed25519.PublicKeySize {
			return ed25519.PublicKey(key), nil
		}
	}
	return nil, fmt.Errorf("invalid public key encoding")
}

// validSecretValue checks a base64url value carrying 32 random bytes.
func validSecretValue(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := decodeSegment(value)
	return err == nil && len(decoded) == 32
}

func postOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		next(w, r)
	}
}

func getOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		next(w, r)
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
