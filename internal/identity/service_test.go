package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu      sync.Mutex
	current time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = c.current.Add(d)
}

type fakeCode struct {
	nonce         string
	state         string
	redirectURI   string
	clientID      string
	codeChallenge string
	subject       string
}

type fakeIDP struct {
	t           *testing.T
	server      *httptest.Server
	issuer      string
	key         ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	kid         string
	clientID    string
	redirectURI string

	mu              sync.Mutex
	codes           map[string]*fakeCode
	refreshTokens   map[string]string
	issueRefresh    bool
	refreshDisabled bool
	refreshSubject  string
	rotateRefresh   bool
	jwksDown        bool
	badSignature    bool
	nonceOverride   string
	audience        string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate idp key: %v", err)
	}
	f := &fakeIDP{
		t:             t,
		key:           privateKey,
		publicKey:     publicKey,
		kid:           "test-key",
		clientID:      "vanora-test-client",
		redirectURI:   "com.vanora.test:/oauth/callback",
		codes:         make(map[string]*fakeCode),
		refreshTokens: make(map[string]string),
		issueRefresh:  true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/authorize", f.authorize)
	mux.HandleFunc("/token", f.token)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	f.issuer = f.server.URL
	return f
}

func (f *fakeIDP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeTestJSON(w, map[string]any{
		"issuer":                                f.issuer,
		"authorization_endpoint":                f.issuer + "/authorize",
		"token_endpoint":                        f.issuer + "/token",
		"jwks_uri":                              f.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"grant_types_supported":                 []string{"authorization_code"},
	})
}

func (f *fakeIDP) jwks(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	down := f.jwksDown
	f.mu.Unlock()
	if down {
		http.Error(w, "down", http.StatusInternalServerError)
		return
	}
	writeTestJSON(w, map[string]any{"keys": []map[string]string{{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(f.publicKey),
		"kid": f.kid,
		"alg": "EdDSA",
		"use": "sig",
	}}})
}

func (f *fakeIDP) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	for _, name := range []string{"client_id", "redirect_uri", "state", "nonce", "code_challenge"} {
		if query.Get(name) == "" {
			http.Error(w, "missing "+name, http.StatusBadRequest)
			return
		}
	}
	if query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" {
		http.Error(w, "unsupported request", http.StatusBadRequest)
		return
	}
	code, err := newSecret()
	if err != nil {
		http.Error(w, "no code", http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.codes[code] = &fakeCode{
		nonce:         query.Get("nonce"),
		state:         query.Get("state"),
		redirectURI:   query.Get("redirect_uri"),
		clientID:      query.Get("client_id"),
		codeChallenge: query.Get("code_challenge"),
		subject:       "subject-1",
	}
	f.mu.Unlock()

	redirect, err := url.Parse(query.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	values := redirect.Query()
	values.Set("code", code)
	values.Set("state", query.Get("state"))
	redirect.RawQuery = values.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (f *fakeIDP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") == "refresh_token" {
		f.refresh(w, r)
		return
	}
	code := r.PostForm.Get("code")
	f.mu.Lock()
	entry, ok := f.codes[code]
	if ok {
		delete(f.codes, code)
	}
	f.mu.Unlock()
	if !ok || r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("client_id") != entry.clientID ||
		r.PostForm.Get("redirect_uri") != entry.redirectURI {
		writeTestOAuthError(w, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != entry.codeChallenge {
		writeTestOAuthError(w, "invalid_grant")
		return
	}

	f.mu.Lock()
	badSignature := f.badSignature
	nonce := entry.nonce
	if f.nonceOverride != "" {
		nonce = f.nonceOverride
	}
	audience := f.clientID
	if f.audience != "" {
		audience = f.audience
	}
	issueRefresh := f.issueRefresh
	f.mu.Unlock()

	now := time.Now()
	response := map[string]any{
		"id_token":   f.mint(entry.subject, audience, nonce, now, now.Add(30*time.Minute), badSignature),
		"token_type": "Bearer",
		"expires_in": 300,
	}
	if issueRefresh {
		refreshToken, err := newSecret()
		if err != nil {
			http.Error(w, "no token", http.StatusInternalServerError)
			return
		}
		f.mu.Lock()
		f.refreshTokens[refreshToken] = entry.subject
		f.mu.Unlock()
		response["refresh_token"] = refreshToken
	}
	writeTestJSON(w, response)
}

// refresh implements grant_type=refresh_token. It rejects tokens after the
// test disables the account, mimics rotation by deleting the old token, and
// can return an ID token for another subject to exercise issuer/subject
// revalidation.
func (f *fakeIDP) refresh(w http.ResponseWriter, r *http.Request) {
	token := r.PostForm.Get("refresh_token")
	f.mu.Lock()
	subject, ok := f.refreshTokens[token]
	disabled := f.refreshDisabled
	override := f.refreshSubject
	rotate := f.rotateRefresh
	badSignature := f.badSignature
	if rotate && ok {
		delete(f.refreshTokens, token)
	}
	f.mu.Unlock()
	if !ok || disabled {
		writeTestOAuthError(w, "invalid_grant")
		return
	}
	if override != "" {
		subject = override
	}
	now := time.Now()
	response := map[string]any{
		"id_token":   f.mint(subject, f.clientID, "", now, now.Add(30*time.Minute), badSignature),
		"token_type": "Bearer",
		"expires_in": 300,
	}
	if rotate {
		replacement, err := newSecret()
		if err != nil {
			http.Error(w, "no token", http.StatusInternalServerError)
			return
		}
		f.mu.Lock()
		f.refreshTokens[replacement] = subject
		f.mu.Unlock()
		response["refresh_token"] = replacement
	}
	writeTestJSON(w, response)
}

func (f *fakeIDP) setRefreshOptions(issue, disabled bool, subjectOverride string, rotate bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issueRefresh = issue
	f.refreshDisabled = disabled
	f.refreshSubject = subjectOverride
	f.rotateRefresh = rotate
}

func (f *fakeIDP) mint(subject, audience, nonce string, issuedAt, expires time.Time, badSignature bool) string {
	header := map[string]string{"alg": "EdDSA", "kid": f.kid, "typ": "JWT"}
	claims := map[string]any{
		"iss":   f.issuer,
		"sub":   subject,
		"aud":   []string{audience},
		"iat":   issuedAt.Unix(),
		"exp":   expires.Unix(),
		"nonce": nonce,
	}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	key := f.key
	if badSignature {
		_, wrongKey, _ := ed25519.GenerateKey(rand.Reader)
		key = wrongKey
	}
	signature := ed25519.Sign(key, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (f *fakeIDP) setJWKSDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwksDown = down
}

func (f *fakeIDP) setIDTokenOptions(nonce, audience string, badSignature bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonceOverride = nonce
	f.audience = audience
	f.badSignature = badSignature
}

func writeTestJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func writeTestOAuthError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

type testEnvironment struct {
	service *Server
	idp     *fakeIDP
	signer  *Signer
	clock   *testClock
	server  *httptest.Server
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newTestEnvironment(t *testing.T, mutate func(*Config)) *testEnvironment {
	t.Helper()
	clock := &testClock{current: time.Now().UTC().Truncate(time.Second)}
	idp := newFakeIDP(t)
	signer, _ := testSigner(t, 10*time.Minute)
	publicKey, privateKey := testEndpointKey(t)
	cfg := Config{
		OIDCIssuer:      idp.issuer,
		OIDCClientID:    idp.clientID,
		OIDCRedirectURI: idp.redirectURI,
		Signer:          signer,
		ChallengeTTL:    5 * time.Minute,
		LeaseTTL:        30 * time.Second,
		HTTPClient:      idp.server.Client(),
		Now:             clock.Now,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	service, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	server := httptest.NewServer(service.Handler())
	t.Cleanup(server.Close)
	return &testEnvironment{
		service: service,
		idp:     idp,
		signer:  signer,
		clock:   clock,
		server:  server,
		public:  publicKey,
		private: privateKey,
	}
}

func (e *testEnvironment) post(t *testing.T, path string, body any) (int, []byte) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(e.server.URL+path, "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp.StatusCode, raw
}

func (e *testEnvironment) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(e.server.URL + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp.StatusCode, raw
}

func (e *testEnvironment) challenge(t *testing.T, purpose string) challengeResponse {
	t.Helper()
	status, body := e.post(t, "/v1/identity/challenges", challengeRequest{
		Purpose:   purpose,
		PublicKey: base64.RawURLEncoding.EncodeToString(e.public),
	})
	if status != http.StatusOK {
		t.Fatalf("challenge status %d: %s", status, body)
	}
	var response challengeResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("challenge response: %v", err)
	}
	if response.ChallengeID == "" || response.Nonce == "" || response.State == "" {
		t.Fatalf("challenge response incomplete: %+v", response)
	}
	if !strings.HasPrefix(response.AuthorizationURL, e.idp.issuer+"/authorize?") {
		t.Fatalf("authorization url = %q", response.AuthorizationURL)
	}
	parsed, err := url.Parse(response.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	for name, want := range map[string]string{
		"client_id":             e.idp.clientID,
		"redirect_uri":          e.idp.redirectURI,
		"state":                 response.State,
		"nonce":                 response.Nonce,
		"code_challenge_method": "S256",
		"response_type":         "code",
	} {
		if got := query.Get(name); got != want {
			t.Fatalf("authorization url %s = %q, want %q", name, got, want)
		}
	}
	return response
}

// authorize simulates the system browser following the IdP authorize
// endpoint and returns the code and state delivered to the redirect URI.
func (e *testEnvironment) authorize(t *testing.T, challenge challengeResponse) (code, state string) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(challenge.AuthorizationURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status %d: %s", resp.StatusCode, body)
	}
	redirect, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("redirect location: %v", err)
	}
	query := redirect.Query()
	if query.Get("state") != challenge.State {
		t.Fatalf("redirect state mismatch")
	}
	return query.Get("code"), query.Get("state")
}

func (e *testEnvironment) enroll(t *testing.T, challenge challengeResponse, code, purpose string) (int, []byte) {
	t.Helper()
	signature := ed25519.Sign(e.private, ProofMessage(challenge.ChallengeID, challenge.Nonce, purpose, e.public))
	return e.post(t, "/v1/identity/enroll", enrollRequest{
		ChallengeID: challenge.ChallengeID,
		Code:        code,
		State:       challenge.State,
		Signature:   base64.RawURLEncoding.EncodeToString(signature),
	})
}

func decodeEnrollment(t *testing.T, body []byte) enrollResponse {
	t.Helper()
	var response enrollResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("enroll response: %v (%s)", err, body)
	}
	return response
}

func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var response struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("error response: %v (%s)", err, body)
	}
	return response.Error
}

func TestServiceEnrollmentAndLease(t *testing.T) {
	env := newTestEnvironment(t, nil)
	challenge := env.challenge(t, "enroll")
	code, state := env.authorize(t, challenge)

	status, body := env.enroll(t, challenge, code, "enroll")
	if status != http.StatusOK {
		t.Fatalf("enroll status %d: %s", status, body)
	}
	enrollment := decodeEnrollment(t, body)
	now := env.clock.Now()
	principal, err := VerifyCertificate(enrollment.Certificate, env.signer.PublicKey(), now)
	if err != nil {
		t.Fatalf("verify certificate: %v", err)
	}
	if principal.Issuer != env.idp.issuer || principal.Subject != "subject-1" {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	if enrollment.DeviceID != principal.DeviceID {
		t.Fatalf("response device id %q != certificate %q", enrollment.DeviceID, principal.DeviceID)
	}
	wantUser := RemoteUserID(env.idp.issuer, "subject-1")
	if enrollment.RemoteUserID != wantUser || principal.RemoteUserID() != wantUser {
		t.Fatalf("remote user id = %q / %q, want %q", enrollment.RemoteUserID, principal.RemoteUserID(), wantUser)
	}
	if !principal.PublicKey.Equal(env.public) {
		t.Fatalf("certificate bound the wrong endpoint key")
	}
	if state != challenge.State {
		t.Fatalf("state changed between authorize and enroll")
	}

	nonce := testNonce(t)
	leaseSignature := ed25519.Sign(env.private, LeaseProofMessage(nonce, enrollment.Certificate))
	status, body = env.post(t, "/v1/identity/lease", leaseRequest{
		Certificate: enrollment.Certificate,
		Nonce:       nonce,
		Signature:   base64.RawURLEncoding.EncodeToString(leaseSignature),
	})
	if status != http.StatusOK {
		t.Fatalf("lease status %d: %s", status, body)
	}
	var lease leaseResponse
	if err := json.Unmarshal(body, &lease); err != nil {
		t.Fatalf("lease response: %v", err)
	}
	expires, err := VerifyEndpointLease(lease.Lease, env.signer.PublicKey(), env.clock.Now(), enrollment.Certificate, principal)
	if err != nil {
		t.Fatalf("verify endpoint lease: %v", err)
	}
	if lease.DeviceID != principal.DeviceID || lease.RemoteUserID != wantUser {
		t.Fatalf("lease returned wrong bindings: %+v", lease)
	}
	if !expires.Equal(time.Unix(lease.ExpiresAt, 0)) {
		t.Fatalf("lease expiry %s != returned %d", expires, lease.ExpiresAt)
	}

	// A replay of the same lease request must not mint a fresh grace window.
	status, body = env.post(t, "/v1/identity/lease", leaseRequest{
		Certificate: enrollment.Certificate,
		Nonce:       nonce,
		Signature:   base64.RawURLEncoding.EncodeToString(leaseSignature),
	})
	if status != http.StatusConflict || errorCode(t, body) != "nonce_reused" {
		t.Fatalf("replayed lease status %d: %s", status, body)
	}
}

func TestServiceEnrollmentReplayRejected(t *testing.T) {
	env := newTestEnvironment(t, nil)
	challenge := env.challenge(t, "enroll")
	code, _ := env.authorize(t, challenge)
	if status, body := env.enroll(t, challenge, code, "enroll"); status != http.StatusOK {
		t.Fatalf("first enroll status %d: %s", status, body)
	}
	status, body := env.enroll(t, challenge, code, "enroll")
	if status != http.StatusBadRequest || errorCode(t, body) != "challenge_invalid" {
		t.Fatalf("replayed enroll status %d: %s", status, body)
	}
}

func TestServiceWrongProofDoesNotConsumeChallenge(t *testing.T) {
	env := newTestEnvironment(t, nil)
	challenge := env.challenge(t, "enroll")
	code, _ := env.authorize(t, challenge)

	_, wrongKey, _ := ed25519.GenerateKey(rand.Reader)
	signature := ed25519.Sign(wrongKey, ProofMessage(challenge.ChallengeID, challenge.Nonce, "enroll", env.public))
	status, body := env.post(t, "/v1/identity/enroll", enrollRequest{
		ChallengeID: challenge.ChallengeID,
		Code:        code,
		State:       challenge.State,
		Signature:   base64.RawURLEncoding.EncodeToString(signature),
	})
	if status != http.StatusBadRequest || errorCode(t, body) != "proof_invalid" {
		t.Fatalf("wrong proof status %d: %s", status, body)
	}

	status, body = env.enroll(t, challenge, code, "enroll")
	if status != http.StatusOK {
		t.Fatalf("correct proof after wrong proof status %d: %s", status, body)
	}

	// A wrong state must fail without consuming the challenge either.
	challenge2 := env.challenge(t, "enroll")
	code2, _ := env.authorize(t, challenge2)
	signature2 := ed25519.Sign(env.private, ProofMessage(challenge2.ChallengeID, challenge2.Nonce, "enroll", env.public))
	status, body = env.post(t, "/v1/identity/enroll", enrollRequest{
		ChallengeID: challenge2.ChallengeID,
		Code:        code2,
		State:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Signature:   base64.RawURLEncoding.EncodeToString(signature2),
	})
	if status != http.StatusBadRequest || errorCode(t, body) != "challenge_invalid" {
		t.Fatalf("wrong state status %d: %s", status, body)
	}
	if status, body = env.enroll(t, challenge2, code2, "enroll"); status != http.StatusOK {
		t.Fatalf("correct state after wrong state status %d: %s", status, body)
	}
}

func TestServiceOIDCTokenChecks(t *testing.T) {
	cases := map[string]struct {
		nonce    string
		audience string
		badSig   bool
	}{
		"nonce mismatch": {nonce: "not-the-challenge-nonce"},
		"wrong audience": {audience: "another-client"},
		"bad signature":  {badSig: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := newTestEnvironment(t, nil)
			env.idp.setIDTokenOptions(tc.nonce, tc.audience, tc.badSig)
			challenge := env.challenge(t, "enroll")
			code, _ := env.authorize(t, challenge)
			status, body := env.enroll(t, challenge, code, "enroll")
			if status != http.StatusUnauthorized || errorCode(t, body) != "identity_verification_failed" {
				t.Fatalf("status %d: %s", status, body)
			}
		})
	}
}

func TestServiceChallengeExpires(t *testing.T) {
	env := newTestEnvironment(t, nil)
	challenge := env.challenge(t, "enroll")
	code, _ := env.authorize(t, challenge)
	env.clock.Advance(5*time.Minute + time.Second)
	status, body := env.enroll(t, challenge, code, "enroll")
	if status != http.StatusBadRequest || errorCode(t, body) != "challenge_invalid" {
		t.Fatalf("expired challenge status %d: %s", status, body)
	}
}

func TestServiceReadinessGatesLease(t *testing.T) {
	env := newTestEnvironment(t, nil)
	challenge := env.challenge(t, "enroll")
	code, _ := env.authorize(t, challenge)
	status, body := env.enroll(t, challenge, code, "enroll")
	if status != http.StatusOK {
		t.Fatalf("enroll status %d: %s", status, body)
	}
	enrollment := decodeEnrollment(t, body)
	principal, err := VerifyCertificate(enrollment.Certificate, env.signer.PublicKey(), env.clock.Now())
	if err != nil {
		t.Fatal(err)
	}

	env.idp.setJWKSDown(true)
	env.clock.Advance(readinessTTL + time.Second)
	status, body = env.get(t, "/readyz")
	if status != http.StatusServiceUnavailable || !strings.Contains(string(body), "unready") {
		t.Fatalf("readyz while down status %d: %s", status, body)
	}

	nonce := testNonce(t)
	signature := ed25519.Sign(env.private, LeaseProofMessage(nonce, enrollment.Certificate))
	status, body = env.post(t, "/v1/identity/lease", leaseRequest{
		Certificate: enrollment.Certificate,
		Nonce:       nonce,
		Signature:   base64.RawURLEncoding.EncodeToString(signature),
	})
	if status != http.StatusServiceUnavailable || errorCode(t, body) != "provider_unavailable" {
		t.Fatalf("lease while unready status %d: %s", status, body)
	}

	env.idp.setJWKSDown(false)
	env.clock.Advance(readinessTTL + time.Second)
	status, body = env.get(t, "/readyz")
	if status != http.StatusOK || !strings.Contains(string(body), "ready") {
		t.Fatalf("readyz after recovery status %d: %s", status, body)
	}
	nonce = testNonce(t)
	signature = ed25519.Sign(env.private, LeaseProofMessage(nonce, enrollment.Certificate))
	status, body = env.post(t, "/v1/identity/lease", leaseRequest{
		Certificate: enrollment.Certificate,
		Nonce:       nonce,
		Signature:   base64.RawURLEncoding.EncodeToString(signature),
	})
	if status != http.StatusOK {
		t.Fatalf("lease after recovery status %d: %s", status, body)
	}
	if _, err := VerifyEndpointLease(decodeLease(t, body).Lease, env.signer.PublicKey(), env.clock.Now(), enrollment.Certificate, principal); err != nil {
		t.Fatalf("lease after recovery: %v", err)
	}
}

func decodeLease(t *testing.T, body []byte) leaseResponse {
	t.Helper()
	var lease leaseResponse
	if err := json.Unmarshal(body, &lease); err != nil {
		t.Fatalf("lease response: %v (%s)", err, body)
	}
	return lease
}

func TestServiceRequestValidation(t *testing.T) {
	env := newTestEnvironment(t, nil)

	resp, err := http.Get(env.server.URL + "/v1/identity/challenges")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET challenges status = %d", resp.StatusCode)
	}

	status, body := env.post(t, "/v1/identity/challenges", map[string]string{
		"purpose":    "enroll",
		"public_key": base64.RawURLEncoding.EncodeToString(env.public),
		"extra":      "field",
	})
	if status != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
		t.Fatalf("unknown field status %d: %s", status, body)
	}
	status, body = env.post(t, "/v1/identity/challenges", map[string]string{
		"purpose":    "enroll",
		"public_key": "not-a-key",
	})
	if status != http.StatusBadRequest || errorCode(t, body) != "invalid_public_key" {
		t.Fatalf("bad key status %d: %s", status, body)
	}
	status, body = env.post(t, "/v1/identity/challenges", map[string]string{
		"purpose":    "steal",
		"public_key": base64.RawURLEncoding.EncodeToString(env.public),
	})
	if status != http.StatusBadRequest || errorCode(t, body) != "invalid_purpose" {
		t.Fatalf("bad purpose status %d: %s", status, body)
	}

	challenge := env.challenge(t, "renew")
	code, _ := env.authorize(t, challenge)
	status, body = env.enroll(t, challenge, code, "enroll")
	if status != http.StatusBadRequest || errorCode(t, body) != "proof_invalid" {
		t.Fatalf("proof purpose mismatch status %d: %s", status, body)
	}
}

func TestNewServerValidation(t *testing.T) {
	signer, _ := testSigner(t, 10*time.Minute)
	base := Config{
		OIDCIssuer:      "https://id.example.com",
		OIDCClientID:    "client",
		OIDCRedirectURI: "com.vanora.test:/callback",
		Signer:          signer,
	}
	cases := map[string]func(*Config){
		"missing signer":      func(c *Config) { c.Signer = nil },
		"plaintext issuer":    func(c *Config) { c.OIDCIssuer = "http://id.example.com" },
		"issuer query":        func(c *Config) { c.OIDCIssuer = "https://id.example.com?x=1" },
		"missing client":      func(c *Config) { c.OIDCClientID = "" },
		"redirect fragment":   func(c *Config) { c.OIDCRedirectURI = "https://app.example.com/cb#frag" },
		"javascript redirect": func(c *Config) { c.OIDCRedirectURI = "javascript:alert(1)" },
		"challenge ttl":       func(c *Config) { c.ChallengeTTL = MaxChallengeLifetime + time.Second },
		"lease ttl":           func(c *Config) { c.LeaseTTL = MaxLeaseLifetime + time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if _, err := NewServer(cfg); err == nil {
				t.Fatalf("invalid config was accepted")
			}
		})
	}
	if _, err := NewServer(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func (e *testEnvironment) renewRequest(t *testing.T, handle string, key ed25519.PrivateKey) (int, []byte) {
	t.Helper()
	nonce := testNonce(t)
	signature := ed25519.Sign(key, RenewProofMessage(nonce, handle))
	return e.post(t, "/v1/identity/renew", renewRequest{
		RefreshHandle: handle,
		Nonce:         nonce,
		Signature:     base64.RawURLEncoding.EncodeToString(signature),
	})
}

func TestServiceRenewalWithoutBrowser(t *testing.T) {
	env := newTestEnvironment(t, nil)
	env.idp.setRefreshOptions(true, false, "", true)
	challenge := env.challenge(t, "enroll")
	code, _ := env.authorize(t, challenge)
	status, body := env.enroll(t, challenge, code, "enroll")
	if status != http.StatusOK {
		t.Fatalf("enroll status %d: %s", status, body)
	}
	enrollment := decodeEnrollment(t, body)
	if !enrollment.Renewable || enrollment.RefreshHandle == "" {
		t.Fatalf("enrollment is not renewable: %+v", enrollment)
	}
	principal, err := VerifyCertificate(enrollment.Certificate, env.signer.PublicKey(), env.clock.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Renew shortly before the certificate expires; no browser, no OIDC code.
	env.clock.Advance(9 * time.Minute)
	status, body = env.renewRequest(t, enrollment.RefreshHandle, env.private)
	if status != http.StatusOK {
		t.Fatalf("renew status %d: %s", status, body)
	}
	var renewed renewResponse
	if err := json.Unmarshal(body, &renewed); err != nil {
		t.Fatalf("renew response: %v", err)
	}
	if renewed.RefreshHandle == "" || renewed.RefreshHandle == enrollment.RefreshHandle {
		t.Fatalf("refresh handle was not rotated")
	}
	if renewed.DeviceID != enrollment.DeviceID || renewed.RemoteUserID != enrollment.RemoteUserID {
		t.Fatalf("renewal changed stable identity: %+v", renewed)
	}
	renewedPrincipal, err := VerifyCertificate(renewed.Certificate, env.signer.PublicKey(), env.clock.Now())
	if err != nil {
		t.Fatalf("renewed certificate: %v", err)
	}
	if renewedPrincipal.Subject != principal.Subject || renewedPrincipal.DeviceID != principal.DeviceID {
		t.Fatalf("renewed certificate changed owner or device: %+v", renewedPrincipal)
	}
	if !renewedPrincipal.PublicKey.Equal(env.public) {
		t.Fatalf("renewed certificate changed the endpoint key")
	}

	// The provider rotated the refresh token, so the handle carrying the old
	// token must now be rejected.
	status, body = env.renewRequest(t, enrollment.RefreshHandle, env.private)
	if status != http.StatusUnauthorized || errorCode(t, body) != "refresh_rejected" {
		t.Fatalf("old handle status %d: %s", status, body)
	}

	// A fresh renewal with the rotated handle works.
	status, body = env.renewRequest(t, renewed.RefreshHandle, env.private)
	if status != http.StatusOK {
		t.Fatalf("rotated handle status %d: %s", status, body)
	}
}

func TestServiceRenewalReplayAndProof(t *testing.T) {
	env := newTestEnvironment(t, nil)
	challenge := env.challenge(t, "enroll")
	code, _ := env.authorize(t, challenge)
	status, body := env.enroll(t, challenge, code, "enroll")
	if status != http.StatusOK {
		t.Fatalf("enroll status %d: %s", status, body)
	}
	handle := decodeEnrollment(t, body).RefreshHandle

	nonce := testNonce(t)
	signature := ed25519.Sign(env.private, RenewProofMessage(nonce, handle))
	request := renewRequest{RefreshHandle: handle, Nonce: nonce, Signature: base64.RawURLEncoding.EncodeToString(signature)}
	status, body = env.post(t, "/v1/identity/renew", request)
	if status != http.StatusOK {
		t.Fatalf("renew status %d: %s", status, body)
	}
	status, body = env.post(t, "/v1/identity/renew", request)
	if status != http.StatusConflict || errorCode(t, body) != "nonce_reused" {
		t.Fatalf("replayed renew status %d: %s", status, body)
	}

	_, wrongKey, _ := ed25519.GenerateKey(rand.Reader)
	status, body = env.renewRequest(t, handle, wrongKey)
	if status != http.StatusUnauthorized || errorCode(t, body) != "proof_invalid" {
		t.Fatalf("wrong key status %d: %s", status, body)
	}

	tampered := replaceAt(handle, strings.LastIndex(handle, ".")+1)
	status, body = env.renewRequest(t, tampered, env.private)
	if status != http.StatusBadRequest || errorCode(t, body) != "invalid_refresh_handle" {
		t.Fatalf("tampered handle status %d: %s", status, body)
	}

	status, body = env.post(t, "/v1/identity/renew", renewRequest{RefreshHandle: handle, Nonce: "short", Signature: "AAAA"})
	if status != http.StatusBadRequest || errorCode(t, body) != "invalid_request" {
		t.Fatalf("malformed renew status %d: %s", status, body)
	}
}

func TestServiceRenewalRejectsProviderChanges(t *testing.T) {
	cases := map[string]struct {
		disabled bool
		subject  string
		badSig   bool
		code     string
	}{
		"disabled account": {disabled: true, code: "refresh_rejected"},
		"subject changed":  {subject: "someone-else", code: "identity_verification_failed"},
		"forged id token":  {badSig: true, code: "identity_verification_failed"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := newTestEnvironment(t, nil)
			challenge := env.challenge(t, "enroll")
			code, _ := env.authorize(t, challenge)
			status, body := env.enroll(t, challenge, code, "enroll")
			if status != http.StatusOK {
				t.Fatalf("enroll status %d: %s", status, body)
			}
			handle := decodeEnrollment(t, body).RefreshHandle
			env.idp.setRefreshOptions(true, tc.disabled, tc.subject, false)
			if tc.badSig {
				env.idp.mu.Lock()
				env.idp.badSignature = true
				env.idp.mu.Unlock()
			}
			status, body = env.renewRequest(t, handle, env.private)
			if status != http.StatusUnauthorized || errorCode(t, body) != tc.code {
				t.Fatalf("status %d: %s", status, body)
			}
		})
	}
}

func TestServiceRenewalRequiresRefreshToken(t *testing.T) {
	env := newTestEnvironment(t, nil)
	env.idp.setRefreshOptions(false, false, "", false)
	challenge := env.challenge(t, "enroll")
	code, _ := env.authorize(t, challenge)
	status, body := env.enroll(t, challenge, code, "enroll")
	if status != http.StatusOK {
		t.Fatalf("enroll status %d: %s", status, body)
	}
	enrollment := decodeEnrollment(t, body)
	if enrollment.Renewable || enrollment.RefreshHandle != "" {
		t.Fatalf("enrollment without provider refresh token is renewable: %+v", enrollment)
	}
	status, body = env.renewRequest(t, "vanr1.AAAA.BBBB", env.private)
	if status != http.StatusBadRequest || errorCode(t, body) != "invalid_refresh_handle" {
		t.Fatalf("renew without handle status %d: %s", status, body)
	}
}

func TestServiceRefreshHandleExpires(t *testing.T) {
	env := newTestEnvironment(t, nil)
	challenge := env.challenge(t, "enroll")
	code, _ := env.authorize(t, challenge)
	status, body := env.enroll(t, challenge, code, "enroll")
	if status != http.StatusOK {
		t.Fatalf("enroll status %d: %s", status, body)
	}
	handle := decodeEnrollment(t, body).RefreshHandle
	env.clock.Advance(MaxRefreshHandleLifetime + time.Hour)
	status, body = env.renewRequest(t, handle, env.private)
	if status != http.StatusBadRequest || errorCode(t, body) != "invalid_refresh_handle" {
		t.Fatalf("expired handle status %d: %s", status, body)
	}
}

func TestServiceDisableRefreshScope(t *testing.T) {
	env := newTestEnvironment(t, func(cfg *Config) { cfg.DisableRefresh = true })
	challenge := env.challenge(t, "enroll")
	parsed, err := url.Parse(challenge.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if scope := parsed.Query().Get("scope"); strings.Contains(scope, "offline_access") {
		t.Fatalf("offline_access requested while refresh is disabled: %q", scope)
	}
	env.idp.setRefreshOptions(true, false, "", false)
	code, _ := env.authorize(t, challenge)
	status, body := env.enroll(t, challenge, code, "enroll")
	if status != http.StatusOK {
		t.Fatalf("enroll status %d: %s", status, body)
	}
	if decodeEnrollment(t, body).Renewable {
		t.Fatalf("renewal allowed while refresh is disabled")
	}
}

func TestServiceMultipleRedirectURIsAndLoopbackPorts(t *testing.T) {
	env := newTestEnvironment(t, func(cfg *Config) {
		cfg.OIDCRedirectURI = "com.vanora.app:/oauth/callback"
		cfg.OIDCRedirectURIs = []string{
			"http://127.0.0.1/oauth/callback",
			"https://app.example.com/oauth/callback",
		}
	})

	// Exact custom scheme (default when omitted).
	status, body := env.post(t, "/v1/identity/challenges", challengeRequest{
		Purpose:   "enroll",
		PublicKey: base64.RawURLEncoding.EncodeToString(env.public),
	})
	if status != http.StatusOK {
		t.Fatalf("default redirect status %d: %s", status, body)
	}
	var ch challengeResponse
	if err := json.Unmarshal(body, &ch); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(ch.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("redirect_uri"); got != "com.vanora.app:/oauth/callback" {
		t.Fatalf("default redirect_uri = %q", got)
	}

	// RFC 8252 ephemeral loopback port matches portless allowlist entry and exchanges code with exact URI.
	loopbackURI := "http://127.0.0.1:45678/oauth/callback"
	status, body = env.post(t, "/v1/identity/challenges", challengeRequest{
		Purpose:     "enroll",
		PublicKey:   base64.RawURLEncoding.EncodeToString(env.public),
		RedirectURI: loopbackURI,
	})
	if status != http.StatusOK {
		t.Fatalf("loopback redirect status %d: %s", status, body)
	}
	var chLoop challengeResponse
	if err := json.Unmarshal(body, &chLoop); err != nil {
		t.Fatal(err)
	}
	parsed, err = url.Parse(chLoop.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("redirect_uri"); got != loopbackURI {
		t.Fatalf("loopback redirect_uri = %q, want %q", got, loopbackURI)
	}
	code, _ := env.authorize(t, chLoop)
	status, body = env.enroll(t, chLoop, code, "enroll")
	if status != http.StatusOK {
		t.Fatalf("enroll with loopback redirect status %d: %s", status, body)
	}

	// Reject unlisted redirect URIs or wrong loopback path.
	for _, bad := range []string{
		"http://127.0.0.1:45678/other",
		"http://localhost:45678/oauth/callback",
		"https://evil.example.com/oauth/callback",
		"com.evil.app:/oauth/callback",
	} {
		status, body = env.post(t, "/v1/identity/challenges", challengeRequest{
			Purpose:     "enroll",
			PublicKey:   base64.RawURLEncoding.EncodeToString(env.public),
			RedirectURI: bad,
		})
		if status != http.StatusBadRequest || errorCode(t, body) != "invalid_redirect_uri" {
			t.Fatalf("redirect %q status %d: %s", bad, status, body)
		}
	}
}
