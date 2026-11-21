// Package account enrolls a native Vanora endpoint with the identity
// authority using the host client's existing authentication token and supplies
// short-lived credentials to the signaling transport. It is shared by the
// desktop and mobile clients: the host supplies secure storage (an OS keyring
// on desktop, platform secure storage on mobile) and provides the host user's
// live authentication token.
//
// An Account owns the endpoint Ed25519 key, the certificate that binds it to
// the signed-in owner, and an optional opaque renewal handle. The key and
// handle are written to the store as one opaque serialized value. The host
// never parses that value and the package never logs it or the host auth token.
package account

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
)

const (
	stateVersion = 1

	requestTimeout   = 15 * time.Second
	maxResponseBytes = 128 << 10
	maxTokenBytes    = 16384
	maxHandleBytes   = 8192

	// Each explicit Current call obtains a fresh lease; a lease is only reused
	// for this short window so concurrent callers share one request without
	// letting a tight refresh loop keep a stale authority decision forever.
	leaseCacheWindow = 3 * time.Second
	// Certificates live at most 15 minutes, so renewal starts well before
	// expiry instead of waiting for the connection to fail.
	certificateRenewMargin = 2 * time.Minute
	// A failed renewal is retried after this delay while the current
	// certificate is still valid.
	renewalRetryDelay = 15 * time.Second

	challengePath = "/v1/identity/challenges"
	enrollPath    = "/v1/identity/enroll"
	leasePath     = "/v1/identity/lease"
	renewPath     = "/v1/identity/renew"
)

// Errors reported by an Account. Callers may use errors.Is to distinguish
// them without depending on message text.
var (
	// ErrStateInvalid means the stored state could not be authenticated or
	// is structurally inconsistent. The account is not usable and must not
	// silently generate a replacement key: the host has to clear the store
	// (typically after telling the user to sign in again) before enrolling.
	ErrStateInvalid = errors.New("account: stored state is invalid")
	// ErrAuthorityChanged means the stored state belongs to a different
	// pinned authority than the one this Account was opened with.
	ErrAuthorityChanged = errors.New("account: stored state belongs to another authority")
	// ErrNotEnrolled means no certificate has been obtained or saved yet.
	ErrNotEnrolled = errors.New("account: endpoint is not enrolled")
	// ErrCredential means the authority returned a certificate, lease or
	// identity that does not bind the expected endpoint key, user or device,
	// or definitively rejected this endpoint's standing credentials.
	ErrCredential = errors.New("account: identity credential rejected")
	// ErrExpired means the certificate has expired and cannot be renewed
	// without a fresh host auth token or re-enrollment.
	ErrExpired = errors.New("account: endpoint certificate expired")
	// ErrAlreadyEnrolled means enrollment verified an account or device
	// different from the one already stored. Replacing the local account
	// requires an explicit Reset; reauthenticating the same account does not.
	ErrAlreadyEnrolled = errors.New("account: token belongs to a different account; reset to replace the local account")
)

// APIError is a non-success response from the identity authority. Code is the
// machine-readable value from the response body (for example
// "token_rejected", "refresh_rejected", or "provider_unavailable").
type APIError struct {
	StatusCode int
	Code       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("account: identity service returned HTTP %d (%s)", e.StatusCode, e.Code)
}

// Store persists the account's opaque serialized state. The host supplies it:
// an OS keyring on desktop and platform secure storage on mobile.
//
// Load returns an empty string with a nil error when nothing has been saved
// yet. Save must replace the previous value atomically and durably. The value
// contains the endpoint private key and optional renewal handle; it must never
// be logged or written to ordinary application storage.
type Store interface {
	Load() (string, error)
	Save(string) error
}

// Account is the shared identity state of one native endpoint. Its methods are
// safe for concurrent use; network operations are serialized.
type Account struct {
	mu sync.Mutex

	base      *url.URL
	ca        ed25519.PublicKey
	authority string
	store     Store
	client    *http.Client
	now       func() time.Time

	key           ed25519.PrivateKey
	certificate   string
	certExpires   time.Time
	userID        string
	deviceID      string
	refreshHandle string

	// In-memory host auth token used for direct-token renewal; never persisted.
	liveToken     string
	tokenProvider func(context.Context) (string, error)

	lease        string
	leaseCert    string
	leaseIssued  time.Time
	leaseExpires time.Time

	renewRetry      time.Time
	renewErr        error
	renewalDenied   error
	deniedTokenHash [sha256.Size]byte
	hasDeniedToken  bool
}

// persisted is the sole serialized representation kept by the host. Its
// layout is private to this package; bump stateVersion when it changes.
type persisted struct {
	Version       int    `json:"version"`
	Authority     string `json:"authority"`
	Seed          string `json:"seed"`
	Certificate   string `json:"certificate,omitempty"`
	UserID        string `json:"user_id,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
	RefreshHandle string `json:"refresh_handle,omitempty"`
	// RenewalDenied records a definitive authority rejection of the endpoint's
	// standing credentials. It stays until a successful re-enrollment or fresh
	// host token renewal.
	RenewalDenied string `json:"renewal_denied,omitempty"`
}

// New opens the account stored in store for the authority at baseURL. baseURL
// must be HTTPS, or HTTP on a loopback host for local development; it may
// include a path prefix. caHex is the pinned authority public key accepted by
// identity.ParsePublicKey (hex or base64).
//
// New never writes to the store. An absent value yields an account that is not
// yet enrolled. A present but invalid value returns ErrStateInvalid or
// ErrAuthorityChanged instead of generating a new key, so corrupt state cannot
// silently turn into a different device identity.
func New(baseURL, caHex string, store Store) (*Account, error) {
	return newAccount(baseURL, caHex, store, time.Now)
}

// newAccount is New with an injectable clock so tests can exercise restarts at
// simulated times without changing the exported contract.
func newAccount(baseURL, caHex string, store Store, now func() time.Time) (*Account, error) {
	if store == nil {
		return nil, errors.New("account: store is required")
	}
	base, err := parseServiceURL(baseURL)
	if err != nil {
		return nil, err
	}
	ca, err := identity.ParsePublicKey([]byte(caHex))
	if err != nil {
		return nil, fmt.Errorf("account: parse pinned authority key: %w", err)
	}
	a := &Account{
		base:      base,
		ca:        ca,
		authority: authorityFingerprint(ca),
		store:     store,
		client:    newHTTPClient(),
		now:       now,
	}
	raw, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("account: load state: %w", err)
	}
	if raw == "" {
		return a, nil
	}
	if err := a.restore(raw); err != nil {
		return nil, err
	}
	return a, nil
}

// UserID returns the stable remote user identifier bound by the current
// certificate, or "" before enrollment.
func (a *Account) UserID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.userID
}

// DeviceID returns the stable endpoint device identifier bound by the current
// certificate, or "" before enrollment.
func (a *Account) DeviceID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deviceID
}

// SetTokenProvider registers a callback that returns the host client's current
// authentication token on demand during certificate renewal. The callback must
// not call back into Account. Passing nil clears the provider.
func (a *Account) SetTokenProvider(fn func(context.Context) (string, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokenProvider = fn
}

// UpdateToken updates the in-memory host client authentication token used for
// direct-token certificate renewal. The token is never persisted to Store.
func (a *Account) UpdateToken(token string) error {
	tok := strings.TrimSpace(token)
	if tok == "" || len(tok) > maxTokenBytes {
		return errors.New("account: client auth token is required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.liveToken = tok
	a.renewRetry = time.Time{}
	a.renewErr = nil
	return nil
}

// Reset forgets the local account and replaces the endpoint key. It is the only
// way to switch to a different account: enrolling with a token belonging to
// another identity is rejected with ErrAlreadyEnrolled until Reset succeeds.
// Hosts must obtain explicit local user confirmation before calling it, because
// the old device identity cannot be recovered from this device. Reauthenticating
// the same account does not require Reset.
//
// Reset does not contact the identity authority. The new state is saved before
// in-memory identity is changed, so a storage failure leaves the previous
// account usable.
func (a *Account) Reset() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("account: generate endpoint key: %w", err)
	}
	if err := a.saveKeyOnlyLocked(key); err != nil {
		return err
	}
	a.key = key
	a.certificate = ""
	a.certExpires = time.Time{}
	a.userID = ""
	a.deviceID = ""
	a.refreshHandle = ""
	a.liveToken = ""
	a.lease = ""
	a.leaseCert = ""
	a.leaseIssued = time.Time{}
	a.leaseExpires = time.Time{}
	a.renewRetry = time.Time{}
	a.renewErr = nil
	a.renewalDenied = nil
	a.deniedTokenHash = [sha256.Size]byte{}
	a.hasDeniedToken = false
	return nil
}

// Enroll binds this endpoint's Ed25519 key to the account represented by the
// host client's existing authentication token. The endpoint key is created and
// persisted on the first call, so an interrupted enrollment reuses the same
// device identity next time. Enroll is also used to reauthenticate an existing
// account (for example after certificate expiry or credential rejection); the
// verified identity must match the stored account unless Reset is called first.
func (a *Account) Enroll(ctx context.Context, token string) error {
	tok := strings.TrimSpace(token)
	if tok == "" || len(tok) > maxTokenBytes {
		return errors.New("account: client auth token is required")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.key == nil {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("account: generate endpoint key: %w", err)
		}
		a.key = key
		if err := a.saveLocked(); err != nil {
			a.key = nil
			return err
		}
	}

	pub := a.key.Public().(ed25519.PublicKey)
	var chResp challengeResponse
	if err := a.post(ctx, challengePath, challengeRequest{
		Purpose:   "enroll",
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	}, &chResp); err != nil {
		return err
	}
	now := a.now()
	if chResp.ChallengeID == "" || chResp.Nonce == "" || chResp.ExpiresAt == 0 {
		return fmt.Errorf("%w: incomplete challenge response", ErrCredential)
	}
	expires := time.Unix(chResp.ExpiresAt, 0).UTC()
	if !expires.After(now) {
		return fmt.Errorf("%w: expired challenge response", ErrCredential)
	}

	proof := identity.ProofMessage(chResp.ChallengeID, chResp.Nonce, "enroll", pub)
	var resp enrollResponse
	if err := a.post(ctx, enrollPath, enrollRequest{
		ChallengeID: chResp.ChallengeID,
		Token:       tok,
		Signature:   encodeSignature(ed25519.Sign(a.key, proof)),
	}, &resp); err != nil {
		return err
	}
	if err := a.applyEnrollmentLocked(resp, a.now()); err != nil {
		return err
	}
	a.liveToken = tok
	a.deniedTokenHash = [sha256.Size]byte{}
	a.hasDeniedToken = false
	return nil
}

// Current returns credentials for a new signaling connection together with a
// fresh lease. Each explicit call asks the authority for a new lease (a cached
// lease is reused only for leaseCacheWindow so concurrent callers share one
// request). When the certificate is close to expiry and a live token or renewal
// handle exists, Current renews it first. A definitive 401 renewal denial
// (token_rejected, refresh_rejected or identity_verification_failed) is
// returned immediately and keeps denying until a fresh host token is supplied
// or Enroll succeeds, rather than falling back to the still valid certificate.
func (a *Account) Current(ctx context.Context) (*endpoint.Credentials, endpoint.LeaseProof, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	if a.key == nil || a.certificate == "" {
		return nil, endpoint.LeaseProof{}, ErrNotEnrolled
	}
	if err := a.ensureCertificateLocked(ctx, now); err != nil {
		return nil, endpoint.LeaseProof{}, err
	}

	principal, err := identity.VerifyCertificate(a.certificate, a.ca, now)
	if err != nil {
		return nil, endpoint.LeaseProof{}, fmt.Errorf("%w: %v", ErrCredential, err)
	}
	if !principal.PublicKey.Equal(a.key.Public()) || principal.DeviceID != a.deviceID || principal.RemoteUserID() != a.userID {
		return nil, endpoint.LeaseProof{}, fmt.Errorf("%w: certificate no longer matches this endpoint", ErrCredential)
	}

	lease, err := a.leaseLocked(ctx, now, principal)
	if err != nil {
		return nil, endpoint.LeaseProof{}, err
	}
	credentials, err := endpoint.OpenCredentials(a.certificate, a.key, a.ca, now)
	if err != nil {
		return nil, endpoint.LeaseProof{}, fmt.Errorf("%w: %v", ErrCredential, err)
	}
	return credentials, endpoint.LeaseProof{Certificate: a.certificate, Lease: lease}, nil
}

func (a *Account) applyEnrollmentLocked(resp enrollResponse, now time.Time) error {
	if resp.Certificate == "" {
		return fmt.Errorf("%w: enrollment returned no certificate", ErrCredential)
	}
	principal, err := identity.VerifyCertificate(resp.Certificate, a.ca, now)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCredential, err)
	}
	if !principal.PublicKey.Equal(a.key.Public()) {
		return fmt.Errorf("%w: certificate does not bind this endpoint key", ErrCredential)
	}
	if resp.DeviceID != principal.DeviceID || resp.RemoteUserID != principal.RemoteUserID() {
		return fmt.Errorf("%w: enrollment identifiers do not match the certificate", ErrCredential)
	}
	if a.certificate != "" && (principal.DeviceID != a.deviceID || principal.RemoteUserID() != a.userID) {
		return fmt.Errorf("%w: enrollment returned a different account or device", ErrAlreadyEnrolled)
	}
	if resp.ExpiresAt != principal.Expires.Unix() {
		return fmt.Errorf("%w: enrollment expiry does not match the certificate", ErrCredential)
	}
	if !now.Before(principal.Expires) {
		return fmt.Errorf("%w: certificate is already expired", ErrCredential)
	}
	if resp.Renewable && resp.RefreshHandle == "" {
		return fmt.Errorf("%w: renewable enrollment returned no refresh handle", ErrCredential)
	}
	if !resp.Renewable && resp.RefreshHandle != "" {
		return fmt.Errorf("%w: non-renewable enrollment returned a refresh handle", ErrCredential)
	}
	if len(resp.RefreshHandle) > maxHandleBytes {
		return fmt.Errorf("%w: refresh handle is too large", ErrCredential)
	}

	previous := a.credentialLocked()
	a.certificate = resp.Certificate
	a.certExpires = principal.Expires
	a.userID = principal.RemoteUserID()
	a.deviceID = principal.DeviceID
	a.refreshHandle = resp.RefreshHandle
	a.clearLeaseLocked()
	a.renewRetry = time.Time{}
	a.renewErr = nil
	a.renewalDenied = nil
	if err := a.saveLocked(); err != nil {
		a.restoreCredentialLocked(previous)
		return err
	}
	return nil
}

// resolveLiveTokenLocked returns the current host auth token if available.
func (a *Account) resolveLiveTokenLocked(ctx context.Context) (string, bool, error) {
	if a.tokenProvider != nil {
		tok, err := a.tokenProvider(ctx)
		if err != nil {
			return "", true, err
		}
		tok = strings.TrimSpace(tok)
		if tok != "" {
			if len(tok) > maxTokenBytes {
				return "", true, errors.New("account: token provider returned oversized token")
			}
			return tok, true, nil
		}
	}
	if a.liveToken != "" {
		return a.liveToken, false, nil
	}
	return "", false, nil
}

// ensureCertificateLocked renews the certificate when it is close to expiry or
// when recovering from a denial with a fresh host auth token.
func (a *Account) ensureCertificateLocked(ctx context.Context, now time.Time) error {
	if a.renewalDenied != nil {
		tok, _, err := a.resolveLiveTokenLocked(ctx)
		if err != nil || tok == "" {
			return fmt.Errorf("%w: certificate renewal: %v", ErrCredential, a.renewalDenied)
		}
		sum := sha256.Sum256([]byte(tok))
		if a.hasDeniedToken && sum == a.deniedTokenHash {
			return fmt.Errorf("%w: certificate renewal: %v", ErrCredential, a.renewalDenied)
		}
		// A genuinely new host token was supplied after a denial; attempt
		// direct-token renewal immediately and never fall back to the denied cert.
		if err := a.renewWithTokenLocked(ctx, now, tok); err != nil {
			a.renewErr = err
			if isDefinitiveRenewalDenial(err) {
				a.deniedTokenHash = sum
				a.hasDeniedToken = true
				a.renewalDenied = err
				_ = a.saveLocked()
			}
			return fmt.Errorf("%w: certificate renewal: %v", ErrCredential, err)
		}
		a.renewRetry = time.Time{}
		a.renewErr = nil
		return nil
	}

	if now.Before(a.certExpires) && a.certExpires.Sub(now) > certificateRenewMargin {
		return nil
	}

	hasToken := a.liveToken != "" || a.tokenProvider != nil
	if !hasToken && a.refreshHandle == "" {
		if now.Before(a.certExpires) {
			return nil
		}
		return ErrExpired
	}
	if now.Before(a.renewRetry) {
		if now.Before(a.certExpires) {
			return nil
		}
		if a.renewErr != nil {
			return fmt.Errorf("%w: %v", ErrExpired, a.renewErr)
		}
		return ErrExpired
	}

	err := a.renewLocked(ctx, now)
	if err != nil {
		a.renewErr = err
		if isDefinitiveRenewalDenial(err) {
			a.renewalDenied = err
			if saveErr := a.saveLocked(); saveErr != nil {
				return fmt.Errorf("%w: certificate renewal: %v (persist denial: %v)", ErrCredential, err, saveErr)
			}
			return fmt.Errorf("%w: certificate renewal: %v", ErrCredential, err)
		}
		if errors.Is(err, ErrCredential) {
			return fmt.Errorf("account: certificate renewal: %w", err)
		}
		a.renewRetry = now.Add(renewalRetryDelay)
		if now.Before(a.certExpires) {
			return nil
		}
		return fmt.Errorf("%w: renewal failed: %v", ErrExpired, err)
	}
	a.renewRetry = time.Time{}
	a.renewErr = nil
	return nil
}

// isDefinitiveRenewalDenial reports whether the authority explicitly rejected
// this endpoint's standing credentials, rather than failing transiently.
func isDefinitiveRenewalDenial(err error) bool {
	var api *APIError
	return errors.As(err, &api) && api.StatusCode == http.StatusUnauthorized && validRenewalDenialCode(api.Code)
}

func validRenewalDenialCode(code string) bool {
	return code == "refresh_rejected" || code == "token_rejected" || code == "identity_verification_failed"
}

func renewalDenialCode(err error) string {
	var api *APIError
	if errors.As(err, &api) && validRenewalDenialCode(api.Code) {
		return api.Code
	}
	return ""
}

func renewalDenialError(code string) error {
	return &APIError{StatusCode: http.StatusUnauthorized, Code: code}
}

func (a *Account) renewLocked(ctx context.Context, now time.Time) error {
	tok, fromProvider, tokErr := a.resolveLiveTokenLocked(ctx)
	if tokErr != nil && a.refreshHandle == "" {
		return tokErr
	}
	if tok != "" {
		err := a.renewWithTokenLocked(ctx, now, tok)
		if err == nil {
			return nil
		}
		// If a cached startup token expired while an unattended refresh handle
		// is still held, drop the stale cached token and fall back to the handle.
		var api *APIError
		if errors.As(err, &api) && api.StatusCode == http.StatusUnauthorized && api.Code == "token_rejected" {
			if !fromProvider && a.liveToken == tok {
				a.liveToken = ""
			}
			if a.refreshHandle != "" {
				return a.renewWithHandleLocked(ctx, now)
			}
			a.deniedTokenHash = sha256.Sum256([]byte(tok))
			a.hasDeniedToken = true
		}
		return err
	}
	return a.renewWithHandleLocked(ctx, now)
}

func (a *Account) renewWithTokenLocked(ctx context.Context, now time.Time, token string) error {
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	pub := a.key.Public().(ed25519.PublicKey)
	proof := identity.DirectRenewProofMessage(nonce, token, pub)
	var resp renewResponse
	if err := a.post(ctx, renewPath, renewRequest{
		Token:     token,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		Nonce:     nonce,
		Signature: encodeSignature(ed25519.Sign(a.key, proof)),
	}, &resp); err != nil {
		return err
	}
	if err := a.applyRenewalLocked(resp, now, false); err != nil {
		return err
	}
	a.deniedTokenHash = [sha256.Size]byte{}
	a.hasDeniedToken = false
	return nil
}

func (a *Account) renewWithHandleLocked(ctx context.Context, now time.Time) error {
	if a.refreshHandle == "" {
		return errors.New("account: no refresh handle or live token")
	}
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	oldHandle := a.refreshHandle
	proof := identity.RenewProofMessage(nonce, oldHandle)
	var resp renewResponse
	if err := a.post(ctx, renewPath, renewRequest{
		RefreshHandle: oldHandle,
		Nonce:         nonce,
		Signature:     encodeSignature(ed25519.Sign(a.key, proof)),
	}, &resp); err != nil {
		return err
	}
	return a.applyRenewalLocked(resp, now, true)
}

func (a *Account) applyRenewalLocked(resp renewResponse, now time.Time, requireHandle bool) error {
	if resp.Certificate == "" {
		return fmt.Errorf("%w: renewal returned no certificate", ErrCredential)
	}
	principal, err := identity.VerifyCertificate(resp.Certificate, a.ca, now)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCredential, err)
	}
	if !principal.PublicKey.Equal(a.key.Public()) {
		return fmt.Errorf("%w: renewed certificate does not bind this endpoint key", ErrCredential)
	}
	if principal.DeviceID != a.deviceID || principal.RemoteUserID() != a.userID {
		return fmt.Errorf("%w: renewal changed the endpoint identity", ErrCredential)
	}
	if resp.DeviceID != principal.DeviceID || resp.RemoteUserID != principal.RemoteUserID() {
		return fmt.Errorf("%w: renewal identifiers do not match the certificate", ErrCredential)
	}
	if resp.ExpiresAt != principal.Expires.Unix() {
		return fmt.Errorf("%w: renewal expiry does not match the certificate", ErrCredential)
	}
	if !now.Before(principal.Expires) {
		return fmt.Errorf("%w: renewed certificate is already expired", ErrCredential)
	}
	if requireHandle && resp.RefreshHandle == "" {
		return fmt.Errorf("%w: renewal returned no usable refresh handle", ErrCredential)
	}
	if len(resp.RefreshHandle) > maxHandleBytes {
		return fmt.Errorf("%w: renewal returned oversized refresh handle", ErrCredential)
	}

	previous := a.credentialLocked()
	a.certificate = resp.Certificate
	a.certExpires = principal.Expires
	if resp.RefreshHandle != "" {
		a.refreshHandle = resp.RefreshHandle
	}
	a.renewalDenied = nil
	a.clearLeaseLocked()
	if err := a.saveLocked(); err != nil {
		a.restoreCredentialLocked(previous)
		return err
	}
	return nil
}

func (a *Account) leaseLocked(ctx context.Context, now time.Time, principal identity.Principal) (string, error) {
	if a.lease != "" && a.leaseCert == a.certificate && now.Sub(a.leaseIssued) <= leaseCacheWindow && now.Before(a.leaseExpires) {
		return a.lease, nil
	}
	nonce, err := newNonce()
	if err != nil {
		return "", err
	}
	var resp leaseResponse
	if err := a.post(ctx, leasePath, leaseRequest{
		Certificate: a.certificate,
		Nonce:       nonce,
		Signature:   encodeSignature(ed25519.Sign(a.key, identity.LeaseProofMessage(nonce, a.certificate))),
	}, &resp); err != nil {
		return "", err
	}
	if resp.Lease == "" {
		return "", fmt.Errorf("%w: lease response is empty", ErrCredential)
	}
	if resp.DeviceID != principal.DeviceID || resp.RemoteUserID != principal.RemoteUserID() {
		return "", fmt.Errorf("%w: lease identifiers do not match the certificate", ErrCredential)
	}
	expires, err := identity.VerifyEndpointLease(resp.Lease, a.ca, now, a.certificate, principal)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCredential, err)
	}
	if !now.Before(expires) || expires.After(principal.Expires) {
		return "", fmt.Errorf("%w: lease validity is outside the certificate", ErrCredential)
	}
	if resp.ExpiresAt != expires.Unix() {
		return "", fmt.Errorf("%w: lease expiry does not match the lease", ErrCredential)
	}
	a.lease = resp.Lease
	a.leaseCert = a.certificate
	a.leaseIssued = now
	a.leaseExpires = expires
	return a.lease, nil
}

type credential struct {
	certificate   string
	certExpires   time.Time
	userID        string
	deviceID      string
	refreshHandle string
	renewalDenied error
}

func (a *Account) credentialLocked() credential {
	return credential{
		certificate:   a.certificate,
		certExpires:   a.certExpires,
		userID:        a.userID,
		deviceID:      a.deviceID,
		refreshHandle: a.refreshHandle,
		renewalDenied: a.renewalDenied,
	}
}

func (a *Account) restoreCredentialLocked(c credential) {
	a.certificate = c.certificate
	a.certExpires = c.certExpires
	a.userID = c.userID
	a.deviceID = c.deviceID
	a.refreshHandle = c.refreshHandle
	a.renewalDenied = c.renewalDenied
	a.clearLeaseLocked()
}

func (a *Account) clearLeaseLocked() {
	a.lease = ""
	a.leaseCert = ""
	a.leaseIssued = time.Time{}
	a.leaseExpires = time.Time{}
}

func (a *Account) saveLocked() error {
	if a.key == nil {
		return errors.New("account: no endpoint key")
	}
	state := persisted{
		Version:       stateVersion,
		Authority:     a.authority,
		Seed:          base64.RawURLEncoding.EncodeToString(a.key.Seed()),
		Certificate:   a.certificate,
		UserID:        a.userID,
		DeviceID:      a.deviceID,
		RefreshHandle: a.refreshHandle,
		RenewalDenied: renewalDenialCode(a.renewalDenied),
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("account: encode state: %w", err)
	}
	if err := a.store.Save(string(data)); err != nil {
		return fmt.Errorf("account: save state: %w", err)
	}
	return nil
}

func (a *Account) saveKeyOnlyLocked(key ed25519.PrivateKey) error {
	state := persisted{
		Version:   stateVersion,
		Authority: a.authority,
		Seed:      base64.RawURLEncoding.EncodeToString(key.Seed()),
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("account: encode state: %w", err)
	}
	if err := a.store.Save(string(data)); err != nil {
		return fmt.Errorf("account: save state: %w", err)
	}
	return nil
}

func (a *Account) restore(raw string) error {
	var state persisted
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("%w: %v", ErrStateInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing state data", ErrStateInvalid)
	}
	if state.Version != stateVersion {
		return fmt.Errorf("%w: unsupported version %d", ErrStateInvalid, state.Version)
	}
	if state.Authority != a.authority {
		return ErrAuthorityChanged
	}
	seed, err := base64.RawURLEncoding.DecodeString(state.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("%w: endpoint seed", ErrStateInvalid)
	}
	a.key = ed25519.NewKeyFromSeed(seed)

	if state.Certificate == "" {
		if state.UserID != "" || state.DeviceID != "" || state.RefreshHandle != "" || state.RenewalDenied != "" {
			return fmt.Errorf("%w: credentials without a certificate", ErrStateInvalid)
		}
		return nil
	}
	if state.UserID == "" || state.DeviceID == "" || len(state.Certificate) > maxResponseBytes {
		return fmt.Errorf("%w: certificate without identity", ErrStateInvalid)
	}
	if state.RenewalDenied != "" && !validRenewalDenialCode(state.RenewalDenied) {
		return fmt.Errorf("%w: unknown renewal denial", ErrStateInvalid)
	}
	if state.RenewalDenied == "refresh_rejected" && state.RefreshHandle == "" {
		return fmt.Errorf("%w: renewal denial without a refresh handle", ErrStateInvalid)
	}
	a.certificate = state.Certificate
	a.userID = state.UserID
	a.deviceID = state.DeviceID
	a.refreshHandle = state.RefreshHandle
	if state.RenewalDenied != "" {
		a.renewalDenied = renewalDenialError(state.RenewalDenied)
	}

	principal, err := identity.VerifyCertificate(state.Certificate, a.ca, a.now())
	switch {
	case err == nil:
		if principal.DeviceID != a.deviceID || principal.RemoteUserID() != a.userID || !principal.PublicKey.Equal(a.key.Public()) {
			return fmt.Errorf("%w: certificate binding", ErrStateInvalid)
		}
		a.certExpires = principal.Expires
	case errors.Is(err, identity.ErrCertificateExpired):
		// The signature and claims were still verified; only the validity
		// window has passed. Keep the state so renewal can repair it, and
		// mark it expired so the next Current renews or fails closed.
		a.certExpires = time.Time{}
	default:
		return fmt.Errorf("%w: certificate: %v", ErrStateInvalid, err)
	}
	return nil
}

type challengeRequest struct {
	Purpose   string `json:"purpose"`
	PublicKey string `json:"public_key"`
}

type challengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	ExpiresAt   int64  `json:"expires_at"`
}

type enrollRequest struct {
	ChallengeID string `json:"challenge_id"`
	Token       string `json:"token"`
	Signature   string `json:"signature"`
}

type enrollResponse struct {
	Certificate   string `json:"certificate"`
	DeviceID      string `json:"device_id"`
	RemoteUserID  string `json:"remote_user_id"`
	ExpiresAt     int64  `json:"expires_at"`
	RefreshHandle string `json:"refresh_handle,omitempty"`
	Renewable     bool   `json:"renewable"`
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

type renewRequest struct {
	RefreshHandle string `json:"refresh_handle,omitempty"`
	Token         string `json:"token,omitempty"`
	PublicKey     string `json:"public_key,omitempty"`
	Nonce         string `json:"nonce"`
	Signature     string `json:"signature"`
}

type renewResponse struct {
	Certificate   string `json:"certificate"`
	RefreshHandle string `json:"refresh_handle,omitempty"`
	DeviceID      string `json:"device_id"`
	RemoteUserID  string `json:"remote_user_id"`
	ExpiresAt     int64  `json:"expires_at"`
}

var errRedirect = errors.New("account: identity service redirected the request")

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		// The authority endpoint is configured, never discovered. Following a
		// redirect could downgrade the connection or move enrollment to
		// another origin, so any redirect is a failure.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		},
	}
}

func (a *Account) post(ctx context.Context, path string, request, response any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("account: encode %s request: %w", path, err)
	}
	target := *a.base
	target.Path = strings.TrimRight(target.Path, "/") + path
	target.RawPath = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("account: build %s request: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("account: call %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return decodeAPIError(resp)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if err := decoder.Decode(response); err != nil {
		return fmt.Errorf("account: decode %s response: %w", path, err)
	}
	return nil
}

func decodeAPIError(resp *http.Response) error {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body)
	code := body.Error
	if code == "" || len(code) > 64 {
		code = "unknown_error"
	}
	return &APIError{StatusCode: resp.StatusCode, Code: code}
}

// parseServiceURL validates the configured authority base URL. HTTPS is
// required except for loopback development.
func parseServiceURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("account: identity service URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("account: parse identity service URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("account: identity service URL must be an absolute URL without credentials, query or fragment")
	}
	if err := checkTransport(u); err != nil {
		return nil, err
	}
	return u, nil
}

func checkTransport(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if loopbackHost(u.Hostname()) {
			return nil
		}
		return errors.New("account: plaintext HTTP is allowed only for loopback")
	default:
		return fmt.Errorf("account: unsupported URL scheme %q", u.Scheme)
	}
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func authorityFingerprint(ca ed25519.PublicKey) string {
	sum := sha256.Sum256(ca)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newNonce() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("account: generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(nonce[:]), nil
}

func encodeSignature(signature []byte) string {
	return base64.RawURLEncoding.EncodeToString(signature)
}
