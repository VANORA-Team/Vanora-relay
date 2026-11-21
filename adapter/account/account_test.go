package account

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
)

// memStore is an in-memory Store that records calls. Test code only.
type memStore struct {
	value   string
	loads   int
	saves   int
	loadErr error
	saveErr error
}

func (s *memStore) Load() (string, error) {
	s.loads++
	if s.loadErr != nil {
		return "", s.loadErr
	}
	return s.value, nil
}

func (s *memStore) Save(value string) error {
	s.saves++
	if s.saveErr != nil {
		return s.saveErr
	}
	s.value = value
	return nil
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fakeChallenge struct {
	id        string
	nonce     string
	state     string
	publicKey ed25519.PublicKey
	purpose   string
	expires   time.Time
}

type fakeConfig struct {
	redirect      bool
	enrollStatus  int
	enrollCode    string
	renewStatus   int
	renewCode     string
	renewSubject  string
	enrollSubject string
	badLease      bool
	leaseDevice   string
	renewable     bool
}

// fakeAuthority implements the enrollment, lease and renewal endpoints with
// the real identity.Signer, so certificates and leases verify exactly as the
// production authority's would.
type fakeAuthority struct {
	t         *testing.T
	clock     *fakeClock
	signer    *identity.Signer
	untrusted *identity.Signer
	server    *httptest.Server
	issuer    string
	subject   string
	leaseTTL  time.Duration

	mu         sync.Mutex
	config     fakeConfig
	challenges map[string]*fakeChallenge
	handles    map[string]ed25519.PublicKey
	handleSeq  int
	challengeN int
	enrollN    int
	leaseN     int
	renewN     int
}

func newFakeAuthority(t *testing.T) *fakeAuthority {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate authority key: %v", err)
	}
	signer, err := identity.NewSigner(privateKey, 10*time.Minute)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}
	untrusted, err := identity.NewSigner(otherKey, 10*time.Minute)
	if err != nil {
		t.Fatalf("new untrusted signer: %v", err)
	}
	f := &fakeAuthority{
		t:          t,
		clock:      newFakeClock(time.Now().UTC().Truncate(time.Second)),
		signer:     signer,
		untrusted:  untrusted,
		issuer:     "https://idp.example",
		subject:    "user-42",
		leaseTTL:   45 * time.Second,
		config:     fakeConfig{renewable: true},
		challenges: make(map[string]*fakeChallenge),
		handles:    make(map[string]ed25519.PublicKey),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(challengePath, f.handleChallenge)
	mux.HandleFunc(enrollPath, f.handleEnroll)
	mux.HandleFunc(leasePath, f.handleLease)
	mux.HandleFunc(renewPath, f.handleRenew)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAuthority) caHex() string {
	return hex.EncodeToString(f.signer.PublicKey())
}

func (f *fakeAuthority) set(fn func(*fakeConfig)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.config)
}

func (f *fakeAuthority) cfg() fakeConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.config
}

func (f *fakeAuthority) calls() (challenges, enrolls, leases, renews int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.challengeN, f.enrollN, f.leaseN, f.renewN
}

func (f *fakeAuthority) handleChallenge(w http.ResponseWriter, r *http.Request) {
	cfg := f.cfg()
	if cfg.redirect {
		http.Redirect(w, r, "https://elsewhere.example/collect", http.StatusFound)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var req struct {
		Purpose   string `json:"purpose"`
		PublicKey string `json:"public_key"`
	}
	if !decodeBody(f.t, w, r, &req) {
		return
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "public_key_invalid")
		return
	}
	if req.Purpose != "enroll" {
		writeError(w, http.StatusBadRequest, "purpose_invalid")
		return
	}
	id, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "random_failed")
		return
	}
	nonce, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "random_failed")
		return
	}
	state, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "random_failed")
		return
	}
	now := f.clock.Now()
	f.mu.Lock()
	f.challengeN++
	f.challenges[id] = &fakeChallenge{
		id:        id,
		nonce:     nonce,
		state:     state,
		publicKey: ed25519.PublicKey(publicKey),
		purpose:   req.Purpose,
		expires:   now.Add(5 * time.Minute),
	}
	f.mu.Unlock()

	writeJSON(f.t, w, http.StatusOK, map[string]any{
		"challenge_id":          id,
		"nonce":                 nonce,
		"state":                 state,
		"code_challenge":        "challenge",
		"code_challenge_method": "S256",
		"authorization_url":     "https://idp.example/authorize?state=" + url.QueryEscape(state),
		"expires_at":            now.Add(5 * time.Minute).Unix(),
	})
}

func (f *fakeAuthority) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challenge_id"`
		Code        string `json:"code"`
		State       string `json:"state"`
		Signature   string `json:"signature"`
	}
	if !decodeBody(f.t, w, r, &req) {
		return
	}
	now := f.clock.Now()
	f.mu.Lock()
	f.enrollN++
	challenge := f.challenges[req.ChallengeID]
	cfg := f.config
	f.mu.Unlock()
	if challenge == nil || challenge.purpose != "enroll" || challenge.state != req.State {
		writeError(w, http.StatusBadRequest, "challenge_invalid")
		return
	}
	signature, ok := decodeSignature(req.Signature)
	if !ok || !ed25519.Verify(challenge.publicKey, identity.ProofMessage(challenge.id, challenge.nonce, challenge.purpose, challenge.publicKey), signature) {
		writeError(w, http.StatusUnauthorized, "proof_invalid")
		return
	}
	if cfg.enrollStatus != 0 {
		// The challenge is single use even when enrollment fails.
		f.mu.Lock()
		delete(f.challenges, challenge.id)
		f.mu.Unlock()
		writeError(w, cfg.enrollStatus, cfg.enrollCode)
		return
	}

	subject := f.subject
	if cfg.enrollSubject != "" {
		subject = cfg.enrollSubject
	}
	certificate, err := f.signer.Issue(f.issuer, subject, challenge.publicKey, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue_failed")
		return
	}
	principal, err := identity.VerifyCertificate(certificate, f.signer.PublicKey(), now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue_failed")
		return
	}
	handle := ""
	if cfg.renewable {
		handle = f.registerHandle(challenge.publicKey)
	}
	f.mu.Lock()
	delete(f.challenges, challenge.id)
	f.mu.Unlock()

	writeJSON(f.t, w, http.StatusOK, map[string]any{
		"certificate":    certificate,
		"device_id":      principal.DeviceID,
		"remote_user_id": principal.RemoteUserID(),
		"expires_at":     principal.Expires.Unix(),
		"refresh_handle": handle,
		"renewable":      cfg.renewable,
	})
}

func (f *fakeAuthority) handleLease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Certificate string `json:"certificate"`
		Nonce       string `json:"nonce"`
		Signature   string `json:"signature"`
	}
	if !decodeBody(f.t, w, r, &req) {
		return
	}
	now := f.clock.Now()
	f.mu.Lock()
	f.leaseN++
	cfg := f.config
	f.mu.Unlock()

	principal, err := identity.VerifyCertificate(req.Certificate, f.signer.PublicKey(), now)
	if err != nil {
		writeError(w, http.StatusBadRequest, "certificate_invalid")
		return
	}
	signature, ok := decodeSignature(req.Signature)
	if !ok || !ed25519.Verify(principal.PublicKey, identity.LeaseProofMessage(req.Nonce, req.Certificate), signature) {
		writeError(w, http.StatusUnauthorized, "proof_invalid")
		return
	}
	signer := f.signer
	if cfg.badLease {
		signer = f.untrusted
	}
	lease, expires, err := signer.IssueLease(principal, req.Certificate, req.Nonce, now, f.leaseTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lease_failed")
		return
	}
	deviceID := principal.DeviceID
	if cfg.leaseDevice != "" {
		deviceID = cfg.leaseDevice
	}
	writeJSON(f.t, w, http.StatusOK, map[string]any{
		"lease":          lease,
		"device_id":      deviceID,
		"remote_user_id": principal.RemoteUserID(),
		"issued_at":      now.Unix(),
		"expires_at":     expires.Unix(),
	})
}

func (f *fakeAuthority) handleRenew(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshHandle string `json:"refresh_handle"`
		Nonce         string `json:"nonce"`
		Signature     string `json:"signature"`
	}
	if !decodeBody(f.t, w, r, &req) {
		return
	}
	f.mu.Lock()
	f.renewN++
	publicKey, ok := f.handles[req.RefreshHandle]
	cfg := f.config
	f.mu.Unlock()
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_refresh_handle")
		return
	}
	signature, ok := decodeSignature(req.Signature)
	if !ok || !ed25519.Verify(publicKey, identity.RenewProofMessage(req.Nonce, req.RefreshHandle), signature) {
		writeError(w, http.StatusUnauthorized, "proof_invalid")
		return
	}
	if cfg.renewStatus != 0 {
		writeError(w, cfg.renewStatus, cfg.renewCode)
		return
	}
	subject := f.subject
	if cfg.renewSubject != "" {
		subject = cfg.renewSubject
	}
	now := f.clock.Now()
	certificate, err := f.signer.Issue(f.issuer, subject, publicKey, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue_failed")
		return
	}
	principal, err := identity.VerifyCertificate(certificate, f.signer.PublicKey(), now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue_failed")
		return
	}
	handle := f.rotateHandle(req.RefreshHandle, publicKey)
	writeJSON(f.t, w, http.StatusOK, map[string]any{
		"certificate":    certificate,
		"refresh_handle": handle,
		"device_id":      principal.DeviceID,
		"remote_user_id": principal.RemoteUserID(),
		"expires_at":     principal.Expires.Unix(),
	})
}

func (f *fakeAuthority) registerHandle(publicKey ed25519.PublicKey) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handleSeq++
	handle := "handle-" + strconv.Itoa(f.handleSeq)
	f.handles[handle] = publicKey
	return handle
}

func (f *fakeAuthority) rotateHandle(old string, publicKey ed25519.PublicKey) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.handles, old)
	f.handleSeq++
	handle := "handle-" + strconv.Itoa(f.handleSeq)
	f.handles[handle] = publicKey
	return handle
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func decodeBody(t *testing.T, w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		t.Errorf("decode request: %v", err)
		writeError(w, http.StatusBadRequest, "body_invalid")
		return false
	}
	return true
}

func decodeSignature(value string) ([]byte, bool) {
	signature, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, false
	}
	return signature, true
}

func randomToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func newTestAccount(t *testing.T, f *fakeAuthority, store Store) *Account {
	t.Helper()
	a, err := newAccount(f.server.URL, f.caHex(), store, f.clock.Now)
	if err != nil {
		t.Fatalf("new account: %v", err)
	}
	return a
}

func enroll(t *testing.T, a *Account, f *fakeAuthority) {
	t.Helper()
	authURL, err := a.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	state := stateFromURL(t, authURL)
	if err := a.Finish(context.Background(), "authorization-code", state); err != nil {
		t.Fatalf("finish: %v", err)
	}
}

func stateFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("authorization URL has no state: %s", raw)
	}
	return state
}

func mustCurrent(t *testing.T, a *Account, f *fakeAuthority) (*endpoint.Credentials, endpoint.LeaseProof) {
	t.Helper()
	credentials, proof, err := a.Current(context.Background())
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if credentials == nil {
		t.Fatal("current returned nil credentials")
	}
	return credentials, proof
}

func decodePersisted(t *testing.T, raw string) persisted {
	t.Helper()
	var state persisted
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		t.Fatalf("decode stored state: %v", err)
	}
	return state
}

func TestEnrollLeaseCacheAndRestore(t *testing.T) {
	f := newFakeAuthority(t)
	store := &memStore{}
	a := newTestAccount(t, f, store)

	if a.UserID() != "" || a.DeviceID() != "" {
		t.Fatalf("fresh account has identity: user=%q device=%q", a.UserID(), a.DeviceID())
	}
	if _, _, err := a.Current(context.Background()); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Current before enrollment = %v, want ErrNotEnrolled", err)
	}
	if store.saves != 0 {
		t.Fatalf("New saved state")
	}

	authURL, err := a.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if !strings.HasPrefix(authURL, "https://idp.example/authorize?") {
		t.Fatalf("authorization URL = %q", authURL)
	}
	if store.saves != 1 {
		t.Fatalf("Begin did not persist the endpoint key")
	}
	if a.UserID() != "" || a.DeviceID() != "" {
		t.Fatalf("identity set before Finish")
	}
	state := stateFromURL(t, authURL)
	if err := a.Finish(context.Background(), "authorization-code", state); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	wantDevice, err := f.signer.DeviceID(f.issuer, f.subject, a.key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("derive device ID: %v", err)
	}
	wantUser := identity.RemoteUserID(f.issuer, f.subject)
	if a.UserID() != wantUser {
		t.Fatalf("UserID = %q, want %q", a.UserID(), wantUser)
	}
	if a.DeviceID() != wantDevice {
		t.Fatalf("DeviceID = %q, want %q", a.DeviceID(), wantDevice)
	}
	if store.saves != 2 {
		t.Fatalf("Finish did not persist credentials")
	}
	stateAfter := decodePersisted(t, store.value)
	if stateAfter.Certificate == "" || stateAfter.RefreshHandle == "" {
		t.Fatalf("stored state missing certificate or handle")
	}
	if stateAfter.Seed == "" || stateAfter.Authority == "" {
		t.Fatalf("stored state missing seed or authority")
	}

	credentials, proof := mustCurrent(t, a, f)
	if credentials.DeviceID() != a.DeviceID() || credentials.UserID() != a.UserID() {
		t.Fatalf("credentials identity = %q/%q", credentials.DeviceID(), credentials.UserID())
	}
	if proof.Certificate == "" || proof.Lease == "" {
		t.Fatalf("empty lease proof")
	}
	_, enrolls, leases, _ := f.calls()
	if enrolls != 1 || leases != 1 {
		t.Fatalf("calls after first Current: enroll=%d lease=%d", enrolls, leases)
	}
	principal, err := identity.VerifyCertificate(proof.Certificate, f.signer.PublicKey(), f.clock.Now())
	if err != nil {
		t.Fatalf("verify certificate: %v", err)
	}
	expires, err := identity.VerifyEndpointLease(proof.Lease, f.signer.PublicKey(), f.clock.Now(), proof.Certificate, principal)
	if err != nil {
		t.Fatalf("verify lease: %v", err)
	}
	if !expires.After(f.clock.Now()) {
		t.Fatalf("lease already expired")
	}

	// A second call immediately reuses the cached lease.
	mustCurrent(t, a, f)
	if _, _, leases, _ := f.calls(); leases != 1 {
		t.Fatalf("cached lease was not reused: lease=%d", leases)
	}

	// Reuse is bounded so an overfrequent caller still observes authority
	// changes promptly.
	f.clock.Advance(leaseCacheWindow + time.Millisecond)
	_, proof2 := mustCurrent(t, a, f)
	if _, _, leases, _ := f.calls(); leases != 2 {
		t.Fatalf("stale cached lease was not replaced: lease=%d", leases)
	}
	if proof2.Lease == proof.Lease {
		t.Fatalf("lease was not replaced after the cache window")
	}

	f.clock.Advance(f.leaseTTL + time.Second)
	_, proof3 := mustCurrent(t, a, f)
	if _, _, leases, _ := f.calls(); leases != 3 {
		t.Fatalf("expired lease was not replaced: lease=%d", leases)
	}
	if proof3.Lease == proof2.Lease {
		t.Fatalf("expired lease was not replaced")
	}

	// Restoring must not write and must reuse the same device identity.
	saves := store.saves
	loads := store.loads
	restored := newTestAccount(t, f, store)
	if store.saves != saves {
		t.Fatalf("restore wrote state")
	}
	if store.loads != loads+1 {
		t.Fatalf("restore did not load state")
	}
	if restored.UserID() != a.UserID() || restored.DeviceID() != a.DeviceID() {
		t.Fatalf("restored identity = %q/%q", restored.UserID(), restored.DeviceID())
	}
	mustCurrent(t, restored, f)
	if _, _, leases, _ := f.calls(); leases != 4 {
		t.Fatalf("restored account did not obtain a lease: lease=%d", leases)
	}
}

func TestRenewalReplacesCertificateAndHandle(t *testing.T) {
	f := newFakeAuthority(t)
	store := &memStore{}
	a := newTestAccount(t, f, store)
	enroll(t, a, f)
	before := decodePersisted(t, store.value)

	// Restore first, then renew the restored certificate.
	b := newTestAccount(t, f, store)
	f.clock.Advance(7*time.Minute + 59*time.Second)
	mustCurrent(t, b, f)
	if _, _, _, renews := f.calls(); renews != 0 {
		t.Fatalf("renewed before the renewal margin: renew=%d", renews)
	}

	f.clock.Advance(2 * time.Second)
	saves := store.saves
	_, proof := mustCurrent(t, b, f)
	if _, _, _, renews := f.calls(); renews != 1 {
		t.Fatalf("certificate was not renewed: renew=%d", renews)
	}
	after := decodePersisted(t, store.value)
	if after.Certificate == before.Certificate {
		t.Fatalf("certificate was not replaced")
	}
	if after.RefreshHandle == before.RefreshHandle {
		t.Fatalf("refresh handle was not replaced")
	}
	if after.UserID != before.UserID || after.DeviceID != before.DeviceID {
		t.Fatalf("renewal changed identity: %q/%q", after.UserID, after.DeviceID)
	}
	if proof.Certificate != after.Certificate {
		t.Fatalf("Current returned a certificate that is not stored")
	}
	if store.saves != saves+1 {
		t.Fatalf("renewal did not persist the rotated handle")
	}
	if b.UserID() != before.UserID || b.DeviceID() != before.DeviceID {
		t.Fatalf("in-memory identity changed")
	}

	// The renewed certificate is used well past the original expiry.
	f.clock.Advance(6 * time.Minute)
	mustCurrent(t, b, f)
	if _, _, _, renews := f.calls(); renews != 1 {
		t.Fatalf("unexpected second renewal: renew=%d", renews)
	}
}

func TestRenewalRejectsChangedIdentity(t *testing.T) {
	f := newFakeAuthority(t)
	store := &memStore{}
	a := newTestAccount(t, f, store)
	enroll(t, a, f)
	before := decodePersisted(t, store.value)
	saves := store.saves

	f.set(func(config *fakeConfig) {
		config.renewSubject = "some-other-user"
	})
	f.clock.Advance(8*time.Minute + time.Second)

	_, _, err := a.Current(context.Background())
	if !errors.Is(err, ErrCredential) {
		t.Fatalf("Current after identity-changing renewal = %v, want ErrCredential", err)
	}
	after := decodePersisted(t, store.value)
	if after.Certificate != before.Certificate || after.RefreshHandle != before.RefreshHandle {
		t.Fatalf("rejected renewal changed the stored credential")
	}
	if store.saves != saves {
		t.Fatalf("rejected renewal saved state")
	}
	if a.UserID() != before.UserID || a.DeviceID() != before.DeviceID {
		t.Fatalf("rejected renewal changed in-memory identity")
	}
}

func TestCorruptStateFailsClosed(t *testing.T) {
	f := newFakeAuthority(t)
	store := &memStore{}
	a := newTestAccount(t, f, store)
	enroll(t, a, f)
	valid := decodePersisted(t, store.value)

	with := func(change func(*persisted)) string {
		state := valid
		change(&state)
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatalf("encode state: %v", err)
		}
		return string(data)
	}
	tamperCertificate := func(state *persisted) {
		parts := strings.Split(state.Certificate, ".")
		if len(parts) < 2 {
			t.Fatalf("unexpected certificate format")
		}
		last := []byte(parts[len(parts)-1])
		if last[len(last)-1] == 'A' {
			last[len(last)-1] = 'B'
		} else {
			last[len(last)-1] = 'A'
		}
		parts[len(parts)-1] = string(last)
		state.Certificate = strings.Join(parts, ".")
	}

	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"not json", `{"version":1`, ErrStateInvalid},
		{"trailing data", store.value + `{}`, ErrStateInvalid},
		{"unsupported version", with(func(s *persisted) { s.Version = 99 }), ErrStateInvalid},
		{"other authority", with(func(s *persisted) { s.Authority = "not-this-authority" }), ErrAuthorityChanged},
		{"bad seed encoding", with(func(s *persisted) { s.Seed = "!!!" }), ErrStateInvalid},
		{"short seed", with(func(s *persisted) { s.Seed = base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}) }), ErrStateInvalid},
		{"credentials without certificate", with(func(s *persisted) { s.Certificate = "" }), ErrStateInvalid},
		{"certificate without user", with(func(s *persisted) { s.UserID = "" }), ErrStateInvalid},
		{"certificate without device", with(func(s *persisted) { s.DeviceID = "" }), ErrStateInvalid},
		{"tampered certificate", with(tamperCertificate), ErrStateInvalid},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			broken := &memStore{value: testCase.raw}
			_, err := New(f.server.URL, f.caHex(), broken)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("New = %v, want %v", err, testCase.want)
			}
			if broken.saves != 0 {
				t.Fatalf("New overwrote corrupt state")
			}
		})
	}

	// A key-only state is valid and leaves the account unenrolled.
	keyOnly := &memStore{value: with(func(s *persisted) {
		s.Certificate = ""
		s.UserID = ""
		s.DeviceID = ""
		s.RefreshHandle = ""
	})}
	unEnrolled, err := New(f.server.URL, f.caHex(), keyOnly)
	if err != nil {
		t.Fatalf("key-only state: %v", err)
	}
	if unEnrolled.UserID() != "" || unEnrolled.DeviceID() != "" {
		t.Fatalf("key-only state exposes identity")
	}

	loadFailure := &memStore{loadErr: errors.New("keyring unavailable")}
	if _, err := New(f.server.URL, f.caHex(), loadFailure); err == nil || !strings.Contains(err.Error(), "load state") {
		t.Fatalf("load error = %v", err)
	}
}

func TestFinishErrorsAndSaveFailure(t *testing.T) {
	f := newFakeAuthority(t)
	store := &memStore{}
	a := newTestAccount(t, f, store)

	if err := a.Finish(context.Background(), "code", "state"); !errors.Is(err, ErrNoLogin) {
		t.Fatalf("Finish without Begin = %v, want ErrNoLogin", err)
	}
	authURL, err := a.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	state := stateFromURL(t, authURL)
	if err := a.Finish(context.Background(), "code", "wrong-state"); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("Finish with wrong state = %v, want ErrStateMismatch", err)
	}
	if err := a.Finish(context.Background(), "code", state); err != nil {
		t.Fatalf("Finish after state mismatch: %v", err)
	}

	// A rejected authorization is surfaced with its machine-readable code and
	// consumes the pending challenge.
	f2 := newFakeAuthority(t)
	store2 := &memStore{}
	a2 := newTestAccount(t, f2, store2)
	f2.set(func(config *fakeConfig) {
		config.enrollStatus = http.StatusUnauthorized
		config.enrollCode = "identity_verification_failed"
	})
	authURL2, err := a2.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	err = a2.Finish(context.Background(), "code", stateFromURL(t, authURL2))
	var apiError *APIError
	if !errors.As(err, &apiError) {
		t.Fatalf("Finish = %v, want APIError", err)
	}
	if apiError.StatusCode != http.StatusUnauthorized || apiError.Code != "identity_verification_failed" {
		t.Fatalf("APIError = %+v", apiError)
	}
	if err := a2.Finish(context.Background(), "code", stateFromURL(t, authURL2)); !errors.Is(err, ErrNoLogin) {
		t.Fatalf("second Finish = %v, want ErrNoLogin", err)
	}

	// If the store fails, nothing is committed and no in-memory credential is
	// exposed. The endpoint key stays persisted so the device ID is stable.
	f3 := newFakeAuthority(t)
	store3 := &memStore{}
	a3 := newTestAccount(t, f3, store3)
	authURL3, err := a3.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	store3.saveErr = errors.New("keyring locked")
	err = a3.Finish(context.Background(), "code", stateFromURL(t, authURL3))
	if err == nil || !strings.Contains(err.Error(), "save state") {
		t.Fatalf("Finish with failing store = %v", err)
	}
	if a3.UserID() != "" || a3.DeviceID() != "" {
		t.Fatalf("failed enrollment exposed identity")
	}
	keyOnly := decodePersisted(t, store3.value)
	if keyOnly.Certificate != "" || keyOnly.UserID != "" || keyOnly.DeviceID != "" || keyOnly.RefreshHandle != "" {
		t.Fatalf("failed enrollment persisted credentials")
	}
	store3.saveErr = nil
	enroll(t, a3, f3)
	wantDevice, err := f3.signer.DeviceID(f3.issuer, f3.subject, a3.key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("derive device ID: %v", err)
	}
	if a3.DeviceID() != wantDevice {
		t.Fatalf("re-enrollment changed the device ID: %q != %q", a3.DeviceID(), wantDevice)
	}

	// A canceled context aborts the challenge request but keeps the new key.
	f4 := newFakeAuthority(t)
	store4 := &memStore{}
	a4 := newTestAccount(t, f4, store4)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a4.Begin(canceled); err == nil {
		t.Fatalf("Begin with canceled context succeeded")
	}
	if store4.saves != 1 {
		t.Fatalf("canceled Begin did not persist the key")
	}
	if a4.UserID() != "" {
		t.Fatalf("canceled Begin exposed identity")
	}
}

func TestExpiredCertificateReauthenticatesSameAccount(t *testing.T) {
	f := newFakeAuthority(t)
	f.set(func(config *fakeConfig) { config.renewable = false })
	store := &memStore{}
	a := newTestAccount(t, f, store)
	enroll(t, a, f)

	userID, deviceID := a.UserID(), a.DeviceID()
	before := decodePersisted(t, store.value)
	saves := store.saves

	f.clock.Advance(10*time.Minute + 2*time.Second)
	if _, _, err := a.Current(context.Background()); !errors.Is(err, ErrExpired) {
		t.Fatalf("Current with expired certificate = %v, want ErrExpired", err)
	}

	enroll(t, a, f)
	if a.UserID() != userID || a.DeviceID() != deviceID {
		t.Fatalf("reauth changed identity: user %q->%q device %q->%q", userID, a.UserID(), deviceID, a.DeviceID())
	}
	if after := decodePersisted(t, store.value); after.Certificate == before.Certificate {
		t.Fatal("reauth did not replace the expired certificate")
	}
	if store.saves != saves+1 {
		t.Fatalf("reauth saves = %d, want %d", store.saves, saves+1)
	}
	mustCurrent(t, a, f)
}

func TestSameAccountReauthenticationReplacesCredential(t *testing.T) {
	f := newFakeAuthority(t)
	store := &memStore{}
	a := newTestAccount(t, f, store)
	enroll(t, a, f)

	userID, deviceID := a.UserID(), a.DeviceID()
	before := decodePersisted(t, store.value)
	saves := store.saves
	challenges, enrollments, _, _ := f.calls()

	f.clock.Advance(3 * time.Minute)
	enroll(t, a, f)

	after := decodePersisted(t, store.value)
	if a.UserID() != userID || a.DeviceID() != deviceID {
		t.Fatalf("reauth changed identity: user %q->%q device %q->%q", userID, a.UserID(), deviceID, a.DeviceID())
	}
	if after.Certificate == before.Certificate {
		t.Fatal("reauth did not replace the certificate")
	}
	if after.RefreshHandle == before.RefreshHandle {
		t.Fatal("reauth did not replace the refresh handle")
	}
	if store.saves != saves+1 {
		t.Fatalf("reauth saves = %d, want %d", store.saves, saves+1)
	}
	gotChallenges, gotEnrollments, _, _ := f.calls()
	if gotChallenges != challenges+1 || gotEnrollments != enrollments+1 {
		t.Fatalf("reauth calls = %d challenges/%d enrollments, want %d/%d", gotChallenges, gotEnrollments, challenges+1, enrollments+1)
	}
	mustCurrent(t, a, f)
}

func TestCorruptRenewalDenialStateFailsClosed(t *testing.T) {
	f := newFakeAuthority(t)
	store := &memStore{}
	a := newTestAccount(t, f, store)
	enroll(t, a, f)
	base := decodePersisted(t, store.value)

	encode := func(state persisted) string {
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatalf("encode state: %v", err)
		}
		return string(data)
	}
	cases := []struct {
		name   string
		mutate func(*persisted)
	}{
		{"unknown code", func(state *persisted) { state.RenewalDenied = "not_a_denial" }},
		{"denial without handle", func(state *persisted) {
			state.RenewalDenied = "refresh_rejected"
			state.RefreshHandle = ""
		}},
		{"denial without certificate", func(state *persisted) {
			state.Certificate = ""
			state.UserID = ""
			state.DeviceID = ""
			state.RefreshHandle = ""
			state.RenewalDenied = "identity_verification_failed"
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			state := base
			test.mutate(&state)
			store.value = encode(state)
			if _, err := New(f.server.URL, f.caHex(), store); !errors.Is(err, ErrStateInvalid) {
				t.Fatalf("New = %v, want ErrStateInvalid", err)
			}
		})
	}
}

func TestDefinitiveRenewalDenialDeniesBeforeExpiry(t *testing.T) {
	for _, code := range []string{"refresh_rejected", "identity_verification_failed"} {
		t.Run(code, func(t *testing.T) {
			f := newFakeAuthority(t)
			store := &memStore{}
			a := newTestAccount(t, f, store)
			enroll(t, a, f)

			userID, deviceID := a.UserID(), a.DeviceID()
			before := decodePersisted(t, store.value)
			f.set(func(config *fakeConfig) {
				config.renewStatus = http.StatusUnauthorized
				config.renewCode = code
			})
			// One minute thirty seconds of certificate lifetime remains, inside
			// the renewal margin but before expiry.
			f.clock.Advance(8*time.Minute + 30*time.Second)
			if _, _, err := a.Current(context.Background()); !errors.Is(err, ErrCredential) {
				t.Fatalf("Current after %s = %v, want ErrCredential", code, err)
			}

			// A later transient failure must not resurrect the rejected
			// certificate; the denial is sticky until browser sign-in.
			f.set(func(config *fakeConfig) {
				config.renewStatus = http.StatusServiceUnavailable
				config.renewCode = "unavailable"
			})
			f.clock.Advance(5 * time.Second)
			if _, _, err := a.Current(context.Background()); !errors.Is(err, ErrCredential) {
				t.Fatalf("Current after transient failure following %s = %v, want ErrCredential", code, err)
			}

			deniedState := store.value
			if denied := decodePersisted(t, store.value); denied.RenewalDenied != code {
				t.Fatalf("persisted denial = %q, want %q", denied.RenewalDenied, code)
			}

			// A restart during a provider outage must not resume the revoked
			// certificate, and must not contact the authority.
			restored := newTestAccount(t, f, store)
			if restored.UserID() != userID || restored.DeviceID() != deviceID {
				t.Fatalf("restore changed identity: user %q/%q device %q/%q", restored.UserID(), userID, restored.DeviceID(), deviceID)
			}
			_, _, leasesBefore, renewsBefore := f.calls()
			if _, _, err := restored.Current(context.Background()); !errors.Is(err, ErrCredential) {
				t.Fatalf("Current after restart = %v, want ErrCredential", err)
			}
			_, _, leasesAfter, renewsAfter := f.calls()
			if renewsAfter != renewsBefore || leasesAfter != leasesBefore {
				t.Fatalf("restored denial contacted authority: renews %d->%d leases %d->%d", renewsBefore, renewsAfter, leasesBefore, leasesAfter)
			}

			// A rejected sign-in for another account must preserve the denial.
			f.set(func(config *fakeConfig) { config.enrollSubject = "other-user" })
			authURL, err := restored.Begin(context.Background())
			if err != nil {
				t.Fatalf("begin for another account: %v", err)
			}
			if err := restored.Finish(context.Background(), "authorization-code", stateFromURL(t, authURL)); !errors.Is(err, ErrAlreadyEnrolled) {
				t.Fatalf("Finish for another account = %v, want ErrAlreadyEnrolled", err)
			}
			if store.value != deniedState {
				t.Fatal("rejected sign-in changed the denied state")
			}
			if _, _, err := restored.Current(context.Background()); !errors.Is(err, ErrCredential) {
				t.Fatalf("Current after rejected sign-in = %v, want ErrCredential", err)
			}

			// Same-account reauthentication clears the persisted denial.
			f.set(func(config *fakeConfig) {
				config.renewStatus = 0
				config.renewCode = ""
				config.enrollSubject = ""
			})
			enroll(t, restored, f)
			after := decodePersisted(t, store.value)
			if after.RenewalDenied != "" {
				t.Fatalf("reauth kept persisted denial %q", after.RenewalDenied)
			}
			if restored.UserID() != userID || restored.DeviceID() != deviceID {
				t.Fatalf("reauth changed identity: user %q->%q device %q->%q", userID, restored.UserID(), deviceID, restored.DeviceID())
			}
			if after.RefreshHandle == before.RefreshHandle {
				t.Fatal("reauth did not replace the rejected refresh handle")
			}
			mustCurrent(t, restored, f)

			again := newTestAccount(t, f, store)
			mustCurrent(t, again, f)
		})
	}
}

func TestTransientRenewalFailureKeepsValidCertificate(t *testing.T) {
	f := newFakeAuthority(t)
	store := &memStore{}
	a := newTestAccount(t, f, store)
	enroll(t, a, f)

	f.set(func(config *fakeConfig) {
		config.renewStatus = http.StatusServiceUnavailable
		config.renewCode = "unavailable"
	})
	f.clock.Advance(8*time.Minute + 30*time.Second)
	if _, proof := mustCurrent(t, a, f); proof.Lease == "" {
		t.Fatal("transient renewal failure returned no lease")
	}
	if _, _, _, renews := f.calls(); renews != 1 {
		t.Fatalf("renewals = %d, want 1", renews)
	}
}

func TestDifferentAccountRejectedUntilReset(t *testing.T) {
	f := newFakeAuthority(t)
	store := &memStore{}
	a := newTestAccount(t, f, store)
	enroll(t, a, f)

	userID, deviceID := a.UserID(), a.DeviceID()
	before := decodePersisted(t, store.value)
	saves := store.saves

	f.set(func(config *fakeConfig) { config.enrollSubject = "other-user" })
	authURL, err := a.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin for another account: %v", err)
	}
	if err := a.Finish(context.Background(), "authorization-code", stateFromURL(t, authURL)); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("Finish for another account = %v, want ErrAlreadyEnrolled", err)
	}
	after := decodePersisted(t, store.value)
	if after.Certificate != before.Certificate || after.RefreshHandle != before.RefreshHandle || after.UserID != before.UserID || after.DeviceID != before.DeviceID {
		t.Fatal("rejected sign-in changed the stored account")
	}
	if store.saves != saves {
		t.Fatalf("rejected sign-in saved state %d times", store.saves-saves)
	}
	if a.UserID() != userID || a.DeviceID() != deviceID {
		t.Fatal("rejected sign-in changed the active account")
	}
	mustCurrent(t, a, f)

	// A reset that cannot be persisted must leave the account usable.
	store.saveErr = errors.New("keyring unavailable")
	if err := a.Reset(); err == nil {
		t.Fatal("Reset succeeded despite a storage failure")
	}
	store.saveErr = nil
	if a.UserID() != userID || a.DeviceID() != deviceID {
		t.Fatal("failed Reset discarded the active account")
	}
	mustCurrent(t, a, f)
	if stored := decodePersisted(t, store.value); stored.UserID != userID || stored.Certificate != before.Certificate {
		t.Fatal("failed Reset changed the stored account")
	}

	// An explicit local reset allows a different account and a new device.
	f.clock.Advance(3 * time.Minute)
	if err := a.Reset(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if a.UserID() != "" || a.DeviceID() != "" {
		t.Fatalf("reset kept identity: user=%q device=%q", a.UserID(), a.DeviceID())
	}
	keyOnly := decodePersisted(t, store.value)
	if keyOnly.Certificate != "" || keyOnly.UserID != "" || keyOnly.DeviceID != "" || keyOnly.RefreshHandle != "" {
		t.Fatal("reset kept old credentials in the store")
	}

	enroll(t, a, f)
	if a.UserID() == userID {
		t.Fatal("enrollment after reset kept the old user")
	}
	if a.DeviceID() == deviceID {
		t.Fatal("reset did not replace the endpoint key")
	}
	mustCurrent(t, a, f)
}

func TestRestoreAcceptsExpiredCertificateReadOnly(t *testing.T) {
	f := newFakeAuthority(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	issuedAt := time.Now().Add(-20 * time.Minute)
	certificate, err := f.signer.Issue(f.issuer, f.subject, key.Public().(ed25519.PublicKey), issuedAt)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	principal, err := identity.VerifyCertificate(certificate, f.signer.PublicKey(), issuedAt)
	if err != nil {
		t.Fatalf("verify certificate: %v", err)
	}
	state, err := json.Marshal(persisted{
		Version:     stateVersion,
		Authority:   authorityFingerprint(f.signer.PublicKey()),
		Seed:        base64.RawURLEncoding.EncodeToString(key.Seed()),
		Certificate: certificate,
		UserID:      principal.RemoteUserID(),
		DeviceID:    principal.DeviceID,
	})
	if err != nil {
		t.Fatalf("encode state: %v", err)
	}
	store := &memStore{value: string(state)}
	a, err := New(f.server.URL, f.caHex(), store)
	if err != nil {
		t.Fatalf("restore expired certificate: %v", err)
	}
	if a.UserID() != principal.RemoteUserID() || a.DeviceID() != principal.DeviceID {
		t.Fatalf("restored identity = %q/%q", a.UserID(), a.DeviceID())
	}
	if store.saves != 0 {
		t.Fatalf("restore wrote state")
	}
	if _, _, err := a.Current(context.Background()); !errors.Is(err, ErrExpired) {
		t.Fatalf("Current = %v, want ErrExpired", err)
	}
	if _, _, leases, _ := f.calls(); leases != 0 {
		t.Fatalf("expired certificate requested a lease")
	}
}

func TestConfigurationAndRedirectPolicy(t *testing.T) {
	f := newFakeAuthority(t)
	ca := f.caHex()

	cases := []struct {
		name string
		base string
		ok   bool
	}{
		{"https", "https://identity.example", true},
		{"https with path", "https://identity.example/base/", true},
		{"loopback ipv4", "http://127.0.0.1:8080", true},
		{"loopback name", "http://localhost:8080", true},
		{"plaintext remote", "http://identity.example", false},
		{"query", "https://identity.example/?a=1", false},
		{"fragment", "https://identity.example/#x", false},
		{"userinfo", "https://user@identity.example", false},
		{"other scheme", "ftp://identity.example", false},
		{"empty", "", false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := New(testCase.base, ca, &memStore{})
			if testCase.ok && err != nil {
				t.Fatalf("New(%q) = %v", testCase.base, err)
			}
			if !testCase.ok && err == nil {
				t.Fatalf("New(%q) succeeded", testCase.base)
			}
		})
	}
	if _, err := New("https://identity.example", "not-a-key", &memStore{}); err == nil {
		t.Fatalf("New accepted an invalid authority key")
	}
	if _, err := New("https://identity.example", ca, nil); err == nil {
		t.Fatalf("New accepted a nil store")
	}

	f.set(func(config *fakeConfig) { config.redirect = true })
	a := newTestAccount(t, f, &memStore{})
	if _, err := a.Begin(context.Background()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("Begin followed a redirect: %v", err)
	}
}

func TestLeaseValidation(t *testing.T) {
	t.Run("untrusted lease", func(t *testing.T) {
		f := newFakeAuthority(t)
		a := newTestAccount(t, f, &memStore{})
		enroll(t, a, f)
		f.set(func(config *fakeConfig) { config.badLease = true })
		if _, _, err := a.Current(context.Background()); !errors.Is(err, ErrCredential) {
			t.Fatalf("Current = %v, want ErrCredential", err)
		}
	})
	t.Run("device mismatch", func(t *testing.T) {
		f := newFakeAuthority(t)
		a := newTestAccount(t, f, &memStore{})
		enroll(t, a, f)
		f.set(func(config *fakeConfig) { config.leaseDevice = "another-device" })
		if _, _, err := a.Current(context.Background()); !errors.Is(err, ErrCredential) {
			t.Fatalf("Current = %v, want ErrCredential", err)
		}
	})
}

func TestCurrentSerializesConcurrentCallers(t *testing.T) {
	f := newFakeAuthority(t)
	a := newTestAccount(t, f, &memStore{})
	enroll(t, a, f)
	mustCurrent(t, a, f)

	var group sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, _, err := a.Current(context.Background()); err != nil {
				failures <- err
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("concurrent Current: %v", err)
	}
	if _, _, leases, _ := f.calls(); leases != 1 {
		t.Fatalf("concurrent callers issued %d leases, want 1", leases)
	}
}
