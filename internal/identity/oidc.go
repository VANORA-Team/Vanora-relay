package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Errors surfaced by the OIDC integration.
var (
	ErrProviderUnavailable = errors.New("identity: identity provider unavailable")
	ErrCodeRejected        = errors.New("identity: authorization code rejected")
	ErrIDTokenInvalid      = errors.New("identity: ID token verification failed")
)

const (
	// discoveryTTL bounds how long a provider discovery document is trusted.
	// Refreshing it also refreshes readiness information.
	discoveryTTL = 5 * time.Second
	// readinessTTL is how long a successful or failed readiness probe is
	// cached before the next liveness check hits the provider again.
	readinessTTL = 5 * time.Second

	maxIDTokenSize      = 16 << 10
	maxProviderBodySize = 1 << 20

	oidcRequestTimeout = 10 * time.Second
	idTokenClockSkew   = 60 * time.Second
)

// providerMetadata is the subset of the OIDC discovery document we rely on.
type providerMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURL               string `json:"jwks_uri"`
}

// oidcProvider performs discovery, code exchange and ID token verification
// against one configured external issuer. JOSE parsing and key handling are
// delegated to github.com/coreos/go-oidc and github.com/go-jose/go-jose.
type oidcProvider struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
	httpClient   *http.Client
	now          func() time.Time

	mu       sync.Mutex
	provider *oidc.Provider
	metadata providerMetadata
	fetched  time.Time

	readyMu  sync.Mutex
	readyAt  time.Time
	readyErr error
}

func newOIDCProvider(cfg Config) (*oidcProvider, error) {
	if err := validateIssuerURL(cfg.OIDCIssuer); err != nil {
		return nil, fmt.Errorf("identity: OIDC issuer: %w", err)
	}
	if cfg.OIDCClientID == "" || len(cfg.OIDCClientID) > 256 {
		return nil, fmt.Errorf("identity: OIDC client id must be 1..256 characters")
	}
	if cfg.OIDCClientSecret != "" && len(cfg.OIDCClientSecret) > 1024 {
		return nil, fmt.Errorf("identity: OIDC client secret is too long")
	}
	if err := validateRedirectURI(cfg.OIDCRedirectURI); err != nil {
		return nil, fmt.Errorf("identity: OIDC redirect uri: %w", err)
	}
	scopes, err := normalizeScopes(cfg.OIDCScopes, !cfg.DisableRefresh)
	if err != nil {
		return nil, err
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: oidcRequestTimeout}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &oidcProvider{
		issuer:       strings.TrimSuffix(cfg.OIDCIssuer, "/"),
		clientID:     cfg.OIDCClientID,
		clientSecret: cfg.OIDCClientSecret,
		redirectURI:  cfg.OIDCRedirectURI,
		scopes:       scopes,
		httpClient:   httpClient,
		now:          now,
	}, nil
}

// load returns a discovered provider whose metadata is at most discoveryTTL
// old. Concurrent callers may fetch in parallel; results are interchangeable.
func (p *oidcProvider) load(ctx context.Context) (*oidc.Provider, providerMetadata, error) {
	p.mu.Lock()
	cached := p.provider
	cachedMeta := p.metadata
	fetched := p.fetched
	p.mu.Unlock()
	if cached != nil && p.now().Sub(fetched) < discoveryTTL {
		return cached, cachedMeta, nil
	}

	ctx, cancel := context.WithTimeout(ctx, oidcRequestTimeout)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, p.issuer)
	if err != nil {
		return nil, providerMetadata{}, fmt.Errorf("%w: discovery: %v", ErrProviderUnavailable, err)
	}
	var metadata providerMetadata
	if err := provider.Claims(&metadata); err != nil {
		return nil, providerMetadata{}, fmt.Errorf("%w: discovery claims: %v", ErrProviderUnavailable, err)
	}
	if err := validateProviderMetadata(metadata); err != nil {
		return nil, providerMetadata{}, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}

	p.mu.Lock()
	p.provider = provider
	p.metadata = metadata
	p.fetched = p.now()
	p.mu.Unlock()
	return provider, metadata, nil
}

// Ready reports whether the authority can currently discover the issuer and
// reach its key set, which is the practical test of "able to validate and
// issue". A successful or failed probe is cached for readinessTTL.
func (p *oidcProvider) Ready(ctx context.Context) error {
	p.readyMu.Lock()
	if !p.readyAt.IsZero() && p.now().Sub(p.readyAt) < readinessTTL {
		err := p.readyErr
		p.readyMu.Unlock()
		return err
	}
	p.readyMu.Unlock()

	p.mu.Lock()
	p.fetched = time.Time{} // force freshness; leases must not ride a cached probe
	p.mu.Unlock()
	_, metadata, err := p.load(ctx)
	if err == nil {
		err = p.probeJWKS(ctx, metadata.JWKSURL)
	}
	p.readyMu.Lock()
	p.readyAt = p.now()
	p.readyErr = err
	p.readyMu.Unlock()
	return err
}

func (p *oidcProvider) probeJWKS(ctx context.Context, jwksURL string) error {
	ctx, cancel := context.WithTimeout(ctx, oidcRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBodySize))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: jwks status %d", ErrProviderUnavailable, resp.StatusCode)
	}
	var keySet struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &keySet); err != nil {
		return fmt.Errorf("%w: jwks: %v", ErrProviderUnavailable, err)
	}
	if len(keySet.Keys) == 0 {
		return fmt.Errorf("%w: jwks has no keys", ErrProviderUnavailable)
	}
	return nil
}

func (p *oidcProvider) authorizationURL(metadata providerMetadata, ch *challenge) string {
	parsed, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		// validateProviderMetadata guarantees this cannot happen.
		return ""
	}
	query := parsed.Query()
	query.Set("response_type", "code")
	query.Set("client_id", p.clientID)
	query.Set("redirect_uri", p.redirectURI)
	query.Set("scope", strings.Join(p.scopes, " "))
	query.Set("state", ch.state)
	query.Set("nonce", ch.nonce)
	query.Set("code_challenge", pkceChallenge(ch.codeVerifier))
	query.Set("code_challenge_method", "S256")
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// tokenResult is the subset of a token endpoint response the authority needs.
type tokenResult struct {
	IDToken      string
	RefreshToken string
}

// exchangeCode redeems an authorization code with the verifier the authority
// generated for the challenge. The code is never accepted from a client
// without the matching verifier.
func (p *oidcProvider) exchangeCode(ctx context.Context, tokenEndpoint, code, codeVerifier string) (tokenResult, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.redirectURI)
	form.Set("client_id", p.clientID)
	form.Set("code_verifier", codeVerifier)
	return p.tokenRequest(ctx, tokenEndpoint, form)
}

// refresh redeems a provider refresh token. The ID token returned by the
// provider is what proves the account is still enabled and still has the same
// issuer and subject; a provider that does not return one on refresh cannot
// support unattended renewal and is reported as unavailable.
func (p *oidcProvider) refresh(ctx context.Context, tokenEndpoint, refreshToken string) (tokenResult, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", p.clientID)
	tokens, err := p.tokenRequest(ctx, tokenEndpoint, form)
	if err != nil {
		return tokenResult{}, err
	}
	if tokens.IDToken == "" {
		return tokenResult{}, fmt.Errorf("%w: refresh response has no id_token", ErrProviderUnavailable)
	}
	return tokens, nil
}

func (p *oidcProvider) tokenRequest(ctx context.Context, tokenEndpoint string, form url.Values) (tokenResult, error) {
	if p.clientSecret != "" {
		form.Set("client_secret", p.clientSecret)
	}
	ctx, cancel := context.WithTimeout(ctx, oidcRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResult{}, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return tokenResult{}, fmt.Errorf("%w: token request: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBodySize))
	if err != nil {
		return tokenResult{}, fmt.Errorf("%w: token response: %v", ErrProviderUnavailable, err)
	}
	if resp.StatusCode >= 500 {
		return tokenResult{}, fmt.Errorf("%w: token status %d", ErrProviderUnavailable, resp.StatusCode)
	}
	var tokens struct {
		IDToken          string `json:"id_token"`
		RefreshToken     string `json:"refresh_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		if resp.StatusCode != http.StatusOK {
			return tokenResult{}, fmt.Errorf("%w: status %d", ErrCodeRejected, resp.StatusCode)
		}
		return tokenResult{}, fmt.Errorf("%w: token response: %v", ErrProviderUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return tokenResult{}, fmt.Errorf("%w: status %d error %q", ErrCodeRejected, resp.StatusCode, tokens.Error)
	}
	return tokenResult{IDToken: tokens.IDToken, RefreshToken: tokens.RefreshToken}, nil
}

// verifyIDToken verifies an ID token with go-oidc (signature via the issuer's
// JWKS, issuer, audience, expiry) and then checks the nonce that belongs to the
// challenge. An empty expectedNonce skips the nonce check and is used only for
// refresh responses, where the provider does not receive an OIDC nonce; issuer,
// audience, expiry and subject are still verified.
func (p *oidcProvider) verifyIDToken(ctx context.Context, provider *oidc.Provider, rawIDToken, expectedNonce string) (string, error) {
	if rawIDToken == "" || len(rawIDToken) > maxIDTokenSize {
		return "", fmt.Errorf("%w: token size %d", ErrIDTokenInvalid, len(rawIDToken))
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID: p.clientID,
		Now:      p.now,
	})
	ctx, cancel := context.WithTimeout(ctx, oidcRequestTimeout)
	defer cancel()
	token, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrIDTokenInvalid, err)
	}
	if token.Subject == "" || len(token.Subject) > 255 {
		return "", fmt.Errorf("%w: subject must be 1..255 characters", ErrIDTokenInvalid)
	}
	if expectedNonce != "" && subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(expectedNonce)) != 1 {
		return "", fmt.Errorf("%w: nonce mismatch", ErrIDTokenInvalid)
	}
	if token.IssuedAt.After(p.now().Add(idTokenClockSkew)) {
		return "", fmt.Errorf("%w: issued in the future", ErrIDTokenInvalid)
	}
	return token.Subject, nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func validateProviderMetadata(metadata providerMetadata) error {
	for name, raw := range map[string]string{
		"authorization_endpoint": metadata.AuthorizationEndpoint,
		"token_endpoint":         metadata.TokenEndpoint,
		"jwks_uri":               metadata.JWKSURL,
	} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("%s %q is not a bare endpoint URL", name, raw)
		}
		switch parsed.Scheme {
		case "https":
		case "http":
			if !isLoopbackHost(parsed.Hostname()) {
				return fmt.Errorf("%s %q must use https", name, raw)
			}
		default:
			return fmt.Errorf("%s %q has unsupported scheme %q", name, raw, parsed.Scheme)
		}
	}
	return nil
}

func normalizeScopes(scopes []string, offlineAccess bool) ([]string, error) {
	seen := make(map[string]bool, len(scopes)+2)
	out := make([]string, 0, len(scopes)+2)
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || len(scope) > 64 {
			return nil, fmt.Errorf("identity: invalid OIDC scope")
		}
		for _, r := range scope {
			if !(r == '.' || r == '_' || r == '-' || r == ':' ||
				(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
				return nil, fmt.Errorf("identity: invalid OIDC scope %q", scope)
			}
		}
		if !seen[scope] {
			seen[scope] = true
			out = append(out, scope)
		}
	}
	if !seen[oidc.ScopeOpenID] {
		out = append(out, oidc.ScopeOpenID)
	}
	// offline_access is what makes unattended desktop renewal possible. An
	// operator can suppress the automatic request when their IdP rejects it.
	if offlineAccess && !seen["offline_access"] {
		out = append(out, "offline_access")
	}
	return out, nil
}

// validateRedirectURI accepts an HTTPS callback, a loopback HTTP callback
// (RFC 8252 native loopback) or a registered custom-scheme callback.
func validateRedirectURI(raw string) error {
	if raw == "" || len(raw) > 2048 {
		return fmt.Errorf("must be 1..2048 characters")
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains control characters")
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Fragment != "" || parsed.User != nil {
		return fmt.Errorf("must be an absolute URL without fragment or user info")
	}
	switch parsed.Scheme {
	case "https":
		if parsed.Host == "" {
			return fmt.Errorf("https redirect must have a host")
		}
		return nil
	case "http":
		if !isLoopbackHost(parsed.Hostname()) {
			return fmt.Errorf("http redirect must be loopback")
		}
		return nil
	case "javascript", "data", "file", "vbscript":
		return fmt.Errorf("scheme %q is not allowed", parsed.Scheme)
	}
	if parsed.Opaque == "" && parsed.Path == "" {
		return fmt.Errorf("custom scheme redirect needs a path")
	}
	return nil
}
