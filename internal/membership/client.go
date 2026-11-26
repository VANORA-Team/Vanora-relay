// Package membership talks to Vanora's internal membership service.
//
// The service authenticates relay nodes with a high-entropy bearer token and resolves the
// caller-supplied issuer/subject pair against an existing, verified OAuth
// linkage. The check is intentionally fail-closed: configuration errors,
// transport errors, non-200 responses, malformed payloads, and timestamps in
// the past all produce an error or an unentitled result, never a grant.
package membership

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// entitlementPath is the fixed internal endpoint on the Vanora backend.
	entitlementPath = "/internal/v1/relay/entitlement"

	// requestTimeout bounds one entitlement check. Callers may already hold a
	// shorter deadline; context.WithTimeout keeps the earlier one.
	requestTimeout = 8 * time.Second

	// maxResponseBytes caps how much of an error or success payload is read.
	maxResponseBytes = 64 << 10

	// minServiceTokenBytes is the minimum accepted length for the service
	// bearer. Tokens shorter than this are rejected before a request is sent.
	minServiceTokenBytes = 32

	// Identity limits mirror the backend request validation.
	maxIssuerBytes  = 512
	maxSubjectBytes = 256
)

// validIdentityPart enforces the exact bytes the backend accepts. It never
// trims: surrounding whitespace is rejected instead of silently changing an
// account identifier.
func validIdentityPart(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value
}

var (
	// ErrNotConfigured reports that the client is missing its endpoint or
	// bearer token.
	ErrNotConfigured = errors.New("membership: relay client is not configured")

	// ErrUnauthenticated reports that the membership service rejected the
	// configured service bearer.
	ErrUnauthenticated = errors.New("membership: relay service authentication rejected")

	// ErrMalformedResponse reports that the service answered in a shape this
	// client does not understand.
	ErrMalformedResponse = errors.New("membership: malformed entitlement response")

	// ErrInvalidIdentity reports that issuer or subject was empty, too long,
	// or surrounded by whitespace. Identity bytes are never trimmed because a
	// changed subject can name a different account.
	ErrInvalidIdentity = errors.New("membership: invalid identity")
)

var defaultHTTPClient = &http.Client{
	Timeout:       requestTimeout,
	CheckRedirect: refuseRedirects,
}

func refuseRedirects(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// Client is the membership service client.
//
// URL is the Vanora backend base URL. The endpoint path is appended unless the
// URL already ends with it. Plain HTTP is only accepted for loopback hosts, and
// URLs with userinfo are rejected. Token is the high-entropy service bearer.
// HTTP may be nil, in which case a client with a conservative timeout is used;
// redirects are never followed.
type Client struct {
	URL   string
	Token string
	HTTP  *http.Client
}

type entitlementRequest struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type entitlementData struct {
	RelayAllowed         bool            `json:"relay_allowed"`
	ValidUntil           int64           `json:"valid_until"`
	TunnelAllowed        json.RawMessage `json:"tunnel_allowed"`
	TunnelConnectAllowed json.RawMessage `json:"tunnel_connect_allowed"`
	MaxTunnels           json.RawMessage `json:"max_tunnels"`
	TunnelValidUntil     json.RawMessage `json:"tunnel_valid_until"`
}

type entitlementEnvelope struct {
	Success bool             `json:"success"`
	Message string           `json:"message"`
	Data    *entitlementData `json:"data"`
}

// Entitlement is a successful membership lookup. A positive TunnelAllowed
// or an active TURN grant establishes account eligibility. Legacy TURN
// denials are also used for missing and disabled accounts.
type Entitlement struct {
	RelayAllowed         bool
	ValidUntil           time.Time
	TunnelAllowed        *bool
	TunnelConnectAllowed *bool
	MaxTunnels           *int
	TunnelValidUntil     *int64
	TunnelFieldsInvalid  bool
}

// Check returns the end of the caller's relay entitlement, or the zero time
// when the issuer/subject pair has no active, unexpired subscription that
// allows the relay.
//
// A zero time with a nil error is a definitive "not entitled" answer. Any
// error means the answer could not be established and the caller must treat
// the identity as unentitled.
func (c *Client) Check(ctx context.Context, issuer, subject string) (time.Time, error) {
	data, err := c.lookup(ctx, issuer, subject)
	if err != nil {
		return time.Time{}, err
	}
	if end := data.relayEnd(); data.RelayAllowed && end.After(time.Now()) {
		return end, nil
	}
	return time.Time{}, nil
}

// Lookup retrieves the relay grant and optional tunnel-specific overrides.
// Malformed tunnel overrides are flagged independently of the relay grant.
func (c *Client) Lookup(ctx context.Context, issuer, subject string) (Entitlement, error) {
	data, err := c.lookup(ctx, issuer, subject)
	if err != nil {
		return Entitlement{}, err
	}
	ent := Entitlement{RelayAllowed: data.RelayAllowed, ValidUntil: data.relayEnd()}
	ent.TunnelAllowed = tunnelField[bool](data.TunnelAllowed, &ent.TunnelFieldsInvalid)
	ent.TunnelConnectAllowed = tunnelField[bool](data.TunnelConnectAllowed, &ent.TunnelFieldsInvalid)
	ent.MaxTunnels = tunnelField[int](data.MaxTunnels, &ent.TunnelFieldsInvalid)
	ent.TunnelValidUntil = tunnelField[int64](data.TunnelValidUntil, &ent.TunnelFieldsInvalid)
	if ent.MaxTunnels != nil && (*ent.MaxTunnels < 0 || *ent.MaxTunnels > 10000) {
		ent.TunnelFieldsInvalid = true
	}
	if ent.TunnelAllowed != nil && *ent.TunnelAllowed && ent.TunnelValidUntil != nil && *ent.TunnelValidUntil <= 0 {
		ent.TunnelFieldsInvalid = true
	}
	return ent, nil
}

func tunnelField[T any](raw json.RawMessage, invalid *bool) *T {
	if len(raw) == 0 {
		return nil
	}
	var value *T
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		*invalid = true
	}
	return value
}

func (d entitlementData) relayEnd() time.Time {
	if d.ValidUntil <= 0 {
		return time.Time{}
	}
	return time.Unix(d.ValidUntil, 0).UTC()
}

func (c *Client) lookup(ctx context.Context, issuer, subject string) (entitlementData, error) {
	var zero entitlementData
	if c == nil {
		return zero, ErrNotConfigured
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if !validIdentityPart(issuer, maxIssuerBytes) || !validIdentityPart(subject, maxSubjectBytes) {
		return zero, fmt.Errorf("%w: issuer and subject must be non-empty, within limits, and have no surrounding whitespace", ErrInvalidIdentity)
	}
	if len([]byte(c.Token)) < minServiceTokenBytes || strings.ContainsAny(c.Token, " \t\r\n") {
		return zero, fmt.Errorf("%w: service token must be at least %d bytes without whitespace", ErrNotConfigured, minServiceTokenBytes)
	}

	endpoint, err := c.endpoint()
	if err != nil {
		return zero, err
	}
	body, err := json.Marshal(entitlementRequest{Issuer: issuer, Subject: subject})
	if err != nil {
		return zero, fmt.Errorf("membership: encode entitlement request: %w", err)
	}

	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("membership: build entitlement request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.Token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "vanora-relay-membership/1")

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = defaultHTTPClient
	} else {
		// Never forward the service bearer through a redirect, even when the
		// caller supplied its own client.
		clientCopy := *httpClient
		clientCopy.CheckRedirect = refuseRedirects
		httpClient = &clientCopy
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return zero, fmt.Errorf("membership: entitlement request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return zero, fmt.Errorf("%w: status %d", ErrUnauthenticated, response.StatusCode)
	}
	if response.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
		detailText := strings.TrimSpace(string(detail))
		if len(detailText) > 512 {
			detailText = detailText[:512]
		}
		if detailText != "" {
			return zero, fmt.Errorf("membership: entitlement request returned status %d: %s", response.StatusCode, detailText)
		}
		return zero, fmt.Errorf("membership: entitlement request returned status %d", response.StatusCode)
	}

	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	if len(payload) > maxResponseBytes {
		return zero, fmt.Errorf("%w: response exceeds %d bytes", ErrMalformedResponse, maxResponseBytes)
	}
	var envelope entitlementEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	if !envelope.Success {
		message := strings.TrimSpace(envelope.Message)
		if message == "" {
			message = "request rejected"
		}
		return zero, fmt.Errorf("membership: entitlement request rejected: %s", message)
	}
	if envelope.Data == nil {
		return zero, fmt.Errorf("%w: missing data", ErrMalformedResponse)
	}
	if envelope.Data.RelayAllowed && envelope.Data.ValidUntil <= 0 {
		return zero, fmt.Errorf("%w: relay allowed without an entitlement end", ErrMalformedResponse)
	}
	return *envelope.Data, nil
}

func (c *Client) endpoint() (string, error) {
	raw := strings.TrimSpace(c.URL)
	if raw == "" {
		return "", fmt.Errorf("%w: missing URL", ErrNotConfigured)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: invalid URL: %v", ErrNotConfigured, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("%w: URL scheme must be http or https", ErrNotConfigured)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("%w: URL must not contain userinfo", ErrNotConfigured)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("%w: URL host is required", ErrNotConfigured)
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return "", fmt.Errorf("%w: plain HTTP is only allowed for loopback hosts", ErrNotConfigured)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: URL must not contain a query or fragment", ErrNotConfigured)
	}

	path := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(path, entitlementPath) {
		path += entitlementPath
	}
	parsed.Path = path
	parsed.RawPath = ""
	return parsed.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
