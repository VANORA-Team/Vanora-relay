package cftunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/strictjson"
	"vanora-relay/protocol"
)

const managementPrefix = "/v1/tunnels/"

var (
	tunnelIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	errControlIO     = errors.New("cftunnel: management connection failed")
)

type ControlOptions struct {
	Channel       string
	ControlOrigin string
	DeviceID      string
	PrivateKey    ed25519.PrivateKey
	SelfToken     string
	CA            ed25519.PublicKey
	LeaseSource   func(context.Context) (endpoint.LeaseProof, error)
	HTTPClient    *http.Client
}

type ControlClient struct {
	opts ControlOptions
	pub  ed25519.PublicKey
	http http.Client
}

type AllocationView struct {
	DeviceID             string `json:"device_id"`
	State                string `json:"state"`
	Generation           int64  `json:"generation"`
	Incarnation          int64  `json:"incarnation"`
	Hostname             string `json:"hostname,omitempty"`
	ManualResumeRequired bool   `json:"manual_resume_required"`
}

type OperationView struct {
	ID          string     `json:"operation_id"`
	Type        string     `json:"type"`
	Generation  int64      `json:"generation"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

type MutationResult struct {
	Allocation AllocationView
	Operation  OperationView
}

type ConnectorToken struct {
	Generation     int64  `json:"generation"`
	Incarnation    int64  `json:"incarnation"`
	Hostname       string `json:"hostname"`
	TunnelID       string `json:"tunnel_id"`
	ConnectorToken string `json:"connector_token"`
}

type APIError struct {
	Status      int
	Code        string
	RequestID   string
	RetryAfter  time.Duration
	OperationID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cftunnel: management HTTP %d (%s)", e.Status, e.Code)
}

func ControlOriginFromSignalURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Path != "/v1/signal" || parsed.RawPath != "" ||
		(parsed.Scheme != "ws" && parsed.Scheme != "wss") || strings.ContainsAny(raw, "?#") {
		return "", errors.New("cftunnel: invalid signaling URL")
	}
	parsed.Path = ""
	parsed.Scheme = "http" + strings.TrimPrefix(parsed.Scheme, "ws")
	return checkedControlOrigin(parsed.String())
}

func checkedControlOrigin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || strings.ContainsAny(raw, "?#") || identity.ValidateIssuerURL(raw) != nil ||
		parsed.Hostname() == "" || parsed.RawPath != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("cftunnel: management requires HTTPS or loopback HTTP")
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", errors.New("cftunnel: invalid management port")
		}
	}
	return parsed.Scheme + "://" + strings.ToLower(parsed.Host), nil
}

func NewControlClient(opts ControlOptions) (*ControlClient, error) {
	origin, err := checkedControlOrigin(opts.ControlOrigin)
	if err != nil {
		return nil, err
	}
	if !validPrivateKey(opts.PrivateKey) || !tunnelIdentifier.MatchString(opts.DeviceID) {
		return nil, errors.New("cftunnel: invalid management device identity")
	}
	opts.ControlOrigin = origin
	opts.PrivateKey = slices.Clone(opts.PrivateKey)
	opts.CA = slices.Clone(opts.CA)
	pub := opts.PrivateKey.Public().(ed25519.PublicKey)
	switch opts.Channel {
	case "self":
		device, _ := identity.SelfDeviceID(pub)
		if device != opts.DeviceID || !validSelfToken(opts.SelfToken) {
			return nil, errors.New("cftunnel: invalid self-hosted management credentials")
		}
	case "cn", "global":
		if len(opts.CA) != ed25519.PublicKeySize || opts.LeaseSource == nil {
			return nil, errors.New("cftunnel: official management requires an authority and lease source")
		}
	default:
		return nil, errors.New("cftunnel: invalid management channel")
	}
	client := http.Client{}
	if opts.HTTPClient != nil {
		client = *opts.HTTPClient
	}
	if client.Timeout <= 0 {
		client.Timeout = 12 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ControlClient{opts: opts, pub: pub, http: client}, nil
}

func validSelfToken(token string) bool {
	return len(token) >= 32 && len(token) <= 512 && !strings.ContainsFunc(token, func(char rune) bool {
		return char <= ' ' || char >= 127
	})
}

func (c *ControlClient) proof(ctx context.Context) (endpoint.LeaseProof, error) {
	proof, err := c.opts.LeaseSource(ctx)
	if err != nil {
		return endpoint.LeaseProof{}, errors.New("cftunnel: local authority unavailable")
	}
	now := time.Now()
	principal, err := identity.VerifyCertificate(proof.Certificate, c.opts.CA, now)
	if err != nil || principal.DeviceID != c.opts.DeviceID || !principal.PublicKey.Equal(c.pub) || !principal.Expires.After(now) {
		return endpoint.LeaseProof{}, errors.New("cftunnel: local certificate rejected")
	}
	until, err := identity.VerifyEndpointLease(proof.Lease, c.opts.CA, now, proof.Certificate, principal)
	if err != nil || !until.After(now) {
		return endpoint.LeaseProof{}, errors.New("cftunnel: local lease rejected")
	}
	return proof, nil
}

func digestHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (c *ControlClient) request(ctx context.Context, action, path, idem string, body []byte) (int, []byte, error) {
	headers := make(http.Header)
	credentialHash := digestHex(c.pub)
	if c.opts.Channel == "self" {
		headers.Set("Authorization", "Bearer "+c.opts.SelfToken)
	}
	status, raw, err := c.post(ctx, managementPrefix+"challenge", protocol.Encode(struct {
		Action   string `json:"action"`
		DeviceID string `json:"device_id"`
	}{action, c.opts.DeviceID}), headers)
	if err != nil {
		return 0, nil, err
	}
	var challenge struct {
		Value     string    `json:"challenge"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if status != http.StatusOK || strictjson.Decode(raw, &challenge) != nil || challenge.Value == "" || !challenge.ExpiresAt.After(time.Now()) {
		return 0, nil, errors.New("cftunnel: invalid management challenge")
	}
	if c.opts.Channel == "self" {
		headers.Set("Vanora-Public-Key", base64.RawURLEncoding.EncodeToString(c.pub))
	} else {
		proof, err := c.proof(ctx)
		if err != nil {
			return 0, nil, err
		}
		headers.Set("Vanora-Certificate", proof.Certificate)
		headers.Set("Vanora-Lease", proof.Lease)
		credentialHash = digestHex([]byte(proof.Certificate + "\x00" + proof.Lease))
	}
	payload := frameFields("vanora/tunnel-http/v1", c.opts.Channel, c.opts.ControlOrigin, http.MethodPost, path,
		c.opts.DeviceID, challenge.Value, digestHex(body), idem, credentialHash)
	headers.Set("Vanora-Challenge", challenge.Value)
	headers.Set("Vanora-Proof", base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.opts.PrivateKey, payload)))
	if idem != "" {
		headers.Set("Idempotency-Key", idem)
	}
	return c.post(ctx, path, body, headers)
}

func (c *ControlClient) post(ctx context.Context, path string, raw []byte, headers http.Header) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opts.ControlOrigin+path, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, errControlIO
	}
	req.GetBody = nil
	req.Header = headers.Clone()
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		return 0, nil, errControlIO
	}
	defer resp.Body.Close()
	const maxResponse = 64 << 10
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return 0, nil, errControlIO
	}
	if len(data) > maxResponse {
		return 0, nil, errors.New("cftunnel: management response exceeds 64 KiB")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		var body struct {
			Error       string `json:"error"`
			RequestID   string `json:"request_id"`
			RetryAfter  int64  `json:"retry_after,omitempty"`
			OperationID string `json:"operation_id,omitempty"`
		}
		apiErr := &APIError{Status: resp.StatusCode, Code: "invalid_response"}
		if strictjson.Decode(data, &body) == nil && tunnelIdentifier.MatchString(body.Error) &&
			tunnelIdentifier.MatchString(body.RequestID) && body.RetryAfter >= 0 &&
			(body.OperationID == "" || tunnelIdentifier.MatchString(body.OperationID)) {
			apiErr.Code, apiErr.RequestID, apiErr.OperationID = body.Error, body.RequestID, body.OperationID
			apiErr.RetryAfter = retrySeconds(body.RetryAfter)
		}
		header := resp.Header.Get("Retry-After")
		if seconds, err := strconv.ParseInt(header, 10, 64); err == nil {
			apiErr.RetryAfter = max(apiErr.RetryAfter, retrySeconds(seconds))
		} else if at, err := http.ParseTime(header); err == nil {
			apiErr.RetryAfter = max(apiErr.RetryAfter, time.Until(at))
		}
		return 0, nil, apiErr
	}
	return resp.StatusCode, data, nil
}

func retrySeconds(seconds int64) time.Duration {
	return time.Duration(max(0, min(seconds, int64((1<<63-1)/time.Second)))) * time.Second
}

func backoff(ctx context.Context, attempt int, floor time.Duration) error {
	ceiling := min(250*time.Millisecond<<min(attempt, 7), 15*time.Second)
	jitter := rand.N(ceiling)
	timer := time.NewTimer(min(floor, time.Duration(1<<63-1)-jitter) + jitter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryControl(err error) (time.Duration, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) && (apiErr.Status == 429 || apiErr.Status == 503) {
		return apiErr.RetryAfter, true
	}
	return 0, errors.Is(err, errControlIO)
}

func (c *ControlClient) call(ctx context.Context, device, action, op string, body any, mutation bool) (int, []byte, error) {
	if !tunnelIdentifier.MatchString(device) || (action == "operations" && !tunnelIdentifier.MatchString(op)) {
		return 0, nil, errors.New("cftunnel: invalid management identifier")
	}
	path := managementPrefix + device + "/" + action
	if op != "" {
		path += "/" + op
	}
	idem := ""
	if mutation {
		idem = protocol.NewID()
	}
	raw := protocol.Encode(body)
	for attempt := 0; ; attempt++ {
		status, data, err := c.request(ctx, action, path, idem, raw)
		floor, retry := retryControl(err)
		if !mutation || !retry || attempt == 3 {
			return status, data, err
		}
		if err := backoff(ctx, attempt, floor); err != nil {
			return 0, nil, err
		}
	}
}

type originRequest struct {
	Origin       string `json:"origin"`
	RuntimeID    string `json:"runtime_id"`
	IfGeneration int64  `json:"if_generation"`
}

type generationRequest struct {
	IfGeneration int64 `json:"if_generation"`
}

func decodeControl[T any](status, want int, raw []byte, err error) (T, error) {
	var result T
	if err == nil && (status != want || strictjson.Decode(raw, &result) != nil) {
		err = errors.New("cftunnel: invalid management response")
	}
	return result, err
}

func (c *ControlClient) Status(ctx context.Context, deviceID string) (AllocationView, error) {
	status, raw, err := c.call(ctx, deviceID, "status", "", struct{}{}, false)
	return decodeControl[AllocationView](status, http.StatusOK, raw, err)
}

func (c *ControlClient) mutation(ctx context.Context, deviceID, action string, body any) (MutationResult, error) {
	status, raw, err := c.call(ctx, deviceID, action, "", body, true)
	var result MutationResult
	if status == http.StatusAccepted {
		result.Operation, err = decodeControl[OperationView](status, http.StatusAccepted, raw, err)
		if err == nil && !tunnelIdentifier.MatchString(result.Operation.ID) {
			err = errors.New("cftunnel: invalid management operation identifier")
		}
	} else {
		result.Allocation, err = decodeControl[AllocationView](status, http.StatusOK, raw, err)
	}
	return result, err
}

func (c *ControlClient) Register(ctx context.Context, deviceID, origin, runtimeID string, generation int64) (MutationResult, error) {
	return c.mutation(ctx, deviceID, "register", originRequest{origin, runtimeID, generation})
}

func (c *ControlClient) ReconcileOrigin(ctx context.Context, deviceID, origin, runtimeID string, generation int64) (MutationResult, error) {
	return c.mutation(ctx, deviceID, "origin", originRequest{origin, runtimeID, generation})
}

func (c *ControlClient) Recover(ctx context.Context, deviceID, origin, runtimeID string, generation int64) (MutationResult, error) {
	return c.mutation(ctx, deviceID, "recover", originRequest{origin, runtimeID, generation})
}

func (c *ControlClient) Token(ctx context.Context, deviceID, origin, runtimeID string, generation int64) (ConnectorToken, error) {
	status, raw, err := c.call(ctx, deviceID, "token", "", originRequest{origin, runtimeID, generation}, false)
	return decodeControl[ConnectorToken](status, http.StatusOK, raw, err)
}

func (c *ControlClient) Release(ctx context.Context, deviceID string, generation int64) (MutationResult, error) {
	return c.mutation(ctx, deviceID, "release", generationRequest{generation})
}

func (c *ControlClient) Disconnect(ctx context.Context, deviceID string, generation int64) (MutationResult, error) {
	return c.mutation(ctx, deviceID, "disconnect", generationRequest{generation})
}

func (c *ControlClient) Resume(ctx context.Context, deviceID, origin, runtimeID string, generation int64) (MutationResult, error) {
	return c.mutation(ctx, deviceID, "resume", originRequest{origin, runtimeID, generation})
}

func (c *ControlClient) Deprovision(ctx context.Context, deviceID string, generation int64) (MutationResult, error) {
	return c.mutation(ctx, deviceID, "deprovision", generationRequest{generation})
}

func (c *ControlClient) GetOperation(ctx context.Context, deviceID, opID string) (OperationView, error) {
	status, raw, err := c.call(ctx, deviceID, "operations", opID, struct{}{}, false)
	result, err := decodeControl[OperationView](status, http.StatusOK, raw, err)
	if err == nil && result.ID != opID {
		return OperationView{}, errors.New("cftunnel: unexpected management operation")
	}
	return result, err
}

func (c *ControlClient) WaitOperation(ctx context.Context, deviceID, opID string) (OperationView, error) {
	for attempt := 0; ; attempt++ {
		op, err := c.GetOperation(ctx, deviceID, opID)
		floor, retry := retryControl(err)
		if err != nil && !retry {
			return op, err
		}
		if op.CompletedAt != nil {
			if op.Error != "" {
				return op, errors.New("cftunnel: management operation failed")
			}
			return op, nil
		}
		if err := backoff(ctx, attempt, floor); err != nil {
			return op, err
		}
	}
}
