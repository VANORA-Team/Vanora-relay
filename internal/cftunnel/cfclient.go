package cftunnel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultCFBaseURL = "https://api.cloudflare.com/client/v4"
const maxCFResponse = 2 << 20
const defaultRateDelay = time.Minute

const (
	ErrCFNotFound       ErrorCode = "cf_not_found"
	ErrCFConflict       ErrorCode = "cf_conflict"
	ErrCFConfigNotFound ErrorCode = "cf_config_not_found"
	ErrCFTunnelInUse    ErrorCode = "cf_tunnel_in_use"
	ErrCFAuthorization  ErrorCode = "cf_authorization"
	ErrCFRejected       ErrorCode = "cf_rejected"
	ErrCFRateLimited    ErrorCode = "cf_rate_limited"
	ErrCFTransient      ErrorCode = "cf_transient"
)

type CFRateLimitError struct {
	RetryAfter time.Duration
}

func (e CFRateLimitError) Error() string { return ErrCFRateLimited.Error() }
func (e CFRateLimitError) Unwrap() error { return ErrCFRateLimited }

type CFTransientError struct {
	RequestID string
}

func (e CFTransientError) Error() string { return ErrCFTransient.Error() }
func (e CFTransientError) Unwrap() error { return ErrCFTransient }

type CFClientOptions struct {
	BaseURL    string
	HTTPClient *http.Client
	Timeout    time.Duration
	Clock      func() time.Time
}

type CFClient struct {
	base, accountPath, zonePath string
	tunnelToken, dnsToken       string
	http                        *http.Client
	clock                       func() time.Time
	gate                        *GatedCloudflare
}

var _ Cloudflare = (*CFClient)(nil)

func NewCFClient(cfg Config, options CFClientOptions) (*CFClient, error) {
	base := options.BaseURL
	if base == "" {
		base = defaultCFBaseURL
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && (options.BaseURL == "" || parsed.Scheme != "http")) ||
		!validCFSegment(cfg.AccountID) || !validCFSegment(cfg.ZoneID) || cfg.TunnelToken == "" || cfg.DNSToken == "" {
		return nil, ErrInvalidClaim
	}
	client := &http.Client{}
	if options.HTTPClient != nil {
		*client = *options.HTTPClient
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if client.Timeout <= 0 || client.Timeout > timeout {
		client.Timeout = timeout
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &CFClient{base: strings.TrimRight(parsed.String(), "/"), accountPath: "/accounts/" + url.PathEscape(cfg.AccountID) + "/cfd_tunnel",
		zonePath: "/zones/" + url.PathEscape(cfg.ZoneID), tunnelToken: cfg.TunnelToken, dnsToken: cfg.DNSToken, http: client, clock: clock}, nil
}

func validCFSegment(value string) bool {
	return value != "" && len(value) <= 128 && strings.Trim(value, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_") == ""
}

type cfPageInfo struct {
	Count      int `json:"count"`
	PerPage    int `json:"per_page"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

func (p cfPageInfo) pages(page, requested, received int) int {
	if p.TotalPages > 0 {
		return p.TotalPages
	}
	if p.PerPage > 0 {
		requested = p.PerPage
	}
	if requested > 0 {
		if p.TotalCount > 0 {
			return 1 + (p.TotalCount-1)/requested
		}
		if received >= requested {
			return page + 1
		}
	}
	return page
}

type cfEnvelope struct {
	Success    bool            `json:"success"`
	Result     json.RawMessage `json:"result"`
	ResultInfo cfPageInfo      `json:"result_info"`
	Errors     []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

func (c *CFClient) request(ctx context.Context, op, method, path string, query url.Values, payload, result any) (info cfPageInfo, err error) {
	call := func() error {
		info, err = c.requestOnce(ctx, op, method, path, query, payload, result)
		return err
	}
	if c.gate != nil {
		err = c.gate.do(ctx, op, call)
	} else {
		err = call()
	}
	return info, err
}

func (c *CFClient) requestOnce(ctx context.Context, op, method, path string, query url.Values, payload, result any) (cfPageInfo, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return cfPageInfo{}, ErrInvalidClaim
		}
		body = bytes.NewReader(data)
	}
	endpoint := c.base + path
	if len(query) != 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return cfPageInfo{}, ErrInvalidClaim
	}
	token := c.tunnelToken
	if strings.HasPrefix(path, "/zones/") {
		token = c.dnsToken
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return cfPageInfo{}, CFTransientError{}
	}
	defer response.Body.Close()
	requestID := response.Header.Get("Cf-Ray")
	if requestID == "" {
		requestID = response.Header.Get("X-Request-Id")
	}
	if !validCFSegment(requestID) || strings.Contains(requestID, c.tunnelToken) || strings.Contains(requestID, c.dnsToken) {
		requestID = ""
	}
	transient := CFTransientError{RequestID: requestID}
	switch status := response.StatusCode; {
	case status == http.StatusTooManyRequests:
		return cfPageInfo{}, CFRateLimitError{RetryAfter: retryAfter(response.Header, c.clock())}
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return cfPageInfo{}, ErrCFAuthorization
	case status >= 500 || status >= 300 && status < 400 || status == http.StatusRequestTimeout:
		return cfPageInfo{}, transient
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxCFResponse+1))
	if err != nil || len(data) > maxCFResponse {
		return cfPageInfo{}, transient
	}
	var envelope cfEnvelope
	if response.StatusCode == http.StatusNoContent && result == nil {
		return cfPageInfo{}, nil
	}
	parseErr := json.Unmarshal(data, &envelope)
	if response.StatusCode == http.StatusNotFound && (path == c.accountPath || path == c.zonePath || path == c.zonePath+"/dns_records") {
		return cfPageInfo{}, ErrCFAuthorization
	}
	for _, item := range envelope.Errors {
		message := strings.ToLower(item.Message)
		switch {
		case item.Code == 10000 || item.Code == 9109 || item.Code == 9103:
			return cfPageInfo{}, ErrCFAuthorization
		case item.Code == 1055 && op == "get_configuration":
			return cfPageInfo{}, ErrCFConfigNotFound
		case strings.Contains(message, "has active connections"):
			return cfPageInfo{}, ErrCFTunnelInUse
		case strings.Contains(message, "already exists"), strings.Contains(message, "name is already"):
			return cfPageInfo{}, ErrCFConflict
		}
	}
	switch response.StatusCode {
	case http.StatusNotFound:
		if parseErr == nil {
			return cfPageInfo{}, ErrCFNotFound
		}
	case http.StatusConflict:
		return cfPageInfo{}, ErrCFConflict
	}
	if parseErr != nil {
		return cfPageInfo{}, transient
	}
	if response.StatusCode >= 400 || !envelope.Success {
		return cfPageInfo{}, ErrCFRejected
	}
	if result != nil && (len(envelope.Result) == 0 || bytes.Equal(envelope.Result, []byte("null")) || json.Unmarshal(envelope.Result, result) != nil) {
		return cfPageInfo{}, transient
	}
	return envelope.ResultInfo, nil
}

func retryAfter(header http.Header, now time.Time) time.Duration {
	delay := time.Duration(0)
	raw := strings.TrimSpace(header.Get("Retry-After"))
	if date, err := http.ParseTime(raw); err == nil {
		delay = date.Sub(now)
	} else {
		delay = positiveSeconds(raw)
	}
	for _, value := range header.Values("Ratelimit") {
		for limit := range strings.SplitSeq(value, ",") {
			var reset time.Duration
			var exhausted bool
			for field := range strings.SplitSeq(limit, ";") {
				key, value, _ := strings.Cut(strings.TrimSpace(field), "=")
				switch key {
				case "r":
					exhausted = strings.TrimSpace(value) == "0"
				case "t":
					reset = positiveSeconds(strings.TrimSpace(value))
				}
			}
			if exhausted {
				delay = max(delay, reset)
			}
		}
	}
	if delay <= 0 {
		return defaultRateDelay
	}
	return delay
}

func positiveSeconds(raw string) time.Duration {
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(min(seconds, math.MaxInt64/int64(time.Second))) * time.Second
}

type tunnelSecret struct {
	Secret string `json:"tunnel_secret"`
}

func (c *CFClient) CreateTunnel(ctx context.Context, name string, secret []byte) (Tunnel, error) {
	payload := struct {
		Name      string `json:"name"`
		ConfigSrc string `json:"config_src"`
		tunnelSecret
	}{name, "cloudflare", tunnelSecret{base64.StdEncoding.EncodeToString(secret)}}
	var tunnel Tunnel
	_, err := c.request(ctx, "create_tunnel", http.MethodPost, c.accountPath, nil, payload, &tunnel)
	return tunnel, err
}

func (c *CFClient) tunnelRequest(ctx context.Context, op, method, id, suffix string, query url.Values, payload, result any) (cfPageInfo, error) {
	if !validCFSegment(id) {
		return cfPageInfo{}, ErrInvalidClaim
	}
	return c.request(ctx, op, method, c.accountPath+"/"+url.PathEscape(id)+suffix, query, payload, result)
}

func (c *CFClient) GetTunnel(ctx context.Context, id string) (Tunnel, error) {
	var tunnel Tunnel
	_, err := c.tunnelRequest(ctx, "get_tunnel", http.MethodGet, id, "", nil, nil, &tunnel)
	return tunnel, err
}

func cfPageQuery(page, perPage int) url.Values {
	return url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(perPage)}}
}

func (c *CFClient) ListTunnels(ctx context.Context, filter TunnelListQuery) (TunnelListPage, error) {
	page, perPage := max(1, filter.Page), filter.PerPage
	if perPage <= 0 {
		perPage = 50
	}
	query := cfPageQuery(page, perPage)
	query.Set("is_deleted", "false")
	if filter.Name != "" {
		query.Set("name", filter.Name)
	}
	if filter.IncludePrefix != "" {
		query.Set("include_prefix", filter.IncludePrefix)
	}
	if filter.Status != "" {
		query.Set("status", string(filter.Status))
	}
	var tunnels []Tunnel
	info, err := c.request(ctx, "list_tunnels", http.MethodGet, c.accountPath, query, nil, &tunnels)
	return TunnelListPage{Tunnels: tunnels, TotalCount: info.TotalCount, TotalPages: info.pages(page, perPage, len(tunnels))}, err
}

type cfIngressConfig struct {
	Ingress []IngressRule `json:"ingress"`
	Warp    struct {
		Enabled bool `json:"enabled"`
	} `json:"warp-routing"`
}

func (c *CFClient) GetConfiguration(ctx context.Context, id string) (IngressConfig, error) {
	var result struct {
		Config  cfIngressConfig `json:"config"`
		Version int             `json:"version"`
	}
	_, err := c.tunnelRequest(ctx, "get_configuration", http.MethodGet, id, "/configurations", nil, nil, &result)
	return IngressConfig{Ingress: result.Config.Ingress, WarpRoutingEnabled: result.Config.Warp.Enabled, Version: result.Version}, err
}

func (c *CFClient) PutConfiguration(ctx context.Context, id string, config IngressConfig) error {
	var payload struct {
		Config cfIngressConfig `json:"config"`
	}
	payload.Config.Ingress = config.Ingress
	payload.Config.Warp.Enabled = config.WarpRoutingEnabled
	_, err := c.tunnelRequest(ctx, "put_configuration", http.MethodPut, id, "/configurations", nil, payload, nil)
	return err
}

func (c *CFClient) GetToken(ctx context.Context, id string) (string, error) {
	var token string
	_, err := c.tunnelRequest(ctx, "get_token", http.MethodGet, id, "/token", nil, nil, &token)
	if err == nil && token == "" {
		err = CFTransientError{}
	}
	return token, err
}

func (c *CFClient) RotateSecret(ctx context.Context, id string, secret []byte) error {
	payload := tunnelSecret{base64.StdEncoding.EncodeToString(secret)}
	_, err := c.tunnelRequest(ctx, "rotate_secret", http.MethodPatch, id, "", nil, payload, nil)
	return err
}

func (c *CFClient) ListConnections(ctx context.Context, id string) ([]Connection, error) {
	const perPage = 50
	var all []Connection
	for page := 1; ; page++ {
		var connectors []struct {
			ID          string       `json:"id"`
			Connections []Connection `json:"conns"`
		}
		info, err := c.tunnelRequest(ctx, "list_connections", http.MethodGet, id, "/connections", cfPageQuery(page, perPage), nil, &connectors)
		if err != nil {
			return nil, err
		}
		for _, connector := range connectors {
			if len(connector.Connections) == 0 {
				all = append(all, Connection{ID: connector.ID})
			} else {
				all = append(all, connector.Connections...)
			}
		}
		if page >= info.pages(page, perPage, len(connectors)) || len(connectors) == 0 {
			return all, nil
		}
	}
}

func (c *CFClient) DisconnectAll(ctx context.Context, id string) error {
	_, err := c.tunnelRequest(ctx, "disconnect_all", http.MethodDelete, id, "/connections", nil, nil, nil)
	return err
}

func (c *CFClient) DeleteTunnel(ctx context.Context, id string) error {
	_, err := c.tunnelRequest(ctx, "delete_tunnel", http.MethodDelete, id, "", nil, nil, nil)
	return err
}

func (c *CFClient) GetZone(ctx context.Context) (Zone, error) {
	var zone struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Status  string `json:"status"`
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	_, err := c.request(ctx, "get_zone", http.MethodGet, c.zonePath, nil, nil, &zone)
	return Zone{ID: zone.ID, Name: zone.Name, Status: zone.Status, AccountID: zone.Account.ID}, err
}

func (c *CFClient) dnsPage(ctx context.Context, page, perPage int, query url.Values) (DNSListPage, error) {
	var records []DNSRecord
	info, err := c.request(ctx, "list_dns_records", http.MethodGet, c.zonePath+"/dns_records", query, nil, &records)
	return DNSListPage{Records: records, TotalPages: info.pages(page, perPage, len(records))}, err
}

func (c *CFClient) ListDNSRecords(ctx context.Context, hostname string) ([]DNSRecord, error) {
	if hostname == "" {
		return nil, ErrInvalidClaim
	}
	const perPage = 100
	var records []DNSRecord
	for page := 1; ; page++ {
		query := cfPageQuery(page, perPage)
		query.Set("name.exact", hostname)
		result, err := c.dnsPage(ctx, page, perPage, query)
		if err != nil {
			return nil, err
		}
		records = append(records, result.Records...)
		if page >= result.TotalPages || len(result.Records) == 0 {
			return records, nil
		}
	}
}

func (c *CFClient) ListMarkedDNSRecords(ctx context.Context, page, perPage int) (DNSListPage, error) {
	page, perPage = max(1, page), max(1, perPage)
	query := cfPageQuery(page, perPage)
	query.Set("type", "CNAME")
	query.Set("comment.startswith", dnsMarkerPrefix+":")
	return c.dnsPage(ctx, page, perPage, query)
}

func (c *CFClient) CreateDNSRecord(ctx context.Context, record DNSRecord) (DNSRecord, error) {
	return c.writeDNS(ctx, "create_dns_record", http.MethodPost, "", record)
}

func (c *CFClient) PatchDNSRecord(ctx context.Context, record DNSRecord) (DNSRecord, error) {
	if !validCFSegment(record.ID) {
		return DNSRecord{}, ErrInvalidClaim
	}
	return c.writeDNS(ctx, "patch_dns_record", http.MethodPatch, "/"+url.PathEscape(record.ID), record)
}

func (c *CFClient) writeDNS(ctx context.Context, op, method, suffix string, record DNSRecord) (DNSRecord, error) {
	record.ID, record.Type, record.TTL, record.Proxied = "", "CNAME", 1, true
	var result DNSRecord
	_, err := c.request(ctx, op, method, c.zonePath+"/dns_records"+suffix, nil, record, &result)
	return result, err
}

func (c *CFClient) DeleteDNSRecord(ctx context.Context, id string) error {
	if !validCFSegment(id) {
		return ErrInvalidClaim
	}
	_, err := c.request(ctx, "delete_dns_record", http.MethodDelete, c.zonePath+"/dns_records/"+url.PathEscape(id), nil, nil, nil)
	return err
}

func cfRateDelay(err error) (time.Duration, bool) {
	var pointer *CFRateLimitError
	if errors.As(err, &pointer) && pointer != nil {
		if pointer.RetryAfter > 0 {
			return pointer.RetryAfter, true
		}
		return defaultRateDelay, true
	}
	var value CFRateLimitError
	if errors.As(err, &value) {
		if value.RetryAfter > 0 {
			return value.RetryAfter, true
		}
		return defaultRateDelay, true
	}
	return 0, false
}
