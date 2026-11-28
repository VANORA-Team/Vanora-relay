package membership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

var testServiceToken = strings.Repeat("a", 32)

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testEntitlementResponse(allowed bool, end time.Time) *http.Response {
	payload := fmt.Sprintf(`{"success":true,"data":{"relay_allowed":%t,"valid_until":%d}}`, allowed, end.Unix())
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload))}
}

func TestLookupCacheSharesPositiveResultsAndHonorsExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, lifetime := range []time.Duration{time.Second, time.Minute} {
			end := time.Now().Truncate(time.Second).Add(lifetime)
			calls := 0
			client := &Client{
				URL: "https://relay.example", Token: testServiceToken, CacheTTL: 10 * time.Second,
				HTTP: &http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
					calls++
					return testEntitlementResponse(calls == 1, end), nil
				})},
			}
			if got, err := client.Check(t.Context(), "issuer", "subject"); err != nil || !got.Equal(end) {
				t.Fatalf("initial Check = %v, %v, want %v", got, err, end)
			}
			if got, err := client.Lookup(t.Context(), "issuer", "subject"); err != nil || !got.RelayAllowed || calls != 1 {
				t.Fatalf("cached Lookup = %+v, %v, with %d requests", got, err, calls)
			}
			time.Sleep(min(client.CacheTTL, lifetime))
			if got, err := client.Check(t.Context(), "issuer", "subject"); err != nil || !got.IsZero() || calls != 2 {
				t.Fatalf("refreshed Check = %v, %v, with %d requests", got, err, calls)
			}
		}
	})
}

func TestLookupCachesDefinitiveDenialsBriefly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, ttl := range []time.Duration{4 * time.Second, time.Minute} {
			calls := 0
			client := &Client{
				URL: "https://relay.example", Token: testServiceToken, CacheTTL: ttl,
				HTTP: &http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
					calls++
					return testEntitlementResponse(calls > 1, time.Now().Add(time.Hour)), nil
				})},
			}
			negativeTTL := min(ttl/2, 5*time.Second)
			if got, err := client.Lookup(t.Context(), "issuer", "subject"); err != nil || got.RelayAllowed {
				t.Fatalf("initial Lookup = %+v, %v", got, err)
			}
			time.Sleep(negativeTTL - time.Nanosecond)
			if got, err := client.Check(t.Context(), "issuer", "subject"); err != nil || !got.IsZero() || calls != 1 {
				t.Fatalf("cached denial = %v, %v, with %d requests", got, err, calls)
			}
			time.Sleep(time.Nanosecond)
			if got, err := client.Check(t.Context(), "issuer", "subject"); err != nil || got.IsZero() || calls != 2 {
				t.Fatalf("expired denial = %v, %v, with %d requests", got, err, calls)
			}
		}
	})
}

func TestLookupCoalescesCheckAndLookupWithIndependentCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		client := &Client{
			URL: "https://relay.example", Token: testServiceToken,
			HTTP: &http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				<-release
				return testEntitlementResponse(true, time.Now().Add(time.Hour)), nil
			})},
		}
		leader, cancel := context.WithCancel(t.Context())
		checkResult := make(chan error, 1)
		go func() {
			_, err := client.Check(leader, "issuer", "subject")
			checkResult <- err
		}()
		synctest.Wait()
		lookupResult := make(chan error, 1)
		go func() {
			ent, err := client.Lookup(t.Context(), "issuer", "subject")
			if err == nil && !ent.RelayAllowed {
				err = errors.New("shared lookup lost its grant")
			}
			lookupResult <- err
		}()
		synctest.Wait()
		cancel()
		if err := <-checkResult; !errors.Is(err, context.Canceled) {
			t.Errorf("canceled caller returned %v", err)
		}
		close(release)
		if err := <-lookupResult; err != nil {
			t.Fatal(err)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("backend got %d requests, want one shared request", got)
		}
	})
}

func TestCheckGrantsRelayEntitlement(t *testing.T) {
	wantEnd := time.Now().Add(24 * time.Hour).Truncate(time.Second).UTC()
	var gotPath, gotAuthorization string
	var gotRequest entitlementRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthorization = r.Header.Get("Authorization")
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", contentType)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Errorf("decode request: %v", err)
		}
		writeEntitlement(t, w, http.StatusOK, map[string]any{
			"success": true,
			"message": "",
			"data": map[string]any{
				"relay_allowed": true,
				"valid_until":   wantEnd.Unix(),
			},
		})
	}))
	defer server.Close()

	client := &Client{URL: server.URL, Token: testServiceToken}
	gotEnd, err := client.Check(context.Background(), "https://idp.example.com", "subject-123")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !gotEnd.Equal(wantEnd) {
		t.Fatalf("Check() end = %s, want %s", gotEnd, wantEnd)
	}
	if gotPath != entitlementPath {
		t.Fatalf("path = %q, want %q", gotPath, entitlementPath)
	}
	if gotAuthorization != "Bearer "+testServiceToken {
		t.Fatalf("Authorization = %q", gotAuthorization)
	}
	if gotRequest.Issuer != "https://idp.example.com" || gotRequest.Subject != "subject-123" {
		t.Fatalf("request = %#v", gotRequest)
	}
}

func TestCheckAcceptsFullEndpointURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != entitlementPath {
			t.Errorf("path = %q, want %q", r.URL.Path, entitlementPath)
		}
		writeEntitlement(t, w, http.StatusOK, map[string]any{
			"success": true,
			"data": map[string]any{
				"relay_allowed": true,
				"valid_until":   time.Now().Add(time.Hour).Unix(),
			},
		})
	}))
	defer server.Close()

	client := &Client{URL: server.URL + entitlementPath + "/", Token: testServiceToken}
	if _, err := client.Check(context.Background(), "issuer", "subject"); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestCheckDenialReturnsZeroTime(t *testing.T) {
	tests := []struct {
		name string
		data map[string]any
	}{
		{
			name: "relay not allowed",
			data: map[string]any{"relay_allowed": false, "valid_until": 0},
		},
		{
			name: "allowed but already expired",
			data: map[string]any{"relay_allowed": true, "valid_until": time.Now().Add(-time.Minute).Unix()},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeEntitlement(t, w, http.StatusOK, map[string]any{
					"success": true,
					"data":    test.data,
				})
			}))
			defer server.Close()

			client := &Client{URL: server.URL, Token: testServiceToken}
			end, err := client.Check(context.Background(), "issuer", "subject")
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if !end.IsZero() {
				t.Fatalf("Check() end = %s, want zero", end)
			}
		})
	}
}

func TestCheckFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantErr  error
		contains string
	}{
		{
			name:     "unauthorized",
			status:   http.StatusUnauthorized,
			body:     `{"success":false,"message":"unauthorized"}`,
			wantErr:  ErrUnauthenticated,
			contains: "status 401",
		},
		{
			name:     "server error",
			status:   http.StatusInternalServerError,
			body:     `{"success":false,"message":"database unavailable"}`,
			contains: "status 500",
		},
		{
			name:    "malformed response",
			status:  http.StatusOK,
			body:    `{not-json`,
			wantErr: ErrMalformedResponse,
		},
		{
			name:     "missing data",
			status:   http.StatusOK,
			body:     `{"success":true}`,
			wantErr:  ErrMalformedResponse,
			contains: "missing data",
		},
		{
			name:     "allowed without end",
			status:   http.StatusOK,
			body:     `{"success":true,"data":{"relay_allowed":true,"valid_until":0}}`,
			wantErr:  ErrMalformedResponse,
			contains: "without an entitlement end",
		},
		{
			name:     "success false",
			status:   http.StatusOK,
			body:     `{"success":false,"message":"invalid parameters"}`,
			contains: "invalid parameters",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			client := &Client{URL: server.URL, Token: testServiceToken}
			end, err := client.Check(context.Background(), "issuer", "subject")
			if err == nil {
				t.Fatalf("Check() error = nil, end = %s; want error", end)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("Check() error = %v, want errors.Is %v", err, test.wantErr)
			}
			if test.contains != "" && !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("Check() error = %v, want containing %q", err, test.contains)
			}
			if !end.IsZero() {
				t.Fatalf("Check() end = %s, want zero", end)
			}
		})
	}
}

func TestCheckDoesNotFollowRedirects(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		writeEntitlement(t, w, http.StatusOK, map[string]any{
			"success": true,
			"data": map[string]any{
				"relay_allowed": true,
				"valid_until":   time.Now().Add(time.Hour).Unix(),
			},
		})
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+entitlementPath, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	client := &Client{URL: redirector.URL, Token: testServiceToken}
	end, err := client.Check(context.Background(), "issuer", "subject")
	if err == nil {
		t.Fatalf("Check() error = nil, end = %s; want redirect error", end)
	}
	if !strings.Contains(err.Error(), "status 307") {
		t.Fatalf("Check() error = %v, want status 307", err)
	}
	client.HTTP = redirector.Client()
	if _, err := client.Lookup(t.Context(), "issuer", "subject"); err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Fatalf("Lookup() error = %v, want status 307", err)
	}
	if hits := targetHits.Load(); hits != 0 {
		t.Fatalf("redirect target received %d requests, want 0", hits)
	}
}

func TestCheckRejectsInvalidConfiguration(t *testing.T) {
	client := &Client{URL: "http://127.0.0.1:1", Token: testServiceToken}
	if _, err := client.Check(context.Background(), "", "subject"); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("empty issuer error = %v, want ErrInvalidIdentity", err)
	}
	if _, err := client.Check(context.Background(), "issuer", "  "); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("blank subject error = %v, want ErrInvalidIdentity", err)
	}
	for _, identity := range [][2]string{
		{" issuer", "subject"},
		{"issuer", "subject "},
		{"issuer\n", "subject"},
		{"issuer", "subject\t"},
		{strings.Repeat("i", maxIssuerBytes+1), "subject"},
		{"issuer", strings.Repeat("s", maxSubjectBytes+1)},
	} {
		if _, err := client.Check(context.Background(), identity[0], identity[1]); !errors.Is(err, ErrInvalidIdentity) {
			t.Fatalf("identity %q/%q error = %v, want ErrInvalidIdentity", identity[0], identity[1], err)
		}
	}

	short := &Client{URL: "http://127.0.0.1:1", Token: "too-short"}
	if _, err := short.Check(context.Background(), "issuer", "subject"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("short token error = %v, want ErrNotConfigured", err)
	}

	noURL := &Client{Token: testServiceToken}
	if _, err := noURL.Check(context.Background(), "issuer", "subject"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("missing URL error = %v, want ErrNotConfigured", err)
	}

	badScheme := &Client{URL: "ftp://example.com", Token: testServiceToken}
	if _, err := badScheme.Check(context.Background(), "issuer", "subject"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("bad scheme error = %v, want ErrNotConfigured", err)
	}

	insecureRemote := &Client{URL: "http://example.com", Token: testServiceToken}
	if _, err := insecureRemote.Check(context.Background(), "issuer", "subject"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("insecure remote HTTP error = %v, want ErrNotConfigured", err)
	}

	userinfo := &Client{URL: "https://user@example.com", Token: testServiceToken}
	if _, err := userinfo.Check(context.Background(), "issuer", "subject"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("userinfo URL error = %v, want ErrNotConfigured", err)
	}

	var nilClient *Client
	if _, err := nilClient.Check(context.Background(), "issuer", "subject"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("nil client error = %v, want ErrNotConfigured", err)
	}
}

func TestLookupTunnelFields(t *testing.T) {
	end := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	for _, test := range []struct {
		name string
		data map[string]any
		want Entitlement
	}{
		{"legacy grant", map[string]any{"relay_allowed": true, "valid_until": end.Unix()}, Entitlement{RelayAllowed: true, ValidUntil: end}},
		{"legacy denial", map[string]any{"relay_allowed": false, "valid_until": 0}, Entitlement{}},
		{"verified free account", map[string]any{"relay_allowed": false, "tunnel_allowed": true}, Entitlement{TunnelAllowed: new(true)}},
		{"additional slots", map[string]any{"relay_allowed": true, "valid_until": end.Unix(), "tunnel_connect_allowed": true, "max_tunnels": 7, "tunnel_valid_until": end.Unix()},
			Entitlement{RelayAllowed: true, ValidUntil: end, TunnelConnectAllowed: new(true), MaxTunnels: new(7), TunnelValidUntil: new(end.Unix())}},
		{"explicit denial", map[string]any{"tunnel_allowed": false, "tunnel_connect_allowed": false, "max_tunnels": 0, "tunnel_valid_until": 0},
			Entitlement{TunnelAllowed: new(false), TunnelConnectAllowed: new(false), MaxTunnels: new(0), TunnelValidUntil: new(int64(0))}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeEntitlement(t, w, http.StatusOK, map[string]any{"success": true, "data": test.data})
			}))
			defer server.Close()
			client := &Client{URL: server.URL, Token: testServiceToken}
			got, err := client.Lookup(t.Context(), "issuer", "subject")
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("Lookup() = %+v, %v; want %+v", got, err, test.want)
			}
		})
	}
}

func TestLookupMalformedTunnelFieldsDoNotAffectTURN(t *testing.T) {
	end := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	for name, data := range map[string]map[string]any{
		"negative slots":     {"max_tunnels": -1},
		"excessive slots":    {"max_tunnels": 10001},
		"string slots":       {"max_tunnels": "3"},
		"fractional slots":   {"max_tunnels": 2.5},
		"invalid time":       {"tunnel_allowed": true, "tunnel_valid_until": -1},
		"string time":        {"tunnel_valid_until": "tomorrow"},
		"time overflow":      {"tunnel_valid_until": json.Number("9223372036854775808")},
		"null gate":          {"tunnel_allowed": nil},
		"invalid connection": {"tunnel_connect_allowed": "true"},
	} {
		t.Run(name, func(t *testing.T) {
			data["relay_allowed"], data["valid_until"] = true, end.Unix()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeEntitlement(t, w, http.StatusOK, map[string]any{"success": true, "data": data})
			}))
			defer server.Close()
			client := &Client{URL: server.URL, Token: testServiceToken}
			ent, err := client.Lookup(t.Context(), "issuer", "subject")
			if err != nil || !ent.TunnelFieldsInvalid || !ent.RelayAllowed || !ent.ValidUntil.Equal(end) {
				t.Fatalf("Lookup() = %+v, %v", ent, err)
			}
			if until, err := client.Check(t.Context(), "issuer", "subject"); err != nil || !until.Equal(end) {
				t.Fatalf("Check() = %s, %v", until, err)
			}
		})
	}
}

func TestLookupFailureReturnsNoEntitlement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/large") {
			_, _ = w.Write([]byte(`{"success":true,"data":{"tunnel_allowed":true}}` + strings.Repeat(" ", maxResponseBytes)))
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := &Client{URL: server.URL, Token: testServiceToken}
	if ent, err := client.Lookup(t.Context(), "issuer", "subject"); err == nil || ent != (Entitlement{}) {
		t.Fatalf("unavailable lookup = %+v, %v", ent, err)
	}
	client.URL = server.URL + "/large"
	if ent, err := client.Lookup(t.Context(), "issuer", "subject"); !errors.Is(err, ErrMalformedResponse) || ent != (Entitlement{}) {
		t.Fatalf("oversized lookup = %+v, %v", ent, err)
	}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if ent, err := client.Lookup(ctx, "issuer", "subject"); !errors.Is(err, context.DeadlineExceeded) || ent != (Entitlement{}) {
		t.Fatalf("timed-out lookup = %+v, %v", ent, err)
	}
	server.Close()
	if ent, err := client.Lookup(t.Context(), "issuer", "subject"); err == nil || ent != (Entitlement{}) {
		t.Fatalf("unreachable lookup = %+v, %v", ent, err)
	}
}

func writeEntitlement(t *testing.T, w http.ResponseWriter, status int, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
