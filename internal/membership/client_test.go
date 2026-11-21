package membership

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var testServiceToken = strings.Repeat("a", 32)

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

func writeEntitlement(t *testing.T, w http.ResponseWriter, status int, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
