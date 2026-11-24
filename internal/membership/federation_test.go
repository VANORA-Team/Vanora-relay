package membership_test

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

	"vanora-relay/internal/membership"
)

const (
	testIssuer  = "https://issuer.example"
	testSubject = "guest"
)

// siteService starts an entitlement service that answers for one site and
// counts how often it was consulted.
func siteService(t *testing.T, allowed bool) (*membership.Client, *atomic.Int64) {
	t.Helper()
	token := strings.Repeat("a", 40)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var who struct{ Issuer, Subject string }
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/relay/entitlement" ||
			r.Header.Get("Authorization") != "Bearer "+token ||
			json.NewDecoder(r.Body).Decode(&who) != nil ||
			who.Issuer != testIssuer || who.Subject != testSubject {
			http.Error(w, "unexpected identity", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    map[string]any{"relay_allowed": allowed, "valid_until": time.Now().Add(time.Hour).Unix()},
		})
	}))
	t.Cleanup(server.Close)
	return &membership.Client{URL: server.URL, Token: token}, &calls
}

func failingSite(t *testing.T) *membership.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	return &membership.Client{URL: server.URL, Token: strings.Repeat("a", 40)}
}

func TestSitesGrantsWhenAnySiteAllows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	denying, denyingCalls := siteService(t, false)
	allowing, allowingCalls := siteService(t, true)
	until, err := membership.Sites{denying, allowing}.Check(ctx, testIssuer, testSubject)
	if err != nil {
		t.Fatal(err)
	}
	if !until.After(time.Now()) {
		t.Fatalf("expected a future entitlement, got %v", until)
	}
	if denyingCalls.Load() != 1 || allowingCalls.Load() != 1 {
		t.Fatalf("expected both sites to be consulted, got %d and %d", denyingCalls.Load(), allowingCalls.Load())
	}
}

func TestSitesDeniesWhenNoSiteAllows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, _ := siteService(t, false)
	second, _ := siteService(t, false)
	until, err := membership.Sites{first, second}.Check(ctx, testIssuer, testSubject)
	if err != nil {
		t.Fatal(err)
	}
	if !until.IsZero() {
		t.Fatalf("expected no entitlement, got %v", until)
	}
}

func TestSitesGrantWinsOverSiteError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	allowing, _ := siteService(t, true)
	until, err := membership.Sites{failingSite(t), allowing}.Check(ctx, testIssuer, testSubject)
	if err != nil {
		t.Fatal(err)
	}
	if !until.After(time.Now()) {
		t.Fatalf("expected a future entitlement, got %v", until)
	}
}

func TestSitesFailsClosedWithoutGrant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	denying, _ := siteService(t, false)
	_, err := membership.Sites{denying, failingSite(t)}.Check(ctx, testIssuer, testSubject)
	if err == nil {
		t.Fatal("expected an error when the only remaining site cannot answer")
	}
}

func TestSitesRequiresConfiguration(t *testing.T) {
	var sites membership.Sites
	if _, err := sites.Check(context.Background(), testIssuer, testSubject); !errors.Is(err, membership.ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}
