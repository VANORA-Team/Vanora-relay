package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vanora-relay/internal/cftunnel"
	"vanora-relay/internal/cftunnel/sqlstore"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/membership"
	relay "vanora-relay/internal/signal"
)

type startupNetwork struct{ closed bool }

func (*startupNetwork) Config(string, string, time.Time) ([]ice.ICEServer, error) { return nil, nil }
func (*startupNetwork) Revoke(string)                                             {}
func (n *startupNetwork) Close() error                                            { n.closed = true; return nil }

type startupCloudflare struct {
	cftunnel.Cloudflare
	zone cftunnel.Zone
}

func (cf startupCloudflare) GetZone(context.Context) (cftunnel.Zone, error) { return cf.zone, nil }

type canaryTransport func(*http.Request) (*http.Response, error)

func (f canaryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testTunnelConfig(t *testing.T) cftunnel.Config {
	t.Helper()
	return cftunnel.Config{
		Channel: cftunnel.ChannelSelf, Mode: cftunnel.ModeManaged, Process: cftunnel.ProcessAll, Store: cftunnel.StoreSQLite,
		SQLitePath: filepath.Join(t.TempDir(), "tunnels.db"), ControlOrigin: "https://relay.example.com",
		AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), Namespace: "relay",
		BaseDomain: "edge.example.com", MasterKey: bytes.Repeat([]byte{3}, 32), AccountCap: 10,
		EdgeGate: cftunnel.EdgeDesktopOnly, Reaper: cftunnel.ReaperConfig{Mode: cftunnel.ReaperOff},
	}
}

func TestTunnelServerProcessModes(t *testing.T) {
	for _, test := range []struct {
		name        string
		mode        cftunnel.Mode
		process     cftunnel.Process
		signal, api int
	}{
		{"off", cftunnel.ModeOff, cftunnel.ProcessAll, 204, 404},
		{"all", cftunnel.ModeManaged, cftunnel.ProcessAll, 204, 405},
		{"control", cftunnel.ModeManaged, cftunnel.ProcessControl, 404, 405},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testTunnelConfig(t)
			cfg.Mode, cfg.Process = test.mode, test.process
			if cfg.Process == cftunnel.ProcessControl {
				cfg.Store = cftunnel.StorePostgres
			}
			network := new(startupNetwork)
			var storeOpened, cfCreated, networkStarted bool
			handler, closeServer, err := buildServer(t.Context(), cfg, relayStartup{
				selfToken: strings.Repeat("s", 40),
				openStore: func(ctx context.Context, cfg cftunnel.Config) (cftunnel.Store, error) {
					storeOpened = true
					return sqlstore.OpenSQLite(ctx, cfg.SQLitePath, sqlstore.Options{})
				},
				newNetwork: func() (relayNetwork, error) { networkStarted = true; return network, nil },
				newCloudflare: func(cfg cftunnel.Config) (cftunnel.Cloudflare, error) {
					cfCreated = true
					return startupCloudflare{zone: cftunnel.Zone{ID: cfg.ZoneID, AccountID: cfg.AccountID, Name: "example.com", Status: "active"}}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(closeServer)
			for path, want := range map[string]int{"/v1/signal?probe=1": test.signal, "/v1/probe": test.signal,
				"/v1/tunnels/challenge": test.api, "/healthz": 200, "/readyz": 200} {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Header.Set("Authorization", "Bearer "+strings.Repeat("s", 40))
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, req)
				if res.Code != want {
					t.Errorf("%s returned %d, want %d", path, res.Code, want)
				}
			}
			handler.drain(t.Context())
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if res.Code != http.StatusServiceUnavailable || res.Body.String() != "draining\n" {
				t.Fatalf("readiness after drain = %d, %q", res.Code, res.Body.String())
			}
			enabled := cfg.Mode != cftunnel.ModeOff
			if storeOpened != enabled || cfCreated != enabled || networkStarted != (cfg.Process == cftunnel.ProcessAll) {
				t.Fatalf("unexpected startup dependencies: store=%v cloudflare=%v network=%v", storeOpened, cfCreated, networkStarted)
			}
			closeServer()
			if network.closed != networkStarted {
				t.Fatal("network lifecycle differs from process configuration")
			}
		})
	}
}

func TestMetricsAccess(t *testing.T) {
	cfg := cftunnel.Config{Mode: cftunnel.ModeOff, Channel: cftunnel.ChannelSelf,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	handler, closeServer, err := buildServer(t.Context(), cfg, relayStartup{
		metricsToken: "metrics-token",
		newNetwork:   func() (relayNetwork, error) { return new(startupNetwork), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeServer()
	for _, test := range []struct {
		remote, forwarded, token string
		want                     int
	}{
		{"127.0.0.1:1234", "", "", 200},
		{"127.0.0.1:1234", "192.0.2.1", "", 401},
		{"192.0.2.1:1234", "127.0.0.1", "", 401},
		{"192.0.2.1:1234", "", "wrong", 401},
		{"192.0.2.1:1234", "", "metrics-token", 200},
	} {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = test.remote
		if test.forwarded != "" {
			req.Header.Set("X-Forwarded-For", test.forwarded)
		}
		if test.token != "" {
			req.Header.Set("Authorization", "Bearer "+test.token)
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != test.want {
			t.Fatalf("metrics from %s via %q = %d, want %d", test.remote, test.forwarded, res.Code, test.want)
		}
		if res.Code == 200 && (!strings.Contains(res.Body.String(), `"active_peers":0`) ||
			!strings.Contains(res.Body.String(), `"cf_api_requests_total":{}`)) {
			t.Fatalf("missing metrics in %s", res.Body)
		}
	}
}

func TestTunnelServerFailsFast(t *testing.T) {
	t.Run("off control", func(t *testing.T) {
		cfg := testTunnelConfig(t)
		cfg.Mode, cfg.Process, cfg.Store = cftunnel.ModeOff, cftunnel.ProcessControl, cftunnel.StorePostgres
		if _, _, err := buildServer(t.Context(), cfg, relayStartup{}); err == nil {
			t.Fatal("off control started")
		}
	})
	t.Run("official manifest", func(t *testing.T) {
		cfg := testTunnelConfig(t)
		cfg.Channel = cftunnel.ChannelCN
		_, _, err := buildServer(t.Context(), cfg, relayStartup{openStore: func(context.Context, cftunnel.Config) (cftunnel.Store, error) {
			t.Fatal("opened store before validating manifest")
			return nil, errors.New("unexpected store")
		}})
		if err == nil || !strings.Contains(err.Error(), "manifest") {
			t.Fatalf("unexpected manifest error: %v", err)
		}
	})
	t.Run("stored scope", func(t *testing.T) {
		cfg := testTunnelConfig(t)
		scope, err := cfg.BuildScope(nil, "", "")
		if err != nil {
			t.Fatal(err)
		}
		store, err := sqlstore.OpenSQLite(t.Context(), cfg.SQLitePath, sqlstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnsureScope(t.Context(), scope); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		cfg.MasterKey = bytes.Repeat([]byte{4}, 32)
		_, _, err = buildServer(t.Context(), cfg, relayStartup{})
		if !errors.Is(err, cftunnel.ErrScopeMismatch) {
			t.Fatalf("unexpected scope error: %v", err)
		}
	})
	t.Run("edge canary", func(t *testing.T) {
		cfg := testTunnelConfig(t)
		cfg.EdgeCanaryHost = "canary.edge.example.com"
		_, _, err := buildServer(t.Context(), cfg, relayStartup{
			newCloudflare: func(cfg cftunnel.Config) (cftunnel.Cloudflare, error) {
				return startupCloudflare{zone: cftunnel.Zone{ID: cfg.ZoneID, AccountID: cfg.AccountID, Name: "example.com", Status: "active"}}, nil
			},
			newNetwork: func() (relayNetwork, error) { return &startupNetwork{}, nil },
			canaryClient: &http.Client{Transport: canaryTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://canary.edge.example.com/v1/tunnel/ws" {
					t.Errorf("wrong canary URL: %s", r.URL)
				}
				return &http.Response{StatusCode: 530, Body: io.NopCloser(strings.NewReader("ignored"))}, nil
			})},
		})
		if err == nil || !strings.Contains(err.Error(), "HTTP 530") {
			t.Fatalf("unexpected canary error: %v", err)
		}
	})
}

func TestEntitlementVerifier(t *testing.T) {
	token := strings.Repeat("a", 40)
	allKeys := []string{
		"RELAY_MEMBERSHIP_URL", "RELAY_MEMBERSHIP_TOKEN",
		"RELAY_CN_MEMBERSHIP_URL", "RELAY_CN_MEMBERSHIP_TOKEN",
		"RELAY_GLOBAL_MEMBERSHIP_URL", "RELAY_GLOBAL_MEMBERSHIP_TOKEN",
	}
	cases := []struct {
		name    string
		channel relay.Channel
		env     map[string]string
		wantURL string
		wantErr string
	}{
		{
			name:    "self_hosted_has_no_membership",
			channel: relay.ChannelSelf,
			wantURL: "",
		},
		{
			name:    "self_hosted_rejects_legacy_membership",
			channel: relay.ChannelSelf,
			env: map[string]string{
				"RELAY_MEMBERSHIP_URL":   "https://ignored.example",
				"RELAY_MEMBERSHIP_TOKEN": token,
			},
			wantErr: "must not be set with RELAY_CHANNEL=self",
		},
		{
			name:    "self_hosted_rejects_site_membership",
			channel: relay.ChannelSelf,
			env: map[string]string{
				"RELAY_CN_MEMBERSHIP_URL":   "https://cn.example",
				"RELAY_CN_MEMBERSHIP_TOKEN": token,
			},
			wantErr: "must not be set with RELAY_CHANNEL=self",
		},
		{
			name:    "cn_uses_legacy_variables",
			channel: relay.ChannelCN,
			env: map[string]string{
				"RELAY_MEMBERSHIP_URL":   "https://cn.example",
				"RELAY_MEMBERSHIP_TOKEN": token,
			},
			wantURL: "https://cn.example",
		},
		{
			name:    "global_uses_legacy_variables",
			channel: relay.ChannelGlobal,
			env: map[string]string{
				"RELAY_MEMBERSHIP_URL":   "https://global.example",
				"RELAY_MEMBERSHIP_TOKEN": token,
			},
			wantURL: "https://global.example",
		},
		{
			name:    "cn_uses_cn_variables",
			channel: relay.ChannelCN,
			env: map[string]string{
				"RELAY_CN_MEMBERSHIP_URL":   "https://cn.example",
				"RELAY_CN_MEMBERSHIP_TOKEN": token,
			},
			wantURL: "https://cn.example",
		},
		{
			name:    "cn_prefers_cn_over_legacy",
			channel: relay.ChannelCN,
			env: map[string]string{
				"RELAY_MEMBERSHIP_URL":      "https://legacy.example",
				"RELAY_MEMBERSHIP_TOKEN":    token,
				"RELAY_CN_MEMBERSHIP_URL":   "https://cn.example",
				"RELAY_CN_MEMBERSHIP_TOKEN": token,
			},
			wantURL: "https://cn.example",
		},
		{
			name:    "cn_rejects_global_variables",
			channel: relay.ChannelCN,
			env: map[string]string{
				"RELAY_CN_MEMBERSHIP_URL":       "https://cn.example",
				"RELAY_CN_MEMBERSHIP_TOKEN":     token,
				"RELAY_GLOBAL_MEMBERSHIP_URL":   "https://global.example",
				"RELAY_GLOBAL_MEMBERSHIP_TOKEN": token,
			},
			wantErr: "must not configure GLOBAL membership variables",
		},
		{
			name:    "global_rejects_cn_variables",
			channel: relay.ChannelGlobal,
			env: map[string]string{
				"RELAY_CN_MEMBERSHIP_URL":       "https://cn.example",
				"RELAY_CN_MEMBERSHIP_TOKEN":     token,
				"RELAY_GLOBAL_MEMBERSHIP_URL":   "https://global.example",
				"RELAY_GLOBAL_MEMBERSHIP_TOKEN": token,
			},
			wantErr: "must not configure CN membership variables",
		},
		{
			name:    "official_channel_requires_a_service",
			channel: relay.ChannelGlobal,
			wantErr: "requires RELAY_GLOBAL_MEMBERSHIP_URL",
		},
		{
			name:    "url_without_token",
			channel: relay.ChannelCN,
			env: map[string]string{
				"RELAY_CN_MEMBERSHIP_URL": "https://cn.example",
			},
			wantErr: "must both be set",
		},
		{
			name:    "short_token",
			channel: relay.ChannelCN,
			env: map[string]string{
				"RELAY_CN_MEMBERSHIP_URL":   "https://cn.example",
				"RELAY_CN_MEMBERSHIP_TOKEN": "short",
			},
			wantErr: "at least 32 bytes",
		},
		{
			name:    "token_with_whitespace",
			channel: relay.ChannelCN,
			env: map[string]string{
				"RELAY_CN_MEMBERSHIP_URL":   "https://cn.example",
				"RELAY_CN_MEMBERSHIP_TOKEN": strings.Repeat("a", 31) + " ",
			},
			wantErr: "without whitespace",
		},
		{
			name:    "legacy_pair_is_incomplete",
			channel: relay.ChannelCN,
			env: map[string]string{
				"RELAY_MEMBERSHIP_URL": "https://cn.example",
			},
			wantErr: "configure both RELAY_MEMBERSHIP_URL",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range allKeys {
				t.Setenv(key, "")
			}
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			verifier, err := entitlementVerifier(tc.channel)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantURL == "" {
				if verifier != nil {
					t.Fatalf("want no entitlement verifier, got %#v", verifier)
				}
				return
			}
			client, ok := verifier.(*membership.Client)
			if !ok || client.URL != tc.wantURL {
				t.Fatalf("want membership client %q, got %#v", tc.wantURL, verifier)
			}
		})
	}
}

func TestAllowedIssuerConfig(t *testing.T) {
	cases := []struct {
		name    string
		channel relay.Channel
		value   string
		want    string
		wantErr string
	}{
		{"empty_cn", relay.ChannelCN, "", "", ""},
		{"valid_https_cn", relay.ChannelCN, "https://auth.cn.example/realms/vanora", "https://auth.cn.example/realms/vanora", ""},
		{"valid_loopback_global", relay.ChannelGlobal, "http://127.0.0.1:8080/realms/vanora", "http://127.0.0.1:8080/realms/vanora", ""},
		{"plain_http_public_rejected", relay.ChannelCN, "http://auth.cn.example/realms/vanora", "", "invalid RELAY_ALLOWED_ISSUER"},
		{"query_rejected", relay.ChannelGlobal, "https://auth.global.example?x=1", "", "invalid RELAY_ALLOWED_ISSUER"},
		{"self_hosted_rejected", relay.ChannelSelf, "https://auth.cn.example", "", "must not be set with RELAY_CHANNEL=self"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RELAY_ALLOWED_ISSUER", tc.value)
			got, err := allowedIssuerConfig(tc.channel)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got (%q, %v), want (%q, nil)", got, err, tc.want)
			}
		})
	}
}

func TestRunSelfHostedRejectsOfficialIdentityKey(t *testing.T) {
	t.Setenv("RELAY_CHANNEL", "self")
	t.Setenv("RELAY_IDENTITY_PUBLIC_KEY", strings.Repeat("aa", 32))
	t.Setenv("RELAY_IDENTITY_PUBLIC_KEYS", "")
	t.Setenv("RELAY_SELF_TOKEN", strings.Repeat("b", 40))
	t.Setenv("RELAY_ALLOWED_ISSUER", "")
	t.Setenv("RELAY_MEMBERSHIP_URL", "")
	t.Setenv("RELAY_MEMBERSHIP_TOKEN", "")
	t.Setenv("RELAY_CN_MEMBERSHIP_URL", "")
	t.Setenv("RELAY_CN_MEMBERSHIP_TOKEN", "")
	t.Setenv("RELAY_GLOBAL_MEMBERSHIP_URL", "")
	t.Setenv("RELAY_GLOBAL_MEMBERSHIP_TOKEN", "")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "RELAY_IDENTITY_PUBLIC_KEY must not be set") {
		t.Fatalf("expected self-hosted identity key rejection, got %v", err)
	}
}

func TestIdentityPublicKeysAndMembershipCacheTTL(t *testing.T) {
	keyA := strings.Repeat("11", 32)
	keyB := strings.Repeat("22", 32)
	t.Setenv("RELAY_IDENTITY_PUBLIC_KEY", keyA)
	t.Setenv("RELAY_IDENTITY_PUBLIC_KEYS", keyB)
	keys, err := identityPublicKeysConfig()
	if err != nil || len(keys) != 2 {
		t.Fatalf("expected 2 trusted keys, got %d, err=%v", len(keys), err)
	}

	t.Setenv("RELAY_MEMBERSHIP_CACHE_TTL", "")
	if ttl, err := membershipCacheTTLConfig(); err != nil || ttl != defaultMembershipCacheTTL {
		t.Fatalf("default cache ttl = (%v, %v), want %v", ttl, err, defaultMembershipCacheTTL)
	}
	t.Setenv("RELAY_MEMBERSHIP_CACHE_TTL", "0")
	if ttl, err := membershipCacheTTLConfig(); err != nil || ttl != 0 {
		t.Fatalf("disabled cache ttl = (%v, %v), want 0", ttl, err)
	}
	t.Setenv("RELAY_MEMBERSHIP_CACHE_TTL", "30s")
	if ttl, err := membershipCacheTTLConfig(); err != nil || ttl != 30*time.Second {
		t.Fatalf("custom cache ttl = (%v, %v), want 30s", ttl, err)
	}
	t.Setenv("RELAY_MEMBERSHIP_CACHE_TTL", "-5s")
	if _, err := membershipCacheTTLConfig(); err == nil {
		t.Fatal("negative cache ttl accepted")
	}
}
