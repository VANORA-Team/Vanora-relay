package cftunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testEnv map[string]string

func (e testEnv) lookup(key string) string { return e[key] }

func selfEnv() testEnv {
	return testEnv{
		"RELAY_TUNNEL_MODE":                 "managed",
		"RELAY_TUNNEL_SQLITE_PATH":          "state/relay.db",
		"RELAY_TUNNEL_CONTROL_ORIGIN":       "http://127.0.0.1:8080",
		"RELAY_CF_ACCOUNT_ID":               strings.Repeat("a", 32),
		"RELAY_CF_ZONE_ID":                  strings.Repeat("b", 32),
		"RELAY_CF_BASE_DOMAIN":              "Tunnel.Example.",
		"RELAY_CF_NAMESPACE":                "site-self",
		"RELAY_CF_API_TOKEN":                strings.Repeat("x", 32),
		"RELAY_TUNNEL_MASTER_KEY":           strings.Repeat("aa", 32),
		"RELAY_TUNNEL_EDGE_GATE":            "desktop_only",
		"RELAY_TUNNEL_SELF_ALLOWED_DEVICES": "sdev_" + strings.Repeat("a", 26),
	}
}

func TestConfigOffAndSelf(t *testing.T) {
	cfg, err := ConfigFromEnv(ChannelCN, testEnv{}.lookup)
	if err != nil || cfg.Mode != ModeOff || cfg.Store != "" || cfg.SiteManifest != nil {
		t.Fatalf("off config = %+v, %v", cfg, err)
	}
	for _, channel := range []Channel{ChannelCN, ChannelSelf} {
		env := testEnv{"RELAY_TUNNEL_SELF_ALLOWED_DEVICES": "a"}
		if channel.IsSelfHosted() {
			env = testEnv{"RELAY_TUNNEL_SITE_MANIFEST": "missing.json"}
		}
		if _, err := ConfigFromEnv(channel, env.lookup); err == nil {
			t.Fatalf("mode off accepted mixed %s channel config", channel)
		}
	}
	off := testEnv{"RELAY_TUNNEL_SITE_MANIFEST": "missing.json", "RELAY_TUNNEL_SQLITE_PATH": ":memory:"}
	if _, err := ConfigFromEnv(ChannelCN, off.lookup); err != nil {
		t.Fatalf("off read a manifest or a database: %v", err)
	}
	env := selfEnv()
	env["RELAY_TRUSTED_PROXY_CIDRS"] = "192.0.2.0/24, ::1, 127.0.0.2"
	cfg, err = ConfigFromEnv(ChannelSelf, env.lookup)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AccountCap != 16 || cfg.FreeSlots != 1 || cfg.PaidDefaultSlots != 3 || len(cfg.SelfDevices) != 1 ||
		cfg.BaseDomain != "tunnel.example" || len(cfg.TrustedProxies) != 3 || cfg.EdgeGate != EdgeDesktopOnly || len(cfg.EdgeKey) != 0 {
		t.Fatalf("unexpected self-hosted config: %+v", cfg)
	}
	if cfg.Reaper != (ReaperConfig{Mode: ReaperDryRun, DownGrace: 5 * time.Minute, LegacyGrace: 168 * time.Hour,
		InactiveGrace: time.Hour, PendingGrace: 15 * time.Minute, OrphanGrace: 24 * time.Hour,
		Interval: time.Minute, Budget: 30 * time.Second, Concurrency: 2}) ||
		cfg.CloudflareRate != (RateConfig{3, 4, 4}) {
		t.Fatal("unexpected reaper or Cloudflare API rate defaults")
	}
	env["RELAY_TUNNEL_REAPER"] = "active"
	env["RELAY_TUNNEL_REAP_DOWN"] = "4m"
	env["RELAY_TUNNEL_REAP_LEGACY"] = "144h"
	env["RELAY_TUNNEL_REAP_INACTIVE"] = "2h"
	env["RELAY_TUNNEL_REAP_PENDING"] = "19m"
	env["RELAY_TUNNEL_REAP_ORPHAN"] = "30h"
	cfg, err = ConfigFromEnv(ChannelSelf, env.lookup)
	if err != nil || cfg.Reaper.Mode != ReaperActive || cfg.Reaper.DownGrace != 4*time.Minute ||
		cfg.Reaper.LegacyGrace != 144*time.Hour || cfg.Reaper.InactiveGrace != 2*time.Hour ||
		cfg.Reaper.PendingGrace != 19*time.Minute || cfg.Reaper.OrphanGrace != 30*time.Hour {
		t.Fatalf("reaper configuration = %+v, %v", cfg.Reaper, err)
	}
}

func TestConfigFailFast(t *testing.T) {
	for _, test := range []struct {
		key, value, message string
	}{
		{"RELAY_TUNNEL_MODE", "test", "MODE"},
		{"RELAY_TUNNEL_PROCESS", "control", "requires postgres"},
		{"RELAY_TUNNEL_STORE", "memory", "STORE"},
		{"RELAY_TUNNEL_SQLITE_PATH", ":memory:", "SQLite"},
		{"RELAY_TUNNEL_SQLITE_PATH", "file::memory:", "SQLite"},
		{"RELAY_TUNNEL_SQLITE_PATH", "file:relay?mode=memory", "SQLite"},
		{"RELAY_TUNNEL_CONTROL_ORIGIN", "http://192.0.2.1", "CONTROL_ORIGIN"},
		{"RELAY_TUNNEL_CONTROL_ORIGIN", "https://operator@relay.example", "CONTROL_ORIGIN"},
		{"RELAY_TUNNEL_CONTROL_ORIGIN", "https://relay.example?", "CONTROL_ORIGIN"},
		{"RELAY_TUNNEL_CONTROL_ORIGIN", "https://relay.example#", "CONTROL_ORIGIN"},
		{"RELAY_CF_BASE_DOMAIN", "some..example", "BASE_DOMAIN"},
		{"RELAY_CF_ACCOUNT_ID", "abcd", "ACCOUNT_ID"},
		{"RELAY_CF_NAMESPACE", "-site", "NAMESPACE"},
		{"RELAY_CF_API_TOKEN", "short", "API tokens"},
		{"RELAY_CF_TUNNEL_TOKEN", "mixed", "combined"},
		{"RELAY_TUNNEL_MASTER_KEY", strings.Repeat("aa", 20), "MASTER_KEY"},
		{"RELAY_TUNNEL_EDGE_GATE", "unknown", "EDGE_GATE"},
		{"RELAY_TUNNEL_EDGE_CANARY_HOST", "evil-tunnel.example", "CANARY_HOST"},
		{"RELAY_TRUSTED_PROXY_CIDRS", "127.0.0.1/8", "PROXY_CIDRS"},
		{"RELAY_TRUSTED_PROXY_CIDRS", "fe80::1%local", "PROXY_CIDRS"},
		{"RELAY_TRUSTED_PROXY_CIDRS", "192.0.2.1,", "PROXY_CIDRS"},
		{"RELAY_TUNNEL_SELF_ALLOWED_DEVICES", "sdev_bad", "SELF_ALLOWED_DEVICES"},
		{"RELAY_TUNNEL_ACCOUNT_CAP", "1001", "PURCHASED_CAP"},
		{"RELAY_TUNNEL_REAPER_BUDGET", "-1s", "REAPER_BUDGET"},
		{"RELAY_CF_API_BURST", "0", "API_BURST"},
	} {
		t.Run(test.key+"/"+test.value, func(t *testing.T) {
			env := selfEnv()
			env[test.key] = test.value
			if _, err := ConfigFromEnv(ChannelSelf, env.lookup); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("ConfigFromEnv rejected with %v; want %q", err, test.message)
			}
		})
	}
	env := selfEnv()
	env["RELAY_TUNNEL_STORE"] = "postgres"
	env["RELAY_TUNNEL_PROCESS"] = "control"
	env["RELAY_TUNNEL_PG_DSN"] = "postgres://user@localhost/test?sslmode=disable"
	env["RELAY_TUNNEL_ACCOUNT_CAP"] = "1001"
	env["RELAY_TUNNEL_PURCHASED_CAP"] = "1001"
	env["RELAY_TUNNEL_MASTER_KEY"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32))
	if cfg, err := ConfigFromEnv(ChannelSelf, env.lookup); err != nil || cfg.Process != ProcessControl || cfg.Store != StorePostgres {
		t.Fatalf("control config = %+v, %v", cfg, err)
	}
}

func TestConfigOfficialManifestAndEdgeModes(t *testing.T) {
	env := selfEnv()
	delete(env, "RELAY_TUNNEL_SELF_ALLOWED_DEVICES")
	delete(env, "RELAY_TUNNEL_EDGE_GATE")
	env["RELAY_CF_EDGE_KEY"] = strings.Repeat("k", 32)
	env["RELAY_TUNNEL_EDGE_CANARY_HOST"] = "health.tunnel.example"
	env["RELAY_ALLOWED_ISSUER"] = "https://issuer.example/vanora"
	env["RELAY_CN_MEMBERSHIP_URL"] = "https://members.example/relay"
	ca := ed25519.PublicKey(bytes.Repeat([]byte{0x44}, ed25519.PublicKeySize))
	env["RELAY_IDENTITY_PUBLIC_KEY"] = hex.EncodeToString(ca)
	hash := sha256.Sum256(ca)
	manifest := SiteManifest{
		Channel: ChannelCN, CAPublicKeySHA256: hex.EncodeToString(hash[:]),
		AllowedIssuer: env["RELAY_ALLOWED_ISSUER"], MembershipOrigin: "https://members.example",
		ControlOrigin: env["RELAY_TUNNEL_CONTROL_ORIGIN"], AccountID: env["RELAY_CF_ACCOUNT_ID"], ZoneID: env["RELAY_CF_ZONE_ID"],
		BaseDomain: "tunnel.example", Namespace: env["RELAY_CF_NAMESPACE"],
	}
	path := filepath.Join(t.TempDir(), "site.json")
	env["RELAY_TUNNEL_SITE_MANIFEST"] = path
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ConfigFromEnv(ChannelCN, env.lookup)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EdgeGate != EdgeWorkerHMAC || cfg.AccountCap != 900 || cfg.SiteManifest == nil || *cfg.SiteManifest != manifest {
		t.Fatalf("official config = %+v", cfg)
	}
	if err := cfg.ValidateSiteIdentity(ca, manifest.AllowedIssuer, "https://members.example/path"); err != nil {
		t.Fatal(err)
	}
	for variable, replacement := range map[string]string{
		"RELAY_CF_ACCOUNT_ID":           strings.Repeat("c", 32),
		"RELAY_CF_ZONE_ID":              strings.Repeat("c", 32),
		"RELAY_CF_BASE_DOMAIN":          "different.example",
		"RELAY_CF_NAMESPACE":            "another-site",
		"RELAY_ALLOWED_ISSUER":          "https://other.example",
		"RELAY_CN_MEMBERSHIP_URL":       "https://wrong.example",
		"RELAY_TUNNEL_CONTROL_ORIGIN":   "http://127.0.0.1:8081",
		"RELAY_IDENTITY_PUBLIC_KEY":     strings.Repeat("11", 32),
		"RELAY_TUNNEL_EDGE_GATE":        "desktop_only",
		"RELAY_TUNNEL_EDGE_CANARY_HOST": "",
		"RELAY_CF_EDGE_KEY":             "too-short",
		"RELAY_CF_EDGE_PREV_KEY":        "contains whitespace",
		"RELAY_TUNNEL_SITE_MANIFEST":    "",
	} {
		t.Run(variable, func(t *testing.T) {
			original := env[variable]
			env[variable] = replacement
			defer func() { env[variable] = original }()
			if _, err := ConfigFromEnv(ChannelCN, env.lookup); err == nil {
				t.Errorf("accepted altered %s", variable)
			}
		})
	}
	env["RELAY_GLOBAL_MEMBERSHIP_URL"] = env["RELAY_CN_MEMBERSHIP_URL"]
	if _, err := ConfigFromEnv(ChannelGlobal, env.lookup); err == nil {
		t.Fatal("accepted a CN manifest on GLOBAL")
	}
	delete(env, "RELAY_GLOBAL_MEMBERSHIP_URL")
	env["RELAY_TUNNEL_MODE"] = "drain"
	env["RELAY_TUNNEL_EDGE_GATE"] = "waf_hmac"
	env["RELAY_CF_EDGE_PREV_KEY"] = strings.Repeat("p", 32)
	delete(env, "RELAY_TUNNEL_EDGE_CANARY_HOST")
	if cfg, err := ConfigFromEnv(ChannelCN, env.lookup); err != nil || cfg.EdgeGate != EdgeWAFHMAC || len(cfg.EdgePrevKey) != 32 {
		t.Fatalf("drain/WAF config = %+v, %v", cfg, err)
	}
}

func TestPostgresDSNRequiresRemoteVerifyFull(t *testing.T) {
	t.Setenv("PGSSLMODE", "prefer")
	for _, dsn := range []string{
		"postgres://relay@127.0.0.1/db?sslmode=disable",
		"postgres://relay@[::1]/db?sslmode=disable",
		"host=localhost dbname=db sslmode=disable",
		"host=postgres.example,another.example dbname=db sslmode=verify-full",
	} {
		if _, err := ParsePostgresDSN(dsn); err != nil {
			t.Errorf("ParsePostgresDSN(%q): %v", dsn, err)
		}
	}
	for _, dsn := range []string{
		"", "postgres://relay@postgres.example/db",
		"host=localhost,postgres.example dbname=db sslmode=prefer",
		"host=postgres.example dbname=db sslmode=require",
		"host=postgres.example dbname=db sslmode=verify-ca",
		"host=/tmp dbname=db sslmode=disable",
	} {
		if _, err := ParsePostgresDSN(dsn); err == nil {
			t.Errorf("ParsePostgresDSN accepted %q", dsn)
		}
	}
}
