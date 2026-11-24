package main

import (
	"strings"
	"testing"

	"vanora-relay/internal/membership"
	relay "vanora-relay/internal/signal"
)

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
