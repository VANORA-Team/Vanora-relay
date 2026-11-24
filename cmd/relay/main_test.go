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
		sites   int
		wantErr string
	}{
		{
			name:    "self_hosted_checks_nothing",
			channel: relay.ChannelSelf,
			env: map[string]string{
				"RELAY_MEMBERSHIP_URL":   "https://ignored.example",
				"RELAY_MEMBERSHIP_TOKEN": token,
			},
			sites: 0,
		},
		{
			name:    "cn_uses_legacy_variables",
			channel: relay.ChannelCN,
			env: map[string]string{
				"RELAY_MEMBERSHIP_URL":   "https://cn.example",
				"RELAY_MEMBERSHIP_TOKEN": token,
			},
			sites: 1,
		},
		{
			name:    "global_uses_legacy_variables",
			channel: relay.ChannelGlobal,
			env: map[string]string{
				"RELAY_MEMBERSHIP_URL":   "https://global.example",
				"RELAY_MEMBERSHIP_TOKEN": token,
			},
			sites: 1,
		},
		{
			name:    "official_channel_checks_both_sites",
			channel: relay.ChannelCN,
			env: map[string]string{
				"RELAY_CN_MEMBERSHIP_URL":       "https://cn.example",
				"RELAY_CN_MEMBERSHIP_TOKEN":     token,
				"RELAY_GLOBAL_MEMBERSHIP_URL":   "https://global.example",
				"RELAY_GLOBAL_MEMBERSHIP_TOKEN": token,
			},
			sites: 2,
		},
		{
			name:    "legacy_does_not_duplicate_configured_site",
			channel: relay.ChannelCN,
			env: map[string]string{
				"RELAY_MEMBERSHIP_URL":      "https://cn.example",
				"RELAY_MEMBERSHIP_TOKEN":    token,
				"RELAY_CN_MEMBERSHIP_URL":   "https://cn.example",
				"RELAY_CN_MEMBERSHIP_TOKEN": token,
			},
			sites: 1,
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
			if tc.sites == 0 {
				if verifier != nil {
					t.Fatalf("want no entitlement verifier, got %#v", verifier)
				}
				return
			}
			sites, ok := verifier.(membership.Sites)
			if !ok || len(sites) != tc.sites {
				t.Fatalf("want %d sites, got %#v", tc.sites, verifier)
			}
		})
	}
}
