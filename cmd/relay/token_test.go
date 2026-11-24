package main

import (
	"strings"
	"testing"

	relay "vanora-relay/internal/signal"
)

func TestSelfAccessToken(t *testing.T) {
	token := strings.Repeat("a", 40)
	for _, tc := range []struct {
		name    string
		channel relay.Channel
		token   string
		want    string
		fail    bool
	}{
		{"self", relay.ChannelSelf, token, token, false},
		{"self missing", relay.ChannelSelf, "", "", true},
		{"self short", relay.ChannelSelf, strings.Repeat("a", 31), "", true},
		{"self whitespace", relay.ChannelSelf, strings.Repeat("a", 31) + " ", "", true},
		{"official without token", relay.ChannelGlobal, "", "", false},
		{"official with token", relay.ChannelCN, token, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RELAY_SELF_TOKEN", tc.token)
			got, err := selfAccessToken(tc.channel)
			if (err != nil) != tc.fail {
				t.Fatalf("err = %v, want failure %t", err, tc.fail)
			}
			if got != tc.want {
				t.Fatalf("token = %q, want %q", got, tc.want)
			}
		})
	}
}
