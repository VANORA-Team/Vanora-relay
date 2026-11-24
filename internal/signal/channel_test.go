package signal

import "testing"

func TestParseChannel(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    Channel
		checks  bool
		wantErr bool
	}{
		{"", ChannelCN, true, false},
		{"cn", ChannelCN, true, false},
		{" CN ", ChannelCN, true, false},
		{"global", ChannelGlobal, true, false},
		{"Global", ChannelGlobal, true, false},
		{"self", ChannelSelf, false, false},
		{"self-hosted", "", false, true},
		{"unknown", "", false, true},
	} {
		got, err := ParseChannel(tc.value)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseChannel(%q) accepted an unknown channel", tc.value)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("ParseChannel(%q) = %q, %v; want %q", tc.value, got, err, tc.want)
		}
		if got.ChecksEntitlement() != tc.checks {
			t.Fatalf("ChecksEntitlement(%q) = %v", got, got.ChecksEntitlement())
		}
	}
}
