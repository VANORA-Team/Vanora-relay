package cftunnel

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func cryptoFixture(t *testing.T, edge, previous string) *Crypto {
	t.Helper()
	crypto, err := NewCrypto(bytes.Repeat([]byte{0x37}, 32), []byte(edge), []byte(previous))
	if err != nil {
		t.Fatal(err)
	}
	return crypto
}

func TestCloudflareOwnershipDerivations(t *testing.T) {
	crypto := cryptoFixture(t, "", "")
	if bytes.Equal(crypto.nameKey, crypto.proofKey) || bytes.Equal(crypto.rotationKey, crypto.proofKey) ||
		bytes.Equal(crypto.rotationKey, crypto.nameKey) {
		t.Fatal("HKDF domains produced equal keys")
	}
	label, host := crypto.DeriveHostname("scope", "a", "bc", "relay.example")
	other, _ := crypto.DeriveHostname("scope", "ab", "c", "relay.example")
	if len(label) != 26 || !tunnelLabelPattern.MatchString(label) || host != label+".relay.example" || other == label {
		t.Fatalf("hostname = %q and %q, ambiguous input result = %q", label, host, other)
	}
	namespace := "very-long-site31"
	for _, incarnation := range []int64{1, 35, 36, math.MaxInt64} {
		name := crypto.DeriveTunnelName(namespace, label, incarnation)
		gotLabel, gotIncarnation, ok := crypto.VerifyTunnelName(namespace, name)
		if len(name) > 64 || !ok || gotLabel != label || gotIncarnation != incarnation {
			t.Fatalf("verify name %q: %q, %d, %v", name, gotLabel, gotIncarnation, ok)
		}
		if _, _, ok := crypto.VerifyTunnelName("very-long-site32", name); ok {
			t.Fatalf("accepted another namespace's name %q", name)
		}
		if _, _, ok := crypto.VerifyTunnelName(namespace, name+"1"); ok {
			t.Fatalf("accepted modified name %q", name)
		}
		marker := crypto.FormatDNSMarker("zone", host, "tunnel-id", incarnation)
		if got, ok := crypto.VerifyDNSMarker(marker, "zone", host, "tunnel-id"); !ok || got != incarnation {
			t.Fatalf("verify marker %q: %d, %v", marker, got, ok)
		}
		for _, tuple := range [][3]string{{"other", host, "tunnel-id"}, {"zone", "other." + host, "tunnel-id"}, {"zone", host, "another"}} {
			if _, ok := crypto.VerifyDNSMarker(marker, tuple[0], tuple[1], tuple[2]); ok {
				t.Fatalf("accepted marker for %v", tuple)
			}
		}
	}
	secret := crypto.DeriveRotationSecret("operation", "allocation", 2)
	if len(secret) != 32 || !bytes.Equal(secret, cryptoFixture(t, "", "").DeriveRotationSecret("operation", "allocation", 2)) ||
		bytes.Equal(secret, crypto.DeriveRotationSecret("operation", "allocation", 3)) {
		t.Fatal("rotation secret must be reproducible and bound to its incarnation")
	}
}

func TestChallengeBindingAndLifetime(t *testing.T) {
	crypto := cryptoFixture(t, "", "")
	now := time.Unix(1700000000, 0).UTC()
	token, proof, err := crypto.MintChallenge("scope", "provision", "device", now)
	if err != nil || proof.Nonce == "" || proof.ExpiresAt.Sub(now) != ChallengeTTL {
		t.Fatalf("MintChallenge(): %+v, %v", proof, err)
	}
	if got, err := crypto.VerifyChallenge(token, "scope", "provision", "device", now.Add(29*time.Second)); err != nil || got != proof {
		t.Fatalf("VerifyChallenge(): %+v, %v", got, err)
	}
	duplicate, _, err := crypto.MintChallenge("scope", "provision", "device", now)
	if err != nil || duplicate == token {
		t.Fatal("challenge nonce must be random")
	}
	for _, test := range []struct {
		token, scope, action, device string
		when                         time.Time
	}{
		{token, "other", "provision", "device", now},
		{token, "scope", "resume", "device", now},
		{token, "scope", "provision", "other", now},
		{token, "scope", "provision", "device", now.Add(ChallengeTTL)},
		{token, "scope", "provision", "device", now.Add(-time.Second)},
		{token + "x", "scope", "provision", "device", now},
	} {
		if _, err := crypto.VerifyChallenge(test.token, test.scope, test.action, test.device, test.when); !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("invalid challenge accepted: %+v, %v", test, err)
		}
	}
}

func TestEdgeTicketWAFVectorAndKeyRotation(t *testing.T) {
	const (
		oldKey = "0123456789abcdef0123456789abcdef"
		host   = "a.tunnel.example"
		path   = "/v1/connect"
		jti    = "abc_123"
		vector = "1700000000-e9dP5Wmi8Lyq5hidfzv9HYzYs0FbLi8WN-bz65c7I2Y"
	)
	now := time.Unix(1700000000, 0)
	legacy := cryptoFixture(t, oldKey, "")
	current := cryptoFixture(t, strings.Repeat("b", 32), oldKey)
	header, err := legacy.MintEdgeTicket(host, path, jti, now)
	if err != nil || header != vector {
		t.Fatalf("MintEdgeTicket() = %q, %v; want %q", header, err, vector)
	}
	ticket, err := current.MintEdgeTicket(host, path, jti, now)
	if err != nil || ticket == header || !current.VerifyEdgeTicket(ticket, host, path, jti, now) ||
		legacy.VerifyEdgeTicket(ticket, host, path, jti, now) {
		t.Fatalf("key rotation ticket = %q, %v", ticket, err)
	}
	for _, offset := range []time.Duration{-EdgeClockSkew, 0, EdgeTicketTTL} {
		if !current.VerifyEdgeTicket(header, host, path, jti, now.Add(offset)) {
			t.Fatalf("rejected previous key with offset %s", offset)
		}
	}
	for _, offset := range []time.Duration{-EdgeClockSkew - time.Second, EdgeTicketTTL + time.Second} {
		if current.VerifyEdgeTicket(header, host, path, jti, now.Add(offset)) {
			t.Fatalf("accepted timestamp outside window: %s", offset)
		}
	}
	for _, tuple := range [][3]string{{"b.tunnel.example", path, jti}, {host, "/v1/other", jti}, {host, path, "different"}} {
		if current.VerifyEdgeTicket(header, tuple[0], tuple[1], tuple[2], now) {
			t.Fatalf("accepted modified request: %v", tuple)
		}
	}
	for _, malformed := range []string{header + "=", " " + header, header[:10] + "_" + header[11:], header[:53] + "Z"} {
		if current.VerifyEdgeTicket(malformed, host, path, jti, now) {
			t.Fatalf("accepted malformed ticket %q", malformed)
		}
	}
	if _, err := current.MintEdgeTicket(host, "/v1/connect|unbound", jti, now); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("delimiter in path: %v", err)
	}
}

func TestEdgeWorkerInterop(t *testing.T) {
	crypto := cryptoFixture(t, "0123456789abcdef0123456789abcdef", "")
	const want = "1800000000-JRoH8hF8kjS5hI8QPR-9jfnvdgVvIs9n75FJp2WY_S0"
	ticket, err := crypto.MintEdgeTicket("aaaaaaaaaaaaaaaaaaaaaaaaaa.edge.example", "/v1/tunnel/ws", "desktop-42_Abc", time.Unix(1800000000, 0))
	if err != nil || ticket != want {
		t.Fatalf("edge Worker vector = %q, %v; want %q", ticket, err, want)
	}
}
