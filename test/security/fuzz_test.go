package security_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/protocol"
)

func FuzzProtocolDecodeAndVerify(f *testing.F) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)

	valid := protocol.Message{
		Type:       "rtc.offer",
		Connection: protocol.NewID(),
		From:       "sdev_aaaaaaaaaaaaaaaaaaaaaaaaaa",
		To:         "sdev_bbbbbbbbbbbbbbbbbbbbbbbbbb",
		Round:      1,
		Seq:        2,
	}
	_ = valid.Sign(priv, []byte(`{"sdp":"v=0"}`))
	f.Add([]byte(protocol.Encode(valid)), []byte(pub))
	f.Add([]byte(`{"type":"auth.login","seq":0,"body":"!!"}`), []byte(pub))
	f.Add([]byte(`not-json`), []byte("short"))

	f.Fuzz(func(t *testing.T, rawMsg, rawPub []byte) {
		var m protocol.Message
		if json.Unmarshal(rawMsg, &m) == nil {
			_ = protocol.ValidID(m.Connection)
			if len(rawPub) == ed25519.PublicKeySize {
				_, _ = m.Verify(ed25519.PublicKey(rawPub))
			}
			_, _ = m.Verify(pub)
		}
	})
}

func FuzzIdentityVerifyCertificateAndLease(f *testing.F) {
	auth := identitytest.NewAuthority(10 * time.Minute)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1700000000, 0).UTC()
	cert, _ := auth.IssueWithKey("https://issuer.example", "alice", pub, now)
	p, _ := identity.VerifyCertificate(cert, auth.PublicKey(), now)
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 24))
	lease, _, _ := auth.IssueLease(p, cert, nonce, now, 60*time.Second)

	f.Add(cert, lease, []byte(auth.PublicKey()))
	f.Add("vanc1.a.b.c", "vanl1.a.b.c", []byte(auth.PublicKey()))
	f.Add("", "", []byte{})

	f.Fuzz(func(t *testing.T, certTok, leaseTok string, keyBytes []byte) {
		var k ed25519.PublicKey
		if len(keyBytes) == ed25519.PublicKeySize {
			k = ed25519.PublicKey(keyBytes)
		} else {
			k = auth.PublicKey()
		}
		_, _ = identity.ParsePublicKey(keyBytes)
		pr, err := identity.VerifyCertificate(certTok, k, now)
		if err == nil {
			_, _ = identity.VerifyEndpointLease(leaseTok, k, now, certTok, pr)
		}
		_, _ = identity.VerifyLease(leaseTok, k, now)
	})
}

func FuzzIdentityParsePublicKeyAndSelfProof(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	f.Add([]byte(base64.RawURLEncoding.EncodeToString(pub)), "conn-1")
	f.Add([]byte(strings.Repeat("ab", 32)), "conn\n2")
	f.Add([]byte("garbage"), "")

	f.Fuzz(func(t *testing.T, data []byte, connID string) {
		parsed, err := identity.ParsePublicKey(data)
		if err == nil {
			id, err := identity.SelfDeviceID(parsed)
			if err == nil && !identity.ValidSelfDeviceID(id) {
				t.Fatalf("SelfDeviceID produced invalid ID %q", id)
			}
			_, _ = identity.SelfPairProof(data, connID, parsed, pub)
		}
	})
}

func FuzzSelfRelayAndLANTargetParse(f *testing.F) {
	pin := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tok := strings.Repeat("t", 40)
	f.Add("https://relay.example.com/v1/signal#mode=self&pin=" + pin + "&pair=" + pin + "&token=" + tok)
	f.Add("https://192.168.1.10:8443/v1/lan#pin=" + pin + "&pair=" + pin)
	f.Add("http://127.0.0.1:8787/v1/signal#mode=self&pin=" + pin)
	f.Add("://bad\x00url")

	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = selfrelay.ParseTarget(raw)
		_ = selfrelay.ValidateSignalURL(raw)
		_ = selfrelay.ValidateRelayToken(raw)
		_ = selfrelay.Access(raw)
		_, _ = lan.ParseTarget(raw)
		_ = lan.Access(raw)
	})
}
