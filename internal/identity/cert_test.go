package identity_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
)

const testIssuer = "https://id.example.com"

func testEndpointKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate endpoint key: %v", err)
	}
	return publicKey, privateKey
}

func TestCertificateRoundTrip(t *testing.T) {
	auth := identitytest.NewAuthority(10 * time.Minute)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	certificate, err := auth.IssueWithKey(testIssuer, "subject-1", publicKey, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	principal, err := identity.VerifyCertificate(certificate, auth.PublicKey(), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if principal.Issuer != testIssuer || principal.Subject != "subject-1" {
		t.Fatalf("unexpected owner: %+v", principal)
	}
	if !principal.PublicKey.Equal(publicKey) {
		t.Fatalf("public key was not preserved")
	}
	wantDev, err := auth.DeviceID(testIssuer, "subject-1", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if principal.DeviceID != wantDev {
		t.Fatalf("device id %q != %q", principal.DeviceID, wantDev)
	}
	if principal.RemoteUserID() != identity.RemoteUserID(testIssuer, "subject-1") {
		t.Fatalf("remote user id mismatch")
	}
	if got, want := principal.Expires, now.Add(10*time.Minute); !got.Equal(want) {
		t.Fatalf("expires = %s, want %s", got, want)
	}
}

func TestCertificateTamperWrongKeyAndExpiry(t *testing.T) {
	auth := identitytest.NewAuthority(time.Minute)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	certificate, err := auth.IssueWithKey(testIssuer, "subject-1", publicKey, now)
	if err != nil {
		t.Fatal(err)
	}

	tampered := replaceAt(certificate, len(identity.CertificatePrefix))
	if _, err := identity.VerifyCertificate(tampered, auth.PublicKey(), now); !errors.Is(err, identity.ErrCertificateSignature) {
		t.Fatalf("tampered error = %v, want signature error", err)
	}
	other := identitytest.NewAuthority(time.Minute)
	if _, err := identity.VerifyCertificate(certificate, other.PublicKey(), now); !errors.Is(err, identity.ErrCertificateSignature) {
		t.Fatalf("wrong key error = %v, want signature error", err)
	}
	if _, err := identity.VerifyCertificate(certificate, auth.PublicKey(), now.Add(2*time.Minute)); !errors.Is(err, identity.ErrCertificateExpired) {
		t.Fatalf("expired error = %v, want expired", err)
	}
	if _, err := identity.VerifyCertificate(certificate, auth.PublicKey(), now.Add(-time.Minute)); !errors.Is(err, identity.ErrCertificateMalformed) {
		t.Fatalf("future error = %v, want malformed", err)
	}
}

func TestCertificateRejectsWrongClaims(t *testing.T) {
	auth := identitytest.NewAuthority(10 * time.Minute)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	deviceID, err := auth.DeviceID(testIssuer, "subject-1", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]string{"alg": "EdDSA", "typ": "vanc+v1", "kid": auth.KeyID()}
	makeBase := func() map[string]any {
		return map[string]any{
			"v":   1,
			"iss": testIssuer,
			"sub": "subject-1",
			"dev": deviceID,
			"pk":  base64.RawURLEncoding.EncodeToString(publicKey),
			"aud": identity.CertificateAudience,
			"iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(),
		}
	}
	cases := map[string]func(map[string]any){
		"audience": func(c map[string]any) { c["aud"] = "someone-else" },
		"issuer":   func(c map[string]any) { c["iss"] = "http://evil.example.com" },
		"version":  func(c map[string]any) { c["v"] = 2 },
		"device":   func(c map[string]any) { c["dev"] = "dev_short" },
		"lifetime": func(c map[string]any) { c["exp"] = now.Add(identity.MaxCertificateLifetime + time.Second).Unix() },
		"subject":  func(c map[string]any) { c["sub"] = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			claims := makeBase()
			mutate(claims)
			cert, err := auth.SignRaw(identity.CertificatePrefix, header, claims)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := identity.VerifyCertificate(cert, auth.PublicKey(), now); err == nil {
				t.Fatalf("certificate with bad %s was accepted", name)
			}
		})
	}
}

func TestParsePublicKeyFormats(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for name, raw := range map[string][]byte{
		"hex":        []byte(hex.EncodeToString(pub)),
		"std base64": []byte(base64.StdEncoding.EncodeToString(pub)),
		"raw base64": []byte(base64.RawURLEncoding.EncodeToString(pub)),
		"raw bytes":  pub,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := identity.ParsePublicKey(raw)
			if err != nil || !got.Equal(pub) {
				t.Fatalf("ParsePublicKey(%s) = %v, %v", name, got, err)
			}
		})
	}
	if _, err := identity.ParsePublicKey([]byte(hex.EncodeToString(priv))); err == nil {
		t.Fatal("private key was accepted as public key")
	}
}

func replaceAt(s string, index int) string {
	replacement := byte('A')
	if s[index] == 'A' {
		replacement = 'B'
	}
	return s[:index] + string(replacement) + s[index+1:]
}
