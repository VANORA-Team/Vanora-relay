package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

const testIssuer = "https://id.example.com"

func testSigner(t *testing.T, ttl time.Duration) (*Signer, ed25519.PrivateKey) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer, err := NewSigner(privateKey, ttl)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer, privateKey
}

func testEndpointKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate endpoint key: %v", err)
	}
	return publicKey, privateKey
}

func TestCertificateRoundTrip(t *testing.T) {
	signer, _ := testSigner(t, 10*time.Minute)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	certificate, err := signer.Issue(testIssuer, "subject-1", publicKey, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	principal, err := VerifyCertificate(certificate, signer.PublicKey(), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if principal.Issuer != testIssuer || principal.Subject != "subject-1" {
		t.Fatalf("unexpected owner: %+v", principal)
	}
	if !principal.PublicKey.Equal(publicKey) {
		t.Fatalf("public key was not preserved")
	}
	if principal.DeviceID != mustDeviceID(t, signer, testIssuer, "subject-1", publicKey) {
		t.Fatalf("device id %q does not match derivation", principal.DeviceID)
	}
	if principal.RemoteUserID() != RemoteUserID(testIssuer, "subject-1") {
		t.Fatalf("remote user id %q does not match derivation", principal.RemoteUserID())
	}
	if got, want := principal.Expires, now.Add(10*time.Minute); !got.Equal(want) {
		t.Fatalf("expires = %s, want %s", got, want)
	}
}

func TestCertificateDeviceIDStableForSameKey(t *testing.T) {
	signer, _ := testSigner(t, 10*time.Minute)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	first, err := signer.DeviceID(testIssuer, "subject-1", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	second, err := signer.DeviceID(testIssuer, "subject-1", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("device id changed for the same key: %q vs %q", first, second)
	}
	certificate, err := signer.Issue(testIssuer, "subject-1", publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := VerifyCertificate(certificate, signer.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	if principal.DeviceID != first {
		t.Fatalf("certificate device id %q != derived %q", principal.DeviceID, first)
	}

	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := signer.DeviceID(testIssuer, "subject-1", otherPublic)
	if err != nil {
		t.Fatal(err)
	}
	if otherID == first {
		t.Fatalf("different endpoint keys produced the same device id")
	}
	if RemoteUserID(testIssuer, "subject-1") != principal.RemoteUserID() {
		t.Fatalf("remote user id depends on the endpoint key")
	}
	if RemoteUserID(testIssuer, "subject-1") == RemoteUserID(testIssuer, "subject-2") {
		t.Fatalf("remote user id collision")
	}
}

func TestCertificateTamperAndWrongKey(t *testing.T) {
	signer, _ := testSigner(t, 10*time.Minute)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	certificate, err := signer.Issue(testIssuer, "subject-1", publicKey, now)
	if err != nil {
		t.Fatal(err)
	}

	tampered := replaceAt(certificate, len(CertificatePrefix))
	if _, err := VerifyCertificate(tampered, signer.PublicKey(), now); !errors.Is(err, ErrCertificateSignature) {
		t.Fatalf("tampered certificate error = %v, want signature error", err)
	}

	other, _ := testSigner(t, 10*time.Minute)
	if _, err := VerifyCertificate(certificate, other.PublicKey(), now); !errors.Is(err, ErrCertificateSignature) {
		t.Fatalf("wrong trusted key error = %v, want signature error", err)
	}
}

func TestCertificateValidityWindow(t *testing.T) {
	signer, _ := testSigner(t, time.Minute)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	certificate, err := signer.Issue(testIssuer, "subject-1", publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCertificate(certificate, signer.PublicKey(), now.Add(time.Minute+clockSkew+time.Second)); !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("expired certificate error = %v, want expired", err)
	}
	if _, err := VerifyCertificate(certificate, signer.PublicKey(), now.Add(-clockSkew-time.Second)); !errors.Is(err, ErrCertificateMalformed) {
		t.Fatalf("not-yet-valid certificate error = %v, want malformed", err)
	}
}

func TestCertificateRejectsWrongClaims(t *testing.T) {
	signer, privateKey := testSigner(t, 10*time.Minute)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	deviceID := mustDeviceID(t, signer, testIssuer, "subject-1", publicKey)
	header := certificateHeader{Alg: "EdDSA", Typ: "vanc+v1", Kid: signer.KeyID()}

	base := certificateClaims{
		Version:   certificateVersion,
		Issuer:    testIssuer,
		Subject:   "subject-1",
		DeviceID:  deviceID,
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		Audience:  CertificateAudience,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}

	cases := map[string]func(*certificateClaims){
		"audience": func(c *certificateClaims) { c.Audience = "someone-else" },
		"issuer":   func(c *certificateClaims) { c.Issuer = "http://evil.example.com" },
		"version":  func(c *certificateClaims) { c.Version = 2 },
		"device":   func(c *certificateClaims) { c.DeviceID = "dev_short" },
		"lifetime": func(c *certificateClaims) { c.ExpiresAt = c.IssuedAt + int64(MaxCertificateLifetime/time.Second) + 1 },
		"subject":  func(c *certificateClaims) { c.Subject = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			claims := base
			mutate(&claims)
			certificate, err := signToken(CertificatePrefix, privateKey, header, claims)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyCertificate(certificate, signer.PublicKey(), now); err == nil {
				t.Fatalf("certificate with bad %s was accepted", name)
			}
		})
	}
}

func TestNewSignerTTLBounds(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	for _, ttl := range []time.Duration{-time.Minute, MaxCertificateLifetime + time.Second} {
		if _, err := NewSigner(privateKey, ttl); err == nil {
			t.Fatalf("ttl %s was accepted", ttl)
		}
	}
	signer, err := NewSigner(privateKey, 0)
	if err != nil {
		t.Fatalf("zero ttl should select the default: %v", err)
	}
	if signer.CertificateTTL() != DefaultCertificateLifetime {
		t.Fatalf("default ttl = %s", signer.CertificateTTL())
	}
}

func TestParseSigningKeyFormats(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	seed := privateKey.Seed()
	formats := map[string]string{
		"hex seed":        hex.EncodeToString(seed),
		"hex full":        hex.EncodeToString(privateKey),
		"raw seed base64": base64.StdEncoding.EncodeToString(seed),
		"raw full base64": base64.StdEncoding.EncodeToString(privateKey),
		"raw url seed":    base64.RawURLEncoding.EncodeToString(seed),
		"padded url seed": base64.URLEncoding.EncodeToString(seed),
	}
	for name, material := range formats {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseSigningKey([]byte(material))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !parsed.Public().(ed25519.PublicKey).Equal(privateKey.Public().(ed25519.PublicKey)) {
				t.Fatalf("parsed key does not match")
			}
		})
	}
	if _, err := ParseSigningKey([]byte("not-a-key")); err == nil {
		t.Fatalf("garbage key was accepted")
	}
	publicMaterial := []byte(hex.EncodeToString(privateKey.Public().(ed25519.PublicKey)))
	parsedPublic, err := ParsePublicKey(publicMaterial)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if !parsedPublic.Equal(privateKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("parsed public key does not match")
	}
	if _, err := ParsePublicKey([]byte(hex.EncodeToString(privateKey))); err == nil {
		t.Fatalf("private key material was accepted as a public key")
	}
	mismatched := append([]byte(nil), privateKey...)
	mismatched[ed25519.PublicKeySize] ^= 0xff
	if _, err := ParseSigningKey([]byte(hex.EncodeToString(mismatched))); err == nil {
		t.Fatalf("mismatched seed/public key was accepted")
	}
}

func mustDeviceID(t *testing.T, signer *Signer, issuer, subject string, publicKey ed25519.PublicKey) string {
	t.Helper()
	deviceID, err := signer.DeviceID(issuer, subject, publicKey)
	if err != nil {
		t.Fatalf("device id: %v", err)
	}
	return deviceID
}

// replaceAt flips one base64url character of s at index, guaranteeing the
// encoded bytes change.
func replaceAt(s string, index int) string {
	replacement := byte('A')
	if s[index] == 'A' {
		replacement = 'B'
	}
	return s[:index] + string(replacement) + s[index+1:]
}
