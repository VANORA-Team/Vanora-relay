package identity

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func testNonce(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func TestLeaseRoundTripAndBindings(t *testing.T) {
	signer, _ := testSigner(t, 10*time.Minute)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	certificate, err := signer.Issue(testIssuer, "subject-1", publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := VerifyCertificate(certificate, signer.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	nonce := testNonce(t)
	lease, expires, err := signer.IssueLease(principal, certificate, nonce, now, 30*time.Second)
	if err != nil {
		t.Fatalf("issue lease: %v", err)
	}
	if want := now.Add(30 * time.Second); !expires.Equal(want) {
		t.Fatalf("lease expiry = %s, want %s", expires, want)
	}
	verifiedExpires, err := VerifyEndpointLease(lease, signer.PublicKey(), now.Add(time.Second), certificate, principal)
	if err != nil {
		t.Fatalf("verify endpoint lease: %v", err)
	}
	if !verifiedExpires.Equal(expires) {
		t.Fatalf("verified expiry = %s, want %s", verifiedExpires, expires)
	}
	parsed, err := VerifyLease(lease, signer.PublicKey(), now)
	if err != nil {
		t.Fatalf("verify lease: %v", err)
	}
	if parsed.Nonce != nonce || parsed.DeviceID != principal.DeviceID || parsed.RemoteUserID != principal.RemoteUserID() {
		t.Fatalf("lease claims not bound: %+v", parsed)
	}

	otherPublic, _ := testEndpointKey(t)
	otherCertificate, err := signer.Issue(testIssuer, "subject-1", otherPublic, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEndpointLease(lease, signer.PublicKey(), now, otherCertificate, principal); !errors.Is(err, ErrLeaseMalformed) {
		t.Fatalf("lease for another certificate error = %v, want malformed binding", err)
	}
	otherSubject := principal
	otherSubject.Subject = "subject-2"
	if _, err := VerifyEndpointLease(lease, signer.PublicKey(), now, certificate, otherSubject); !errors.Is(err, ErrLeaseMalformed) {
		t.Fatalf("lease for another owner error = %v, want malformed binding", err)
	}
	otherDevice := principal
	otherDevice.DeviceID = "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := VerifyEndpointLease(lease, signer.PublicKey(), now, certificate, otherDevice); !errors.Is(err, ErrLeaseMalformed) {
		t.Fatalf("lease for another device error = %v, want malformed binding", err)
	}
}

func TestLeaseCappedByCertificateAndExpiry(t *testing.T) {
	tightSigner, _ := testSigner(t, 5*time.Second)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	certificate, err := tightSigner.Issue(testIssuer, "subject-1", publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := VerifyCertificate(certificate, tightSigner.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	_, expires, err := tightSigner.IssueLease(principal, certificate, testNonce(t), now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(5 * time.Second); !expires.Equal(want) {
		t.Fatalf("lease expiry = %s, want certificate expiry %s", expires, want)
	}

	lease, _, err := tightSigner.IssueLease(principal, certificate, testNonce(t), now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEndpointLease(lease, tightSigner.PublicKey(), now.Add(5*time.Second+clockSkew+time.Second), certificate, principal); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired lease error = %v, want expired", err)
	}
	if _, _, err := tightSigner.IssueLease(principal, certificate, testNonce(t), now.Add(5*time.Second), 30*time.Second); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("lease at certificate expiry error = %v, want expired", err)
	}
}

func TestLeaseRejectsBadNonceAndTTL(t *testing.T) {
	signer, _ := testSigner(t, 10*time.Minute)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	certificate, _ := signer.Issue(testIssuer, "subject-1", publicKey, now)
	principal, _ := VerifyCertificate(certificate, signer.PublicKey(), now)

	for _, nonce := range []string{"", "short", "!!!!", string(make([]byte, 200))} {
		if _, _, err := signer.IssueLease(principal, certificate, nonce, now, 30*time.Second); !errors.Is(err, ErrLeaseMalformed) {
			t.Fatalf("nonce %q error = %v, want malformed", nonce, err)
		}
	}
	if _, _, err := signer.IssueLease(principal, certificate, testNonce(t), now, MaxLeaseLifetime+time.Second); !errors.Is(err, ErrCertificateLifetime) {
		t.Fatalf("oversized ttl error = %v", err)
	}
	if _, _, err := signer.IssueLease(principal, certificate, testNonce(t), now, 0); !errors.Is(err, ErrCertificateLifetime) {
		t.Fatalf("zero ttl error = %v", err)
	}
	if _, _, err := signer.IssueLease(principal, "", testNonce(t), now, 30*time.Second); !errors.Is(err, ErrLeaseMalformed) {
		t.Fatalf("missing certificate error = %v", err)
	}
}
