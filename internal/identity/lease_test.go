package identity_test

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
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
	auth := identitytest.NewAuthority(10 * time.Minute)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	certificate, err := auth.IssueWithKey(testIssuer, "subject-1", publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := identity.VerifyCertificate(certificate, auth.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	nonce := testNonce(t)
	lease, expires, err := auth.IssueLease(principal, certificate, nonce, now, 30*time.Second)
	if err != nil {
		t.Fatalf("issue lease: %v", err)
	}
	verifiedExpires, err := identity.VerifyEndpointLease(lease, auth.PublicKey(), now.Add(time.Second), certificate, principal)
	if err != nil {
		t.Fatalf("verify endpoint lease: %v", err)
	}
	if !verifiedExpires.Equal(expires) {
		t.Fatalf("verified expiry = %s, want %s", verifiedExpires, expires)
	}

	otherPublic, _ := testEndpointKey(t)
	otherCertificate, err := auth.IssueWithKey(testIssuer, "subject-1", otherPublic, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.VerifyEndpointLease(lease, auth.PublicKey(), now, otherCertificate, principal); !errors.Is(err, identity.ErrLeaseMalformed) {
		t.Fatalf("wrong cert binding = %v", err)
	}
	otherSubject := principal
	otherSubject.Subject = "subject-2"
	if _, err := identity.VerifyEndpointLease(lease, auth.PublicKey(), now, certificate, otherSubject); !errors.Is(err, identity.ErrLeaseMalformed) {
		t.Fatalf("wrong owner binding = %v", err)
	}
	otherDevice := principal
	otherDevice.DeviceID = "dev_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := identity.VerifyEndpointLease(lease, auth.PublicKey(), now, certificate, otherDevice); !errors.Is(err, identity.ErrLeaseMalformed) {
		t.Fatalf("wrong device binding = %v", err)
	}
}

func TestLeaseExpiry(t *testing.T) {
	auth := identitytest.NewAuthority(5 * time.Second)
	publicKey, _ := testEndpointKey(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	certificate, err := auth.IssueWithKey(testIssuer, "subject-1", publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := identity.VerifyCertificate(certificate, auth.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	lease, expires, err := auth.IssueLease(principal, certificate, testNonce(t), now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !expires.Equal(now.Add(5 * time.Second)) {
		t.Fatalf("lease was not capped by cert expiry: %s", expires)
	}
	if _, err := identity.VerifyEndpointLease(lease, auth.PublicKey(), now.Add(time.Minute), certificate, principal); !errors.Is(err, identity.ErrLeaseExpired) {
		t.Fatalf("expired lease = %v", err)
	}
}
