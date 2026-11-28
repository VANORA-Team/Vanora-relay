package identity_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
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

func TestEndpointLeaseKeyRotationAndCertificateExpiry(t *testing.T) {
	previous, current := identitytest.NewAuthority(time.Minute), identitytest.NewAuthority(time.Minute)
	keys := []ed25519.PublicKey{current.PublicKey(), previous.PublicKey()}
	publicKey, _ := testEndpointKey(t)
	now := time.Now().Truncate(time.Second)
	certificate, err := previous.IssueWithKey(testIssuer, "subject-1", publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := identity.VerifyCertificateWithKeys(certificate, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, _, err := current.IssueLease(principal, certificate, testNonce(t), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if expiry, err := identity.VerifyEndpointLeaseWithKeys(lease, keys, now, certificate, principal); err != nil || !expiry.Equal(principal.Expires) {
		t.Fatalf("lease signed by rotated key = %v, %v", expiry, err)
	}
	if _, err := identity.VerifyLeaseWithKeys(lease, keys[1:], now); !errors.Is(err, identity.ErrLeaseSignature) {
		t.Fatalf("lease with untrusted signer = %v", err)
	}

	hash := sha256.Sum256([]byte(certificate))
	claims := map[string]any{
		"v": 1, "aud": identity.CertificateAudience, "uid": principal.RemoteUserID(),
		"dev": principal.DeviceID, "ch": base64.RawURLEncoding.EncodeToString(hash[:]),
		"n": testNonce(t), "iat": now.Add(time.Second).Unix(), "exp": principal.Expires.Add(time.Second).Unix(),
	}
	header := map[string]string{"alg": "EdDSA", "typ": "vanl+v1"}
	lease, err = current.SignRaw(identity.LeasePrefix, header, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.VerifyLease(lease, current.PublicKey(), now); err != nil {
		t.Fatalf("unbound lease verification = %v", err)
	}
	if _, err := identity.VerifyEndpointLease(lease, current.PublicKey(), now, certificate, principal); !errors.Is(err, identity.ErrLeaseMalformed) {
		t.Fatalf("accepted lease that outlived its certificate: %v", err)
	}

	for _, test := range []struct{ typ, owner string }{
		{"vanc+v1", principal.RemoteUserID()},
		{"vanl+v1", "usr_" + strings.ToUpper(strings.TrimPrefix(principal.RemoteUserID(), "usr_"))},
	} {
		header["typ"], claims["uid"] = test.typ, test.owner
		lease, err := current.SignRaw(identity.LeasePrefix, header, claims)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := identity.VerifyLease(lease, current.PublicKey(), now); !errors.Is(err, identity.ErrLeaseMalformed) {
			t.Fatalf("lease with typ %q and owner %q = %v", test.typ, test.owner, err)
		}
	}
}
