package endpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/protocol"
)

func TestNewPeerAccess(t *testing.T) {
	authority := identitytest.NewAuthority(0)
	now := time.Now().Truncate(time.Second)
	local, localProof := issueAccessProof(t, authority, "host", now, 30*time.Second)
	remote, remoteProof := issueAccessProof(t, authority, "visitor", now, 20*time.Second)
	for _, test := range []struct {
		name string
		ca   ed25519.PublicKey
		edit func(*identity.Principal, *identity.Principal)
	}{
		{"CA", nil, func(*identity.Principal, *identity.Principal) {}},
		{"local device", authority.PublicKey(), func(local, _ *identity.Principal) { local.DeviceID = "" }},
		{"remote device", authority.PublicKey(), func(_, remote *identity.Principal) { remote.DeviceID = "" }},
		{"local key", authority.PublicKey(), func(local, _ *identity.Principal) { local.PublicKey = nil }},
		{"remote key", authority.PublicKey(), func(_, remote *identity.Principal) { remote.PublicKey = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			localPin, remotePin := local, remote
			test.edit(&localPin, &remotePin)
			if _, err := NewPeerAccess(test.ca, localPin, remotePin); err == nil {
				t.Fatal("accepted an incomplete pin")
			}
		})
	}
	access, err := NewPeerAccess(authority.PublicKey(), local, remote)
	if err != nil {
		t.Fatal(err)
	}
	if access.Allows(now, false, true) || access.Allows(now, true, true) {
		t.Fatal("started with access")
	}
	if err := access.Update(true, localProof, now); err != nil {
		t.Fatal(err)
	}
	if access.Allows(now, false, true) {
		t.Fatal("granted access with only one lease")
	}
	if err := access.Update(false, remoteProof, now); err != nil {
		t.Fatal(err)
	}
	if !access.Allows(now, true, true) || access.Allows(now, false, false) {
		t.Fatal("did not enforce both leases and resource grant")
	}
	if err := access.Update(false, localProof, now); err == nil {
		t.Fatal("accepted another identity's proof")
	}
	for _, edit := range []func(*identity.Principal){
		func(pin *identity.Principal) { pin.DeviceID = local.DeviceID },
		func(pin *identity.Principal) { pin.PublicKey = local.PublicKey },
		func(pin *identity.Principal) { pin.Subject = local.Subject },
	} {
		pin := remote
		edit(&pin)
		wrong, err := NewPeerAccess(authority.PublicKey(), local, pin)
		if err != nil {
			t.Fatal(err)
		}
		if err := wrong.Update(false, remoteProof, now); err == nil {
			t.Fatal("accepted a lease with a mismatched device, key or account pin")
		}
	}
	access.AuthorityLost()
	if err := access.Update(false, remoteProof, now); err != nil {
		t.Fatal(err)
	}
	if access.Allows(now, true, true) || !access.Allows(now, false, true) {
		t.Fatal("authority loss did not preserve read-only access")
	}
	if err := access.Update(true, localProof, now); err != nil || !access.Allows(now, true, true) {
		t.Fatalf("local authority renewal did not restore online access: %v", err)
	}
	expiry := now.Add(20 * time.Second)
	if access.Allows(expiry, false, true) || access.Allows(expiry, true, true) {
		t.Fatal("remote lease expiry did not fail closed")
	}
	if err := access.Update(false, remoteProof, expiry.Add(time.Minute)); err == nil {
		t.Fatal("accepted a lease past the verifier's clock skew window")
	}
}

func issueAccessProof(t *testing.T, authority *identitytest.Authority, subject string, now time.Time, ttl time.Duration) (identity.Principal, LeaseProof) {
	t.Helper()
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := authority.IssueWithKey("https://issuer.example", subject, key, now)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := identity.VerifyCertificate(cert, authority.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	lease, _, err := authority.IssueLease(principal, cert, protocol.NewID(), now, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return principal, LeaseProof{Certificate: cert, Lease: lease}
}
