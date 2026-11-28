package endpoint

import (
	"crypto/ed25519"
	"errors"
	"slices"
	"time"

	"vanora-relay/internal/identity"
)

// LeaseProof is sent over an authenticated transport on open and renewal.
// Both endpoints also obtain their own proof directly from the authority.
type LeaseProof struct {
	Certificate string `json:"certificate"`
	Lease       string `json:"lease"`
}

// Access checks both endpoints' leases. Its caller serializes access to it.
type Access struct {
	session                 *Session
	ca                      ed25519.PublicKey
	local, remote           identity.Principal
	localUntil, remoteUntil time.Time
	authorityOnline         bool
}

func (s *Session) Access() (*Access, error) {
	if s.nonce == "" {
		return nil, errors.New("accepted session required")
	}
	return &Access{session: s}, nil
}

// NewPeerAccess starts fail-closed with identities pinned by the transport.
func NewPeerAccess(ca ed25519.PublicKey, local, remote identity.Principal) (*Access, error) {
	if len(ca) != ed25519.PublicKeySize || local.DeviceID == "" || remote.DeviceID == "" ||
		len(local.PublicKey) != ed25519.PublicKeySize || len(remote.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("lease authority and pinned peer identities required")
	}
	local.PublicKey = slices.Clone(local.PublicKey)
	remote.PublicKey = slices.Clone(remote.PublicKey)
	return &Access{ca: slices.Clone(ca), local: local, remote: remote}, nil
}

// Update accepts a renewed certificate only for the pinned key and identity.
// A successful local update confirms connectivity to the authority. A failure
// to fetch a local lease must be reported immediately with AuthorityLost.
func (a *Access) Update(local bool, proof LeaseProof, now time.Time) error {
	ca, localPin, remotePin := a.ca, a.local, a.remote
	if a.session != nil {
		ca, localPin, remotePin = a.session.local.ca, a.session.local.principal, a.session.remote
	}
	expected := remotePin
	if local {
		expected = localPin
	}
	p, err := identity.VerifyCertificate(proof.Certificate, ca, now)
	if err != nil {
		return err
	}
	if p.DeviceID != expected.DeviceID || p.RemoteUserID() != expected.RemoteUserID() || !p.PublicKey.Equal(expected.PublicKey) {
		return errors.New("lease identity changed")
	}
	until, err := identity.VerifyEndpointLease(proof.Lease, ca, now, proof.Certificate, p)
	if err != nil {
		return err
	}
	if p.Expires.Before(until) {
		until = p.Expires
	}
	if a.session != nil {
		if local {
			updated := *a.session.local
			updated.cert, updated.principal = proof.Certificate, p
			a.session.local = &updated
		} else {
			a.session.remote = p
		}
	}
	if local {
		a.localUntil = until
		a.authorityOnline = true
	} else {
		a.remoteUntil = until
	}
	return nil
}
func (a *Access) AuthorityLost() { a.authorityOnline = false }

// Allows checks both cryptographic leases and the current local resource ACL.
// Pass requiresOnline for establishing a new session and for tool-enabled
// remote access, including every tool dispatch and continued output delivery.
func (a *Access) Allows(now time.Time, requiresOnline, resourceGranted bool) bool {
	return resourceGranted && (!requiresOnline || a.authorityOnline) && now.Before(a.localUntil) && now.Before(a.remoteUntil)
}
