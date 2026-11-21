package endpoint

import (
	"errors"
	"time"

	"vanora-relay/internal/identity"
)

// LeaseProof is sent over the authenticated DataChannel on open and renewal.
// Both endpoints also obtain their own proof directly from the authority.
type LeaseProof struct {
	Certificate string `json:"certificate"`
	Lease       string `json:"lease"`
}

// Access is owned by the adapter's serial session event loop. Each endpoint
// checks the other endpoint's lease before accepting data on its channel.
type Access struct {
	session                 *Session
	localUntil, remoteUntil time.Time
	authorityOnline         bool
}

func (s *Session) Access() (*Access, error) {
	if s.nonce == "" {
		return nil, errors.New("accepted session required")
	}
	return &Access{session: s}, nil
}

// Update accepts a renewed certificate only for the pinned key and identity.
// A successful local update confirms connectivity to the authority. A failure
// to fetch a local lease must be reported immediately with AuthorityLost.
func (a *Access) Update(local bool, proof LeaseProof, now time.Time) error {
	expected := a.session.remote
	if local {
		expected = a.session.local.principal
	}
	p, err := identity.VerifyCertificate(proof.Certificate, a.session.local.ca, now)
	if err != nil {
		return err
	}
	if p.DeviceID != expected.DeviceID || p.RemoteUserID() != expected.RemoteUserID() || !p.PublicKey.Equal(expected.PublicKey) {
		return errors.New("lease identity changed")
	}
	until, err := identity.VerifyEndpointLease(proof.Lease, a.session.local.ca, now, proof.Certificate, p)
	if err != nil {
		return err
	}
	if local {
		updated := *a.session.local
		updated.cert, updated.principal = proof.Certificate, p
		a.session.local = &updated
		a.localUntil = until
		a.authorityOnline = true
	} else {
		a.session.remote = p
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
