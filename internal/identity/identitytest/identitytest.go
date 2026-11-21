// Package identitytest mints endpoint certificates for tests. It is the only
// place outside internal/identity that can create valid certificates without
// going through the OIDC flow; production code must never import it.
package identitytest

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"vanora-relay/internal/identity"
)

// Authority is a test certificate issuer.
type Authority struct {
	signer *identity.Signer
}

// NewAuthority returns an authority with a fresh random signing key. A zero
// ttl selects identity's default certificate lifetime.
func NewAuthority(ttl time.Duration) *Authority {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("identitytest: generate authority key: %v", err))
	}
	authority, err := NewAuthorityWithKey(privateKey, ttl)
	if err != nil {
		panic(fmt.Sprintf("identitytest: %v", err))
	}
	return authority
}

// NewAuthorityWithKey returns an authority that signs with privateKey.
func NewAuthorityWithKey(privateKey ed25519.PrivateKey, ttl time.Duration) (*Authority, error) {
	signer, err := identity.NewSigner(privateKey, ttl)
	if err != nil {
		return nil, err
	}
	return &Authority{signer: signer}, nil
}

// PublicKey returns the key to trust in VerifyCertificate and
// VerifyEndpointLease.
func (a *Authority) PublicKey() ed25519.PublicKey {
	return a.signer.PublicKey()
}

// KeyID returns the certificate key id produced by this authority.
func (a *Authority) KeyID() string {
	return a.signer.KeyID()
}

// Issue mints a certificate for a new random endpoint key. The private half is
// discarded; tests that need to prove possession should use IssueWithKey.
func (a *Authority) Issue(issuer, subject string, now time.Time) (string, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return a.IssueWithKey(issuer, subject, privateKey.Public().(ed25519.PublicKey), now)
}

// IssueWithKey mints a certificate binding issuer/subject to publicKey.
func (a *Authority) IssueWithKey(issuer, subject string, publicKey ed25519.PublicKey, now time.Time) (string, error) {
	return a.signer.Issue(issuer, subject, publicKey, now)
}
