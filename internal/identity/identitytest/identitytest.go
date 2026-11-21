// Package identitytest mints endpoint certificates and leases for unit and
// integration tests. Production code must never import it.
package identitytest

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"vanora-relay/internal/identity"
)

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// Authority is a test-only certificate and lease issuer.
type Authority struct {
	privateKey ed25519.PrivateKey
	deviceKey  [sha256.Size]byte
	keyID      string
	ttl        time.Duration
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
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("identitytest: invalid signing key size %d", len(privateKey))
	}
	if ttl == 0 {
		ttl = identity.DefaultCertificateLifetime
	}
	if ttl < 0 || ttl > identity.MaxCertificateLifetime {
		return nil, fmt.Errorf("identitytest: ttl %s out of range", ttl)
	}
	mac := hmac.New(sha256.New, append([]byte("vanora/device-key/v1\x00"), privateKey.Seed()...))
	var deviceKey [sha256.Size]byte
	copy(deviceKey[:], mac.Sum(nil))

	publicKey := privateKey.Public().(ed25519.PublicKey)
	fp := sha256.Sum256(publicKey)
	return &Authority{
		privateKey: privateKey,
		deviceKey:  deviceKey,
		keyID:      base64.RawURLEncoding.EncodeToString(fp[:8]),
		ttl:        ttl,
	}, nil
}

// PublicKey returns the key to trust in VerifyCertificate and VerifyEndpointLease.
func (a *Authority) PublicKey() ed25519.PublicKey {
	return a.privateKey.Public().(ed25519.PublicKey)
}

// KeyID returns the certificate key id produced by this authority.
func (a *Authority) KeyID() string { return a.keyID }

// CertificateTTL returns the configured certificate lifetime.
func (a *Authority) CertificateTTL() time.Duration { return a.ttl }

// DeviceID derives a deterministic device identifier for tests.
func (a *Authority) DeviceID(issuer, subject string, publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("identitytest: invalid endpoint public key")
	}
	mac := hmac.New(sha256.New, a.deviceKey[:])
	mac.Write([]byte("vanora/device/v1\x00"))
	writeLengthPrefixed(mac, []byte(issuer))
	writeLengthPrefixed(mac, []byte(subject))
	mac.Write(publicKey)
	return "dev_" + strings.ToLower(base32NoPad.EncodeToString(mac.Sum(nil)[:16])), nil
}

// Issue mints a certificate for a fresh random endpoint key.
func (a *Authority) Issue(issuer, subject string, now time.Time) (string, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return a.IssueWithKey(issuer, subject, privateKey.Public().(ed25519.PublicKey), now)
}

// IssueWithKey mints a certificate binding issuer/subject to publicKey.
func (a *Authority) IssueWithKey(issuer, subject string, publicKey ed25519.PublicKey, now time.Time) (string, error) {
	deviceID, err := a.DeviceID(issuer, subject, publicKey)
	if err != nil {
		return "", err
	}
	now = now.UTC()
	header := map[string]string{"alg": "EdDSA", "typ": "vanc+v1", "kid": a.keyID}
	claims := map[string]any{
		"v":   1,
		"iss": issuer,
		"sub": subject,
		"dev": deviceID,
		"pk":  base64.RawURLEncoding.EncodeToString(publicKey),
		"aud": identity.CertificateAudience,
		"iat": now.Unix(),
		"exp": now.Add(a.ttl).Unix(),
	}
	return a.SignRaw(identity.CertificatePrefix, header, claims)
}

// IssueLease mints a liveness lease bound to principal and certificate.
func (a *Authority) IssueLease(principal identity.Principal, certificate, nonce string, now time.Time, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 || ttl > identity.MaxLeaseLifetime {
		return "", time.Time{}, fmt.Errorf("%w: lease ttl %s out of range", identity.ErrCertificateLifetime, ttl)
	}
	if certificate == "" {
		return "", time.Time{}, fmt.Errorf("%w: missing certificate", identity.ErrLeaseMalformed)
	}
	decodedNonce, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(decodedNonce) < 16 || len(decodedNonce) > 64 {
		return "", time.Time{}, fmt.Errorf("%w: invalid nonce", identity.ErrLeaseMalformed)
	}
	now = now.UTC()
	expires := now.Add(ttl)
	if !principal.Expires.IsZero() && principal.Expires.Before(expires) {
		expires = principal.Expires
	}
	if !expires.After(now) {
		return "", time.Time{}, fmt.Errorf("%w: certificate already expired", identity.ErrLeaseExpired)
	}
	hash := sha256.Sum256([]byte(certificate))
	header := map[string]string{"alg": "EdDSA", "typ": "vanl+v1", "kid": a.keyID}
	claims := map[string]any{
		"v":   1,
		"aud": identity.CertificateAudience,
		"uid": principal.RemoteUserID(),
		"dev": principal.DeviceID,
		"ch":  base64.RawURLEncoding.EncodeToString(hash[:]),
		"n":   nonce,
		"iat": now.Unix(),
		"exp": expires.Unix(),
	}
	token, err := a.SignRaw(identity.LeasePrefix, header, claims)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// SignRaw signs arbitrary header/claims with this test authority's key (for negative verification tests).
func (a *Authority) SignRaw(prefix string, header, claims any) (string, error) {
	hBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := prefix + base64.RawURLEncoding.EncodeToString(hBytes) + "." + base64.RawURLEncoding.EncodeToString(cBytes)
	sig := ed25519.Sign(a.privateKey, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func writeLengthPrefixed(w io.Writer, b []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(b)))
	w.Write(size[:])
	w.Write(b)
}
