package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Lease is a short-lived signed statement that the authority observed the
// holder of an endpoint key and was itself able to operate at IssuedAt. It
// carries no revocation information and must never be used as authority
// health or access state beyond its Expires time.
type Lease struct {
	// Nonce is the client-generated nonce bound into the lease.
	Nonce string
	// RemoteUserID is the owner the leased endpoint belongs to.
	RemoteUserID string
	// DeviceID is the endpoint the lease was issued for.
	DeviceID string
	// CertificateHash is the unpadded base64url SHA-256 of the presented
	// certificate, binding the lease to that exact certificate string.
	CertificateHash string
	// IssuedAt is when the authority issued the lease.
	IssuedAt time.Time
	// Expires is when the lease stops being valid.
	Expires time.Time
}

type leaseClaims struct {
	Version         int    `json:"v"`
	Audience        string `json:"aud"`
	RemoteUserID    string `json:"uid"`
	DeviceID        string `json:"dev"`
	CertificateHash string `json:"ch"`
	Nonce           string `json:"n"`
	IssuedAt        int64  `json:"iat"`
	ExpiresAt       int64  `json:"exp"`
}

// VerifyLease checks the lease signature, audience, validity window and claim
// shapes and returns the parsed lease.
func VerifyLease(token string, trusted ed25519.PublicKey, now time.Time) (Lease, error) {
	return VerifyLeaseWithKeys(token, []ed25519.PublicKey{trusted}, now)
}

// VerifyLeaseWithKeys accepts a liveness lease signed by any trusted key.
func VerifyLeaseWithKeys(token string, keys []ed25519.PublicKey, now time.Time) (Lease, error) {
	payload, err := verifyTokenSignature(token, LeasePrefix, "vanl+v1", keys, maxLeaseSize)
	if err != nil {
		return Lease{}, mapLeaseError(err)
	}
	var claims leaseClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Lease{}, fmt.Errorf("%w: claims: %v", ErrLeaseMalformed, err)
	}
	if claims.Version != leaseVersion {
		return Lease{}, fmt.Errorf("%w: version %d", ErrLeaseMalformed, claims.Version)
	}
	if claims.Audience != CertificateAudience {
		return Lease{}, fmt.Errorf("%w: audience %q", ErrLeaseMalformed, claims.Audience)
	}
	if !ValidRemoteUserID(claims.RemoteUserID) {
		return Lease{}, fmt.Errorf("%w: remote user id", ErrLeaseMalformed)
	}
	if !ValidDeviceID(claims.DeviceID) {
		return Lease{}, fmt.Errorf("%w: device id", ErrLeaseMalformed)
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(claims.CertificateHash); err != nil {
		return Lease{}, fmt.Errorf("%w: certificate hash", ErrLeaseMalformed)
	}
	if !validNonce(claims.Nonce) {
		return Lease{}, fmt.Errorf("%w: nonce", ErrLeaseMalformed)
	}
	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	expires := time.Unix(claims.ExpiresAt, 0).UTC()
	if claims.IssuedAt == 0 || claims.ExpiresAt == 0 || !expires.After(issuedAt) {
		return Lease{}, fmt.Errorf("%w: invalid validity window", ErrLeaseMalformed)
	}
	if expires.Sub(issuedAt) > MaxLeaseLifetime {
		return Lease{}, fmt.Errorf("%w: %s", ErrLeaseMalformed, expires.Sub(issuedAt))
	}
	if issuedAt.After(now.Add(clockSkew)) {
		return Lease{}, fmt.Errorf("%w: issued in the future", ErrLeaseMalformed)
	}
	if !expires.Add(clockSkew).After(now) {
		return Lease{}, fmt.Errorf("%w: expired at %s", ErrLeaseExpired, expires.Format(time.RFC3339))
	}
	return Lease{
		Nonce:           claims.Nonce,
		RemoteUserID:    claims.RemoteUserID,
		DeviceID:        claims.DeviceID,
		CertificateHash: claims.CertificateHash,
		IssuedAt:        issuedAt,
		Expires:         expires,
	}, nil
}

// VerifyEndpointLease verifies a lease and every binding that ties it to a
// specific endpoint and certificate. It returns the lease expiry. Callers must
// also have verified certificate themselves and pass the resulting principal.
func VerifyEndpointLease(token string, trusted ed25519.PublicKey, now time.Time, certificate string, principal Principal) (time.Time, error) {
	return VerifyEndpointLeaseWithKeys(token, []ed25519.PublicKey{trusted}, now, certificate, principal)
}

// VerifyEndpointLeaseWithKeys verifies the endpoint binding with any trusted key.
func VerifyEndpointLeaseWithKeys(token string, keys []ed25519.PublicKey, now time.Time, certificate string, principal Principal) (time.Time, error) {
	if principal.Subject == "" || !ValidDeviceID(principal.DeviceID) {
		return time.Time{}, fmt.Errorf("%w: incomplete principal", ErrLeaseMalformed)
	}
	lease, err := VerifyLeaseWithKeys(token, keys, now)
	if err != nil {
		return time.Time{}, err
	}
	if subtle.ConstantTimeCompare([]byte(lease.RemoteUserID), []byte(principal.RemoteUserID())) != 1 {
		return time.Time{}, fmt.Errorf("%w: remote user binding", ErrLeaseMalformed)
	}
	if subtle.ConstantTimeCompare([]byte(lease.DeviceID), []byte(principal.DeviceID)) != 1 {
		return time.Time{}, fmt.Errorf("%w: device binding", ErrLeaseMalformed)
	}
	expectedHash := sha256.Sum256([]byte(certificate))
	if subtle.ConstantTimeCompare([]byte(lease.CertificateHash), []byte(base64.RawURLEncoding.EncodeToString(expectedHash[:]))) != 1 {
		return time.Time{}, fmt.Errorf("%w: certificate binding", ErrLeaseMalformed)
	}
	if lease.Expires.After(principal.Expires) {
		return time.Time{}, fmt.Errorf("%w: expires after certificate", ErrLeaseMalformed)
	}
	return lease.Expires, nil
}

func mapLeaseError(err error) error {
	switch {
	case errors.Is(err, ErrCertificateSignature):
		return fmt.Errorf("%w: %v", ErrLeaseSignature, err)
	case errors.Is(err, ErrCertificateMalformed):
		return fmt.Errorf("%w: %v", ErrLeaseMalformed, err)
	default:
		return err
	}
}

func validNonce(nonce string) bool {
	if len(nonce) < 22 || len(nonce) > 128 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil {
		return false
	}
	return len(decoded) >= 16 && len(decoded) <= 64
}
