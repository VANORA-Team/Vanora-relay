package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	// RefreshPrefix identifies the opaque refresh handle given to a client:
	// "vanr1.<base64url nonce>.<base64url ciphertext>".
	RefreshPrefix = "vanr1."

	// MaxRefreshHandleLifetime bounds how long a refresh handle can be used.
	// The provider's refresh token may expire sooner; renewal then fails and
	// the user signs in again.
	MaxRefreshHandleLifetime = 90 * 24 * time.Hour

	refreshHandleVersion = 1
	maxRefreshHandleSize = 12 << 10
	maxRefreshTokenSize  = 4096
)

// ErrRefreshHandle is returned for a refresh handle that is malformed,
// tampered with, or expired. It deliberately does not reveal which.
var ErrRefreshHandle = errors.New("identity: refresh handle invalid or expired")

// refreshGrant is the encrypted payload behind a refresh handle. It binds a
// provider refresh token to the issuer, subject, device, and endpoint key that
// earned the original certificate.
type refreshGrant struct {
	Version      int    `json:"v"`
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
	DeviceID     string `json:"dev"`
	PublicKey    string `json:"pk"`
	RefreshToken string `json:"rt"`
	ExpiresAt    int64  `json:"exp"`
}

// refreshKey derives the handle encryption key from the authority signing
// seed, so the handle is opaque to clients and the relay. It never leaves the
// identity service.
func (s *Signer) refreshKey() [sha256.Size]byte {
	mac := hmac.New(sha256.New, s.privateKey.Seed())
	mac.Write([]byte("vanora/refresh-key/v1\x00"))
	var key [sha256.Size]byte
	copy(key[:], mac.Sum(nil))
	return key
}

// sealRefresh encrypts a provider refresh token into an opaque handle bound to
// the owner, device, and endpoint key.
func (s *Signer) sealRefresh(issuer, subject string, publicKey ed25519.PublicKey, refreshToken string, now time.Time) (string, error) {
	if err := validateIssuerURL(issuer); err != nil {
		return "", err
	}
	if subject == "" || len(subject) > 255 {
		return "", fmt.Errorf("%w: subject must be 1..255 characters", ErrCertificateIssuer)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: got %d bytes", ErrPublicKey, len(publicKey))
	}
	if refreshToken == "" || len(refreshToken) > maxRefreshTokenSize {
		return "", fmt.Errorf("%w: refresh token must be 1..%d bytes", ErrRefreshHandle, maxRefreshTokenSize)
	}
	deviceID, err := s.DeviceID(issuer, subject, publicKey)
	if err != nil {
		return "", err
	}
	grant := refreshGrant{
		Version:      refreshHandleVersion,
		Issuer:       issuer,
		Subject:      subject,
		DeviceID:     deviceID,
		PublicKey:    base64.RawURLEncoding.EncodeToString(publicKey),
		RefreshToken: refreshToken,
		ExpiresAt:    now.Add(MaxRefreshHandleLifetime).Unix(),
	}
	plaintext, err := json.Marshal(grant)
	if err != nil {
		return "", fmt.Errorf("identity: marshal refresh grant: %w", err)
	}
	key := s.refreshKey()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("identity: refresh cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("identity: refresh aead: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("identity: refresh nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, refreshHandleAAD())
	handle := RefreshPrefix +
		base64.RawURLEncoding.EncodeToString(nonce) + "." +
		base64.RawURLEncoding.EncodeToString(sealed)
	if len(handle) > maxRefreshHandleSize {
		return "", fmt.Errorf("%w: handle too large", ErrRefreshHandle)
	}
	return handle, nil
}

// openRefresh decrypts and validates a refresh handle. The returned key is the
// endpoint key the handle is bound to.
func (s *Signer) openRefresh(handle string, now time.Time) (refreshGrant, ed25519.PublicKey, error) {
	var zero refreshGrant
	if handle == "" || len(handle) > maxRefreshHandleSize {
		return zero, nil, fmt.Errorf("%w: size %d", ErrRefreshHandle, len(handle))
	}
	rest, ok := cutPrefix(handle, RefreshPrefix)
	if !ok {
		return zero, nil, fmt.Errorf("%w: unknown prefix", ErrRefreshHandle)
	}
	parts := splitOnce(rest, '.')
	if parts == nil {
		return zero, nil, fmt.Errorf("%w: missing segments", ErrRefreshHandle)
	}
	nonce, err := decodeSegment(parts[0])
	if err != nil {
		return zero, nil, fmt.Errorf("%w: nonce", ErrRefreshHandle)
	}
	ciphertext, err := decodeSegment(parts[1])
	if err != nil {
		return zero, nil, fmt.Errorf("%w: ciphertext", ErrRefreshHandle)
	}
	key := s.refreshKey()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return zero, nil, fmt.Errorf("%w: cipher", ErrRefreshHandle)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return zero, nil, fmt.Errorf("%w: aead", ErrRefreshHandle)
	}
	if len(nonce) != aead.NonceSize() {
		return zero, nil, fmt.Errorf("%w: nonce size", ErrRefreshHandle)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, refreshHandleAAD())
	if err != nil {
		return zero, nil, fmt.Errorf("%w: authentication", ErrRefreshHandle)
	}
	var grant refreshGrant
	if err := json.Unmarshal(plaintext, &grant); err != nil {
		return zero, nil, fmt.Errorf("%w: payload", ErrRefreshHandle)
	}
	if grant.Version != refreshHandleVersion {
		return zero, nil, fmt.Errorf("%w: version", ErrRefreshHandle)
	}
	if err := validateIssuerURL(grant.Issuer); err != nil {
		return zero, nil, fmt.Errorf("%w: issuer", ErrRefreshHandle)
	}
	if grant.Subject == "" || len(grant.Subject) > 255 || !validDeviceID(grant.DeviceID) {
		return zero, nil, fmt.Errorf("%w: owner", ErrRefreshHandle)
	}
	if grant.RefreshToken == "" || len(grant.RefreshToken) > maxRefreshTokenSize {
		return zero, nil, fmt.Errorf("%w: refresh token", ErrRefreshHandle)
	}
	publicKey, err := decodeSegment(grant.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return zero, nil, fmt.Errorf("%w: public key", ErrRefreshHandle)
	}
	if !grantExpiry(grant.ExpiresAt).After(now) {
		return zero, nil, fmt.Errorf("%w: expired", ErrRefreshHandle)
	}
	return grant, ed25519.PublicKey(publicKey), nil
}

func grantExpiry(expiresAt int64) time.Time {
	return time.Unix(expiresAt, 0)
}

// RenewProofMessage returns the bytes an endpoint signs with its enrolled key
// to prove possession during certificate renewal. A fresh client-generated
// nonce makes every renewal signature unique; the authority also rejects
// replayed nonces.
func RenewProofMessage(nonce, handle string) []byte {
	sum := sha256.Sum256([]byte(handle))
	return []byte("vanora-identity-renew-v1\n" +
		nonce + "\n" +
		base64.RawURLEncoding.EncodeToString(sum[:]))
}

func refreshHandleAAD() []byte {
	return []byte("vanora/refresh-handle/v1")
}

// splitOnce splits s around the first sep. It returns nil when sep is absent.
func splitOnce(s string, sep byte) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return []string{s[:i], s[i+1:]}
		}
	}
	return nil
}
