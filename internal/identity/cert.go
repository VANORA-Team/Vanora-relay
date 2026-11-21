// Package identity implements the Vanora independent remote identity
// service. It authenticates users through a configurable external OIDC
// provider and issues short-lived Ed25519 certificates that bind an owner
// (issuer and subject) to an endpoint public key and a stable device ID.
//
// The package holds the authority signing key and verifies the certificates
// it issues. It does not implement login UI, password management, an OAuth
// provider or account recovery; those remain with the configured identity
// provider and the native clients.
package identity

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	// CertificatePrefix identifies the wire format of an endpoint
	// certificate: "vanc1.<header>.<claims>.<signature>", where every part
	// after the prefix is unpadded base64url.
	CertificatePrefix = "vanc1."

	// CertificateAudience is the only audience an endpoint certificate may
	// name. Certificates are consumed by the Vanora relay only.
	CertificateAudience = "vanora-relay"

	// DefaultCertificateLifetime is used when NewSigner is given a zero ttl.
	DefaultCertificateLifetime = 10 * time.Minute

	// MaxCertificateLifetime bounds how long an issued certificate can live.
	MaxCertificateLifetime = 15 * time.Minute

	// LeasePrefix identifies the wire format of a liveness lease:
	// "vanl1.<header>.<claims>.<signature>".
	LeasePrefix = "vanl1."

	// MaxLeaseLifetime bounds how long an issued liveness lease can live.
	MaxLeaseLifetime = 60 * time.Second

	certificateVersion = 1
	leaseVersion       = 1

	maxCertificateSize = 4096
	maxLeaseSize       = 2048

	// clockSkew tolerates small clock differences between the authority and
	// relying parties. It never extends a certificate's validity by more than
	// this amount.
	clockSkew = 30 * time.Second

	deviceIDPrefix     = "dev_"
	remoteUserIDPrefix = "usr_"
)

// Errors reported by certificate and lease verification. Callers may use
// errors.Is to distinguish failures without relying on error text.
var (
	ErrCertificateMalformed = errors.New("identity: malformed certificate")
	ErrCertificateSignature = errors.New("identity: certificate signature verification failed")
	ErrCertificateExpired   = errors.New("identity: certificate expired")
	ErrCertificateAudience  = errors.New("identity: certificate audience mismatch")
	ErrCertificateIssuer    = errors.New("identity: certificate issuer rejected")
	ErrCertificateLifetime  = errors.New("identity: certificate lifetime exceeds limit")
	ErrLeaseMalformed       = errors.New("identity: malformed lease")
	ErrLeaseSignature       = errors.New("identity: lease signature verification failed")
	ErrLeaseExpired         = errors.New("identity: lease expired")
	ErrSigningKey           = errors.New("identity: invalid signing key")
	ErrPublicKey            = errors.New("identity: invalid endpoint public key")
)

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// Principal is the verified identity carried by an endpoint certificate.
type Principal struct {
	// Issuer is the OIDC issuer URL that authenticated the owner.
	Issuer string
	// Subject is the OIDC subject identifier for the owner.
	Subject string
	// DeviceID is stable for the same owner and endpoint public key. It is
	// derived with the authority's private key, so relying parties cannot
	// compute it and must compare it against a previously learned value.
	DeviceID string
	// PublicKey is the endpoint Ed25519 public key bound by the certificate.
	PublicKey ed25519.PublicKey
	// Expires is the end of the certificate's validity.
	Expires time.Time
}

// RemoteUserID returns the stable identifier used for access control. It is
// derived only from the issuer and subject, never from mutable profile data
// such as email addresses or display names.
func (p Principal) RemoteUserID() string {
	return RemoteUserID(p.Issuer, p.Subject)
}

// RemoteUserID derives a stable remote user identifier from an OIDC issuer and
// subject. The result depends on the exact issuer string, so deployments must
// pin the issuer URL.
func RemoteUserID(issuer, subject string) string {
	h := sha256.New()
	h.Write([]byte("vanora/remote-user/v1\x00"))
	writeLengthPrefixed(h, []byte(issuer))
	writeLengthPrefixed(h, []byte(subject))
	return remoteUserIDPrefix + strings.ToLower(base32NoPad.EncodeToString(h.Sum(nil)[:16]))
}

// Signer issues endpoint certificates and liveness leases with an Ed25519
// authority key. The key never leaves the identity service.
type Signer struct {
	privateKey ed25519.PrivateKey
	deviceKey  [sha256.Size]byte
	keyID      string
	ttl        time.Duration
}

// NewSigner builds a signer from an Ed25519 private key and a certificate
// lifetime. The lifetime must be positive and at most MaxCertificateLifetime.
func NewSigner(privateKey ed25519.PrivateKey, ttl time.Duration) (*Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrSigningKey, len(privateKey))
	}
	if ttl == 0 {
		ttl = DefaultCertificateLifetime
	}
	if ttl < 0 || ttl > MaxCertificateLifetime {
		return nil, fmt.Errorf("%w: ttl %s must be in (0, %s]", ErrCertificateLifetime, ttl, MaxCertificateLifetime)
	}
	seed := privateKey.Seed()
	mac := hmac.New(sha256.New, append([]byte("vanora/device-key/v1\x00"), seed...))
	sum := mac.Sum(nil)
	var deviceKey [sha256.Size]byte
	copy(deviceKey[:], sum)

	publicKey := privateKey.Public().(ed25519.PublicKey)
	fingerprint := sha256.Sum256(publicKey)
	return &Signer{
		privateKey: privateKey,
		deviceKey:  deviceKey,
		keyID:      base64.RawURLEncoding.EncodeToString(fingerprint[:8]),
		ttl:        ttl,
	}, nil
}

// PublicKey returns the authority public key relying parties must pin.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.privateKey.Public().(ed25519.PublicKey)
}

// KeyID returns a short fingerprint of the authority public key for logs and
// client configuration verification.
func (s *Signer) KeyID() string {
	return s.keyID
}

// CertificateTTL returns the lifetime given to newly issued certificates.
func (s *Signer) CertificateTTL() time.Duration {
	return s.ttl
}

// DeviceID derives the stable device identifier for an owner and endpoint
// public key. Changing the owner, the key or the authority signing key changes
// the result.
func (s *Signer) DeviceID(issuer, subject string, publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: got %d bytes", ErrPublicKey, len(publicKey))
	}
	mac := hmac.New(sha256.New, s.deviceKey[:])
	mac.Write([]byte("vanora/device/v1\x00"))
	writeLengthPrefixed(mac, []byte(issuer))
	writeLengthPrefixed(mac, []byte(subject))
	mac.Write(publicKey)
	return deviceIDPrefix + strings.ToLower(base32NoPad.EncodeToString(mac.Sum(nil)[:16])), nil
}

// Issue returns a signed endpoint certificate for the owner and key. The
// returned string is handed to the client unchanged.
func (s *Signer) Issue(issuer, subject string, publicKey ed25519.PublicKey, now time.Time) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: got %d bytes", ErrPublicKey, len(publicKey))
	}
	if err := validateIssuerURL(issuer); err != nil {
		return "", err
	}
	if subject == "" || len(subject) > 255 {
		return "", fmt.Errorf("%w: subject must be 1..255 characters", ErrCertificateIssuer)
	}
	deviceID, err := s.DeviceID(issuer, subject, publicKey)
	if err != nil {
		return "", err
	}
	now = now.UTC()
	header := certificateHeader{Alg: "EdDSA", Typ: "vanc+v1", Kid: s.keyID}
	claims := certificateClaims{
		Version:   certificateVersion,
		Issuer:    issuer,
		Subject:   subject,
		DeviceID:  deviceID,
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		Audience:  CertificateAudience,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.ttl).Unix(),
	}
	return signToken(CertificatePrefix, s.privateKey, header, claims)
}

type certificateHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type certificateClaims struct {
	Version   int    `json:"v"`
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	DeviceID  string `json:"dev"`
	PublicKey string `json:"pk"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// VerifyCertificate checks the certificate signature against trusted, the
// audience, the issuer and the validity window, and returns the bound
// principal. Clients compare the returned Issuer, Subject and DeviceID with
// the values they expected for the selected computer before trusting it.
func VerifyCertificate(token string, trusted ed25519.PublicKey, now time.Time) (Principal, error) {
	payload, err := verifyTokenSignature(token, CertificatePrefix, trusted, maxCertificateSize)
	if err != nil {
		return Principal{}, err
	}
	var claims certificateClaims
	if err := json.Unmarshal(payload.Claims, &claims); err != nil {
		return Principal{}, fmt.Errorf("%w: claims: %v", ErrCertificateMalformed, err)
	}
	if claims.Version != certificateVersion {
		return Principal{}, fmt.Errorf("%w: version %d", ErrCertificateMalformed, claims.Version)
	}
	if claims.Audience != CertificateAudience {
		return Principal{}, fmt.Errorf("%w: got %q", ErrCertificateAudience, claims.Audience)
	}
	if claims.Issuer == "" || claims.Subject == "" {
		return Principal{}, fmt.Errorf("%w: missing owner", ErrCertificateMalformed)
	}
	if err := validateIssuerURL(claims.Issuer); err != nil {
		return Principal{}, err
	}
	if !validDeviceID(claims.DeviceID) {
		return Principal{}, fmt.Errorf("%w: invalid device id", ErrCertificateMalformed)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(claims.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return Principal{}, fmt.Errorf("%w: invalid endpoint public key", ErrCertificateMalformed)
	}
	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	expires := time.Unix(claims.ExpiresAt, 0).UTC()
	if claims.ExpiresAt == 0 || claims.IssuedAt == 0 || !expires.After(issuedAt) {
		return Principal{}, fmt.Errorf("%w: invalid validity window", ErrCertificateMalformed)
	}
	if expires.Sub(issuedAt) > MaxCertificateLifetime {
		return Principal{}, fmt.Errorf("%w: %s", ErrCertificateLifetime, expires.Sub(issuedAt))
	}
	if issuedAt.After(now.Add(clockSkew)) {
		return Principal{}, fmt.Errorf("%w: issued in the future", ErrCertificateMalformed)
	}
	if !expires.Add(clockSkew).After(now) {
		return Principal{}, fmt.Errorf("%w: expired at %s", ErrCertificateExpired, expires.Format(time.RFC3339))
	}
	return Principal{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		DeviceID:  claims.DeviceID,
		PublicKey: ed25519.PublicKey(publicKey),
		Expires:   expires,
	}, nil
}

// verifiedToken is the parsed signing input of a token.
type verifiedToken struct {
	Claims json.RawMessage
}

// verifyTokenSignature parses the compact token, verifies its Ed25519
// signature over the exact transmitted bytes and returns the claims.
func verifyTokenSignature(token, prefix string, trusted ed25519.PublicKey, maxSize int) (verifiedToken, error) {
	var zero verifiedToken
	if len(trusted) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("%w: trusted key has %d bytes", ErrCertificateSignature, len(trusted))
	}
	if token == "" || len(token) > maxSize {
		return zero, fmt.Errorf("%w: token size %d", ErrCertificateMalformed, len(token))
	}
	rest, ok := strings.CutPrefix(token, prefix)
	if !ok {
		return zero, fmt.Errorf("%w: unknown prefix", ErrCertificateMalformed)
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return zero, fmt.Errorf("%w: expected 3 segments", ErrCertificateMalformed)
	}
	for _, part := range parts[:2] {
		if part == "" {
			return zero, fmt.Errorf("%w: empty segment", ErrCertificateMalformed)
		}
		if _, err := decodeSegment(part); err != nil {
			return zero, fmt.Errorf("%w: %v", ErrCertificateMalformed, err)
		}
	}
	signature, err := decodeSegment(parts[2])
	if err != nil {
		return zero, fmt.Errorf("%w: signature: %v", ErrCertificateMalformed, err)
	}
	signingInput := prefix + parts[0] + "." + parts[1]
	if !ed25519.Verify(trusted, []byte(signingInput), signature) {
		return zero, ErrCertificateSignature
	}
	var header certificateHeader
	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return zero, fmt.Errorf("%w: header: %v", ErrCertificateMalformed, err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return zero, fmt.Errorf("%w: header: %v", ErrCertificateMalformed, err)
	}
	if header.Alg != "EdDSA" {
		return zero, fmt.Errorf("%w: alg %q", ErrCertificateMalformed, header.Alg)
	}
	claims, err := decodeSegment(parts[1])
	if err != nil {
		return zero, fmt.Errorf("%w: claims: %v", ErrCertificateMalformed, err)
	}
	return verifiedToken{Claims: claims}, nil
}

// signToken marshals and signs the header and claims into a compact token.
func signToken(prefix string, key ed25519.PrivateKey, header, claims any) (string, error) {
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("identity: marshal header: %w", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("identity: marshal claims: %w", err)
	}
	signingInput := prefix + encodeSegment(headerBytes) + "." + encodeSegment(claimsBytes)
	signature := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + encodeSegment(signature), nil
}

func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeSegment(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url segment")
	}
	return b, nil
}

// validDeviceID reports whether id has the shape produced by Signer.DeviceID.
func validDeviceID(id string) bool {
	rest, ok := strings.CutPrefix(id, deviceIDPrefix)
	if !ok || len(rest) != 26 {
		return false
	}
	if _, err := base32NoPad.DecodeString(strings.ToUpper(rest)); err != nil {
		return false
	}
	return true
}

// validateIssuerURL accepts an HTTPS issuer without query, fragment or user
// info. Loopback HTTP issuers are accepted for local development only.
func validateIssuerURL(raw string) error {
	if raw == "" || len(raw) > 2048 {
		return fmt.Errorf("%w: empty or oversized issuer", ErrCertificateIssuer)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCertificateIssuer, err)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil || parsed.Host == "" {
		return fmt.Errorf("%w: issuer must be a bare origin", ErrCertificateIssuer)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(parsed.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("%w: scheme %q is not allowed", ErrCertificateIssuer, parsed.Scheme)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func writeLengthPrefixed(w io.Writer, b []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(b)))
	w.Write(size[:])
	w.Write(b)
}

// ParseSigningKey decodes an Ed25519 signing key from raw bytes, hex or
// base64. It accepts either the 32-byte seed or the 64-byte private key.
func ParseSigningKey(data []byte) (ed25519.PrivateKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrSigningKey)
	}
	raw, err := decodeKeyMaterial(data)
	if err != nil {
		return nil, err
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		derived := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if subtle.ConstantTimeCompare(derived, raw) != 1 {
			return nil, fmt.Errorf("%w: public half does not match seed", ErrSigningKey)
		}
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("%w: %d bytes", ErrSigningKey, len(raw))
	}
}

// ParsePublicKey parses the authority's trusted Ed25519 public key from the
// hex or base64 text written by `relay-identity keygen -public-out`. Relays
// and clients use it to load the verifying key; it never contains private
// material.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	raw, err := decodeKeyMaterial(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPublicKey, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key must be %d bytes, got %d", ErrPublicKey, ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func decodeKeyMaterial(data []byte) ([]byte, error) {
	text := strings.TrimSpace(string(data))
	if text == "" && !isKeySize(len(data)) {
		return nil, fmt.Errorf("%w: empty", ErrSigningKey)
	}
	if len(text)%2 == 0 {
		if decoded, err := hex.DecodeString(text); err == nil && isKeySize(len(decoded)) {
			return decoded, nil
		}
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(text); err == nil && isKeySize(len(decoded)) {
			return decoded, nil
		}
	}
	if len(data) == ed25519.SeedSize || len(data) == ed25519.PrivateKeySize {
		return data, nil
	}
	return nil, fmt.Errorf("%w: unrecognized encoding", ErrSigningKey)
}

func isKeySize(size int) bool {
	return size == ed25519.SeedSize || size == ed25519.PrivateKeySize
}
