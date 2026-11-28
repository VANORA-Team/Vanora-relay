// Package identity verifies Vanora endpoint certificates and liveness leases
// issued by an external private identity authority, and builds client proof-of-
// possession signing inputs.
//
// This open-source repository contains verification and client proof helpers
// only; certificate signing and account authentication stay in the deployment's
// private identity backend.
package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
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
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	// CertificatePrefix identifies the wire format of an endpoint
	// certificate: "vanc1.<header>.<claims>.<signature>", where every part
	// after the prefix is unpadded base64url.
	CertificatePrefix = "vanc1."

	// CertificateAudience is the only audience an endpoint certificate may
	// name. Certificates are consumed by the Vanora relay only.
	CertificateAudience = "vanora-relay"

	// DefaultCertificateLifetime is the recommended short certificate lifetime.
	DefaultCertificateLifetime = 10 * time.Minute

	// MaxCertificateLifetime bounds how long an accepted certificate can live.
	MaxCertificateLifetime = 15 * time.Minute

	// LeasePrefix identifies the wire format of a liveness lease:
	// "vanl1.<header>.<claims>.<signature>".
	LeasePrefix = "vanl1."

	// MaxLeaseLifetime bounds how long an accepted liveness lease can live.
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
	ErrPublicKey            = errors.New("identity: invalid endpoint public key")
)

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// Principal is the verified identity carried by an endpoint certificate.
type Principal struct {
	// Issuer identifies the account authority that authenticated the owner.
	Issuer string
	// Subject is the stable account identifier for the owner.
	Subject string
	// DeviceID is stable for the same owner and endpoint public key. It is
	// derived by the authority, so relying parties compare it against a
	// previously learned value.
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

// RemoteUserID derives a stable remote user identifier from an issuer and
// subject. The result depends on the exact issuer string, so deployments must
// pin the issuer URL.
func RemoteUserID(issuer, subject string) string {
	h := sha256.New()
	h.Write([]byte("vanora/remote-user/v1\x00"))
	writeLengthPrefixed(h, []byte(issuer))
	writeLengthPrefixed(h, []byte(subject))
	return remoteUserIDPrefix + strings.ToLower(base32NoPad.EncodeToString(h.Sum(nil)[:16]))
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
	return VerifyCertificateWithKeys(token, []ed25519.PublicKey{trusted}, now)
}

// VerifyCertificateWithKeys accepts a certificate signed by any trusted key.
func VerifyCertificateWithKeys(token string, keys []ed25519.PublicKey, now time.Time) (Principal, error) {
	payload, err := verifyTokenSignature(token, CertificatePrefix, "vanc+v1", keys, maxCertificateSize)
	if err != nil {
		return Principal{}, err
	}
	var claims certificateClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
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
	if !ValidDeviceID(claims.DeviceID) {
		return Principal{}, fmt.Errorf("%w: invalid device id", ErrCertificateMalformed)
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(claims.PublicKey)
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

// verifyTokenSignature parses the compact token, verifies its Ed25519
// signature over the exact transmitted bytes and returns the claims.
func verifyTokenSignature(token, prefix, typ string, keys []ed25519.PublicKey, maxSize int) ([]byte, error) {
	if len(keys) == 1 && len(keys[0]) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: trusted key has %d bytes", ErrCertificateSignature, len(keys[0]))
	}
	if token == "" || len(token) > maxSize {
		return nil, fmt.Errorf("%w: token size %d", ErrCertificateMalformed, len(token))
	}
	rest, ok := strings.CutPrefix(token, prefix)
	if !ok {
		return nil, fmt.Errorf("%w: unknown prefix", ErrCertificateMalformed)
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 segments", ErrCertificateMalformed)
	}
	if parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("%w: empty segment", ErrCertificateMalformed)
	}
	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrCertificateMalformed, err)
	}
	claims, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrCertificateMalformed, err)
	}
	signature, err := decodeSegment(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature", ErrCertificateMalformed)
	}
	signingInput := []byte(token[:len(token)-len(parts[2])-1])
	if !slices.ContainsFunc(keys, func(key ed25519.PublicKey) bool {
		return len(key) == ed25519.PublicKeySize && ed25519.Verify(key, signingInput, signature)
	}) {
		return nil, ErrCertificateSignature
	}
	var header certificateHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrCertificateMalformed, err)
	}
	if header.Alg != "EdDSA" {
		return nil, fmt.Errorf("%w: alg %q", ErrCertificateMalformed, header.Alg)
	}
	if header.Typ != "" && header.Typ != typ {
		return nil, fmt.Errorf("%w: typ %q", ErrCertificateMalformed, header.Typ)
	}
	return claims, nil
}

func decodeSegment(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url segment")
	}
	return b, nil
}

// ValidDeviceID reports whether id has the shape dev_<26-char-lowercase-base32>.
func ValidDeviceID(id string) bool {
	return validID(id, deviceIDPrefix)
}

// ValidRemoteUserID reports whether id has the shape usr_<26-char-lowercase-base32>.
func ValidRemoteUserID(id string) bool {
	return validID(id, remoteUserIDPrefix)
}

func validID(id, prefix string) bool {
	rest, ok := strings.CutPrefix(id, prefix)
	if !ok || len(rest) != 26 {
		return false
	}
	for _, char := range rest {
		if (char < 'a' || char > 'z') && (char < '2' || char > '7') {
			return false
		}
	}
	return true
}

// ValidateIssuerURL accepts an HTTPS issuer without query, fragment or user
// info. Loopback HTTP issuers are accepted for local development only.
func ValidateIssuerURL(raw string) error {
	return validateIssuerURL(raw)
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

// ParsePublicKey parses the authority's trusted Ed25519 public key from hex,
// base64, or raw 32-byte key material. Relays and clients use it to pin the
// verifying key; it never accepts private key material.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrPublicKey)
	}
	if key := parseEncodedPublicKey(strings.TrimSpace(string(data))); key != nil {
		return key, nil
	}
	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), data...)), nil
	}
	return nil, fmt.Errorf("%w: unrecognized public key encoding", ErrPublicKey)
}

// ParsePublicKeys parses comma- or whitespace-separated hex or base64 public
// keys, or a single raw Ed25519 public key.
func ParsePublicKeys(data []byte) ([]ed25519.PublicKey, error) {
	if len(data) == ed25519.PublicKeySize {
		return []ed25519.PublicKey{ed25519.PublicKey(append([]byte(nil), data...))}, nil
	}
	fields := strings.FieldsFunc(string(data), func(char rune) bool {
		return char == ',' || unicode.IsSpace(char)
	})
	if len(fields) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrPublicKey)
	}
	keys := make([]ed25519.PublicKey, 0, len(fields))
	for index, field := range fields {
		key := parseEncodedPublicKey(field)
		if key == nil {
			return nil, fmt.Errorf("%w: unrecognized encoding for key %d", ErrPublicKey, index+1)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func parseEncodedPublicKey(text string) ed25519.PublicKey {
	if len(text) == ed25519.PublicKeySize*2 {
		if decoded, err := hex.DecodeString(text); err == nil && len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded)
		}
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(text); err == nil && len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded)
		}
	}
	return nil
}
