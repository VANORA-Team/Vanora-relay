package cftunnel

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	nameKeyInfo     = "vanora/cftunnel/v1/name"
	proofKeyInfo    = "vanora/cftunnel/v1/proof"
	rotationKeyInfo = "vanora/cftunnel/v1/rotation"
	dnsMarkerPrefix = "vr1"

	ChallengeTTL  = 30 * time.Second
	EdgeTicketTTL = 20 * time.Second
	EdgeClockSkew = 3 * time.Second
)

var tunnelLabelPattern = regexp.MustCompile(`^[a-z2-7]{25}[aeimquy4]$`)
var ticketJTIPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Crypto holds domain-separated internal keys and independent edge keys.
type Crypto struct {
	nameKey     []byte
	proofKey    []byte
	rotationKey []byte
	edgeKey     []byte
	edgePrevKey []byte
}

// NewCrypto constructs the derivation and ticket service. The edge keys may
// be omitted for desktop_only deployments.
func NewCrypto(masterKey, edgeKey, edgePrevKey []byte) (*Crypto, error) {
	if len(masterKey) < 32 || len(edgeKey) != 0 && len(edgeKey) < 32 ||
		len(edgePrevKey) != 0 && (len(edgeKey) == 0 || len(edgePrevKey) < 32) {
		return nil, errors.New("cftunnel: invalid key length")
	}
	derive := func(info string) ([]byte, error) {
		return hkdf.Key(sha256.New, masterKey, nil, info, sha256.Size)
	}
	name, err := derive(nameKeyInfo)
	if err != nil {
		return nil, err
	}
	proof, err := derive(proofKeyInfo)
	if err != nil {
		return nil, err
	}
	rotation, err := derive(rotationKeyInfo)
	if err != nil {
		return nil, err
	}
	return &Crypto{name, proof, rotation, append([]byte(nil), edgeKey...), append([]byte(nil), edgePrevKey...)}, nil
}

// DeriveHostname generates a stable, opaque DNS label for a device.
func (c *Crypto) DeriveHostname(scopeID, ownerID, deviceID, baseDomain string) (label, hostname string) {
	sum := framedMAC(c.nameKey, "hostname", scopeID, ownerID, deviceID)
	label = strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:16]))
	return label, label + "." + baseDomain
}

// DeriveTunnelName binds the name to the full namespace. The display prefix
// can be shortened to fit Cloudflare's 64-character name with large epochs.
func (c *Crypto) DeriveTunnelName(namespace, label string, incarnation int64) string {
	if !namespacePattern.MatchString(namespace) || !tunnelLabelPattern.MatchString(label) || incarnation < 1 {
		return ""
	}
	epoch := strconv.FormatInt(incarnation, 36)
	mac := framedMAC(c.nameKey, "tunnel-name", namespace, label, epoch)
	prefix := namespace[:min(len(namespace), 23-len(epoch))]
	return "vr-" + prefix + "-" + label + "-i" + epoch + "-" + hex.EncodeToString(mac[:4])
}

// VerifyTunnelName extracts an authenticated tunnel label and incarnation.
func (c *Crypto) VerifyTunnelName(namespace, name string) (label string, incarnation int64, ok bool) {
	if len(name) > 64 || !strings.HasPrefix(name, "vr-") {
		return "", 0, false
	}
	parts := strings.Split(name, "-")
	if len(parts) < 5 {
		return "", 0, false
	}
	label = parts[len(parts)-3]
	epoch, ok := strings.CutPrefix(parts[len(parts)-2], "i")
	incarnation, err := strconv.ParseInt(epoch, 36, 64)
	if !ok || err != nil || !hmac.Equal([]byte(name), []byte(c.DeriveTunnelName(namespace, label, incarnation))) {
		return "", 0, false
	}
	return label, incarnation, true
}

// FormatDNSMarker authenticates the exact DNS and tunnel ownership tuple.
func (c *Crypto) FormatDNSMarker(zoneID, hostname, tunnelID string, incarnation int64) string {
	if zoneID == "" || hostname == "" || tunnelID == "" || incarnation < 1 {
		return ""
	}
	epoch := strconv.FormatInt(incarnation, 36)
	mac := framedMAC(c.nameKey, "dns-marker", zoneID, hostname, tunnelID, epoch)
	return dnsMarkerPrefix + ":" + epoch + ":" + base64.RawURLEncoding.EncodeToString(mac[:16])
}

// VerifyDNSMarker extracts the authenticated incarnation from a DNS comment.
func (c *Crypto) VerifyDNSMarker(marker, zoneID, hostname, tunnelID string) (int64, bool) {
	parts := strings.SplitN(marker, ":", 3)
	if len(parts) != 3 || parts[0] != dnsMarkerPrefix {
		return 0, false
	}
	incarnation, err := strconv.ParseInt(parts[1], 36, 64)
	if err != nil || !hmac.Equal([]byte(marker), []byte(c.FormatDNSMarker(zoneID, hostname, tunnelID, incarnation))) {
		return 0, false
	}
	return incarnation, true
}

// DeriveRotationSecret makes a retried operation reproduce its tunnel secret.
func (c *Crypto) DeriveRotationSecret(operationID, allocationID string, incarnation int64) []byte {
	return framedMAC(c.rotationKey, "rotation-secret", operationID, allocationID, strconv.FormatInt(incarnation, 10))
}

// MintChallenge returns a short-lived token and its nonce, which must be
// consumed once by the store after verification and device authentication.
func (c *Crypto) MintChallenge(scope, action, deviceID string, now time.Time) (string, ProofUse, error) {
	if scope == "" || action == "" || deviceID == "" || now.IsZero() {
		return "", ProofUse{}, ErrInvalidProof
	}
	var random [16]byte
	rand.Read(random[:])
	nonce := base64.RawURLEncoding.EncodeToString(random[:])
	expires := now.Add(ChallengeTTL).Truncate(time.Second)
	exp := strconv.FormatInt(expires.Unix(), 10)
	mac := framedMAC(c.proofKey, "challenge", scope, action, deviceID, nonce, exp)
	token := nonce + "." + exp + "." + base64.RawURLEncoding.EncodeToString(mac)
	return token, ProofUse{ScopeID: scope, Nonce: nonce, ExpiresAt: expires.UTC()}, nil
}

// VerifyChallenge validates the MAC, binding and lifetime. Replay prevention
// is performed by consuming the returned ProofUse in the store.
func (c *Crypto) VerifyChallenge(token, scope, action, deviceID string, now time.Time) (ProofUse, error) {
	if len(token) > 100 || scope == "" || action == "" || deviceID == "" || now.IsZero() {
		return ProofUse{}, ErrInvalidProof
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ProofUse{}, ErrInvalidProof
	}
	nonce, nonceErr := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	exp, expErr := strconv.ParseInt(parts[1], 10, 64)
	expires := time.Unix(exp, 0).UTC()
	mac, macErr := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if nonceErr != nil || len(nonce) != 16 || expErr != nil || macErr != nil ||
		!expires.After(now) || expires.After(now.Add(ChallengeTTL)) {
		return ProofUse{}, ErrInvalidProof
	}
	expected := framedMAC(c.proofKey, "challenge", scope, action, deviceID, parts[0], parts[1])
	if !hmac.Equal(mac, expected) {
		return ProofUse{}, ErrInvalidProof
	}
	return ProofUse{ScopeID: scope, Nonce: parts[0], ExpiresAt: expires}, nil
}

// MintEdgeTicket signs the exact CDN hostname, raw path and JTI. For WAF,
// concatenate "hostname|path|jti|" with the header, with separator length 0
// and flag "s" in is_timed_hmac_valid_v0.
func (c *Crypto) MintEdgeTicket(hostname, path, jti string, now time.Time) (string, error) {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	if len(c.edgeKey) == 0 || len(timestamp) != 10 || timestamp[0] == '-' || !validEdgeInput(hostname, path, jti) {
		return "", ErrInvalidProof
	}
	mac := edgeMAC(c.edgeKey, hostname, path, jti, timestamp)
	return timestamp + "-" + base64.RawURLEncoding.EncodeToString(mac), nil
}

// VerifyEdgeTicket accepts either edge key during rotation and limits both
// expiration and future timestamps independently.
func (c *Crypto) VerifyEdgeTicket(ticket, hostname, path, jti string, now time.Time) bool {
	if len(c.edgeKey) == 0 || len(ticket) != 54 || ticket[10] != '-' ||
		strings.Trim(ticket[:10], "0123456789") != "" || !validEdgeInput(hostname, path, jti) {
		return false
	}
	seconds, err := strconv.ParseInt(ticket[:10], 10, 64)
	mac, decodeErr := base64.RawURLEncoding.Strict().DecodeString(ticket[11:])
	age := now.Unix() - seconds
	if err != nil || decodeErr != nil || age > int64(EdgeTicketTTL/time.Second) || age < -int64(EdgeClockSkew/time.Second) {
		return false
	}
	current := subtle.ConstantTimeCompare(mac, edgeMAC(c.edgeKey, hostname, path, jti, ticket[:10]))
	if len(c.edgePrevKey) != 0 {
		current |= subtle.ConstantTimeCompare(mac, edgeMAC(c.edgePrevKey, hostname, path, jti, ticket[:10]))
	}
	return current == 1
}

func validEdgeInput(hostname, path, jti string) bool {
	return hostname != "" && hostname == normalizeDomain(hostname) && len(path) <= 8192 &&
		strings.HasPrefix(path, "/") && !strings.ContainsAny(path, "|?#\\") &&
		!strings.ContainsFunc(path, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) &&
		ticketJTIPattern.MatchString(jti)
}

func edgeMAC(key []byte, hostname, path, jti, timestamp string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(hostname + "|" + path + "|" + jti + "|" + timestamp))
	return mac.Sum(nil)
}

func framedMAC(key []byte, fields ...string) []byte {
	mac := hmac.New(sha256.New, key)
	var length [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		mac.Write(length[:])
		mac.Write([]byte(field))
	}
	return mac.Sum(nil)
}

func frameFields(fields ...string) []byte {
	var payload []byte
	for _, field := range fields {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(field)))
		payload = append(payload, field...)
	}
	return payload
}

func hashHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
