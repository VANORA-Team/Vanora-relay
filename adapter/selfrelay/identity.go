// Package selfrelay implements account-free, pairing-only remote access through
// a user-hosted Vanora relay (RELAY_CHANNEL=self).
//
// Access to the relay node is gated by the operator's RELAY_SELF_TOKEN bearer
// secret, while desktop authorization and end-to-end WebRTC integrity are
// enforced exclusively by locally generated Ed25519 device keys and one-time
// pairing invitations stored on the desktop. No Vanora account or external
// identity authority is involved.
package selfrelay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

const (
	Read    = "read"
	Control = "control"

	inviteTTL  = 5 * time.Minute
	maxInvites = 32
	maxClients = 128
)

var (
	// ErrUnpaired reports that this device is not paired with (or was revoked
	// by) the target desktop on the self-hosted relay.
	ErrUnpaired = errors.New("selfrelay: device authorization required")
	// ErrUnauthorized reports that the self-hosted relay rejected the
	// configured RELAY_SELF_TOKEN bearer credential.
	ErrUnauthorized = errors.New("selfrelay: invalid relay token")
)

// Store persists opaque encrypted self-relay state in secure storage.
type Store interface {
	Load() (string, error)
	Save(string) error
}

// ClientInfo describes one paired mobile device authorized to connect through
// the desktop's self-hosted relay channel.
type ClientInfo struct {
	ID         string    `json:"id"`
	PublicKey  string    `json:"public_key"`
	Name       string    `json:"name"`
	Role       string    `json:"role,omitempty"`
	Access     string    `json:"access"`
	PairedAt   time.Time `json:"paired_at"`
	Connected  bool      `json:"connected"`
	Epoch      uint64    `json:"membership_epoch,omitempty"`
	LocalEpoch uint64    `json:"local_epoch,omitempty"`
}

// Invitation is an active one-time pairing invitation for the self-hosted relay.
type Invitation struct {
	ID        string    `json:"id"`
	Access    string    `json:"access"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Status is a snapshot of the desktop's self-hosted relay state.
type Status struct {
	Enabled     bool         `json:"enabled"`
	Online      bool         `json:"online"`
	SignalURL   string       `json:"signal_url,omitempty"`
	DeviceID    string       `json:"device_id,omitempty"`
	Error       string       `json:"error,omitempty"`
	Clients     []ClientInfo `json:"clients"`
	Invitations []Invitation `json:"invitations"`
}

// Target identifies a paired desktop reachable through a self-hosted relay.
// Pair is present only in a one-time invitation link and is stripped after
// pairing succeeds.
type Target struct {
	SignalURL string
	Pin       string
	Pair      string
	Token     string
}

func newSeed() (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(seed), nil
}

// LoadClientKey loads or initializes the mobile device's Ed25519 seed in store.
func LoadClientKey(store Store) (string, error) {
	if store == nil {
		return "", errors.New("selfrelay: secure storage required")
	}
	key, err := store.Load()
	if err != nil {
		return "", err
	}
	if key == "" {
		key, err = newSeed()
		if err != nil {
			return "", err
		}
		if err := store.Save(key); err != nil {
			return "", err
		}
	}
	if !validToken32(key) {
		return "", errors.New("selfrelay: invalid stored device key")
	}
	return key, nil
}

func parseKeySeed(seed string) (ed25519.PrivateKey, ed25519.PublicKey, string, string, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(seed)
	if err != nil || len(raw) != ed25519.SeedSize {
		return nil, nil, "", "", errors.New("selfrelay: invalid device key")
	}
	priv := ed25519.NewKeyFromSeed(raw)
	pub := priv.Public().(ed25519.PublicKey)
	devID, err := identity.SelfDeviceID(pub)
	if err != nil {
		return nil, nil, "", "", err
	}
	return priv, pub, base64.RawURLEncoding.EncodeToString(pub), devID, nil
}

func parsePublicKeyB64(raw string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("selfrelay: invalid public key")
	}
	return ed25519.PublicKey(b), nil
}

func fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func ClientIdentity(seed string) (string, string) {
	_, pub, pin, _, err := parseKeySeed(seed)
	if err != nil {
		return "", ""
	}
	return fingerprint(pub), pin
}

func validToken32(value string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == sha256.Size
}

// ValidateRelayToken checks the bearer secret presented to a self-hosted relay.
func ValidateRelayToken(token string) error {
	if len(token) < 32 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return errors.New("selfrelay: relay token must be 32-512 bytes without whitespace")
	}
	return nil
}

// ValidateSignalURL enforces wss:// for remote hosts and allows ws:// only on
// loopback hosts.
func ValidateSignalURL(raw string) error {
	_, err := NormalizeSignalURL(raw)
	return err
}

func NormalizeSignalURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("selfrelay: invalid signaling URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "wss", "https":
		u.Scheme = "wss"
	case "ws", "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", errors.New("selfrelay: plain ws/http is allowed only on loopback hosts")
		}
		u.Scheme = "ws"
	default:
		return "", errors.New("selfrelay: signaling URL must use wss or loopback ws")
	}
	if u.Path == "" {
		u.Path = "/v1/signal"
	}
	return u.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ParseTarget validates a self-hosted pairing link or saved reconnect target.
func ParseTarget(link string) (Target, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery {
		return Target{}, errors.New("selfrelay: invalid pairing link")
	}
	base := *parsed
	base.Fragment = ""
	signalURL, err := NormalizeSignalURL(base.String())
	if err != nil {
		return Target{}, errors.New("selfrelay: invalid pairing link URL")
	}
	params, err := url.ParseQuery(parsed.Fragment)
	if err != nil || params.Get("mode") != "self" {
		return Target{}, errors.New("selfrelay: invalid pairing mode")
	}
	pin := params.Get("pin")
	if !validToken32(pin) {
		return Target{}, errors.New("selfrelay: invalid desktop pin")
	}
	pair := params.Get("pair")
	if pair != "" && !validToken32(pair) {
		return Target{}, errors.New("selfrelay: invalid pairing token")
	}
	token := params.Get("token")
	if token != "" {
		if err := ValidateRelayToken(token); err != nil {
			return Target{}, err
		}
	}
	return Target{
		SignalURL: signalURL,
		Pin:       pin,
		Pair:      pair,
		Token:     token,
	}, nil
}

// Link formats Target as an HTTPS (or loopback HTTP) pairing/reconnect URI
// carrying all sensitive parameters in the fragment so intermediaries never see
// them in HTTP requests.
func (t Target) Link() string {
	u, err := url.Parse(t.SignalURL)
	if err != nil {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "wss", "https":
		u.Scheme = "https"
	case "ws", "http":
		u.Scheme = "http"
	default:
		return ""
	}
	params := url.Values{
		"mode": {"self"},
		"pin":  {t.Pin},
	}
	if t.Pair != "" {
		params.Set("pair", t.Pair)
	}
	if t.Token != "" {
		params.Set("token", t.Token)
	}
	u.Fragment = params.Encode()
	return u.String()
}

// Access returns the granted access level ("read" or "control") for a
// self-hosted paired user ID, or "" if userID is not a self-hosted identifier.
func Access(userID string) string {
	prefix, suffix, _ := strings.Cut(userID, ":")
	level, id, _ := strings.Cut(suffix, ":")
	if prefix == "self" && (level == Read || level == Control) && validToken32(id) {
		return level
	}
	return ""
}

func userID(client ClientInfo) string {
	return "self:" + client.Access + ":" + client.ID
}

func validName(name string) bool {
	return name != "" && len(name) <= 128 && utf8.ValidString(name) &&
		strings.TrimSpace(name) == name && !strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf)
	})
}

func sameSignalOrigin(raw string, got *url.URL) bool {
	want, err := url.Parse(raw)
	if err != nil || got == nil {
		return false
	}
	scheme := "http"
	if want.Scheme == "wss" {
		scheme = "https"
	}
	return strings.EqualFold(got.Scheme, scheme) &&
		strings.EqualFold(got.Host, want.Host) &&
		got.RequestURI() == want.RequestURI()
}

func parseErrf(format string, args ...any) error {
	return fmt.Errorf("selfrelay: "+format, args...)
}

// SignActivityPoll signs a timestamped activity.poll proof for querying redacted
// session states of a paired self-hosted desktop identified by targetPin.
func SignActivityPoll(seed, targetPin string, now time.Time) (pubKeyB64, targetDeviceID, proofB64 string, err error) {
	priv, _, pubB64, callerDevID, err := parseKeySeed(seed)
	if err != nil {
		return "", "", "", err
	}
	targetPub, err := parsePublicKeyB64(strings.TrimSpace(targetPin))
	if err != nil {
		return "", "", "", err
	}
	targetDevID, err := identity.SelfDeviceID(targetPub)
	if err != nil {
		return "", "", "", err
	}
	if callerDevID == targetDevID {
		return "", "", "", errors.New("selfrelay: cannot poll self")
	}
	m := protocol.Message{
		Type: "activity.poll",
		From: callerDevID,
		To:   targetDevID,
	}
	if err := m.Sign(priv, []byte(strconv.FormatInt(now.UnixMilli(), 10))); err != nil {
		return "", "", "", err
	}
	return pubB64, targetDevID, base64.RawURLEncoding.EncodeToString(protocol.Encode(m)), nil
}
