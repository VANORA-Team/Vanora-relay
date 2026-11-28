package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/url"
	"strings"

	"vanora-relay/internal/identity"
)

type Official struct {
	Channel, Relay, Device, Owner string
	Pin                           ed25519.PublicKey
	Token                         []byte
}

func NewOfficial(channel, relay, device, owner string, pin ed25519.PublicKey) Official {
	token := make([]byte, 32)
	rand.Read(token)
	return Official{channel, relay, device, owner, pin, token}
}

func (target Official) Link() string {
	fields := url.Values{
		"relay": {target.Relay}, "device": {target.Device}, "owner": {target.Owner},
		"pin": {base64.RawURLEncoding.EncodeToString(target.Pin)}, "pair": {base64.RawURLEncoding.EncodeToString(target.Token)},
	}
	return (&url.URL{Scheme: "vanora", Host: "pair", Path: "/" + target.Channel, Fragment: fields.Encode()}).String()
}

func ParseOfficial(raw, relay string) (Official, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "vanora" || u.Host != "pair" || u.User != nil || u.RawQuery != "" || (u.Path != "/cn" && u.Path != "/global") {
		return Official{}, ErrInvalid
	}
	fields, err := url.ParseQuery(u.Fragment)
	device, owner := fields.Get("device"), fields.Get("owner")
	wantRelay := normalizeRelayURL(relay)
	if err != nil || wantRelay == "" || normalizeRelayURL(fields.Get("relay")) != wantRelay ||
		!identity.ValidDeviceID(device) || !identity.ValidRemoteUserID(owner) {
		return Official{}, ErrInvalid
	}
	pin, err := base64.RawURLEncoding.Strict().DecodeString(fields.Get("pin"))
	if err != nil || len(pin) != ed25519.PublicKeySize {
		return Official{}, ErrInvalid
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(fields.Get("pair"))
	if err != nil || len(token) != 32 {
		return Official{}, ErrInvalid
	}
	return Official{u.Path[1:], relay, device, owner, pin, token}, nil
}

func normalizeRelayURL(raw string) string {
	relay, err := url.Parse(raw)
	if err != nil || relay.Hostname() == "" || relay.User != nil || relay.Fragment != "" {
		return ""
	}
	relay.Scheme = strings.ToLower(relay.Scheme)
	host, port := strings.ToLower(relay.Hostname()), relay.Port()
	switch relay.Scheme {
	case "https", "wss":
		if port == "443" {
			port = ""
		}
	case "http", "ws":
		if port == "80" {
			port = ""
		}
	default:
		return ""
	}
	switch {
	case port != "":
		relay.Host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		relay.Host = "[" + host + "]"
	default:
		relay.Host = host
	}
	relay.RawPath = strings.TrimRight(relay.EscapedPath(), "/")
	relay.Path, _ = url.PathUnescape(relay.RawPath)
	return relay.String()
}
