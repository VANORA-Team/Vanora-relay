package endpoint

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"time"
	"unicode"

	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

// Device is safe to display after verifying the directory entry. Retain the
// selected DeviceID and Owner for Request. Names alone are not identifiers.
type Device struct{ DeviceID, Owner, Issuer, Subject, Name string }

func validName(name string) bool {
	return len(name) > 0 && len(name) <= 128 && strings.TrimSpace(name) == name && strings.IndexFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.In(r, unicode.Cf) }) < 0
}

func (c *Credentials) Online(name string, guests []string) (protocol.Message, error) {
	if !validName(name) {
		return protocol.Message{}, errors.New("invalid device name")
	}
	card := protocol.Message{Type: "device.card", From: c.DeviceID(), To: c.UserID(), Certificate: c.cert}
	if err := card.Sign(c.key, []byte(name)); err != nil {
		return protocol.Message{}, err
	}
	return protocol.Message{Type: "device.online", Data: protocol.Encode(struct {
		Card   protocol.Message `json:"card"`
		Guests []string         `json:"guests"`
	}{card, guests})}, nil
}

func VerifyDevice(card protocol.Message, ca ed25519.PublicKey, now time.Time) (Device, error) {
	return VerifyDeviceWithKeys(card, []ed25519.PublicKey{ca}, now)
}

func VerifyDeviceWithKeys(card protocol.Message, keys []ed25519.PublicKey, now time.Time) (Device, error) {
	p, err := identity.VerifyCertificateWithKeys(card.Certificate, keys, now)
	if err != nil {
		return Device{}, err
	}
	name, err := card.Verify(p.PublicKey)
	if err != nil {
		return Device{}, err
	}
	if card.Type != "device.card" || card.From != p.DeviceID || card.To != p.RemoteUserID() || card.Connection != "" || card.Round != 0 || card.Seq != 0 || !validName(string(name)) {
		return Device{}, errors.New("invalid signed device card")
	}
	return Device{p.DeviceID, p.RemoteUserID(), p.Issuer, p.Subject, string(name)}, nil
}
