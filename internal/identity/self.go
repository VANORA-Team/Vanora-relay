package identity

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	// SelfDeviceIDPrefix identifies a self-hosted endpoint derived directly
	// from its local Ed25519 public key without an external identity authority.
	SelfDeviceIDPrefix = "sdev_"
)

// SelfDeviceID derives the deterministic self-hosted device identifier for an
// endpoint Ed25519 public key.
func SelfDeviceID(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: self-hosted public key has %d bytes", ErrPublicKey, len(pub))
	}
	h := sha256.New()
	h.Write([]byte("vanora/self-device/v1\x00"))
	h.Write(pub)
	return SelfDeviceIDPrefix + strings.ToLower(base32NoPad.EncodeToString(h.Sum(nil)[:16])), nil
}

// ValidSelfDeviceID reports whether id has the shape sdev_<26-char-base32>.
func ValidSelfDeviceID(id string) bool {
	rest, ok := strings.CutPrefix(id, SelfDeviceIDPrefix)
	if !ok || len(rest) != 26 || rest != strings.ToLower(rest) {
		return false
	}
	_, err := base32NoPad.DecodeString(strings.ToUpper(rest))
	return err == nil
}

// SelfPairProof computes the HMAC-SHA256 pairing proof for a self-hosted
// connection request. Binding connectionID and both endpoint public keys keeps
// the raw one-time pairing token off the relay wire and prevents replay across
// connections or devices.
func SelfPairProof(pairToken []byte, connectionID string, mobilePub, desktopPub ed25519.PublicKey) ([]byte, error) {
	if len(pairToken) == 0 {
		return nil, errors.New("identity: pairing token is empty")
	}
	if connectionID == "" || strings.ContainsAny(connectionID, "\r\n\x00") {
		return nil, errors.New("identity: invalid pairing connection id")
	}
	if len(mobilePub) != ed25519.PublicKeySize || len(desktopPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid endpoint public key", ErrPublicKey)
	}
	mac := hmac.New(sha256.New, pairToken)
	input := strings.Join([]string{
		"vanora-self-pair-v1",
		connectionID,
		base64.RawURLEncoding.EncodeToString(mobilePub),
		base64.RawURLEncoding.EncodeToString(desktopPub),
	}, "\n")
	mac.Write([]byte(input))
	return mac.Sum(nil), nil
}
