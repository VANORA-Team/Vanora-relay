// Package protocol defines the native endpoint wire format for the Vanora relay.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// Message is a v1 JSON WebSocket text record. Body contains base64url bytes so
// signatures survive intermediary JSON parsing and serialization unchanged.
type Message struct {
	Type        string          `json:"type"`
	Connection  string          `json:"connection_id,omitempty"`
	From        string          `json:"from,omitempty"`
	To          string          `json:"to,omitempty"`
	Round       uint32          `json:"round,omitempty"`
	Seq         uint64          `json:"seq,omitempty"`
	Body        string          `json:"body,omitempty"`
	Proof       string          `json:"proof,omitempty"`
	Certificate string          `json:"certificate,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
}

func NewID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func ValidID(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == strings.ToLower(s)
}

func Encode(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	} // internal wire structs contain only JSON types
	return b
}

func (m Message) bytes() ([]byte, error) {
	fields := []string{"vanora-relay/v1", m.Type, m.Connection, m.From, m.To, strconv.FormatUint(uint64(m.Round), 10), strconv.FormatUint(m.Seq, 10), m.Body}
	for _, field := range fields {
		if strings.ContainsAny(field, "\n\r\x00") {
			return nil, errors.New("invalid signed field")
		}
	}
	return []byte(strings.Join(fields, "\n")), nil
}

func (m *Message) Sign(key ed25519.PrivateKey, body []byte) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid endpoint key")
	}
	m.Body = base64.RawURLEncoding.EncodeToString(body)
	data, err := m.bytes()
	if err != nil {
		return err
	}
	m.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, data))
	return nil
}

// Verify authenticates the record. Callers must separately match the trusted
// certificate, expected peer IDs, active connection, direction and sequence.
func (m Message) Verify(key ed25519.PublicKey) ([]byte, error) {
	if len(m.Proof) != base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid endpoint signature")
	}
	data, err := m.bytes()
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(m.Proof)
	if err != nil || !ed25519.Verify(key, data, sig) {
		return nil, errors.New("invalid endpoint signature")
	}
	return base64.RawURLEncoding.Strict().DecodeString(m.Body)
}
