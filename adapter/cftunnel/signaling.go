package cftunnel

import (
	"crypto/ed25519"
	"time"

	"vanora-relay/internal/strictjson"
	"vanora-relay/protocol"
)

const tunnelAudience = "tunnel-v1"

type signalDomain struct {
	Audience string `json:"aud"`
	Scope    string `json:"scope"`
}

func (d signalDomain) valid(scope string) bool {
	return d.Audience == tunnelAudience && d.Scope == scope
}

type signalBinding struct {
	Generation  int64  `json:"generation"`
	Incarnation int64  `json:"incarnation"`
	RuntimeID   string `json:"runtime_id"`
}

func (b signalBinding) valid() bool {
	return b.Generation >= b.Incarnation && b.Incarnation > 0 && tunnelIdentifier.MatchString(b.RuntimeID)
}

type connectBody struct {
	signalDomain
	ExpectedOwner string `json:"expected_owner"`
	TargetPinHash string `json:"target_pin_hash"`
	ClientNonce   string `json:"client_nonce"`
	Lease         string `json:"lease,omitempty"`
	PairProof     string `json:"pair_proof,omitempty"`
	Role          string `json:"role,omitempty"`
}

type permitBody struct {
	signalDomain
	signalBinding
	Hostname       string    `json:"hostname"`
	JTI            string    `json:"jti"`
	ClientNonce    string    `json:"client_nonce"`
	VisitorKeyHash string    `json:"visitor_key_hash"`
	Path           string    `json:"path"`
	ExpiresAt      time.Time `json:"expires_at"`
	Lease          string    `json:"lease,omitempty"`
}

type accessBody struct {
	signalBinding
	JTI         string    `json:"jti"`
	AccessUntil time.Time `json:"access_until"`
}

type closeBody struct {
	signalDomain
	Reason     string `json:"reason"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

func readSigned(m protocol.Message, key ed25519.PublicKey, body any) bool {
	raw, err := m.Verify(key)
	return err == nil && len(raw) <= 8<<10 && strictjson.Decode(raw, body) == nil
}

func unsignedRelayMessage(m protocol.Message) bool {
	return m.Round == 0 && m.Seq == 0 && m.Body == "" && m.Proof == "" && m.Certificate == ""
}

func endpointMessage(m protocol.Message, kind, connection, from, to string) bool {
	return m.Type == kind && m.Connection == connection && m.From == from && m.To == to &&
		m.Round == 0 && m.Seq > 0 && len(m.Data) == 0
}

func validRole(role string) bool {
	return role == "mobile" || role == "desktop"
}
