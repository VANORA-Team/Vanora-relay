// Package endpoint authenticates WebRTC negotiation before native clients hand
// the SDP or ICE candidates to their WebRTC implementation. A Session belongs
// to one connection, and callers serialize its methods on the signaling loop.
package endpoint

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

type Credentials struct {
	cert      string
	key       ed25519.PrivateKey
	ca        ed25519.PublicKey
	principal identity.Principal
}

func OpenCredentials(cert string, key ed25519.PrivateKey, ca ed25519.PublicKey, now time.Time) (*Credentials, error) {
	p, err := identity.VerifyCertificate(cert, ca, now)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize || !p.PublicKey.Equal(key.Public()) {
		return nil, errors.New("certificate and endpoint key differ")
	}
	return &Credentials{cert, key, ca, p}, nil
}
func (c *Credentials) DeviceID() string { return c.principal.DeviceID }
func (c *Credentials) UserID() string   { return c.principal.RemoteUserID() }

// Certificate returns the signed certificate string this endpoint presents.
func (c *Credentials) Certificate() string { return c.cert }

// CA returns the authority public key these credentials were opened against.
func (c *Credentials) CA() ed25519.PublicKey { return c.ca }
func (c *Credentials) Login(challenge protocol.Message, role, lease string) (protocol.Message, error) {
	if challenge.Type != "auth.challenge" || !protocol.ValidID(challenge.Connection) || (role != "desktop" && role != "mobile") {
		return protocol.Message{}, errors.New("invalid login challenge or role")
	}
	m := protocol.Message{Type: "auth.login", Connection: challenge.Connection, From: c.DeviceID(), To: "signal", Certificate: c.cert}
	err := m.Sign(c.key, protocol.Encode(map[string]string{"role": role, "lease": lease}))
	return m, err
}

type Session struct {
	local                            *Credentials
	remote                           identity.Principal
	target, owner, connection, nonce string
	desktop                          bool
	sent, received                   uint64
	round                            uint32
	answered                         bool
}

func (s *Session) ID() string           { return s.connection }
func (s *Session) RemoteUserID() string { return s.remote.RemoteUserID() }

func (s *Session) sign(kind string, body []byte) (protocol.Message, error) {
	m := protocol.Message{Type: kind, Connection: s.connection, From: s.local.DeviceID(), To: s.target, Round: s.round, Seq: s.sent + 1}
	err := m.Sign(s.local.key, body)
	if err == nil {
		s.sent++
	}
	return m, err
}

// Request pins the selected machine and its owner. Obtain both identifiers from
// a trusted binding or invitation, independently of the signaling directory.
func (c *Credentials) Request(device, owner string) (*Session, protocol.Message, error) {
	if device == "" || owner == "" {
		return nil, protocol.Message{}, errors.New("expected device and owner required")
	}
	s := &Session{local: c, target: device, owner: owner, connection: protocol.NewID()}
	m, err := s.sign("connect.request", nil)
	return s, m, err
}

func (c *Credentials) checkPeer(m protocol.Message, kind string, now time.Time) (identity.Principal, []byte, error) {
	p, err := identity.VerifyCertificate(m.Certificate, c.ca, now)
	if err != nil {
		return p, nil, err
	}
	if !now.Before(c.principal.Expires) || m.Type != kind || !protocol.ValidID(m.Connection) || m.From != p.DeviceID || m.To != c.DeviceID() || m.Round != 0 || m.Seq != 1 {
		return p, nil, errors.New("invalid peer binding")
	}
	body, err := m.Verify(p.PublicKey)
	return p, body, err
}

// Accept requires the desktop's local ACL decision before releasing its nonce.
func (c *Credentials) Accept(m protocol.Message, allows func(string) bool, now time.Time) (*Session, protocol.Message, error) {
	p, body, err := c.checkPeer(m, "connect.request", now)
	if err != nil {
		return nil, protocol.Message{}, err
	}
	if len(body) != 0 || allows == nil || !allows(p.RemoteUserID()) {
		return nil, protocol.Message{}, errors.New("access denied")
	}
	s := &Session{local: c, remote: p, target: p.DeviceID, owner: p.RemoteUserID(), connection: m.Connection, nonce: protocol.NewID(), desktop: true, received: m.Seq}
	reply, err := s.sign("connect.accept", []byte(s.nonce))
	return s, reply, err
}

func (s *Session) Accepted(m protocol.Message, now time.Time) error {
	if s.desktop || s.nonce != "" || m.Connection != s.connection {
		return errors.New("unexpected accept")
	}
	p, body, err := s.local.checkPeer(m, "connect.accept", now)
	if err != nil {
		return err
	}
	if p.DeviceID != s.target || p.RemoteUserID() != s.owner || !protocol.ValidID(string(body)) {
		return errors.New("unexpected remote endpoint")
	}
	s.remote, s.nonce, s.received = p, string(body), m.Seq
	return nil
}

type negotiation struct {
	Nonce string          `json:"nonce"`
	Value json.RawMessage `json:"value"`
}

func (s *Session) validStep(kind string, round uint32, fromHost bool) bool {
	switch kind {
	case "rtc.offer":
		return !fromHost && round != 0 && round == s.round+1 && (s.round == 0 || s.answered)
	case "rtc.answer":
		return fromHost && round != 0 && round == s.round && !s.answered
	case "rtc.candidate":
		return round != 0 && round == s.round
	}
	return false
}
func (s *Session) advance(kind string, round uint32) {
	switch kind {
	case "rtc.offer":
		s.round, s.answered = round, false
	case "rtc.answer":
		s.answered = true
	}
}

func (s *Session) Seal(kind string, value json.RawMessage) (protocol.Message, error) {
	round := s.round
	if kind == "rtc.offer" {
		round++
	}
	if s.nonce == "" || !json.Valid(value) || !s.validStep(kind, round, s.desktop) {
		return protocol.Message{}, errors.New("invalid negotiation step")
	}
	s.advance(kind, round)
	return s.sign(kind, protocol.Encode(negotiation{s.nonce, value}))
}
func (s *Session) Open(m protocol.Message, now time.Time) (json.RawMessage, error) {
	if s.nonce == "" || !now.Before(s.remote.Expires) || !now.Before(s.local.principal.Expires) || m.Connection != s.connection || m.From != s.target || m.To != s.local.DeviceID() || m.Seq <= s.received || !s.validStep(m.Type, m.Round, !s.desktop) {
		return nil, errors.New("unexpected negotiation record")
	}
	body, err := m.Verify(s.remote.PublicKey)
	if err != nil {
		return nil, err
	}
	var v negotiation
	if json.Unmarshal(body, &v) != nil || v.Nonce != s.nonce || !json.Valid(v.Value) {
		return nil, errors.New("invalid negotiation binding")
	}
	s.received = m.Seq
	s.advance(m.Type, m.Round)
	return v.Value, nil
}

func (s *Session) Close() (protocol.Message, error) { return s.sign("connect.close", nil) }
