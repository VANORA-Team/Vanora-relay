// Package endpoint authenticates WebRTC negotiation before native clients hand
// the SDP or ICE candidates to their WebRTC implementation. A Session belongs
// to one connection, and callers serialize its methods on the signaling loop.
package endpoint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
func (c *Credentials) DeviceID() string             { return c.principal.DeviceID }
func (c *Credentials) UserID() string               { return c.principal.RemoteUserID() }
func (c *Credentials) PublicKey() ed25519.PublicKey { return c.key.Public().(ed25519.PublicKey) }

// Certificate returns the signed certificate string this endpoint presents.
func (c *Credentials) Certificate() string { return c.cert }

// CA returns the authority public key these credentials were opened against.
func (c *Credentials) CA() ed25519.PublicKey { return c.ca }
func (c *Credentials) Login(challenge protocol.Message, role, lease string) (protocol.Message, error) {
	return c.LoginFor(challenge, role, lease, "")
}

func (c *Credentials) LoginFor(challenge protocol.Message, role, lease, desktop string) (protocol.Message, error) {
	if challenge.Type != "auth.challenge" || !protocol.ValidID(challenge.Connection) || (role != "desktop" && role != "mobile") {
		return protocol.Message{}, errors.New("invalid login challenge or role")
	}
	m := protocol.Message{Type: "auth.login", Connection: challenge.Connection, From: c.DeviceID(), To: "signal", Certificate: c.cert}
	fields := map[string]string{"role": role, "lease": lease}
	if desktop != "" {
		fields["desktop"] = desktop
	}
	err := m.Sign(c.key, protocol.Encode(fields))
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
	pin                              ed25519.PublicKey
}

func (s *Session) ID() string                          { return s.connection }
func (s *Session) RemoteUserID() string                { return s.remote.RemoteUserID() }
func (s *Session) RemotePrincipal() identity.Principal { return s.remote }

func (s *Session) sign(kind string, body []byte) (protocol.Message, error) {
	m := protocol.Message{Type: kind, Connection: s.connection, From: s.local.DeviceID(), To: s.target, Round: s.round, Seq: s.sent + 1}
	err := m.Sign(s.local.key, body)
	if err == nil {
		s.sent++
	}
	return m, err
}

// ConnectRequestMeta carries optional caller role and display name inside an
// endpoint-signed connect.request body.
type ConnectRequestMeta struct {
	Role string `json:"role,omitempty"`
	Name string `json:"name,omitempty"`
}

type connectRequestEnvelope struct {
	Role  string `json:"role,omitempty"`
	Name  string `json:"name,omitempty"`
	Proof string `json:"proof,omitempty"`
}

// Request pins the selected machine and its owner. Obtain both identifiers from
// a trusted binding or invitation, independently of the signaling directory.
func (c *Credentials) Request(device, owner string) (*Session, protocol.Message, error) {
	return c.RequestPaired(device, owner, nil, nil)
}

func (c *Credentials) RequestPaired(device, owner string, pin ed25519.PublicKey, token []byte) (*Session, protocol.Message, error) {
	return c.RequestPairedWithMeta(device, owner, pin, token, ConnectRequestMeta{})
}

func (c *Credentials) RequestPairedWithMeta(device, owner string, pin ed25519.PublicKey, token []byte, meta ConnectRequestMeta) (*Session, protocol.Message, error) {
	if device == "" || owner == "" {
		return nil, protocol.Message{}, errors.New("expected device and owner required")
	}
	if device == c.DeviceID() {
		return nil, protocol.Message{}, errors.New("cannot connect to self")
	}
	s := &Session{local: c, target: device, owner: owner, pin: pin, connection: protocol.NewID()}
	var proof []byte
	if len(token) != 0 {
		var err error
		proof, err = identity.SelfPairProof(token, s.connection, c.principal.PublicKey, pin)
		if err != nil {
			return nil, protocol.Message{}, err
		}
	}
	body := proof
	if meta.Role != "" || meta.Name != "" {
		role := meta.Role
		if role == "" {
			role = "mobile"
		}
		if role != "mobile" && role != "desktop" {
			return nil, protocol.Message{}, errors.New("invalid connect request role")
		}
		name := strings.TrimSpace(meta.Name)
		if name != "" && !validPeerName(name) {
			return nil, protocol.Message{}, errors.New("invalid connect request name")
		}
		env := connectRequestEnvelope{Role: role, Name: name}
		if len(proof) != 0 {
			env.Proof = base64.RawURLEncoding.EncodeToString(proof)
		}
		body = protocol.Encode(env)
	}
	m, err := s.sign("connect.request", body)
	return s, m, err
}

func parseConnectRequestBody(body []byte) (role, name string, proof []byte, err error) {
	if len(body) == 0 {
		return "mobile", "", nil, nil
	}
	if body[0] == '{' {
		var env connectRequestEnvelope
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if decErr := dec.Decode(&env); decErr == nil {
			var extra any
			if errors.Is(dec.Decode(&extra), io.EOF) && (env.Role == "mobile" || env.Role == "desktop") {
				if env.Name != "" && !validPeerName(env.Name) {
					return "", "", nil, errors.New("invalid connect request name")
				}
				if env.Proof != "" {
					p, decProofErr := base64.RawURLEncoding.Strict().DecodeString(env.Proof)
					if decProofErr != nil || len(p) != sha256.Size {
						return "", "", nil, errors.New("invalid pairing proof")
					}
					proof = p
				}
				return env.Role, env.Name, proof, nil
			}
		}
	}
	if len(body) == sha256.Size {
		return "mobile", "", body, nil
	}
	return "", "", nil, errors.New("invalid connect request body")
}

func validPeerName(name string) bool {
	return len(name) > 0 && len(name) <= 128 && utf8.ValidString(name) &&
		strings.TrimSpace(name) == name && !strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf)
	})
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
	return c.AcceptPaired(m, allows, nil, now)
}

type PeerIdentity = identity.Principal

type PairAuthorizer func(connection string, mobile PeerIdentity, proof []byte) bool

type PairRoleAuthorizer func(connection string, peer PeerIdentity, role, name string, proof []byte) bool

func (c *Credentials) AcceptPaired(m protocol.Message, allows func(string) bool, paired PairAuthorizer, now time.Time) (*Session, protocol.Message, error) {
	var fn PairRoleAuthorizer
	if paired != nil {
		fn = func(connection string, peer PeerIdentity, _, _ string, proof []byte) bool {
			return paired(connection, peer, proof)
		}
	}
	return c.AcceptPairedWithRole(m, allows, fn, now)
}

func (c *Credentials) AcceptPairedWithRole(m protocol.Message, allows func(string) bool, paired PairRoleAuthorizer, now time.Time) (*Session, protocol.Message, error) {
	p, body, err := c.checkPeer(m, "connect.request", now)
	if err != nil {
		return nil, protocol.Message{}, err
	}
	if p.DeviceID == c.DeviceID() {
		return nil, protocol.Message{}, errors.New("cannot connect to self")
	}
	role, name, proof, err := parseConnectRequestBody(body)
	if err != nil {
		return nil, protocol.Message{}, errors.New("access denied")
	}
	if allows == nil || !allows(p.RemoteUserID()) || (len(proof) != 0 && paired == nil) {
		return nil, protocol.Message{}, errors.New("access denied")
	}
	s := &Session{local: c, remote: p, target: p.DeviceID, owner: p.RemoteUserID(), connection: m.Connection, nonce: protocol.NewID(), desktop: true, received: m.Seq}
	if paired != nil && !paired(m.Connection, p, role, name, proof) {
		denied, _ := s.Close()
		return nil, denied, errors.New("pairing required")
	}
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
	if p.DeviceID != s.target || p.RemoteUserID() != s.owner || (s.pin != nil && !s.pin.Equal(p.PublicKey)) || !protocol.ValidID(string(body)) {
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
