package cftunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/coder/websocket"

	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/strictjson"
	"vanora-relay/protocol"
)

var ErrTunnelUnavailable = errors.New("cftunnel: managed tunnel unavailable")

type SelfConnectOptions struct {
	SignalURL     string
	SelfToken     string
	PrivateKey    ed25519.PrivateKey
	HostDeviceID  string
	HostPublicKey ed25519.PublicKey
	Role          string
	Allows        func() bool
	Handler       transport.Handler
	DialURL       string
	HTTPClient    *http.Client
}

type OfficialConnectOptions struct {
	SignalURL     string
	Channel       string
	HostDeviceID  string
	HostPublicKey ed25519.PublicKey
	OwnerID       string
	Role          string
	CA            ed25519.PublicKey
	LeaseSource   transport.IdentitySource
	Allows        func() bool
	Handler       transport.Handler
	DialURL       string
	HTTPClient    *http.Client
}

type visitorSession struct {
	signalURL    string
	selfToken    string
	privateKey   ed25519.PrivateKey
	local        identity.Principal
	channel      string
	hostID       string
	hostKey      ed25519.PublicKey
	owner        string
	role         string
	ca           ed25519.PublicKey
	source       transport.IdentitySource
	allows       func() bool
	handler      transport.Handler
	dialURL      string
	httpClient   *http.Client
	credentials  *endpoint.Credentials
	proof        endpoint.LeaseProof
	domain       signalDomain
	connectionID string
	nonce        string
	ws           *websocket.Conn
	writeMu      sync.Mutex
}

func ConnectSelf(ctx context.Context, opts SelfConnectOptions) (transport.Peer, error) {
	peer, start, err := ConnectSelfDeferred(ctx, opts)
	if err == nil {
		start()
	}
	return peer, err
}

// ConnectSelfDeferred authenticates a paired self-hosted visitor before start.
func ConnectSelfDeferred(ctx context.Context, opts SelfConnectOptions) (transport.Peer, func(), error) {
	if !validPrivateKey(opts.PrivateKey) || !validSelfToken(opts.SelfToken) {
		return nil, nil, errors.New("cftunnel: invalid self-hosted visitor credentials")
	}
	host, err := identity.SelfDeviceID(opts.HostPublicKey)
	if err != nil || opts.HostDeviceID != "" && host != opts.HostDeviceID {
		return nil, nil, errors.New("cftunnel: invalid self-hosted host pin")
	}
	key := slices.Clone(opts.PrivateKey)
	pub := key.Public().(ed25519.PublicKey)
	device, _ := identity.SelfDeviceID(pub)
	session := &visitorSession{signalURL: opts.SignalURL, selfToken: opts.SelfToken, privateKey: key,
		local: identity.Principal{DeviceID: device, Subject: device, PublicKey: pub}, channel: "self",
		hostID: host, hostKey: slices.Clone(opts.HostPublicKey), owner: host, role: opts.Role,
		allows: opts.Allows, handler: opts.Handler, dialURL: opts.DialURL, httpClient: opts.HTTPClient}
	return session.connect(ctx)
}

func ConnectOfficial(ctx context.Context, opts OfficialConnectOptions) (transport.Peer, error) {
	peer, start, err := ConnectOfficialDeferred(ctx, opts)
	if err == nil {
		start()
	}
	return peer, err
}

// ConnectOfficialDeferred authenticates a paired official visitor before start.
func ConnectOfficialDeferred(ctx context.Context, opts OfficialConnectOptions) (transport.Peer, func(), error) {
	if (opts.Channel != "cn" && opts.Channel != "global") || len(opts.CA) != ed25519.PublicKeySize || opts.LeaseSource == nil {
		return nil, nil, errors.New("cftunnel: invalid official visitor configuration")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	session := &visitorSession{signalURL: opts.SignalURL, channel: opts.Channel, hostID: opts.HostDeviceID,
		hostKey: slices.Clone(opts.HostPublicKey), owner: opts.OwnerID, role: opts.Role, ca: slices.Clone(opts.CA),
		source: opts.LeaseSource, allows: opts.Allows, handler: opts.Handler, dialURL: opts.DialURL, httpClient: opts.HTTPClient}
	creds, proof, principal, err := session.current(ctx)
	if err != nil {
		return nil, nil, err
	}
	session.credentials, session.proof, session.local = creds, proof, principal
	session.privateKey = creds.PrivateKey()
	return session.connect(ctx)
}

func (s *visitorSession) current(ctx context.Context) (*endpoint.Credentials, endpoint.LeaseProof, identity.Principal, error) {
	creds, proof, err := s.source.Current(ctx)
	if err != nil || creds == nil || !s.ca.Equal(creds.CA()) || creds.Certificate() != proof.Certificate {
		return nil, endpoint.LeaseProof{}, identity.Principal{}, errors.New("cftunnel: visitor authority unavailable")
	}
	now := time.Now()
	p, err := identity.VerifyCertificate(proof.Certificate, s.ca, now)
	if err != nil || !p.Expires.After(now) || p.DeviceID != creds.DeviceID() || !p.PublicKey.Equal(creds.PublicKey()) ||
		proof.Lease == "" || !validPresentedLease(s.ca, proof.Certificate, proof.Lease, p, now) {
		return nil, endpoint.LeaseProof{}, identity.Principal{}, errors.New("cftunnel: visitor lease rejected")
	}
	if s.local.DeviceID != "" && (p.DeviceID != s.local.DeviceID || p.RemoteUserID() != s.local.RemoteUserID() ||
		!p.PublicKey.Equal(s.local.PublicKey)) {
		return nil, endpoint.LeaseProof{}, identity.Principal{}, transport.ErrIdentityChanged
	}
	return creds, proof, p, nil
}

func (s *visitorSession) connect(ctx context.Context) (transport.Peer, func(), error) {
	if _, err := ControlOriginFromSignalURL(s.signalURL); err != nil {
		return nil, nil, err
	}
	if s.role == "" {
		s.role = "mobile"
	}
	if !validRole(s.role) || !tunnelIdentifier.MatchString(s.hostID) || s.hostID == s.local.DeviceID ||
		len(s.hostKey) != ed25519.PublicKeySize || s.owner == "" {
		return nil, nil, errors.New("cftunnel: invalid visitor target")
	}
	if s.allows == nil {
		s.allows = func() bool { return true }
	}
	if !s.allows() {
		return nil, nil, transport.ErrUnauthorized
	}
	setup, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := s.login(setup); err != nil {
		return nil, nil, err
	}
	ready := false
	defer func() {
		if !ready {
			_ = s.ws.CloseNow()
		}
	}()
	s.connectionID, s.nonce = protocol.NewID(), protocol.NewID()
	body := connectBody{signalDomain: s.domain, ExpectedOwner: s.owner, TargetPinHash: KeyHash(s.hostKey),
		ClientNonce: s.nonce, Lease: s.proof.Lease}
	if s.role == "desktop" {
		body.Role = s.role
	}
	if err := s.signAndSend(setup, "tunnel.connect", 1, body); err != nil {
		return nil, nil, err
	}
	target, err := s.readTarget(setup)
	if err != nil {
		return nil, nil, err
	}
	options, err := s.targetOptions(target)
	if err != nil {
		return nil, nil, err
	}
	dialCtx, stop := context.WithDeadline(setup, options.AccessUntil)
	defer stop()
	conn, start, err := DialDeferred(dialCtx, options)
	if err != nil {
		return nil, nil, err
	}
	peer := conn.(*Peer)
	context.AfterFunc(peer.ctx, func() { _ = s.ws.CloseNow() })
	ready = true
	return peer, sync.OnceFunc(func() {
		if peer.ctx.Err() == nil {
			start()
			go s.maintain(peer, options.ConnectionContext)
		}
	}), nil
}

func (s *visitorSession) login(ctx context.Context) error {
	var client http.Client
	if s.httpClient != nil {
		client = *s.httpClient
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	headers := make(http.Header)
	if s.channel == "self" {
		headers.Set("Authorization", "Bearer "+s.selfToken)
	}
	ws, response, err := websocket.Dial(ctx, s.signalURL, &websocket.DialOptions{HTTPClient: &client, HTTPHeader: headers})
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		return errors.New("cftunnel: signaling connection failed")
	}
	ok := false
	defer func() {
		if !ok {
			_ = ws.CloseNow()
		}
	}()
	s.ws = ws
	ws.SetReadLimit(64 << 10)
	challenge, err := s.read(ctx)
	if err != nil || challenge.Type != "auth.challenge" || !protocol.ValidID(challenge.Connection) {
		return errors.New("cftunnel: invalid signaling challenge")
	}
	var login protocol.Message
	if s.channel == "self" {
		login = protocol.Message{Type: "auth.login", Connection: challenge.Connection, From: s.local.DeviceID, To: "signal"}
		err = login.Sign(s.privateKey, protocol.Encode(map[string]any{
			"role": s.role, "desktop": s.hostID, "public_key": base64.RawURLEncoding.EncodeToString(s.local.PublicKey),
			"tunnel": true,
		}))
	} else {
		login, err = s.credentials.LoginTunnelFor(challenge, s.role, s.proof.Lease, s.hostID)
	}
	if err != nil {
		return err
	}
	if err := s.write(ctx, login); err != nil {
		return err
	}
	reply, err := s.read(ctx)
	if websocket.CloseStatus(err) == websocket.StatusPolicyViolation {
		return transport.SignalError("device_unavailable")
	}
	var accepted struct {
		Device string `json:"device_id"`
		User   string `json:"remote_user_id,omitempty"`
		Mode   string `json:"mode,omitempty"`
		Scope  string `json:"tunnel_scope,omitempty"`
	}
	if err != nil || reply.Type != "auth.ok" || strictjson.Decode(reply.Data, &accepted) != nil ||
		accepted.Device != s.local.DeviceID {
		return errors.New("cftunnel: signaling authentication failed")
	}
	if s.channel == "self" && accepted.Mode != "self" ||
		s.channel != "self" && (accepted.Mode != "" || accepted.User != s.local.RemoteUserID()) {
		return errors.New("cftunnel: signaling identity mismatch")
	}
	if !tunnelIdentifier.MatchString(accepted.Scope) {
		return ErrTunnelUnavailable
	}
	s.domain = signalDomain{tunnelAudience, accepted.Scope}
	ok = true
	return nil
}

func (s *visitorSession) read(ctx context.Context) (protocol.Message, error) {
	var m protocol.Message
	kind, raw, err := s.ws.Read(ctx)
	if err != nil {
		return m, err
	}
	if kind != websocket.MessageText || strictjson.Decode(raw, &m) != nil {
		return m, transport.ErrMalformedResponse
	}
	return m, nil
}

func (s *visitorSession) write(ctx context.Context, m protocol.Message) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if s.ws.Write(ctx, websocket.MessageText, protocol.Encode(m)) != nil {
		return errors.New("cftunnel: signaling write failed")
	}
	return nil
}

func (s *visitorSession) signAndSend(ctx context.Context, kind string, seq uint64, body any) error {
	m := protocol.Message{Type: kind, Connection: s.connectionID, From: s.local.DeviceID, To: s.hostID, Seq: seq}
	if err := m.Sign(s.privateKey, protocol.Encode(body)); err != nil {
		return err
	}
	return s.write(ctx, m)
}

func (s *visitorSession) readTarget(ctx context.Context) (protocol.Message, error) {
	for {
		m, err := s.read(ctx)
		if err != nil {
			return m, err
		}
		if m.Connection != s.connectionID || !unsignedRelayMessage(m) {
			continue
		}
		switch m.Type {
		case "tunnel.target":
			return m, nil
		case "tunnel.close":
			return m, transport.SignalError("device_unavailable")
		case "error":
			if string(m.Data) == `"tunnel_released"` {
				return m, transport.SignalError("tunnel_released")
			}
			if string(m.Data) == `"tunnel_unavailable"` {
				return m, ErrTunnelUnavailable
			}
			return m, transport.SignalError("device_unavailable")
		}
	}
}

func (s *visitorSession) targetOptions(m protocol.Message) (DialOptions, error) {
	var target struct {
		Permit      protocol.Message `json:"permit"`
		EdgeTicket  string           `json:"edge_ticket"`
		AccessUntil time.Time        `json:"access_until"`
	}
	var body permitBody
	now := time.Now()
	if m.From != s.hostID || m.To != s.local.DeviceID || strictjson.Decode(m.Data, &target) != nil ||
		!endpointMessage(target.Permit, "tunnel.permit", s.connectionID, s.hostID, s.local.DeviceID) ||
		!readSigned(target.Permit, s.hostKey, &body) || !body.signalDomain.valid(s.domain.Scope) || !body.signalBinding.valid() ||
		!validHostname(body.Hostname) || !tunnelIdentifier.MatchString(body.JTI) || body.ClientNonce != s.nonce ||
		body.VisitorKeyHash != KeyHash(s.local.PublicKey) || body.Path != tunnelPath ||
		!body.ExpiresAt.After(now) || body.ExpiresAt.After(now.Add(20*time.Second)) {
		return DialOptions{}, errors.New("cftunnel: invalid signed host permit")
	}
	target.AccessUntil = boundedAccessUntil(target.AccessUntil, now)
	if target.AccessUntil.IsZero() {
		return DialOptions{}, errors.New("cftunnel: invalid signed host permit")
	}
	var remote identity.Principal
	var provider leaseProvider
	userID := base64.RawURLEncoding.EncodeToString(s.hostKey)
	if s.channel == "self" {
		if target.Permit.Certificate != "" || body.Lease != "" {
			return DialOptions{}, errors.New("cftunnel: unexpected host credentials on self relay")
		}
	} else {
		var err error
		cert := target.Permit.Certificate
		remote, err = identity.VerifyCertificate(cert, s.ca, now)
		if err != nil || remote.DeviceID != s.hostID || remote.Issuer != s.local.Issuer ||
			remote.RemoteUserID() != s.owner || !remote.PublicKey.Equal(s.hostKey) || !remote.Expires.After(now) ||
			!validPresentedLease(s.ca, cert, body.Lease, remote, now) {
			return DialOptions{}, errors.New("cftunnel: host certificate or lease rejected")
		}
		userID = remote.RemoteUserID()
		loginProof := s.proof
		provider = func(context.Context) (endpoint.LeaseProof, error) { return loginProof, nil }
	}
	return DialOptions{ConnectionContext: ConnectionContext{
		Channel: s.channel, Scope: s.domain.Scope, ConnectionID: s.connectionID, Hostname: body.Hostname,
		Generation: body.Generation, Incarnation: body.Incarnation, RuntimeID: body.RuntimeID, JTI: body.JTI,
		HostDeviceID: s.hostID, HostKeyHash: KeyHash(s.hostKey), VisitorDeviceID: s.local.DeviceID,
		VisitorKeyHash: body.VisitorKeyHash, VisitorRole: s.role,
	}, PrivateKey: s.privateKey, HostPublicKey: s.hostKey, UserID: userID,
		AccessUntil: target.AccessUntil, Allows: s.allows, Handler: s.handler, DialURL: s.dialURL,
		EdgeTicket: target.EdgeTicket, CA: s.ca, LocalPrincipal: s.local, RemotePrincipal: remote, LocalLeaseProvider: provider}, nil
}

func (s *visitorSession) maintain(peer *Peer, binding ConnectionContext) {
	go s.readUpdates(peer, binding)
	defer func() {
		peer.Close()
		_ = s.ws.CloseNow()
	}()
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	seq := uint64(1)
	for {
		select {
		case <-peer.ctx.Done():
			return
		case <-timer.C:
		}
		if s.channel != "self" {
			ctx, cancel := context.WithTimeout(peer.ctx, 8*time.Second)
			_, proof, _, err := s.current(ctx)
			cancel()
			if err != nil {
				peer.AuthorityLost()
				timer.Reset(20 * time.Second)
				continue
			}
			if err := s.write(peer.ctx, protocol.Message{Type: "auth.lease", Data: protocol.Encode(proof)}); err != nil {
				return
			}
			if err := peer.UpdateLocalLease(proof); err != nil {
				return
			}
		}
		seq++
		body := struct {
			signalDomain
			signalBinding
			JTI string `json:"jti"`
		}{s.domain, signalBinding{binding.Generation, binding.Incarnation, binding.RuntimeID}, binding.JTI}
		if err := s.signAndSend(peer.ctx, "tunnel.refresh", seq, body); err != nil {
			return
		}
		timer.Reset(20 * time.Second)
	}
}

func (s *visitorSession) readUpdates(peer *Peer, binding ConnectionContext) {
	defer peer.Close()
	for {
		m, err := s.read(peer.ctx)
		if err != nil {
			return
		}
		if m.Connection != binding.ConnectionID || !unsignedRelayMessage(m) || m.From != "" || m.To != "" {
			continue
		}
		switch m.Type {
		case "tunnel.close", "error":
			return
		case "tunnel.access":
			var access accessBody
			if strictjson.Decode(m.Data, &access) == nil && access.Generation == binding.Generation &&
				access.Incarnation == binding.Incarnation && access.RuntimeID == binding.RuntimeID &&
				access.JTI == binding.JTI {
				if until := boundedAccessUntil(access.AccessUntil, time.Now()); !until.IsZero() {
					peer.UpdateAccessUntil(until)
				}
			}
		}
	}
}
