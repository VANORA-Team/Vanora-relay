package selfrelay

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"vanora-relay/adapter/transport"
	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

type serverState struct {
	Key     string                `json:"key"`
	Clients map[string]ClientInfo `json:"clients"`
}

type runningConn struct {
	signalURL  string
	relayToken string
	name       string
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
}

// Server owns the desktop's self-hosted Ed25519 key, one-time pairing
// invitations, paired device allowlist, and active self-hosted relay session.
type Server struct {
	mu       sync.Mutex
	store    Store
	handler  transport.Handler
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	pin      string
	deviceID string
	state    serverState

	running     *runningConn
	online      bool
	lastErr     string
	observer    func(online bool, err string)
	invitations map[string]Invitation
	links       map[string]*peerLink
	clientLinks map[string]map[*peerLink]struct{}
}

// OpenServer opens or initializes persisted self-hosted pairing state in store.
func OpenServer(store Store, handler transport.Handler) (*Server, error) {
	if store == nil || handler == nil {
		return nil, errors.New("selfrelay: secure storage and a connection handler are required")
	}
	raw, err := store.Load()
	if err != nil {
		return nil, err
	}
	state := serverState{Clients: make(map[string]ClientInfo)}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &state); err != nil {
			return nil, err
		}
		if state.Clients == nil || len(state.Clients) > maxClients {
			return nil, errors.New("selfrelay: invalid stored clients")
		}
		for id, client := range state.Clients {
			pub, err := parsePublicKeyB64(client.PublicKey)
			if err != nil || id != client.ID || id != fingerprint(pub) || Access(userID(client)) == "" || !validName(client.Name) {
				return nil, errors.New("selfrelay: invalid stored client")
			}
		}
	} else {
		state.Key, err = newSeed()
		if err != nil {
			return nil, err
		}
		if err := saveState(store, state); err != nil {
			return nil, err
		}
	}
	priv, pub, pin, devID, err := parseKeySeed(state.Key)
	if err != nil {
		return nil, err
	}
	return &Server{
		store:       store,
		handler:     handler,
		priv:        priv,
		pub:         pub,
		pin:         pin,
		deviceID:    devID,
		state:       state,
		invitations: make(map[string]Invitation),
		links:       make(map[string]*peerLink),
		clientLinks: make(map[string]map[*peerLink]struct{}),
	}, nil
}

func saveState(store Store, state serverState) error {
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return store.Save(string(b))
}

func (s *Server) DeviceID() string { return s.deviceID }
func (s *Server) Pin() string      { return s.pin }

// SetObserver registers an optional callback invoked when the self-hosted
// signaling connection transitions between online and offline.
func (s *Server) SetObserver(fn func(online bool, err string)) {
	s.mu.Lock()
	s.observer = fn
	s.mu.Unlock()
}

// Connect starts maintaining a desktop presence on the configured self-hosted
// relay. Call Stop before changing the signaling URL or relay token.
func (s *Server) Connect(ctx context.Context, rawSignalURL, relayToken, desktopName string) error {
	signalURL, err := normalizeSignalURL(rawSignalURL)
	if err != nil {
		return err
	}
	if err := ValidateRelayToken(relayToken); err != nil {
		return err
	}
	name := strings.TrimSpace(desktopName)
	if !validName(name) {
		return errors.New("selfrelay: invalid desktop name")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running != nil {
		return errors.New("selfrelay: stop the self-hosted relay before changing its configuration")
	}
	runCtx, cancel := context.WithCancel(ctx)
	entry := &runningConn{
		signalURL:  signalURL,
		relayToken: relayToken,
		name:       name,
		ctx:        runCtx,
		cancel:     cancel,
		done:       make(chan struct{}),
	}
	s.running = entry
	s.online = false
	s.lastErr = ""
	go s.runLoop(entry)
	return nil
}

// Stop disconnects the self-hosted relay and all active self-hosted peers while
// preserving paired devices in secure storage.
func (s *Server) Stop() {
	s.mu.Lock()
	entry := s.running
	if entry == nil {
		s.mu.Unlock()
		return
	}
	s.running = nil
	wasOnline := s.online
	s.online = false
	s.lastErr = ""
	clear(s.invitations)
	links := make([]*peerLink, 0, len(s.links))
	for _, l := range s.links {
		links = append(links, l)
	}
	s.links = make(map[string]*peerLink)
	s.clientLinks = make(map[string]map[*peerLink]struct{})
	obs := s.observer
	entry.cancel()
	s.mu.Unlock()

	for _, l := range links {
		l.close(transport.ErrClosed, true)
	}
	<-entry.done
	if wasOnline && obs != nil {
		obs(false, "")
	}
}

// Allows reports whether user is a currently authorized paired self-hosted
// mobile device and the self-hosted channel is enabled.
func (s *Server) Allows(user string) bool {
	if Access(user) == "" {
		return false
	}
	id := user[strings.LastIndex(user, ":")+1:]
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.state.Clients[id]
	return s.running != nil && s.running.ctx.Err() == nil && ok && userID(client) == user
}

// Status returns a snapshot of the self-hosted relay channel, paired clients,
// and active one-time invitations.
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		DeviceID:    s.deviceID,
		Online:      s.online,
		Error:       s.lastErr,
		Clients:     make([]ClientInfo, 0, len(s.state.Clients)),
		Invitations: make([]Invitation, 0, len(s.invitations)),
	}
	if s.running != nil && s.running.ctx.Err() == nil {
		st.Enabled = true
		st.SignalURL = s.running.signalURL
	}
	for id, client := range s.state.Clients {
		active := false
		for l := range s.clientLinks[id] {
			if !l.closed.Load() {
				active = true
				break
			}
		}
		client.Connected = active
		st.Clients = append(st.Clients, client)
	}
	s.pruneInvitationsLocked(time.Now())
	for _, inv := range s.invitations {
		st.Invitations = append(st.Invitations, inv)
	}
	slices.SortFunc(st.Clients, func(a, b ClientInfo) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(st.Invitations, func(a, b Invitation) int { return a.ExpiresAt.Compare(b.ExpiresAt) })
	return st
}

// Invite creates a 5-minute, one-time pairing invitation and returns its
// pairing link. When includeToken is true, the relay bearer token is embedded
// in the URL fragment for one-scan pairing.
func (s *Server) Invite(access string, includeToken bool) (Invitation, string, error) {
	if access != Read && access != Control {
		return Invitation{}, "", errors.New("selfrelay: access must be read or control")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == nil || s.running.ctx.Err() != nil {
		return Invitation{}, "", errors.New("selfrelay: self-hosted relay is disabled")
	}
	now := time.Now()
	s.pruneInvitationsLocked(now)
	if len(s.invitations) >= maxInvites || len(s.state.Clients) >= maxClients {
		return Invitation{}, "", errors.New("selfrelay: pairing limit reached")
	}
	pairToken, err := newSeed()
	if err != nil {
		return Invitation{}, "", err
	}
	invID, err := newSeed()
	if err != nil {
		return Invitation{}, "", err
	}
	inv := Invitation{ID: invID, Access: access, ExpiresAt: now.Add(inviteTTL)}
	s.invitations[pairToken] = inv
	target := Target{
		SignalURL: s.running.signalURL,
		Pin:       s.pin,
		Pair:      pairToken,
	}
	if includeToken {
		target.Token = s.running.relayToken
	}
	return inv, target.Link(), nil
}

// RevokeInvitation cancels a pending one-time invitation by ID.
func (s *Server) RevokeInvitation(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, inv := range s.invitations {
		if inv.ID == id {
			delete(s.invitations, tok)
			return true
		}
	}
	return false
}

// RevokeClients removes one paired device (by client ID) or all paired devices
// and invitations (when id == ""), immediately closing active peers and
// notifying the relay to revoke TURN allocations.
func (s *Server) RevokeClients(id string) error {
	s.mu.Lock()
	clients := make(map[string]ClientInfo, len(s.state.Clients))
	for clientID, client := range s.state.Clients {
		if id != "" && id != clientID {
			clients[clientID] = client
		}
	}
	if id != "" && len(clients) == len(s.state.Clients) {
		s.mu.Unlock()
		return errors.New("selfrelay: unknown client")
	}
	next := serverState{Key: s.state.Key, Clients: clients}
	if err := saveState(s.store, next); err != nil {
		s.mu.Unlock()
		return err
	}
	s.state = next
	if id == "" {
		clear(s.invitations)
	}
	var revoked []*peerLink
	for clientID, set := range s.clientLinks {
		if _, allowed := clients[clientID]; !allowed {
			for l := range set {
				revoked = append(revoked, l)
				delete(s.links, l.id)
			}
			delete(s.clientLinks, clientID)
		}
	}
	s.mu.Unlock()

	for _, l := range revoked {
		l.close(ErrUnpaired, true)
	}
	return nil
}

func (s *Server) pruneInvitationsLocked(now time.Time) {
	for tok, inv := range s.invitations {
		if !now.Before(inv.ExpiresAt) {
			delete(s.invitations, tok)
		}
	}
}

func (s *Server) setOnline(entry *runningConn, online bool, reason string) {
	s.mu.Lock()
	if s.running != entry {
		s.mu.Unlock()
		return
	}
	changed := s.online != online || (reason != "" && reason != s.lastErr)
	s.online = online
	s.lastErr = reason
	obs := s.observer
	s.mu.Unlock()
	if changed && obs != nil {
		obs(online, reason)
	}
}

func (s *Server) runLoop(entry *runningConn) {
	defer close(entry.done)
	for delay := time.Second; entry.ctx.Err() == nil; {
		err := s.runOnce(entry)
		if entry.ctx.Err() != nil {
			return
		}
		reason := ""
		if err != nil {
			reason = err.Error()
		}
		s.setOnline(entry, false, reason)
		timer := time.NewTimer(delay)
		select {
		case <-entry.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			delay = min(delay*2, 10*time.Second)
		}
	}
}

func (s *Server) runOnce(entry *runningConn) error {
	ws, err := dialSignal(entry.ctx, entry.signalURL, entry.relayToken, "desktop", s.priv, s.pub, s.deviceID)
	if err != nil {
		return err
	}
	defer ws.CloseNow()

	var writeMu sync.Mutex
	send := func(m protocol.Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeSignal(entry.ctx, ws, m)
	}

	card := protocol.Message{Type: "device.card", From: s.deviceID, To: "self"}
	if err := card.Sign(s.priv, []byte(entry.name)); err != nil {
		return err
	}
	if err := send(protocol.Message{
		Type: "device.online",
		Data: protocol.Encode(struct {
			Card protocol.Message `json:"card"`
		}{Card: card}),
	}); err != nil {
		return err
	}
	reg, err := readSignal(entry.ctx, ws)
	if err != nil {
		return err
	}
	if reg.Type != "device.registered" {
		return parseErrf("unexpected register reply %s", reg.Type)
	}
	s.setOnline(entry, true, "")

	sessionCtx, sessionCancel := context.WithCancel(entry.ctx)
	defer func() {
		sessionCancel()
		s.closeAllLinks()
	}()

	for {
		m, err := readSignal(sessionCtx, ws)
		if err != nil {
			return err
		}
		switch m.Type {
		case "connect.request":
			go s.handleConnectRequest(sessionCtx, entry, send, m)
		case "ice.config":
			if l := s.getLink(m.Connection); l != nil {
				var servers []iceServer
				if json.Unmarshal(m.Data, &servers) == nil {
					l.setICE(servers)
				} else {
					l.close(errors.New("selfrelay: invalid ice.config"), false)
				}
			}
		case "connect.closed", "rtc.offer", "rtc.answer", "rtc.candidate", "error":
			if l := s.getLink(m.Connection); l != nil {
				l.route(m)
			}
		}
	}
}

func (s *Server) closeAllLinks() {
	s.mu.Lock()
	links := make([]*peerLink, 0, len(s.links))
	for _, l := range s.links {
		links = append(links, l)
	}
	s.links = make(map[string]*peerLink)
	s.clientLinks = make(map[string]map[*peerLink]struct{})
	s.mu.Unlock()
	for _, l := range links {
		l.close(transport.ErrClosed, false)
	}
}

func (s *Server) getLink(connID string) *peerLink {
	if !protocol.ValidID(connID) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.links[connID]
}

func (s *Server) removeLink(clientID string, l *peerLink) {
	s.mu.Lock()
	if s.links[l.id] == l {
		delete(s.links, l.id)
	}
	if set := s.clientLinks[clientID]; set != nil {
		delete(set, l)
		if len(set) == 0 {
			delete(s.clientLinks, clientID)
		}
	}
	s.mu.Unlock()
}

func (s *Server) rejectRequest(send func(protocol.Message) error, m protocol.Message) {
	if !protocol.ValidID(m.Connection) || !identity.ValidSelfDeviceID(m.From) {
		return
	}
	closeMsg := protocol.Message{
		Type:       "connect.close",
		Connection: m.Connection,
		From:       s.deviceID,
		To:         m.From,
		Seq:        1,
	}
	if closeMsg.Sign(s.priv, nil) == nil {
		_ = send(closeMsg)
	}
}

func (s *Server) handleConnectRequest(ctx context.Context, entry *runningConn, send func(protocol.Message) error, m protocol.Message) {
	if m.Type != "connect.request" || !protocol.ValidID(m.Connection) || m.To != s.deviceID || m.Round != 0 || m.Seq != 1 || m.Certificate != "" {
		s.rejectRequest(send, m)
		return
	}
	rawBody, err := base64.RawURLEncoding.Strict().DecodeString(m.Body)
	if err != nil {
		s.rejectRequest(send, m)
		return
	}
	var req connectRequestBody
	if json.Unmarshal(rawBody, &req) != nil || !validName(req.Name) {
		s.rejectRequest(send, m)
		return
	}
	mobilePub, err := parsePublicKeyB64(req.PublicKey)
	if err != nil {
		s.rejectRequest(send, m)
		return
	}
	mobileDevID, err := identity.SelfDeviceID(mobilePub)
	if err != nil || mobileDevID != m.From {
		s.rejectRequest(send, m)
		return
	}
	if _, err := m.Verify(mobilePub); err != nil {
		s.rejectRequest(send, m)
		return
	}

	client, ok := s.authorizePeer(entry, m.Connection, mobilePub, req.PublicKey, req.Name, req.PairProof)
	if !ok {
		s.rejectRequest(send, m)
		return
	}

	sess := &selfSession{
		connID:    m.Connection,
		nonce:     protocol.NewID(),
		localID:   s.deviceID,
		remoteID:  mobileDevID,
		localKey:  s.priv,
		remotePub: mobilePub,
		desktop:   true,
		received:  m.Seq,
	}
	reply, err := sess.sign("connect.accept", protocol.Encode(connectAcceptBody{
		Nonce:     sess.nonce,
		PublicKey: s.pin,
	}))
	if err != nil {
		s.rejectRequest(send, m)
		return
	}

	uid := userID(client)
	clientID := client.ID
	l := newPeerLink(
		ctx,
		sess,
		uid,
		true,
		true,
		false,
		func() bool { return s.Allows(uid) },
		send,
		func(closed *peerLink) { s.removeLink(clientID, closed) },
		s.handler,
	)

	s.mu.Lock()
	if s.running != entry || entry.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	s.links[l.id] = l
	if s.clientLinks[clientID] == nil {
		s.clientLinks[clientID] = make(map[*peerLink]struct{})
	}
	s.clientLinks[clientID][l] = struct{}{}
	s.mu.Unlock()

	go l.run()
	if err := send(reply); err != nil {
		l.close(err, false)
	}
}

func (s *Server) authorizePeer(entry *runningConn, connID string, mobilePub ed25519.PublicKey, mobilePubB64, name, pairProofB64 string) (ClientInfo, bool) {
	fp := fingerprint(mobilePub)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running != entry || entry.ctx.Err() != nil {
		return ClientInfo{}, false
	}
	if client, ok := s.state.Clients[fp]; ok {
		return client, true
	}
	if pairProofB64 == "" || len(s.state.Clients) >= maxClients {
		return ClientInfo{}, false
	}
	presentedProof, err := base64.RawURLEncoding.Strict().DecodeString(pairProofB64)
	if err != nil || len(presentedProof) != 32 {
		return ClientInfo{}, false
	}
	now := time.Now()
	s.pruneInvitationsLocked(now)
	var (
		matchedToken string
		matchedInv   Invitation
		found        bool
	)
	for tok, inv := range s.invitations {
		rawTok, err := base64.RawURLEncoding.Strict().DecodeString(tok)
		if err != nil {
			continue
		}
		expected, err := identity.SelfPairProof(rawTok, connID, mobilePub, s.pub)
		if err != nil {
			continue
		}
		if hmac.Equal(expected, presentedProof) {
			matchedToken = tok
			matchedInv = inv
			found = true
			break
		}
	}
	if !found {
		return ClientInfo{}, false
	}
	client := ClientInfo{
		ID:        fp,
		PublicKey: mobilePubB64,
		Name:      name,
		Access:    matchedInv.Access,
		PairedAt:  now.UTC(),
	}
	s.state.Clients[fp] = client
	if err := saveState(s.store, s.state); err != nil {
		delete(s.state.Clients, fp)
		return ClientInfo{}, false
	}
	delete(s.invitations, matchedToken)
	return client, true
}
