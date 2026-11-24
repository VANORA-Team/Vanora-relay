package selfrelay

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"vanora-relay/adapter/transport"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/pairnet"
	"vanora-relay/protocol"
)

type serverState struct {
	Key     string                           `json:"key"`
	Clients map[string]ClientInfo            `json:"clients"`
	Service string                           `json:"service,omitempty"`
	Other   map[string]map[string]ClientInfo `json:"other_relays,omitempty"`
}

type runningConn struct {
	signalURL  string
	relayToken string
	name       string
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	seenConns  map[string]struct{}
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
	pairTicket  string
	observer    func(online bool, err string)
	netObserver func()
	invitations map[string]Invitation
	retire      map[string]func()
	links       map[string]*peerLink
	clientLinks map[string]map[*peerLink]struct{}
	db          *pairnet.Database
	group       *pairnet.Group
	network     *transport.NetworkHandler
}

// OpenServer opens or initializes persisted self-hosted pairing state in store.
func OpenServer(store Store, handler transport.Handler) (*Server, error) {
	if store == nil || handler == nil {
		return nil, errors.New("selfrelay: secure storage and a connection handler are required")
	}
	db, err := pairnet.Open(store)
	if err != nil {
		return nil, err
	}
	store = db
	raw, err := store.Load()
	if err != nil {
		return nil, err
	}
	state := serverState{Clients: make(map[string]ClientInfo)}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &state); err != nil {
			return nil, err
		}
		all := append([]map[string]ClientInfo{state.Clients}, slices.Collect(maps.Values(state.Other))...)
		for _, clients := range all {
			if clients == nil || len(clients) > maxClients {
				return nil, errors.New("selfrelay: invalid stored clients")
			}
			for id, client := range clients {
				pub, err := parsePublicKeyB64(client.PublicKey)
				validID := err == nil && (id == fingerprint(pub) || (client.Role == "desktop" && id == client.PublicKey))
				if err != nil || id != client.ID || !validID || Access(userID(client)) == "" || !validName(client.Name) {
					return nil, errors.New("selfrelay: invalid stored client")
				}
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
	s := &Server{
		db:          db,
		store:       store,
		handler:     handler,
		priv:        priv,
		pub:         pub,
		pin:         pin,
		deviceID:    devID,
		state:       state,
		invitations: make(map[string]Invitation),
		retire:      make(map[string]func()),
		links:       make(map[string]*peerLink),
		clientLinks: make(map[string]map[*peerLink]struct{}),
	}
	if state.Service != "" {
		s.group = db.Group(state.Service, pin)
	}
	s.network = &transport.NetworkHandler{Handler: handler, Group: s.Network, Device: func(p transport.Peer) string {
		user := p.UserID()
		return user[strings.LastIndex(user, ":")+1:]
	}, Changed: s.closeRemoved}
	s.handler = s.network
	return s, nil
}

func (s *Server) Network() *pairnet.Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.group
}

// Seed returns the desktop's persisted self-hosted Ed25519 key seed so
// outbound PC-to-PC connections reuse the exact same endpoint identity.
func (s *Server) Seed() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Key
}

// Profile returns the persisted self-hosted relay profile (last service URL,
// relay bearer token, and device name) stored inside the encrypted self vault.
func (s *Server) Profile() pairnet.Profile {
	return s.db.Profile()
}

// SetProfile updates the persisted self-hosted relay profile in the encrypted
// self vault so outbound desktop connections can reconnect after restart.
func (s *Server) SetProfile(profile pairnet.Profile) error {
	return s.db.SetProfile(profile)
}

// GroupFor returns the pairing network group and local desktop member identity
// scoped to rawSignalURL.
func (s *Server) GroupFor(rawSignalURL, name string) (*pairnet.Group, pairnet.Member, error) {
	signalURL, err := NormalizeSignalURL(rawSignalURL)
	if err != nil {
		return nil, pairnet.Member{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" && s.running != nil {
		name = s.running.name
	}
	return s.db.Group(signalURL, s.pin), pairnet.Member{
		ID:   s.pin,
		Pin:  s.pin,
		Role: "desktop",
		Name: strings.TrimSpace(name),
	}, nil
}

// BroadcastNetwork pushes the current pairing network snapshot to all
// subscribed inbound peers and runs local revocation cleanup.
func (s *Server) BroadcastNetwork() {
	s.network.Broadcast()
}

// SetNetworkObserver registers an optional callback triggered whenever the
// self-hosted pairing network changes.
func (s *Server) SetNetworkObserver(fn func()) {
	s.mu.Lock()
	s.netObserver = fn
	s.mu.Unlock()
}

// SetClientAccess updates the local inbound access level ("read" or "control")
// for an active member of the current self-hosted pairing network.
func (s *Server) SetClientAccess(id, access string) error {
	if access != Read && access != Control {
		return errors.New("selfrelay: access must be read or control")
	}
	s.mu.Lock()
	if s.group == nil {
		s.mu.Unlock()
		return errors.New("selfrelay: self-hosted relay is disabled")
	}
	member, known := s.group.Get(id)
	if !known || id == s.pin || (member.Role != "mobile" && member.Role != "desktop") || !s.group.Allows(id) {
		s.mu.Unlock()
		return errors.New("selfrelay: unknown active network member")
	}
	local, _ := s.group.Get(s.pin)
	prev, hadPrev := s.state.Clients[id]
	pairedAt := time.Now().UTC()
	name := member.Name
	if hadPrev {
		if !prev.PairedAt.IsZero() {
			pairedAt = prev.PairedAt
		}
		if name == "" {
			name = prev.Name
		}
	}
	if !validName(name) {
		name = "Peer"
	}
	next := s.state
	next.Clients = maps.Clone(next.Clients)
	if next.Clients == nil {
		next.Clients = make(map[string]ClientInfo)
	}
	next.Clients[id] = ClientInfo{
		ID:         id,
		PublicKey:  member.Pin,
		Name:       name,
		Role:       member.Role,
		Access:     access,
		PairedAt:   pairedAt,
		Epoch:      member.Epoch,
		LocalEpoch: local.Epoch,
	}
	if err := saveState(s.store, next); err != nil {
		s.mu.Unlock()
		return err
	}
	s.state = next
	var closed []*peerLink
	for l := range s.clientLinks[id] {
		closed = append(closed, l)
		delete(s.links, l.id)
	}
	delete(s.clientLinks, id)
	s.mu.Unlock()
	for _, l := range closed {
		l.close(transport.ErrPeerClosed, true)
	}
	if service, ok := s.network.Handler.(interface{ RefreshSelfAccess() }); ok {
		service.RefreshSelfAccess()
	}
	return nil
}

// SetPeerAccessFor persists the local inbound access level for a paired member
// on a specific self-hosted relay URL (whether or not it is currently active).
func (s *Server) SetPeerAccessFor(rawSignalURL, id, access string) error {
	if access != Read && access != Control {
		return errors.New("selfrelay: access must be read or control")
	}
	signalURL, err := NormalizeSignalURL(rawSignalURL)
	if err != nil {
		return err
	}
	s.mu.Lock()
	group := s.db.Group(signalURL, s.pin)
	member, known := group.Get(id)
	if !known || id == s.pin || (member.Role != "mobile" && member.Role != "desktop") || !group.Allows(id) {
		s.mu.Unlock()
		return errors.New("selfrelay: unknown active network member")
	}
	local, _ := group.Get(s.pin)
	next := s.state
	var targetMap map[string]ClientInfo
	activeService := next.Service == "" || next.Service == signalURL
	if activeService {
		if next.Service == "" {
			next.Service = signalURL
		}
		targetMap = maps.Clone(next.Clients)
		if targetMap == nil {
			targetMap = make(map[string]ClientInfo)
		}
		next.Clients = targetMap
	} else {
		next.Other = maps.Clone(next.Other)
		if next.Other == nil {
			next.Other = make(map[string]map[string]ClientInfo)
		}
		targetMap = maps.Clone(next.Other[signalURL])
		if targetMap == nil {
			targetMap = make(map[string]ClientInfo)
		}
		next.Other[signalURL] = targetMap
	}
	prev, hadPrev := targetMap[id]
	pairedAt := time.Now().UTC()
	name := member.Name
	if hadPrev {
		if !prev.PairedAt.IsZero() {
			pairedAt = prev.PairedAt
		}
		if name == "" {
			name = prev.Name
		}
	}
	if !validName(name) {
		name = "Peer"
	}
	targetMap[id] = ClientInfo{
		ID:         id,
		PublicKey:  member.Pin,
		Name:       name,
		Role:       member.Role,
		Access:     access,
		PairedAt:   pairedAt,
		Epoch:      member.Epoch,
		LocalEpoch: local.Epoch,
	}
	if err := saveState(s.store, next); err != nil {
		s.mu.Unlock()
		return err
	}
	s.state = next
	if activeService && s.group == nil {
		s.group = group
	}
	var closed []*peerLink
	if activeService {
		for l := range s.clientLinks[id] {
			closed = append(closed, l)
			delete(s.links, l.id)
		}
		delete(s.clientLinks, id)
	}
	s.mu.Unlock()
	for _, l := range closed {
		l.close(transport.ErrPeerClosed, true)
	}
	if activeService {
		if service, ok := s.network.Handler.(interface{ RefreshSelfAccess() }); ok {
			service.RefreshSelfAccess()
		}
	}
	return nil
}

func (s *Server) RemoveDevice(id string) error {
	g := s.Network()
	if g == nil {
		return errors.New("self-hosted relay is disabled")
	}
	if err := g.Remove(id); err != nil {
		return err
	}
	s.network.Broadcast()
	return nil
}

func (s *Server) closeRemoved() {
	s.mu.Lock()
	if s.group != nil {
		next := s.state
		next.Clients = maps.Clone(next.Clients)
		maps.DeleteFunc(next.Clients, func(id string, client ClientInfo) bool {
			return s.group.GrantExpired(id, client.LocalEpoch, client.Epoch)
		})
		if len(next.Clients) < len(s.state.Clients) && saveState(s.store, next) == nil {
			s.state = next
		}
	}
	var closed []*peerLink
	for id, links := range s.clientLinks {
		if s.group != nil && !s.group.Allows(id) {
			for l := range links {
				closed = append(closed, l)
			}
		}
	}
	netObs := s.netObserver
	s.mu.Unlock()
	for _, l := range closed {
		l.close(ErrUnpaired, true)
	}
	if service, ok := s.network.Handler.(interface{ RefreshSelfAccess() }); ok {
		service.RefreshSelfAccess()
	}
	if netObs != nil {
		netObs()
	}
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

func (s *Server) PairingTicket() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.online {
		return ""
	}
	return s.pairTicket
}

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
	signalURL, err := NormalizeSignalURL(rawSignalURL)
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
	if s.state.Service != signalURL {
		next := s.state
		if next.Service != "" {
			next.Other = maps.Clone(next.Other)
			if next.Other == nil {
				next.Other = make(map[string]map[string]ClientInfo)
			}
			next.Other[next.Service] = next.Clients
			next.Clients = next.Other[signalURL]
			delete(next.Other, signalURL)
			if next.Clients == nil {
				next.Clients = make(map[string]ClientInfo)
			}
		}
		next.Service = signalURL
		if err := saveState(s.store, next); err != nil {
			return err
		}
		s.state = next
	}
	runCtx, cancel := context.WithCancel(ctx)
	entry := &runningConn{
		signalURL:  signalURL,
		relayToken: relayToken,
		name:       name,
		ctx:        runCtx,
		cancel:     cancel,
		done:       make(chan struct{}),
		seenConns:  make(map[string]struct{}),
	}
	s.running = entry
	s.group = s.db.Group(signalURL, s.pin)
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
	clear(s.retire)
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
	client, ok := s.networkClient(id)
	return s.running != nil && s.running.ctx.Err() == nil && ok && userID(client) == user
}

func (s *Server) networkClient(id string) (ClientInfo, bool) {
	if s.group == nil {
		return ClientInfo{}, false
	}
	member, known := s.group.Get(id)
	if !known || id == s.pin || (member.Role != "mobile" && member.Role != "desktop") || !s.group.Allows(id) {
		return ClientInfo{}, false
	}
	if client, ok := s.state.Clients[id]; ok && client.PublicKey == member.Pin && !s.group.GrantExpired(id, client.LocalEpoch, client.Epoch) {
		if client.Role == "" {
			client.Role = member.Role
		}
		return client, true
	}
	return ClientInfo{ID: id, PublicKey: member.Pin, Name: member.Name, Role: member.Role, Access: Read, Epoch: member.Epoch}, true
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
			s.retireLocked(id)
			return true
		}
	}
	return false
}

func (s *Server) InvitePairing(ctx context.Context, access string, includeToken bool) (Invitation, pairing.Display, error) {
	inv, link, err := s.Invite(access, includeToken)
	if err != nil {
		return Invitation{}, pairing.Display{}, err
	}
	target, err := ParseTarget(link)
	if err != nil {
		s.RevokeInvitation(inv.ID)
		return Invitation{}, pairing.Display{}, err
	}
	display, retire, err := pairing.Present(ctx, target.SignalURL, s.deviceID, s.PairingTicket(), link, inv.ExpiresAt)
	if err != nil {
		s.RevokeInvitation(inv.ID)
		return Invitation{}, pairing.Display{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.invitations[target.Pair]; !ok {
		retire()
		return Invitation{}, pairing.Display{}, pairing.ErrInvalid
	}
	s.retire[inv.ID] = retire
	return inv, display, nil
}

func (s *Server) retireLocked(id string) {
	if retire := s.retire[id]; retire != nil {
		delete(s.retire, id)
		retire()
	}
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
	var removed []string
	if s.group != nil {
		for key, member := range s.group.Snapshot() {
			if key != s.pin && (member.Role == "mobile" || member.Role == "desktop") && member.Active() && (id == "" || key == id) {
				removed = append(removed, key)
			}
		}
	}
	if id != "" && len(clients) == len(s.state.Clients) && len(removed) == 0 {
		s.mu.Unlock()
		return errors.New("selfrelay: unknown client")
	}
	if len(removed) > 0 {
		if err := s.group.Remove(removed...); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	next := s.state
	next.Clients = clients
	if err := saveState(s.store, next); err != nil {
		s.mu.Unlock()
		return err
	}
	s.state = next
	if id == "" {
		clear(s.invitations)
		for id := range s.retire {
			s.retireLocked(id)
		}
	}
	var revoked []*peerLink
	for clientID, set := range s.clientLinks {
		if id == "" || id == clientID {
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
	s.network.Broadcast()
	return nil
}

func (s *Server) pruneInvitationsLocked(now time.Time) {
	for tok, inv := range s.invitations {
		if !now.Before(inv.ExpiresAt) {
			delete(s.invitations, tok)
			delete(s.retire, inv.ID)
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
	if s.online && !online {
		clear(s.invitations)
		clear(s.retire)
	}
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
	var registered struct {
		Ticket string `json:"pairing_ticket"`
	}
	_ = json.Unmarshal(reg.Data, &registered)
	s.mu.Lock()
	s.pairTicket = registered.Ticket
	s.mu.Unlock()
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
	s.mu.Lock()
	if s.running != entry || entry.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	if _, active := s.links[m.Connection]; active {
		s.mu.Unlock()
		return
	}
	if _, seen := entry.seenConns[m.Connection]; seen {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
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
	role := req.Role
	if role == "" {
		role = "mobile"
	}
	if role != "mobile" && role != "desktop" {
		s.rejectRequest(send, m)
		return
	}
	mobilePub, err := parsePublicKeyB64(req.PublicKey)
	if err != nil {
		s.rejectRequest(send, m)
		return
	}
	mobileDevID, err := identity.SelfDeviceID(mobilePub)
	if err != nil || mobileDevID != m.From || mobileDevID == s.deviceID {
		s.rejectRequest(send, m)
		return
	}
	if _, err := m.Verify(mobilePub); err != nil {
		s.rejectRequest(send, m)
		return
	}

	client, ok := s.authorizePeer(entry, m.Connection, mobilePub, req.PublicKey, req.Name, role, req.PairProof)
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
	if _, active := s.links[l.id]; active {
		s.mu.Unlock()
		return
	}
	if _, seen := entry.seenConns[l.id]; seen {
		s.mu.Unlock()
		return
	}
	if len(entry.seenConns) >= 4096 {
		clear(entry.seenConns)
		for activeID := range s.links {
			entry.seenConns[activeID] = struct{}{}
		}
	}
	entry.seenConns[l.id] = struct{}{}
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

func (s *Server) authorizePeer(entry *runningConn, connID string, mobilePub ed25519.PublicKey, mobilePubB64, name, role, pairProofB64 string) (ClientInfo, bool) {
	fp := fingerprint(mobilePub)
	if role == "desktop" {
		fp = mobilePubB64
	}
	if fp == s.pin {
		return ClientInfo{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running != entry || entry.ctx.Err() != nil {
		return ClientInfo{}, false
	}
	if s.group == nil {
		s.group = s.db.Group(entry.signalURL, s.pin)
	}
	existing, paired := s.networkClient(fp)
	if paired && (existing.PublicKey != mobilePubB64 || (existing.Role != "" && existing.Role != role)) {
		return ClientInfo{}, false
	}
	admit := func(fresh bool) error {
		return s.group.Admit(pairnet.Member{ID: s.pin, Pin: s.pin, Role: "desktop", Name: entry.name},
			pairnet.Member{ID: fp, Pin: mobilePubB64, Role: role, Name: name}, fresh)
	}
	if legacy, ok := s.state.Clients[fp]; ok && !paired && legacy.PublicKey == mobilePubB64 && legacy.Epoch == 0 {
		_, known := s.group.Get(fp)
		local, _ := s.group.Get(s.pin)
		if !known && local.Epoch <= 1 && admit(false) == nil {
			existing, paired = s.networkClient(fp)
		}
	}
	if paired && pairProofB64 == "" {
		return existing, true
	}
	if pairProofB64 == "" || (!paired && len(s.state.Clients) >= maxClients) {
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
	prior, direct := s.state.Clients[fp]
	if paired && direct && !s.group.GrantExpired(fp, prior.LocalEpoch, prior.Epoch) {
		return existing, true
	}
	if err := admit(true); err != nil {
		return ClientInfo{}, false
	}
	member, _ := s.group.Get(fp)
	local, _ := s.group.Get(s.pin)
	client := ClientInfo{
		Epoch:      member.Epoch,
		LocalEpoch: local.Epoch,
		ID:         fp,
		PublicKey:  mobilePubB64,
		Name:       name,
		Role:       role,
		Access:     matchedInv.Access,
		PairedAt:   now.UTC(),
	}
	s.state.Clients[fp] = client
	if err := saveState(s.store, s.state); err != nil {
		if direct {
			s.state.Clients[fp] = prior
		} else {
			delete(s.state.Clients, fp)
		}
		_ = s.group.Remove(fp)
		return ClientInfo{}, false
	}
	delete(s.invitations, matchedToken)
	s.retireLocked(matchedInv.ID)
	return client, true
}
