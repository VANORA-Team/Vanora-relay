package lan

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/pairnet"
)

const (
	inviteTTL   = 5 * time.Minute
	maxInvites  = 32
	maxClients  = 128
	requestSize = 2 << 20
)

type ClientInfo struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Role       string    `json:"role,omitempty"`
	Access     string    `json:"access"`
	PairedAt   time.Time `json:"paired_at"`
	Connected  bool      `json:"connected"`
	Epoch      uint64    `json:"membership_epoch,omitempty"`
	LocalEpoch uint64    `json:"local_epoch,omitempty"`
}

type Invitation struct {
	ID        string    `json:"id"`
	Access    string    `json:"access"`
	ExpiresAt time.Time `json:"expires_at"`
	record    pairing.Record
}

type Status struct {
	Enabled     bool         `json:"enabled"`
	Address     string       `json:"address,omitempty"`
	Clients     []ClientInfo `json:"clients"`
	Invitations []Invitation `json:"invitations"`
}

type serverState struct {
	Key     string                `json:"key"`
	Clients map[string]ClientInfo `json:"clients"`
}

type listener struct {
	target Target
	server *http.Server
	ctx    context.Context
	cancel context.CancelFunc
}

type Server struct {
	mu          sync.Mutex
	store       Store
	handler     transport.Handler
	certificate tls.Certificate
	pin         string
	state       serverState
	listening   *listener
	invitations map[string]Invitation
	peers       map[string]*peer
	group       *pairnet.Group
	network     *transport.NetworkHandler
	netObserver func()
}

func OpenServer(store Store, handler transport.Handler) (*Server, error) {
	if store == nil || handler == nil {
		return nil, errors.New("LAN: secure storage and a connection handler are required")
	}
	db, err := pairnet.Open(store)
	if err != nil {
		return nil, err
	}
	store = db
	data, err := store.Load()
	if err != nil {
		return nil, err
	}
	state := serverState{Clients: make(map[string]ClientInfo)}
	if data != "" {
		if err := json.Unmarshal([]byte(data), &state); err != nil {
			return nil, err
		}
		if state.Clients == nil || len(state.Clients) > maxClients {
			return nil, errors.New("LAN: invalid stored clients")
		}
		for id, client := range state.Clients {
			if id != client.ID || Access(userID(client)) == "" || !validName(client.Name) {
				return nil, errors.New("LAN: invalid stored client")
			}
		}
	} else {
		state.Key, err = newKey()
		if err != nil {
			return nil, err
		}
		if err := saveState(store, state); err != nil {
			return nil, err
		}
	}
	certificate, pin, err := makeCertificate(state.Key)
	if err != nil {
		return nil, err
	}
	s := &Server{
		store: store, handler: handler, certificate: certificate, pin: pin, state: state,
		invitations: make(map[string]Invitation), peers: make(map[string]*peer), group: db.Group("lan", pin),
	}
	s.network = &transport.NetworkHandler{Handler: handler, Group: s.Network, Device: func(p transport.Peer) string {
		user := p.UserID()
		return user[strings.LastIndex(user, ":")+1:]
	}, Changed: s.closeRemoved}
	s.handler = s.network
	return s, nil
}

func (s *Server) Network() *pairnet.Group { return s.group }
func (s *Server) Pin() string             { return s.pin }
func (s *Server) Seed() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Key
}
func (s *Server) Address() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listening == nil || s.listening.ctx.Err() != nil {
		return ""
	}
	return s.listening.target.Address
}

func (s *Server) BroadcastNetwork() { s.network.Broadcast() }

func (s *Server) SetNetworkObserver(fn func()) {
	s.mu.Lock()
	s.netObserver = fn
	s.mu.Unlock()
}

func (s *Server) SetClientAccess(id, access string) error {
	if access != Read && access != Control {
		return errors.New("LAN: access must be read or control")
	}
	s.mu.Lock()
	member, known := s.group.Get(id)
	if !known || id == s.pin || (member.Role != "mobile" && member.Role != "desktop") || !s.group.Allows(id) {
		s.mu.Unlock()
		return errors.New("LAN: unknown active network member")
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
	var closed *peer
	if p := s.peers[id]; p != nil {
		p.cancel()
		closed = p
		delete(s.peers, id)
	}
	s.mu.Unlock()
	if closed != nil {
		closed.Close()
	}
	if service, ok := s.network.Handler.(interface{ RefreshLANAccess() }); ok {
		service.RefreshLANAccess()
	}
	return nil
}

func (s *Server) RemoveDevice(id string) error {
	if err := s.group.Remove(id); err != nil {
		return err
	}
	s.network.Broadcast()
	return nil
}

func (s *Server) closeRemoved() {
	s.mu.Lock()
	next := s.state
	next.Clients = maps.Clone(next.Clients)
	maps.DeleteFunc(next.Clients, func(id string, client ClientInfo) bool {
		return s.group.GrantExpired(id, client.LocalEpoch, client.Epoch)
	})
	if len(next.Clients) < len(s.state.Clients) && saveState(s.store, next) == nil {
		s.state = next
	}
	var closed []*peer
	for id, p := range s.peers {
		if !s.group.Allows(id) {
			closed = append(closed, p)
		}
	}
	netObs := s.netObserver
	s.mu.Unlock()
	for _, p := range closed {
		p.Close()
	}
	if service, ok := s.network.Handler.(interface{ RefreshLANAccess() }); ok {
		service.RefreshLANAccess()
	}
	if netObs != nil {
		netObs()
	}
}

func saveState(store Store, state serverState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return store.Save(string(data))
}

func (s *Server) Listen(ctx context.Context, address string) error {
	bind, err := parseLocalAddress(strings.TrimSpace(address))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listening != nil {
		return errors.New("LAN: stop the listener before changing its address")
	}
	socket, err := (&net.ListenConfig{}).Listen(ctx, "tcp", bind.String())
	if err != nil {
		return err
	}
	listenCtx, cancel := context.WithCancel(ctx)
	entry := &listener{
		target: Target{Address: socket.Addr().String(), Pin: s.pin},
		ctx:    listenCtx,
		cancel: cancel,
	}
	entry.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.serve(entry, w, r)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    4096,
	}
	tlsConfig := &tls.Config{
		Certificates:           []tls.Certificate{s.certificate},
		ClientAuth:             tls.RequireAnyClientCert,
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		NextProtos:             []string{"http/1.1"},
	}
	s.listening = entry
	_ = s.group.UpdateSelf(pairnet.Member{ID: s.pin, Address: entry.target.Address})
	go func() {
		_ = entry.server.Serve(tls.NewListener(socket, tlsConfig))
		s.stop(entry)
	}()
	go func() {
		<-listenCtx.Done()
		s.stop(entry)
	}()
	return nil
}

func (s *Server) Stop() { s.stop(nil) }

func (s *Server) stop(entry *listener) {
	s.mu.Lock()
	if s.listening == nil || (entry != nil && entry != s.listening) {
		s.mu.Unlock()
		return
	}
	entry = s.listening
	s.listening = nil
	clear(s.invitations)
	peers := s.peers
	s.peers = make(map[string]*peer)
	entry.cancel()
	s.mu.Unlock()
	for _, p := range peers {
		p.Close()
	}
	_ = entry.server.Close()
}

func (s *Server) Allows(user string) bool {
	id := user[strings.LastIndex(user, ":")+1:]
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.networkClient(id)
	return s.listening != nil && s.listening.ctx.Err() == nil && ok && userID(client) == user
}

func (s *Server) networkClient(id string) (ClientInfo, bool) {
	member, known := s.group.Get(id)
	if !known || id == s.pin || (member.Role != "mobile" && member.Role != "desktop") || member.Pin != id || !s.group.Allows(id) {
		return ClientInfo{}, false
	}
	if client, ok := s.state.Clients[id]; ok && !s.group.GrantExpired(id, client.LocalEpoch, client.Epoch) {
		if client.Role == "" {
			client.Role = member.Role
		}
		return client, true
	}
	return ClientInfo{ID: id, Name: member.Name, Role: member.Role, Access: Read, Epoch: member.Epoch}, true
}

func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := Status{
		Clients:     make([]ClientInfo, 0, len(s.state.Clients)),
		Invitations: make([]Invitation, 0, len(s.invitations)),
	}
	if s.listening != nil {
		status.Enabled = s.listening.ctx.Err() == nil
		status.Address = s.listening.target.Address
	}
	seen := make(map[string]struct{}, len(s.state.Clients))
	for id, client := range s.state.Clients {
		seen[id] = struct{}{}
		p := s.peers[id]
		client.Connected = p != nil && p.ctx.Err() == nil
		status.Clients = append(status.Clients, client)
	}
	if s.group != nil {
		for _, member := range s.group.Snapshot().Members() {
			if _, ok := seen[member.ID]; ok {
				continue
			}
			if client, allowed := s.networkClient(member.ID); allowed {
				p := s.peers[member.ID]
				client.Connected = p != nil && p.ctx.Err() == nil
				status.Clients = append(status.Clients, client)
			}
		}
	}
	s.pruneInvitations(time.Now())
	for _, invite := range s.invitations {
		status.Invitations = append(status.Invitations, invite)
	}
	slices.SortFunc(status.Clients, func(a, b ClientInfo) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(status.Invitations, func(a, b Invitation) int { return a.ExpiresAt.Compare(b.ExpiresAt) })
	return status
}

func (s *Server) pruneInvitations(now time.Time) {
	for token, invite := range s.invitations {
		if !now.Before(invite.ExpiresAt) {
			delete(s.invitations, token)
		}
	}
}

func (s *Server) Invite(access string) (Invitation, string, error) {
	if access != Read && access != Control {
		return Invitation{}, "", errors.New("LAN: access must be read or control")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listening == nil || s.listening.ctx.Err() != nil {
		return Invitation{}, "", errors.New("LAN: listener is disabled")
	}
	now := time.Now()
	s.pruneInvitations(now)
	if len(s.invitations) >= maxInvites || len(s.state.Clients) >= maxClients {
		return Invitation{}, "", errors.New("LAN: pairing limit reached")
	}
	token, err := newKey()
	if err != nil {
		return Invitation{}, "", err
	}
	id, err := newKey()
	if err != nil {
		return Invitation{}, "", err
	}
	invite := Invitation{ID: id, Access: access, ExpiresAt: now.Add(inviteTTL)}
	s.invitations[token] = invite
	target := s.listening.target
	target.Token = token
	return invite, target.Link(), nil
}

func (s *Server) RevokeInvitation(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, invite := range s.invitations {
		if invite.ID == id {
			delete(s.invitations, token)
			return true
		}
	}
	return false
}

func (s *Server) InvitePairing(access string) (Invitation, pairing.Display, error) {
	inv, link, err := s.Invite(access)
	if err != nil {
		return Invitation{}, pairing.Display{}, err
	}
	target, err := ParseTarget(link)
	if err != nil {
		s.RevokeInvitation(inv.ID)
		return Invitation{}, pairing.Display{}, err
	}
	display, record, err := pairing.DisplayLink(link, inv.ExpiresAt)
	if err != nil {
		s.RevokeInvitation(inv.ID)
		return Invitation{}, pairing.Display{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.invitations[target.Token]; !ok {
		return Invitation{}, pairing.Display{}, pairing.ErrInvalid
	}
	inv.record = record
	s.invitations[target.Token] = inv
	display.Code += "@" + target.Address
	return inv, display, nil
}

func (s *Server) RevokeClients(id string) error {
	s.mu.Lock()
	clients := make(map[string]ClientInfo, len(s.state.Clients))
	for clientID, client := range s.state.Clients {
		if id != "" && id != clientID {
			clients[clientID] = client
		}
	}
	var removed []string
	for key, member := range s.group.Snapshot() {
		if key != s.pin && (member.Role == "mobile" || member.Role == "desktop") && member.Active() && (id == "" || key == id) {
			removed = append(removed, key)
		}
	}
	if id != "" && len(clients) == len(s.state.Clients) && len(removed) == 0 {
		s.mu.Unlock()
		return errors.New("LAN: unknown client")
	}
	if len(removed) > 0 {
		if err := s.group.Remove(removed...); err != nil {
			s.mu.Unlock()
			return err
		}
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
	var revoked []*peer
	for clientID, p := range s.peers {
		if id == "" || clientID == id {
			p.cancel()
			revoked = append(revoked, p)
			delete(s.peers, clientID)
		}
	}
	s.mu.Unlock()
	for _, p := range revoked {
		p.Close()
	}
	s.network.Broadcast()
	return nil
}

func (s *Server) serve(entry *listener, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != path || r.Header.Get("Origin") != "" || r.TLS == nil {
		http.NotFound(w, r)
		return
	}
	source, err := netip.ParseAddrPort(r.RemoteAddr)
	id := peerFingerprint(*r.TLS)
	if err == nil && localAddress(source.Addr()) && id != "" && id != s.pin && r.URL.Query().Get("probe") == "1" {
		w.Header().Set("Cache-Control", "no-store")
		s.mu.Lock()
		_, ok := s.networkClient(id)
		live := s.listening == entry && entry.ctx.Err() == nil
		s.mu.Unlock()
		if !live {
			http.NotFound(w, r)
			return
		}
		if !ok {
			http.Error(w, "LAN access denied", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err == nil && localAddress(source.Addr()) && id != "" && r.URL.Query().Has("pairing") {
		locator := r.URL.Query().Get("pairing")
		s.mu.Lock()
		s.pruneInvitations(time.Now())
		box := ""
		for _, inv := range s.invitations {
			if s.listening == entry && locator != "" && inv.record.Locator == locator {
				box = inv.record.Box
				break
			}
		}
		s.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		if box == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(box))
		return
	}
	name, nameErr := base64.RawURLEncoding.DecodeString(r.Header.Get(nameHeader))
	roleHeaderVal := strings.TrimSpace(r.Header.Get(roleHeader))
	if roleHeaderVal != "" && roleHeaderVal != "mobile" && roleHeaderVal != "desktop" {
		http.Error(w, "LAN access denied", http.StatusUnauthorized)
		return
	}
	peerAddr := strings.TrimSpace(r.Header.Get(addressHeader))
	if peerAddr != "" {
		parsedPeer, parseErr := parseLocalAddress(peerAddr)
		if parseErr != nil || parsedPeer.Port() == 0 {
			http.Error(w, "LAN access denied", http.StatusUnauthorized)
			return
		}
		peerAddr = parsedPeer.String()
	}
	if err != nil || !localAddress(source.Addr()) || id == "" || id == s.pin || nameErr != nil || !validName(string(name)) {
		http.Error(w, "LAN access denied", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	client, status := s.authorize(entry, id, r.Header.Get(tokenHeader), string(name), roleHeaderVal, peerAddr)
	s.mu.Unlock()
	if status != http.StatusOK {
		http.Error(w, "LAN access unavailable", status)
		return
	}
	socket, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	user := userID(client)
	p := newPeer(entry.ctx, socket, user, pathForAddress(source.Addr()), func() bool { return s.Allows(user) })
	s.mu.Lock()
	if current, ok := s.networkClient(id); s.listening != entry || !ok || userID(current) != user {
		s.mu.Unlock()
		p.Close()
		return
	}
	previous := s.peers[id]
	s.peers[id] = p
	s.mu.Unlock()
	if previous != nil {
		previous.Close()
	}
	p.run(s.handler, requestSize)
	s.mu.Lock()
	if s.peers[id] == p {
		delete(s.peers, id)
	}
	s.mu.Unlock()
}

func (s *Server) authorize(entry *listener, id, token, name, role, peerAddr string) (ClientInfo, int) {
	if s.listening != entry || entry.ctx.Err() != nil || id == s.pin {
		return ClientInfo{}, http.StatusUnauthorized
	}
	now := time.Now()
	invite, ok := s.invitations[token]
	fresh := ok && now.Before(invite.ExpiresAt)
	if token != "" && !fresh {
		return ClientInfo{}, http.StatusUnauthorized
	}
	prior, legacy := s.state.Clients[id]
	member, known := s.group.Get(id)
	local, _ := s.group.Get(s.pin)
	if role == "" {
		if known && (member.Role == "mobile" || member.Role == "desktop") {
			role = member.Role
		} else {
			role = "mobile"
		}
	}
	if known && member.Epoch != 0 && member.Role != role {
		return ClientInfo{}, http.StatusUnauthorized
	}
	if !fresh && !(legacy && !known && local.Epoch <= 1) && !(known && (member.Role == "mobile" || member.Role == "desktop") && member.Pin == id && s.group.Allows(id)) {
		return ClientInfo{}, http.StatusUnauthorized
	}
	if fresh && !legacy && len(s.state.Clients) >= maxClients {
		return ClientInfo{}, http.StatusUnauthorized
	}
	if err := s.group.Admit(pairnet.Member{ID: s.pin, Pin: s.pin, Role: "desktop", Address: entry.target.Address},
		pairnet.Member{ID: id, Pin: id, Role: role, Name: name, Address: peerAddr}, fresh); err != nil {
		return ClientInfo{}, http.StatusUnauthorized
	}
	if current, allowed := s.networkClient(id); allowed && (!fresh || known && member.Active() && legacy && !s.group.GrantExpired(id, prior.LocalEpoch, prior.Epoch)) {
		return current, http.StatusOK
	}
	member, _ = s.group.Get(id)
	client := ClientInfo{ID: id, Name: name, Role: role, Access: invite.Access, PairedAt: now.UTC()}
	client.Epoch = member.Epoch
	local, _ = s.group.Get(s.pin)
	client.LocalEpoch = local.Epoch
	s.state.Clients[id] = client
	if err := saveState(s.store, s.state); err != nil {
		if legacy {
			s.state.Clients[id] = prior
		} else {
			delete(s.state.Clients, id)
		}
		_ = s.group.Remove(id)
		return ClientInfo{}, http.StatusServiceUnavailable
	}
	delete(s.invitations, token)
	return client, http.StatusOK
}
