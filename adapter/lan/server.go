package lan

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/adapter/transport"
)

const (
	inviteTTL   = 5 * time.Minute
	maxInvites  = 32
	maxClients  = 128
	requestSize = 2 << 20
)

type ClientInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Access    string    `json:"access"`
	PairedAt  time.Time `json:"paired_at"`
	Connected bool      `json:"connected"`
}

type Invitation struct {
	ID        string    `json:"id"`
	Access    string    `json:"access"`
	ExpiresAt time.Time `json:"expires_at"`
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
}

func OpenServer(store Store, handler transport.Handler) (*Server, error) {
	if store == nil || handler == nil {
		return nil, errors.New("LAN: secure storage and a connection handler are required")
	}
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
	return &Server{
		store: store, handler: handler, certificate: certificate, pin: pin, state: state,
		invitations: make(map[string]Invitation), peers: make(map[string]*peer),
	}, nil
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
	client, ok := s.state.Clients[id]
	return s.listening != nil && s.listening.ctx.Err() == nil && ok && userID(client) == user
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
	for id, client := range s.state.Clients {
		p := s.peers[id]
		client.Connected = p != nil && p.ctx.Err() == nil
		status.Clients = append(status.Clients, client)
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
		return errors.New("LAN: unknown client")
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
		if _, allowed := clients[clientID]; !allowed {
			p.cancel()
			revoked = append(revoked, p)
			delete(s.peers, clientID)
		}
	}
	s.mu.Unlock()
	for _, p := range revoked {
		p.Close()
	}
	return nil
}

func (s *Server) serve(entry *listener, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != path || r.Header.Get("Origin") != "" || r.TLS == nil {
		http.NotFound(w, r)
		return
	}
	source, err := netip.ParseAddrPort(r.RemoteAddr)
	id := peerFingerprint(*r.TLS)
	name, nameErr := base64.RawURLEncoding.DecodeString(r.Header.Get(nameHeader))
	if err != nil || !localAddress(source.Addr()) || id == "" || nameErr != nil || !validName(string(name)) {
		http.Error(w, "LAN access denied", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	client, status := s.authorize(entry, id, r.Header.Get(tokenHeader), string(name))
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
	p := newPeer(entry.ctx, socket, user, func() bool { return s.Allows(user) })
	s.mu.Lock()
	if current, ok := s.state.Clients[id]; s.listening != entry || !ok || current != client {
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

func (s *Server) authorize(entry *listener, id, token, name string) (ClientInfo, int) {
	if s.listening != entry || entry.ctx.Err() != nil {
		return ClientInfo{}, http.StatusUnauthorized
	}
	if client, ok := s.state.Clients[id]; ok {
		return client, http.StatusOK
	}
	now := time.Now()
	invite, ok := s.invitations[token]
	if !ok || !now.Before(invite.ExpiresAt) || len(s.state.Clients) >= maxClients {
		return ClientInfo{}, http.StatusUnauthorized
	}
	client := ClientInfo{ID: id, Name: name, Access: invite.Access, PairedAt: now.UTC()}
	s.state.Clients[id] = client
	if err := saveState(s.store, s.state); err != nil {
		delete(s.state.Clients, id)
		return ClientInfo{}, http.StatusServiceUnavailable
	}
	delete(s.invitations, token)
	return client, http.StatusOK
}
