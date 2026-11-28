package selfrelay

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"slices"

	"vanora-relay/adapter/transport"
	"vanora-relay/protocol"
)

type TunnelHooks struct {
	OnSessionStart  func(ctx context.Context, scope, signalURL, relayToken string, send func(protocol.Message) error)
	OnMessage       func(protocol.Message)
	OnRevokeClient  func(clientID string)
	OnRevokeAll     func()
	OnNetworkChange func()
}

func (s *Server) SetTunnelHooks(hooks TunnelHooks) { s.tunnelHooks.Store(&hooks) }

func (s *Server) PrivateKey() ed25519.PrivateKey   { return slices.Clone(s.priv) }
func (s *Server) TunnelHandler() transport.Handler { return s.handler }

func (s *Server) AuthorizePairedTunnel(pub ed25519.PublicKey, role string) (ClientInfo, string, bool) {
	if len(pub) != ed25519.PublicKeySize || (role != "mobile" && role != "desktop") {
		return ClientInfo{}, "", false
	}
	pin := base64.RawURLEncoding.EncodeToString(pub)
	id := pin
	if role == "mobile" {
		id = fingerprint(pub)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == nil || s.running.ctx.Err() != nil {
		return ClientInfo{}, "", false
	}
	client, ok := s.networkClient(id)
	if !ok || client.PublicKey != pin || client.Role != role {
		return ClientInfo{}, "", false
	}
	return client, userID(client), true
}

func (s *Server) revokeTunnelClient(id string) {
	if hooks := s.tunnelHooks.Load(); hooks != nil && hooks.OnRevokeClient != nil {
		hooks.OnRevokeClient(id)
	}
}

func (s *Server) revokeAllTunnelClients() {
	if hooks := s.tunnelHooks.Load(); hooks != nil && hooks.OnRevokeAll != nil {
		hooks.OnRevokeAll()
	}
}
