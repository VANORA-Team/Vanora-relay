package transport

import (
	"context"
	"crypto/ed25519"
	"slices"

	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

type TunnelHooks struct {
	OnMessage       func(protocol.Message)
	OnRevokeDevice  func(deviceID string)
	OnRevokeUser    func(userID string)
	OnAuthorityLost func()
	OnLeaseUpdated  func(endpoint.LeaseProof)
	OnNetworkChange func()
}

func (c *Client) SetTunnelHooks(hooks TunnelHooks) { c.tunnelHooks.Store(&hooks) }

func (c *Client) TunnelScope() string { return c.tunnelScope }
func (c *Client) SignalURL() string   { return c.signalURL }
func (c *Client) DeviceID() string    { return c.deviceID }
func (c *Client) UserID() string      { return c.userID }
func (c *Client) PublicKey() ed25519.PublicKey {
	return slices.Clone(c.publicKey)
}

func (c *Client) TunnelHandler() Handler { return c.handler }

func (c *Client) SendTunnel(m protocol.Message) error {
	if c.tunnelScope == "" {
		return ErrUnauthorized
	}
	switch m.Type {
	case "tunnel.host", "tunnel.connect", "tunnel.permit", "tunnel.refresh", "tunnel.close":
		return c.sendSignal(m)
	default:
		return ErrInvalidArgument
	}
}

func (c *Client) CurrentLease(ctx context.Context) (*endpoint.Credentials, endpoint.LeaseProof, error) {
	creds, proof, _, err := c.current(ctx)
	return creds, proof, err
}

func (c *Client) SetPairedTunnelAuthorizer(paired endpoint.PairRoleAuthorizer) {
	c.mu.Lock()
	c.tunnelPairedRole = paired
	c.mu.Unlock()
}

func (c *Client) AuthorizePairedTunnel(connID string, remote identity.Principal, role string) bool {
	c.mu.Lock()
	paired := c.tunnelPairedRole
	c.mu.Unlock()
	if paired == nil {
		paired = c.pairedRole
	}
	return c.tunnelScope != "" && c.role == RoleDesktop && c.desktop == "" && !c.closed.Load() &&
		paired != nil && c.allowsUser(remote.RemoteUserID()) && paired(connID, remote, role, "", nil)
}

func (c *Client) tunnelAuthorityLost() {
	if hooks := c.tunnelHooks.Load(); hooks != nil && hooks.OnAuthorityLost != nil {
		hooks.OnAuthorityLost()
	}
}

func (c *Client) RevokeTunnelDevice(device string) {
	if hooks := c.tunnelHooks.Load(); hooks != nil && hooks.OnRevokeDevice != nil {
		hooks.OnRevokeDevice(device)
	}
}
