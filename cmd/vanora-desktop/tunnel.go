package main

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"vanora-relay/adapter/cftunnel"
	"vanora-relay/adapter/desktop"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/protocol"
)

type tunnelSession struct {
	ctx     context.Context
	channel string
	slot    *officialSlot
	options func(context.Context) (cftunnel.HostOptions, error)
	host    atomic.Pointer[cftunnel.HostManager]
}

func (s *tunnelSession) routeSignal(msg protocol.Message) {
	if host := s.host.Load(); host != nil {
		host.HandleSignal(msg)
	}
}

func (m *accessManager) currentTunnelHost() *cftunnel.HostManager {
	if session := m.tunnelSession.Load(); session != nil {
		return session.host.Load()
	}
	return nil
}

func (m *accessManager) tunnelStatus() cftunnel.HostStatus {
	m.tunnelMu.Lock()
	defer m.tunnelMu.Unlock()
	return m.tunnelStatusLocked()
}

func (m *accessManager) tunnelStatusLocked() cftunnel.HostStatus {
	if host := m.currentTunnelHost(); host != nil {
		return host.Status()
	}
	status := cftunnel.HostStatus{Enabled: m.tunnelEnabled, State: "disabled"}
	if status.Enabled {
		status.State = "unavailable"
	}
	return status
}

func (m *accessManager) emitTunnelStatus(channel string, status cftunnel.HostStatus) {
	m.emitter.Emit(map[string]any{"type": "tunnel.status", "channel": channel, "tunnel": status})
}

func (m *accessManager) startTunnelLocked() error {
	session := m.tunnelSession.Load()
	if !m.tunnelEnabled || session == nil || session.ctx.Err() != nil || session.host.Load() != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(session.ctx, 15*time.Second)
	defer cancel()
	opts, err := session.options(ctx)
	if err != nil {
		return m.tunnelStartFailed(session.channel)
	}
	opts.CloudflaredBinary, opts.PinnedConnector = m.cloudflared, m.tunnelPinned
	opts.Observe = func(status cftunnel.HostStatus) {
		m.emitTunnelStatus(session.channel, status)
	}
	host, err := cftunnel.NewHostManager(opts)
	if err != nil {
		return m.tunnelStartFailed(session.channel)
	}
	session.host.Store(host)
	if err := host.Start(session.ctx); err != nil {
		session.host.Store(nil)
		return m.tunnelStartFailed(session.channel)
	}
	return nil
}

func (m *accessManager) tunnelStartFailed(channel string) error {
	m.emitTunnelStatus(channel, cftunnel.HostStatus{Enabled: true, State: "unavailable", Error: "tunnel_start_failed"})
	return errors.New("managed tunnel startup failed")
}

func (m *accessManager) setTunnelSession(session *tunnelSession) {
	m.tunnelMu.Lock()
	defer m.tunnelMu.Unlock()
	if session.ctx.Err() != nil {
		return
	}
	m.stopTunnelLocked()
	m.tunnelSession.Store(session)
	_ = m.startTunnelLocked()
}

func (m *accessManager) stopTunnelLocked() {
	if session := m.tunnelSession.Load(); session != nil {
		if host := session.host.Swap(nil); host != nil {
			host.Stop()
		}
	}
}

func (m *accessManager) stopTunnelChannel(channel string) {
	m.tunnelMu.Lock()
	defer m.tunnelMu.Unlock()
	if session := m.tunnelSession.Load(); session != nil && session.channel == channel {
		m.stopTunnelLocked()
		m.tunnelSession.Store(nil)
	}
}

func (m *accessManager) endTunnelSession(session *tunnelSession) {
	m.tunnelMu.Lock()
	defer m.tunnelMu.Unlock()
	if session != nil && m.tunnelSession.Load() == session {
		m.stopTunnelLocked()
		m.tunnelSession.Store(nil)
	}
}

func (m *accessManager) tunnelCommand(cmd accessCommand, result map[string]any) error {
	switch cmd.Type {
	case "access.tunnel.status":
		result["type"] = "tunnel.status"
	case "access.tunnel.set":
		if cmd.Enabled == nil {
			return errors.New("enabled is required")
		}
		m.tunnelMu.Lock()
		changed := m.tunnelEnabled != *cmd.Enabled
		hadHost := m.currentTunnelHost() != nil
		m.tunnelEnabled = *cmd.Enabled
		var err error
		if m.tunnelEnabled {
			err = m.startTunnelLocked()
		} else {
			m.stopTunnelLocked()
		}
		status := m.tunnelStatusLocked()
		m.tunnelMu.Unlock()
		if changed && !hadHost && (status.State == "unavailable" || status.State == "disabled") && err == nil {
			m.emitTunnelStatus("", status)
		}
		if err != nil {
			return err
		}
	default:
		host := m.currentTunnelHost()
		if host == nil {
			return cftunnel.ErrTunnelUnavailable
		}
		ctx, cancel := context.WithTimeout(m.ctx, 45*time.Second)
		defer cancel()
		var err error
		switch cmd.Type {
		case "access.tunnel.disconnect":
			err = host.Disconnect(ctx)
		case "access.tunnel.resume":
			err = host.Resume(ctx)
		case "access.tunnel.deprovision":
			err = host.Deprovision(ctx)
		}
		if err != nil {
			return errors.New("managed tunnel operation failed")
		}
	}
	result["tunnel"] = m.tunnelStatus()
	return nil
}

func (m *accessManager) selfTunnelSession() *tunnelSession {
	session := m.tunnelSession.Load()
	if session != nil && session.channel == "self" {
		return session
	}
	return nil
}

func (m *accessManager) setSelfTunnelHooks(server *selfrelay.Server) {
	server.SetTunnelHooks(selfrelay.TunnelHooks{
		OnSessionStart: func(ctx context.Context, scope, signalURL, token string, send func(protocol.Message) error) {
			session := &tunnelSession{ctx: ctx, channel: "self", options: func(context.Context) (cftunnel.HostOptions, error) {
				origin, err := cftunnel.ControlOriginFromSignalURL(signalURL)
				if err != nil {
					return cftunnel.HostOptions{}, err
				}
				return cftunnel.HostOptions{
					Channel: "self", Scope: scope, ControlOrigin: origin, SelfToken: token, DeviceID: server.DeviceID(),
					OwnerID: server.DeviceID(), PrivateKey: server.PrivateKey(), Handler: server.TunnelHandler(), SendSignal: send,
					AuthorizeOffer: func(req cftunnel.OfferRequest) (cftunnel.OfferDecision, error) {
						_, user, ok := server.AuthorizePairedTunnel(req.Principal.PublicKey, req.Role)
						if !ok {
							return cftunnel.OfferDecision{}, transport.ErrUnauthorized
						}
						return cftunnel.OfferDecision{UserID: user, Allows: func() bool { return server.Allows(user) }}, nil
					},
				}, nil
			}}
			m.setTunnelSession(session)
			go func() {
				<-ctx.Done()
				m.endTunnelSession(session)
			}()
		},
		OnMessage: func(msg protocol.Message) {
			if session := m.selfTunnelSession(); session != nil {
				session.routeSignal(msg)
			}
		},
		OnRevokeClient: func(id string) {
			if session := m.selfTunnelSession(); session != nil {
				if host := session.host.Load(); host != nil {
					host.RevokeUser("self:" + selfrelay.Read + ":" + id)
					host.RevokeUser("self:" + selfrelay.Control + ":" + id)
				}
			}
		},
		OnRevokeAll: func() {
			if session := m.selfTunnelSession(); session != nil {
				if host := session.host.Load(); host != nil {
					host.RevokeVisitor("")
				}
			}
		},
	})
}

func (m *accessManager) setOfficialTunnelHooks(ctx context.Context, slot *officialSlot, socket *transport.Client) *tunnelSession {
	if socket.TunnelScope() == "" {
		return nil
	}
	slot.updateTunnelGuests(m.config(), socket.UserID())
	socket.SetPairedTunnelAuthorizer(slot.authorizeTunnel)
	session := &tunnelSession{ctx: ctx, channel: slot.name, slot: slot}
	socket.SetTunnelHooks(transport.TunnelHooks{
		OnMessage: session.routeSignal,
		OnRevokeDevice: func(id string) {
			if host := session.host.Load(); host != nil {
				host.RevokeVisitor(id)
			}
		},
		OnRevokeUser: func(id string) {
			if host := session.host.Load(); host != nil {
				host.RevokeUser(id)
			}
		},
		OnNetworkChange: func() {
			if host := session.host.Load(); host != nil {
				host.RecheckPeers()
			}
		},
		OnAuthorityLost: func() {
			if host := session.host.Load(); host != nil {
				host.AuthorityLost()
			}
		},
		OnLeaseUpdated: func(proof endpoint.LeaseProof) {
			if host := session.host.Load(); host != nil {
				host.UpdateLocalLease(proof)
			}
		},
	})
	session.options = func(ctx context.Context) (cftunnel.HostOptions, error) {
		origin, err := cftunnel.ControlOriginFromSignalURL(socket.SignalURL())
		if err != nil {
			return cftunnel.HostOptions{}, err
		}
		creds, _, err := socket.CurrentLease(ctx)
		if err != nil {
			return cftunnel.HostOptions{}, err
		}
		return cftunnel.HostOptions{
			Channel: slot.name, Scope: socket.TunnelScope(), ControlOrigin: origin, DeviceID: socket.DeviceID(),
			OwnerID: socket.UserID(), PrivateKey: creds.PrivateKey(), CA: slot.ca, Handler: socket.TunnelHandler(),
			SendSignal: socket.SendTunnel, LeaseSource: func(ctx context.Context) (endpoint.LeaseProof, error) {
				_, proof, err := socket.CurrentLease(ctx)
				return proof, err
			},
			AuthorizeOffer: func(req cftunnel.OfferRequest) (cftunnel.OfferDecision, error) {
				user := req.Principal.RemoteUserID()
				allows := func() bool {
					allowed := slot.tunnelGuests.Load()
					return allowed != nil && (*allowed)[user] && socket.AuthorizePairedTunnel(req.ConnectionID, req.Principal, req.Role)
				}
				if !allows() {
					return cftunnel.OfferDecision{}, transport.ErrUnauthorized
				}
				return cftunnel.OfferDecision{UserID: user, Allows: allows}, nil
			},
		}, nil
	}
	m.setTunnelSession(session)
	return session
}

func (slot *officialSlot) updateTunnelGuests(cfg *desktop.Config, owner string) {
	allowed := map[string]bool{owner: owner != ""}
	if cfg != nil {
		users, err := guests(cfg, owner)
		if err == nil {
			for _, user := range users {
				allowed[user] = true
			}
		}
	}
	slot.tunnelGuests.Store(&allowed)
}

func (m *accessManager) reloadTunnelACL(cfg *desktop.Config) {
	m.tunnelMu.Lock()
	defer m.tunnelMu.Unlock()
	if session := m.tunnelSession.Load(); session != nil && session.slot != nil {
		slot := session.slot
		slot.updateTunnelGuests(cfg, slot.account.UserID())
		if host := session.host.Load(); host != nil {
			host.RecheckPeers()
		}
	}
}
