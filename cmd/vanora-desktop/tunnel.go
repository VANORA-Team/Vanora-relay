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
	ctx        context.Context
	channel    string
	slot       *officialSlot
	deviceID   string
	ownerID    string
	socket     atomic.Pointer[transport.Client]
	options    func(context.Context) (cftunnel.HostOptions, error)
	host       atomic.Pointer[cftunnel.HostManager]
	graceTimer *time.Timer
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
	if host := m.currentTunnelHost(); host != nil {
		return host.Status()
	}
	m.tunnelMu.Lock()
	enabled := m.tunnelEnabled
	m.tunnelMu.Unlock()
	status := cftunnel.HostStatus{Enabled: enabled, State: "disabled"}
	if status.Enabled {
		status.State = "unavailable"
	}
	return status
}

func (m *accessManager) isTunnelEnabled() bool {
	m.tunnelMu.Lock()
	enabled := m.tunnelEnabled
	m.tunnelMu.Unlock()
	return enabled
}

func (m *accessManager) emitTunnelStatus(channel string, status cftunnel.HostStatus) {
	m.emitter.Emit(map[string]any{"type": "tunnel.status", "channel": channel, "tunnel": status})
}

func (m *accessManager) startTunnelLocked() error {
	session := m.tunnelSession.Load()
	if !m.isTunnelEnabled() || session == nil || session.ctx.Err() != nil || session.host.Load() != nil {
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
	m.tunnelOpMu.Lock()
	defer m.tunnelOpMu.Unlock()
	if session.ctx.Err() != nil {
		return
	}
	m.stopTunnelLocked()
	m.tunnelSession.Store(session)
	_ = m.startTunnelLocked()
}

func (m *accessManager) stopTunnelLocked() {
	if session := m.tunnelSession.Load(); session != nil {
		if session.graceTimer != nil {
			session.graceTimer.Stop()
			session.graceTimer = nil
		}
		if host := session.host.Swap(nil); host != nil {
			host.Stop()
		}
	}
}

func (m *accessManager) stopTunnelChannel(channel string) {
	m.tunnelOpMu.Lock()
	defer m.tunnelOpMu.Unlock()
	if session := m.tunnelSession.Load(); session != nil && session.channel == channel {
		m.stopTunnelLocked()
		m.tunnelSession.Store(nil)
	}
}

func (m *accessManager) endTunnelSession(session *tunnelSession) {
	m.tunnelOpMu.Lock()
	defer m.tunnelOpMu.Unlock()
	if session != nil && m.tunnelSession.Load() == session {
		m.stopTunnelLocked()
		m.tunnelSession.Store(nil)
	}
}

func (m *accessManager) deferEndTunnelSession(session *tunnelSession, grace time.Duration) {
	if session == nil {
		return
	}
	m.tunnelOpMu.Lock()
	defer m.tunnelOpMu.Unlock()
	if m.tunnelSession.Load() != session {
		return
	}
	if session.graceTimer != nil {
		session.graceTimer.Stop()
	}
	session.graceTimer = time.AfterFunc(grace, func() {
		m.endTunnelSession(session)
	})
}

func (m *accessManager) tunnelCommand(cmd accessCommand, result map[string]any) error {
	switch cmd.Type {
	case "access.tunnel.status":
		result["type"] = "tunnel.status"
	case "access.tunnel.set":
		if cmd.Enabled == nil {
			return errors.New("enabled is required")
		}
		m.tunnelOpMu.Lock()
		hadHost := m.currentTunnelHost() != nil
		m.tunnelMu.Lock()
		changed := m.tunnelEnabled != *cmd.Enabled
		m.tunnelEnabled = *cmd.Enabled
		enabled := m.tunnelEnabled
		m.tunnelMu.Unlock()
		var err error
		if enabled {
			err = m.startTunnelLocked()
		} else {
			m.stopTunnelLocked()
		}
		status := m.tunnelStatus()
		m.tunnelOpMu.Unlock()
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
		OnNetworkChange: func() {
			if session := m.selfTunnelSession(); session != nil {
				if host := session.host.Load(); host != nil {
					host.RecheckPeers()
				}
			}
		},
	})
}

func bindOfficialSocketTunnelHooks(socket *transport.Client, session *tunnelSession) {
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
}

func (m *accessManager) setOfficialTunnelHooks(ctx context.Context, slot *officialSlot, socket *transport.Client) *tunnelSession {
	if socket.TunnelScope() == "" {
		return nil
	}
	slot.updateTunnelGuests(m.config(), socket.UserID())
	socket.SetPairedTunnelAuthorizer(slot.authorizeTunnel)

	m.tunnelOpMu.Lock()
	defer m.tunnelOpMu.Unlock()
	if cur := m.tunnelSession.Load(); cur != nil && cur.channel == slot.name && cur.slot == slot &&
		cur.deviceID == socket.DeviceID() && cur.ownerID == socket.UserID() && cur.ctx.Err() == nil {
		if cur.graceTimer != nil {
			cur.graceTimer.Stop()
			cur.graceTimer = nil
		}
		cur.socket.Store(socket)
		bindOfficialSocketTunnelHooks(socket, cur)
		if host := cur.host.Load(); host != nil {
			host.ReattachSignal(socket.TunnelScope(), socket.SendTunnel)
			return cur
		}
		_ = m.startTunnelLocked()
		return cur
	}

	session := &tunnelSession{
		ctx:      ctx,
		channel:  slot.name,
		slot:     slot,
		deviceID: socket.DeviceID(),
		ownerID:  socket.UserID(),
	}
	session.socket.Store(socket)
	bindOfficialSocketTunnelHooks(socket, session)
	session.options = func(ctx context.Context) (cftunnel.HostOptions, error) {
		sock := session.socket.Load()
		if sock == nil {
			return cftunnel.HostOptions{}, transport.ErrPeerClosed
		}
		origin, err := cftunnel.ControlOriginFromSignalURL(sock.SignalURL())
		if err != nil {
			return cftunnel.HostOptions{}, err
		}
		creds, _, err := sock.CurrentLease(ctx)
		if err != nil {
			return cftunnel.HostOptions{}, err
		}
		return cftunnel.HostOptions{
			Channel: slot.name, Scope: sock.TunnelScope(), ControlOrigin: origin, DeviceID: sock.DeviceID(),
			OwnerID: sock.UserID(), PrivateKey: creds.PrivateKey(), CA: slot.ca, Handler: sock.TunnelHandler(),
			SendSignal: func(msg protocol.Message) error {
				if cur := session.socket.Load(); cur != nil {
					return cur.SendTunnel(msg)
				}
				return transport.ErrPeerClosed
			},
			LeaseSource: func(ctx context.Context) (endpoint.LeaseProof, error) {
				cur := session.socket.Load()
				if cur == nil {
					return endpoint.LeaseProof{}, transport.ErrPeerClosed
				}
				_, proof, err := cur.CurrentLease(ctx)
				return proof, err
			},
			AuthorizeOffer: func(req cftunnel.OfferRequest) (cftunnel.OfferDecision, error) {
				user := req.Principal.RemoteUserID()
				allows := func() bool {
					cur := session.socket.Load()
					allowed := slot.tunnelGuests.Load()
					return cur != nil && allowed != nil && (*allowed)[user] && cur.AuthorizePairedTunnel(req.ConnectionID, req.Principal, req.Role)
				}
				if !allows() {
					return cftunnel.OfferDecision{}, transport.ErrUnauthorized
				}
				return cftunnel.OfferDecision{UserID: user, Allows: allows}, nil
			},
		}, nil
	}
	if session.ctx.Err() != nil {
		return nil
	}
	m.stopTunnelLocked()
	m.tunnelSession.Store(session)
	_ = m.startTunnelLocked()
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
	if session := m.tunnelSession.Load(); session != nil && session.slot != nil {
		slot := session.slot
		slot.updateTunnelGuests(cfg, slot.account.UserID())
		if host := session.host.Load(); host != nil {
			host.RecheckPeers()
		}
	}
}
