package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/desktop"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/transport"
)

type accessOptions struct {
	lanListen    string
	relayEnabled bool
	token        string
}

type accessCommand struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Token     string `json:"token"`
	Enabled   *bool  `json:"enabled"`
	Address   string `json:"address"`
	Access    string `json:"access"`
	ID        string `json:"id"`
}

type accessManager struct {
	ctx     context.Context
	account *account.Account
	ca      ed25519.PublicKey
	url     string
	name    string
	service *desktop.Adapter
	dir     string
	emitter *jsonEmitter
	config  func() *desktop.Config
	updates <-chan struct{}
	retry   chan struct{}

	mu               sync.Mutex
	local            *lan.Server
	relayEnabled     bool
	requireHostToken bool
	token            string
	stopRelay        context.CancelFunc
	relayDone        chan struct{}
	online           atomic.Bool
	verified         atomic.Bool
}

func (m *accessManager) userID() string {
	if m.account == nil {
		return ""
	}
	return m.account.UserID()
}

func (m *accessManager) deviceID() string {
	if m.account == nil {
		return ""
	}
	return m.account.DeviceID()
}

func (m *accessManager) status() map[string]any {
	status := lan.Status{Clients: []lan.ClientInfo{}, Invitations: []lan.Invitation{}}
	if m.local != nil {
		status = m.local.Status()
	}
	return map[string]any{
		"type": "access.status", "lan": status,
		"relay_configured": m.account != nil && m.url != "", "relay_enabled": m.relayEnabled,
		"relay_authorized": m.verified.Load(), "relay_online": m.online.Load(),
	}
}

func (m *accessManager) loadLAN() error {
	if m.local != nil {
		return nil
	}
	local, err := lan.OpenServer(namedVault(m.dir, "lan.enc", "lan"), m.service)
	if err != nil {
		return err
	}
	m.local = local
	m.service.SetLANAuthority(local.Allows)
	return nil
}

func (m *accessManager) loadExistingLAN() error {
	if m.local != nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(m.dir, "lan.enc")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return m.loadLAN()
}

func (m *accessManager) listen(address string) error {
	if err := m.loadLAN(); err != nil {
		return err
	}
	return m.local.Listen(m.ctx, address)
}

func (m *accessManager) command(cmd accessCommand) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return
	}
	result := map[string]any{"type": "access.ok", "request_id": cmd.RequestID}
	var err error
	switch cmd.Type {
	case "access.status":
		err = m.loadExistingLAN()
		result = m.status()
		result["request_id"] = cmd.RequestID
	case "access.lan.set":
		switch {
		case cmd.Enabled == nil:
			err = errors.New("enabled is required")
		case *cmd.Enabled:
			if m.local == nil || !m.local.Status().Enabled {
				err = m.listen(cmd.Address)
			}
		case m.local != nil:
			m.local.Stop()
			m.service.RefreshLANAccess()
		}
	case "access.relay.set":
		switch {
		case cmd.Enabled == nil:
			err = errors.New("enabled is required")
		case *cmd.Enabled && (m.account == nil || m.url == ""):
			err = errors.New("official relay is not configured")
		case *cmd.Enabled && m.requireHostToken && m.token == "":
			err = errors.New("Vanora sign-in required")
		default:
			m.relayEnabled = *cmd.Enabled
			if m.relayEnabled {
				m.startRelay()
			} else {
				m.stopOfficial()
			}
		}
	case "access.invite.create":
		if m.local == nil {
			err = errors.New("LAN listener is disabled")
			break
		}
		level := cmd.Access
		if level == "" {
			level = lan.Read
		}
		var invite lan.Invitation
		var link string
		invite, link, err = m.local.Invite(level)
		result["type"], result["invitation"], result["link"] = "access.invite.created", invite, link
	case "access.invite.revoke":
		if m.local == nil || !m.local.RevokeInvitation(cmd.ID) {
			err = errors.New("unknown pairing link")
		}
	case "access.client.revoke", "access.clients.revoke":
		if err = m.loadExistingLAN(); err != nil {
			break
		}
		switch {
		case m.local == nil:
			err = errors.New("LAN sharing has not been opened")
		case cmd.Type == "access.clients.revoke":
			err = m.local.RevokeClients("")
		case cmd.ID == "":
			err = errors.New("client ID required")
		default:
			err = m.local.RevokeClients(cmd.ID)
		}
		if err == nil {
			m.service.RefreshLANAccess()
		}
	case "auth.token":
		m.updateToken(cmd.Token)
		return
	case "auth.logout":
		m.stopOfficial()
		m.token = ""
		if m.account != nil && m.account.UserID() != "" {
			err = m.account.Reset()
		}
		result["type"] = "auth.logout.ok"
	default:
		return
	}
	if err != nil {
		result = map[string]any{"type": "access.error", "request_id": cmd.RequestID, "error": err.Error()}
	}
	m.emitter.Emit(result)
	if err == nil && cmd.Type != "access.status" {
		m.emitter.Emit(m.status())
	}
}

func (m *accessManager) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.local != nil {
		m.local.Stop()
		m.service.RefreshLANAccess()
	}
	m.stopOfficial()
}

func (m *accessManager) updateToken(token string) {
	token = strings.TrimSpace(token)
	if m.account == nil || m.url == "" || token == "" || len(token) > 16<<10 {
		m.emitter.Emit(map[string]any{"type": "auth.error", "error": "configured official relay and a valid host token required"})
		return
	}
	m.token = token
	if !m.verified.Load() && m.relayDone != nil {
		m.stopOfficial()
	}
	if m.relayDone == nil && m.relayEnabled {
		m.startRelay()
		return
	}
	if err := m.account.UpdateToken(token); err != nil {
		m.emitter.Emit(map[string]any{"type": "auth.error", "error": err.Error()})
		return
	}
	m.emitter.Emit(map[string]any{"type": "auth.ok"})
	select {
	case m.retry <- struct{}{}:
	default:
	}
}

func (m *accessManager) startRelay() {
	if m.relayDone != nil || !m.relayEnabled || (m.requireHostToken && m.token == "") || m.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	done := make(chan struct{})
	m.stopRelay, m.relayDone = cancel, done
	token := m.token
	go func() {
		defer close(done)
		defer m.verified.Store(false)
		defer m.setOnline(false, "")
		if token != "" {
			authCtx, stop := context.WithTimeout(ctx, 30*time.Second)
			err := m.account.Enroll(authCtx, token)
			stop()
			if err != nil {
				if ctx.Err() == nil {
					m.reportOffline(err)
					m.emitter.Emit(map[string]any{"type": "auth.error", "error": err.Error()})
				}
				return
			}
			m.verified.Store(true)
			m.emitter.Emit(map[string]any{"type": "auth.ok", "user_id": m.userID(), "device_id": m.deviceID()})
		}
		m.runRelay(ctx)
	}()
}

func (m *accessManager) stopOfficial() {
	if m.stopRelay == nil {
		return
	}
	m.stopRelay()
	<-m.relayDone
	m.stopRelay, m.relayDone = nil, nil
	m.service.SetOfficialOwner("")
	m.service.AuthorityLost()
}

func (m *accessManager) runRelay(ctx context.Context) {
	source := &authority{account: m.account, adapter: m.service, ca: m.ca}
	for delay := time.Second; ctx.Err() == nil; {
		socket, err := transport.Dial(ctx, m.url, "desktop", source, m.service)
		if err == nil {
			err = m.publish(ctx, socket)
			if err == nil {
				m.verified.Store(true)
				delay = time.Second
				m.setOnline(true, "")
			online:
				for {
					select {
					case <-ctx.Done():
						break online
					case <-socket.Done():
						break online
					case <-m.updates:
						if err = m.publish(ctx, socket); err != nil {
							break online
						}
					}
				}
			}
			socket.Close()
		}
		if ctx.Err() != nil {
			return
		}
		m.reportOffline(err)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-m.retry:
			timer.Stop()
			delay = time.Second
		case <-timer.C:
			delay = min(delay*2, 10*time.Second)
		}
	}
}

func (m *accessManager) publish(ctx context.Context, socket *transport.Client) error {
	user := m.account.UserID()
	allowed, err := guests(m.config(), user)
	if err != nil {
		return err
	}
	m.service.SetOfficialOwner(user)
	return publish(ctx, socket, m.name, allowed)
}

func (m *accessManager) reportOffline(err error) {
	reason := ""
	if err != nil {
		reason = err.Error()
		if isAuthRequiredError(err) {
			m.emitter.Emit(map[string]any{"type": "auth.required", "error": reason})
		}
	}
	m.setOnline(false, reason)
}

func (m *accessManager) setOnline(online bool, reason string) {
	wasOnline := m.online.Swap(online)
	if online {
		m.emitter.Emit(map[string]any{
			"type": "online", "device_id": m.deviceID(), "user_id": m.userID(), "name": strings.TrimSpace(m.name),
		})
		if m.emitter == nil {
			log.Printf("desktop online: %s", m.deviceID())
		}
	} else if wasOnline || reason != "" {
		m.emitter.Emit(map[string]any{"type": "offline", "device_id": m.deviceID(), "error": reason})
		if m.emitter == nil && reason != "" {
			log.Printf("desktop offline: %s", reason)
		}
	}
}
