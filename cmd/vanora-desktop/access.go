package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
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
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
)

type accessOptions struct {
	lanListen     string
	relayEnabled  bool
	activeChannel string
	selfURL       string
	selfToken     string
	selfStore     selfrelay.Store
	token         string
	tokens        map[string]string
}

type accessCommand struct {
	Type         string `json:"type"`
	RequestID    string `json:"request_id"`
	Channel      string `json:"channel"`
	Token        string `json:"token"`
	SignalURL    string `json:"signal_url"`
	SignalToken  string `json:"signal_token"`
	Enabled      *bool  `json:"enabled"`
	IncludeToken *bool  `json:"include_token"`
	Address      string `json:"address"`
	Access       string `json:"access"`
	ID           string `json:"id"`
}

type officialSlot struct {
	name     string
	account  *account.Account
	ca       ed25519.PublicKey
	url      string
	token    string
	online   atomic.Bool
	verified atomic.Bool
}

type accessManager struct {
	ctx              context.Context
	slots            map[string]*officialSlot
	name             string
	service          *desktop.Adapter
	dir              string
	emitter          *jsonEmitter
	config           func() *desktop.Config
	updates          <-chan struct{}
	retry            chan struct{}
	requireHostToken bool

	mu            sync.Mutex
	local         *lan.Server
	selfServer    *selfrelay.Server
	selfStore     selfrelay.Store
	selfURL       string
	selfToken     string
	activeChannel string // "", "cn", "global", or "self"
	activeSlot    *officialSlot
	stopRelay     context.CancelFunc
	relayDone     chan struct{}
}

func (m *accessManager) primaryOfficialSlotLocked() *officialSlot {
	if m.activeSlot != nil {
		return m.activeSlot
	}
	if slot := m.slots[m.activeChannel]; slot != nil {
		return slot
	}
	if len(m.slots) == 1 {
		for _, slot := range m.slots {
			return slot
		}
	}
	return nil
}

func (m *accessManager) currentChannel() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeChannel
}

func (m *accessManager) isOnline() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.activeChannel {
	case "cn", "global":
		if slot := m.slots[m.activeChannel]; slot != nil {
			return slot.online.Load()
		}
	case "self":
		if m.selfServer != nil {
			return m.selfServer.Status().Online
		}
	}
	return false
}

func (m *accessManager) userID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if slot := m.primaryOfficialSlotLocked(); slot != nil && slot.account != nil {
		return slot.account.UserID()
	}
	return ""
}

func (m *accessManager) deviceID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeChannel == "self" && m.selfServer != nil {
		return m.selfServer.DeviceID()
	}
	if slot := m.primaryOfficialSlotLocked(); slot != nil && slot.account != nil {
		return slot.account.DeviceID()
	}
	return ""
}

func (m *accessManager) statusLocked() map[string]any {
	lanStatus := lan.Status{Clients: []lan.ClientInfo{}, Invitations: []lan.Invitation{}}
	if m.local != nil {
		lanStatus = m.local.Status()
	}
	selfStatus := selfrelay.Status{Clients: []selfrelay.ClientInfo{}, Invitations: []selfrelay.Invitation{}}
	if m.selfServer != nil {
		selfStatus = m.selfServer.Status()
	}
	channels := map[string]any{
		"self": selfStatus,
	}
	for _, ch := range []string{"cn", "global"} {
		slot := m.slots[ch]
		if slot == nil {
			channels[ch] = map[string]any{
				"configured": false,
				"enrolled":   false,
				"authorized": false,
				"online":     false,
				"user_id":    "",
				"device_id":  "",
			}
			continue
		}
		channels[ch] = map[string]any{
			"configured": slot.account != nil && slot.url != "",
			"enrolled":   slot.account != nil && slot.account.UserID() != "",
			"authorized": slot.verified.Load(),
			"online":     slot.online.Load(),
			"user_id":    slot.account.UserID(),
			"device_id":  slot.account.DeviceID(),
		}
	}

	relayConfigured := false
	relayEnabled := m.activeChannel != ""
	relayAuthorized := false
	relayOnline := false
	switch m.activeChannel {
	case "cn", "global":
		if slot := m.slots[m.activeChannel]; slot != nil {
			relayConfigured = slot.account != nil && slot.url != ""
			relayAuthorized = slot.verified.Load()
			relayOnline = slot.online.Load()
		}
	case "self":
		relayConfigured = m.selfURL != "" && m.selfToken != ""
		relayAuthorized = selfStatus.Online
		relayOnline = selfStatus.Online
	default:
		if slot := m.primaryOfficialSlotLocked(); slot != nil {
			relayConfigured = slot.account != nil && slot.url != ""
			relayAuthorized = slot.verified.Load()
			relayOnline = slot.online.Load()
		}
	}
	return map[string]any{
		"type":             "access.status",
		"active_channel":   m.activeChannel,
		"channels":         channels,
		"lan":              lanStatus,
		"relay_configured": relayConfigured,
		"relay_enabled":    relayEnabled,
		"relay_authorized": relayAuthorized,
		"relay_online":     relayOnline,
	}
}

func (m *accessManager) loadLANLocked() error {
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

func (m *accessManager) loadExistingLANLocked() error {
	if m.local != nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(m.dir, "lan.enc")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return m.loadLANLocked()
}

func (m *accessManager) loadSelfLocked() error {
	if m.selfServer != nil {
		return nil
	}
	store := m.selfStore
	if store == nil {
		store = namedVault(m.dir, "self.enc", "self")
	}
	srv, err := selfrelay.OpenServer(store, m.service)
	if err != nil {
		return err
	}
	srv.SetObserver(func(online bool, reason string) {
		if online {
			m.emitter.Emit(map[string]any{
				"type":      "online",
				"channel":   "self",
				"device_id": srv.DeviceID(),
				"name":      strings.TrimSpace(m.name),
			})
			if m.emitter == nil {
				log.Printf("desktop self-relay online: %s", srv.DeviceID())
			}
		} else {
			m.emitter.Emit(map[string]any{
				"type":      "offline",
				"channel":   "self",
				"device_id": srv.DeviceID(),
				"error":     reason,
			})
			if m.emitter == nil && reason != "" {
				log.Printf("desktop self-relay offline: %s", reason)
			}
		}
	})
	m.selfServer = srv
	m.service.SetSelfAuthority(srv.Allows)
	return nil
}

func (m *accessManager) loadExistingSelfLocked() error {
	if m.selfServer != nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(m.dir, "self.enc")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return m.loadSelfLocked()
}

func (m *accessManager) listen(address string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.loadLANLocked(); err != nil {
		return err
	}
	return m.local.Listen(m.ctx, address)
}

func (m *accessManager) resolveOfficialChannelLocked(raw string) (*officialSlot, error) {
	ch := strings.ToLower(strings.TrimSpace(raw))
	if ch == "self" {
		return nil, errors.New("self-hosted relay uses pairing and does not use account tokens")
	}
	if ch == "" {
		if m.activeChannel == "cn" || m.activeChannel == "global" {
			ch = m.activeChannel
		} else if len(m.slots) == 1 {
			for k := range m.slots {
				ch = k
			}
		} else if len(m.slots) > 1 {
			return nil, errors.New("channel is required (cn or global)")
		}
	}
	if ch != "cn" && ch != "global" {
		return nil, fmt.Errorf("unknown official channel %q (want cn or global)", ch)
	}
	slot := m.slots[ch]
	if slot == nil || slot.account == nil || slot.url == "" {
		return nil, fmt.Errorf("official relay channel %s is not configured", ch)
	}
	return slot, nil
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
		if err = m.loadExistingLANLocked(); err == nil {
			err = m.loadExistingSelfLocked()
		}
		result = m.statusLocked()
		result["request_id"] = cmd.RequestID
	case "access.lan.set":
		switch {
		case cmd.Enabled == nil:
			err = errors.New("enabled is required")
		case *cmd.Enabled:
			if m.local == nil || !m.local.Status().Enabled {
				if err = m.loadLANLocked(); err == nil {
					err = m.local.Listen(m.ctx, cmd.Address)
				}
			}
		case m.local != nil:
			m.local.Stop()
			m.service.RefreshLANAccess()
		}
	case "access.relay.set":
		if cmd.Enabled == nil {
			err = errors.New("enabled is required")
			break
		}
		err = m.setRelayLocked(*cmd.Enabled, cmd.Channel, cmd.SignalURL, cmd.SignalToken)
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
		if err = m.loadExistingLANLocked(); err != nil {
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
	case "access.self.invite.create":
		if m.selfServer == nil || !m.selfServer.Status().Enabled {
			err = errors.New("self-hosted relay is disabled")
			break
		}
		level := cmd.Access
		if level == "" {
			level = selfrelay.Read
		}
		includeToken := true
		if cmd.IncludeToken != nil {
			includeToken = *cmd.IncludeToken
		}
		var invite selfrelay.Invitation
		var link string
		invite, link, err = m.selfServer.Invite(level, includeToken)
		result["type"], result["invitation"], result["link"] = "access.self.invite.created", invite, link
	case "access.self.invite.revoke":
		if m.selfServer == nil || !m.selfServer.RevokeInvitation(cmd.ID) {
			err = errors.New("unknown self-relay pairing link")
		}
	case "access.self.client.revoke", "access.self.clients.revoke":
		if err = m.loadExistingSelfLocked(); err != nil {
			break
		}
		switch {
		case m.selfServer == nil:
			err = errors.New("self-hosted relay has not been opened")
		case cmd.Type == "access.self.clients.revoke":
			err = m.selfServer.RevokeClients("")
		case cmd.ID == "":
			err = errors.New("client ID required")
		default:
			err = m.selfServer.RevokeClients(cmd.ID)
		}
		if err == nil {
			m.service.RefreshSelfAccess()
		}
	case "auth.token":
		m.updateTokenLocked(cmd.Channel, cmd.Token)
		return
	case "auth.logout":
		slot, slotErr := m.resolveOfficialChannelLocked(cmd.Channel)
		if slotErr != nil {
			err = slotErr
			break
		}
		if m.activeChannel == slot.name {
			m.stopOfficialLocked()
			m.activeChannel = ""
		}
		slot.token = ""
		slot.verified.Store(false)
		slot.online.Store(false)
		if slot.account != nil && slot.account.UserID() != "" {
			err = slot.account.Reset()
		}
		result["type"] = "auth.logout.ok"
		result["channel"] = slot.name
	default:
		return
	}
	if err != nil {
		result = map[string]any{"type": "access.error", "request_id": cmd.RequestID, "error": err.Error()}
	}
	m.emitter.Emit(result)
	if err == nil && cmd.Type != "access.status" {
		m.emitter.Emit(m.statusLocked())
	}
}

func (m *accessManager) setRelayLocked(enabled bool, rawChannel, signalURL, signalToken string) error {
	if !enabled {
		m.stopAllWANLocked()
		m.activeChannel = ""
		return nil
	}
	ch := strings.ToLower(strings.TrimSpace(rawChannel))
	if ch == "" {
		if m.activeChannel != "" {
			ch = m.activeChannel
		} else if len(m.slots) == 1 {
			for k := range m.slots {
				ch = k
			}
		} else {
			return errors.New("channel is required (cn, global, or self)")
		}
	}
	switch ch {
	case "cn", "global":
		slot := m.slots[ch]
		if slot == nil || slot.account == nil || slot.url == "" {
			return fmt.Errorf("official relay channel %s is not configured", ch)
		}
		if m.requireHostToken && slot.token == "" {
			return fmt.Errorf("Vanora sign-in required for %s channel", ch)
		}
		if m.activeChannel == ch && m.relayDone != nil {
			return nil
		}
		m.stopAllWANLocked()
		m.activeChannel = ch
		return m.startOfficialLocked(slot)
	case "self":
		url := strings.TrimSpace(signalURL)
		if url == "" {
			url = m.selfURL
		}
		tok := strings.TrimSpace(signalToken)
		if tok == "" {
			tok = m.selfToken
		}
		if err := selfrelay.ValidateSignalURL(url); err != nil {
			return err
		}
		if err := selfrelay.ValidateRelayToken(tok); err != nil {
			return err
		}
		if m.activeChannel == "self" && m.selfServer != nil && m.selfServer.Status().Enabled && m.selfURL == url && m.selfToken == tok {
			return nil
		}
		m.stopAllWANLocked()
		m.selfURL = url
		m.selfToken = tok
		if err := m.startSelfLocked(); err != nil {
			m.activeChannel = ""
			return err
		}
		m.activeChannel = "self"
		return nil
	default:
		return fmt.Errorf("unknown relay channel %q (want cn, global or self)", ch)
	}
}

func (m *accessManager) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.local != nil {
		m.local.Stop()
		m.service.RefreshLANAccess()
	}
	m.stopAllWANLocked()
}

func (m *accessManager) updateTokenLocked(rawChannel, token string) {
	token = strings.TrimSpace(token)
	slot, err := m.resolveOfficialChannelLocked(rawChannel)
	if err != nil || token == "" || len(token) > 16<<10 {
		msg := "configured official relay and a valid host token required"
		if err != nil {
			msg = err.Error()
		}
		ev := map[string]any{"type": "auth.error", "error": msg}
		if strings.TrimSpace(rawChannel) != "" {
			ev["channel"] = strings.ToLower(strings.TrimSpace(rawChannel))
		}
		m.emitter.Emit(ev)
		return
	}
	slot.token = token
	if m.activeChannel == slot.name {
		if !slot.verified.Load() && m.relayDone != nil {
			m.stopOfficialLocked()
		}
		if m.relayDone == nil {
			_ = m.startOfficialLocked(slot)
			return
		}
		if err := slot.account.UpdateToken(token); err != nil {
			m.emitter.Emit(map[string]any{"type": "auth.error", "channel": slot.name, "error": err.Error()})
			return
		}
		m.emitter.Emit(map[string]any{"type": "auth.ok", "channel": slot.name, "user_id": slot.account.UserID(), "device_id": slot.account.DeviceID()})
		select {
		case m.retry <- struct{}{}:
		default:
		}
		return
	}
	if err := slot.account.UpdateToken(token); err != nil {
		m.emitter.Emit(map[string]any{"type": "auth.error", "channel": slot.name, "error": err.Error()})
		return
	}
	m.emitter.Emit(map[string]any{"type": "auth.ok", "channel": slot.name, "user_id": slot.account.UserID(), "device_id": slot.account.DeviceID()})
}

func (m *accessManager) startActiveWANLocked() error {
	switch m.activeChannel {
	case "cn", "global":
		slot := m.slots[m.activeChannel]
		if slot == nil {
			return nil
		}
		return m.startOfficialLocked(slot)
	case "self":
		return m.startSelfLocked()
	default:
		return nil
	}
}

func (m *accessManager) startSelfLocked() error {
	if m.ctx.Err() != nil {
		return m.ctx.Err()
	}
	if err := m.loadSelfLocked(); err != nil {
		return err
	}
	return m.selfServer.Connect(m.ctx, m.selfURL, m.selfToken, m.name)
}

func (m *accessManager) stopSelfLocked() {
	if m.selfServer != nil {
		m.selfServer.Stop()
		m.service.RefreshSelfAccess()
	}
}

func (m *accessManager) stopAllWANLocked() {
	m.stopOfficialLocked()
	m.stopSelfLocked()
}

func (m *accessManager) startOfficialLocked(slot *officialSlot) error {
	if slot == nil || m.relayDone != nil || (m.requireHostToken && slot.token == "") || m.ctx.Err() != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(m.ctx)
	done := make(chan struct{})
	m.stopRelay, m.relayDone, m.activeSlot = cancel, done, slot
	token := slot.token
	go func() {
		defer close(done)
		defer slot.verified.Store(false)
		defer m.setOnline(slot, false, "")
		if token != "" {
			authCtx, stop := context.WithTimeout(ctx, 30*time.Second)
			err := slot.account.Enroll(authCtx, token)
			stop()
			if err != nil {
				if ctx.Err() == nil {
					m.reportOffline(slot, err)
					m.emitter.Emit(map[string]any{"type": "auth.error", "channel": slot.name, "error": err.Error()})
				}
				return
			}
			slot.verified.Store(true)
			m.emitter.Emit(map[string]any{
				"type":      "auth.ok",
				"channel":   slot.name,
				"user_id":   slot.account.UserID(),
				"device_id": slot.account.DeviceID(),
			})
		}
		m.runOfficialRelay(ctx, slot)
	}()
	return nil
}

func (m *accessManager) stopOfficialLocked() {
	if m.stopRelay == nil {
		return
	}
	m.stopRelay()
	<-m.relayDone
	m.stopRelay, m.relayDone, m.activeSlot = nil, nil, nil
	m.service.SetOfficialOwner("")
	m.service.AuthorityLost()
}

func (m *accessManager) runOfficialRelay(ctx context.Context, slot *officialSlot) {
	source := &authority{account: slot.account, adapter: m.service, ca: slot.ca}
	for delay := time.Second; ctx.Err() == nil; {
		socket, err := transport.Dial(ctx, slot.url, "desktop", source, m.service)
		if err == nil {
			err = m.publish(ctx, slot, socket)
			if err == nil {
				slot.verified.Store(true)
				delay = time.Second
				m.setOnline(slot, true, "")
			online:
				for {
					select {
					case <-ctx.Done():
						break online
					case <-socket.Done():
						break online
					case <-m.updates:
						if err = m.publish(ctx, slot, socket); err != nil {
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
		m.reportOffline(slot, err)
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

func (m *accessManager) publish(ctx context.Context, slot *officialSlot, socket *transport.Client) error {
	user := slot.account.UserID()
	allowed, err := guests(m.config(), user)
	if err != nil {
		return err
	}
	m.service.SetOfficialOwner(user)
	return publish(ctx, socket, m.name, allowed)
}

func (m *accessManager) reportOffline(slot *officialSlot, err error) {
	reason := ""
	if err != nil {
		reason = err.Error()
		if isAuthRequiredError(err) {
			m.emitter.Emit(map[string]any{"type": "auth.required", "channel": slot.name, "error": reason})
		}
	}
	m.setOnline(slot, false, reason)
}

func (m *accessManager) setOnline(slot *officialSlot, online bool, reason string) {
	wasOnline := slot.online.Swap(online)
	if online {
		m.emitter.Emit(map[string]any{
			"type":      "online",
			"channel":   slot.name,
			"device_id": slot.account.DeviceID(),
			"user_id":   slot.account.UserID(),
			"name":      strings.TrimSpace(m.name),
		})
		if m.emitter == nil {
			log.Printf("desktop online (%s): %s", slot.name, slot.account.DeviceID())
		}
	} else if wasOnline || reason != "" {
		m.emitter.Emit(map[string]any{
			"type":      "offline",
			"channel":   slot.name,
			"device_id": slot.account.DeviceID(),
			"error":     reason,
		})
		if m.emitter == nil && reason != "" {
			log.Printf("desktop offline (%s): %s", slot.name, reason)
		}
	}
}
