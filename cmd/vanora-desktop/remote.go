package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"vanora-relay/adapter/remote"
	"vanora-relay/adapter/transport"
)

func (m *accessManager) initRemote() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil || m.remote != nil {
		return
	}
	m.remote = remote.NewManager(m.ctx, m, func(ev map[string]any) {
		m.emitter.Emit(ev)
	})
}

func (m *accessManager) remoteManager() *remote.Manager {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil {
		return nil
	}
	if m.remote == nil {
		m.remote = remote.NewManager(m.ctx, m, func(ev map[string]any) {
			m.emitter.Emit(ev)
		})
	}
	return m.remote
}

func (m *accessManager) dispatchRemoteCommand(cmd accessCommand) {
	m.mu.Lock()
	if m.closed || m.ctx.Err() != nil {
		m.mu.Unlock()
		return
	}
	m.remoteWG.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.remoteWG.Done()
		m.remoteCommand(cmd)
	}()
}

func (m *accessManager) onNetworkChanged(channel string) {
	go func() {
		m.mu.Lock()
		rm := m.remote
		m.mu.Unlock()
		if rm != nil {
			rm.OnNetworkChanged(channel)
		}
	}()
}

// remote.Provider implementation on accessManager.

func (m *accessManager) DesktopName() string {
	return strings.TrimSpace(m.name)
}

func (m *accessManager) ListOfficialChannels() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.slots))
	for k, slot := range m.slots {
		if slot != nil && slot.account != nil && slot.url != "" {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func (m *accessManager) Official(channel string) (*remote.OfficialChannel, error) {
	ch := strings.ToLower(strings.TrimSpace(channel))
	m.mu.Lock()
	slot := m.slots[ch]
	if slot == nil || slot.account == nil || slot.url == "" {
		m.mu.Unlock()
		return nil, fmt.Errorf("official relay channel %s is not configured", ch)
	}
	token := slot.token
	acc := slot.account
	url := slot.url
	m.mu.Unlock()

	if acc.UserID() == "" && token != "" {
		enrollCtx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
		err := acc.Enroll(enrollCtx, token)
		cancel()
		if err != nil {
			return nil, err
		}
	}
	return &remote.OfficialChannel{
		Channel:    ch,
		SignalURL:  url,
		Account:    acc,
		Source:     acc,
		LiveSocket: slot.socket.Load,
	}, nil
}

func (m *accessManager) Self() (*remote.SelfChannel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.loadSelfLocked(); err != nil {
		return nil, err
	}
	return &remote.SelfChannel{
		SignalURL: m.selfURL,
		Token:     m.selfToken,
		Server:    m.selfServer,
	}, nil
}

func (m *accessManager) LAN() (*remote.LANChannel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.loadLANLocked(); err != nil {
		return nil, err
	}
	return &remote.LANChannel{
		Server: m.local,
	}, nil
}

var errTransitiveDelegation = errors.New("transitive peer delegation is not permitted from a linked session")

func isOutboundMutationCommand(cmdType string) bool {
	switch cmdType {
	case "remote.pair", "remote.session.create", "remote.run.start", "remote.run.cancel", "remote.ui.respond", "remote.guest.request", "remote.guest.respond":
		return true
	default:
		return false
	}
}

// remoteCommand handles outbound remote.* Sidecar commands without holding
// accessManager.mu during network I/O.
func (m *accessManager) remoteCommand(cmd accessCommand) {
	if m.ctx.Err() != nil {
		return
	}
	rm := m.remoteManager()
	if rm == nil {
		return
	}
	output := m.emitter
	if output == nil {
		output = &jsonEmitter{out: os.Stdout}
	}
	emitErr := func(err error) {
		ev := map[string]any{
			"type":       "remote.error",
			"request_id": cmd.RequestID,
			"error":      err.Error(),
		}
		if cmd.PeerID != "" {
			ev["peer_id"] = cmd.PeerID
		}
		if code := remoteErrorCode(err); code != "" {
			ev["code"] = code
		}
		output.Emit(ev)
	}
	if strings.TrimSpace(os.Getenv("VANORA_LINK_ORIGIN")) != "" && isOutboundMutationCommand(cmd.Type) {
		emitErr(errTransitiveDelegation)
		return
	}
	emitData := func(data json.RawMessage) {
		output.Emit(map[string]any{
			"type":       "remote.result",
			"request_id": cmd.RequestID,
			"peer_id":    cmd.PeerID,
			"data":       data,
		})
	}

	ctx := m.ctx
	switch cmd.Type {
	case "remote.peers.list":
		peers, err := rm.ListPeers(ctx, cmd.Channel)
		if err != nil {
			emitErr(err)
			return
		}
		output.Emit(map[string]any{
			"type":       "remote.peers",
			"request_id": cmd.RequestID,
			"peers":      peers,
		})
	case "remote.pair":
		info, err := rm.Pair(ctx, remote.PairOptions{
			Channel:     cmd.Channel,
			Input:       cmd.Input,
			SignalURL:   cmd.SignalURL,
			SignalToken: cmd.SignalToken,
			GrantAccess: cmd.GrantAccess,
		})
		if err != nil {
			emitErr(err)
			return
		}
		output.Emit(map[string]any{
			"type":       "remote.paired",
			"request_id": cmd.RequestID,
			"peer":       info,
		})
	case "remote.connect":
		info, err := rm.Connect(ctx, cmd.Channel, cmd.PeerID)
		if err != nil {
			emitErr(err)
			return
		}
		output.Emit(map[string]any{
			"type":       "remote.connected",
			"request_id": cmd.RequestID,
			"peer":       info,
		})
	case "remote.disconnect":
		if err := rm.Disconnect(cmd.Channel, cmd.PeerID); err != nil {
			emitErr(err)
			return
		}
		output.Emit(map[string]any{
			"type":       "remote.disconnected",
			"request_id": cmd.RequestID,
			"peer_id":    cmd.PeerID,
			"channel":    cmd.Channel,
		})
	case "remote.reconnect":
		info, err := rm.Reconnect(ctx, cmd.Channel, cmd.PeerID)
		if err != nil {
			emitErr(err)
			return
		}
		output.Emit(map[string]any{
			"type":       "remote.connected",
			"request_id": cmd.RequestID,
			"peer":       info,
		})
	case "remote.wakeup":
		longResume := cmd.LongResume != nil && *cmd.LongResume
		info, err := rm.Wakeup(ctx, cmd.Channel, cmd.PeerID, longResume)
		if err != nil {
			emitErr(err)
			return
		}
		output.Emit(map[string]any{
			"type":       "remote.connected",
			"request_id": cmd.RequestID,
			"peer":       info,
		})
	case "remote.route.add":
		info, err := rm.AddRoute(cmd.Channel, cmd.PeerID, cmd.Address)
		if err != nil {
			emitErr(err)
			return
		}
		output.Emit(map[string]any{
			"type":       "remote.route.updated",
			"request_id": cmd.RequestID,
			"peer":       info,
		})
	case "remote.route.remove":
		info, err := rm.RemoveRoute(cmd.Channel, cmd.PeerID, cmd.Address)
		if err != nil {
			emitErr(err)
			return
		}
		output.Emit(map[string]any{
			"type":       "remote.route.updated",
			"request_id": cmd.RequestID,
			"peer":       info,
		})
	case "remote.workspace.list":
		data, err := rm.ListWorkspaces(ctx, cmd.Channel, cmd.PeerID)
		if err != nil {
			emitErr(err)
			return
		}
		emitData(data)
	case "remote.session.create":
		data, err := rm.CreateSessionWithOptions(ctx, cmd.Channel, cmd.PeerID, cmd.WorkspaceID, cmd.RequestID, cmd.Title, remote.RequestOptions{
			Namespace:  cmd.Namespace,
			LinkOrigin: cmd.LinkOrigin,
			ModeLimit:  cmd.ModeLimit,
		})
		if err != nil {
			emitErr(err)
			return
		}
		emitData(data)
	case "remote.session.list":
		data, err := rm.ListSessions(ctx, cmd.Channel, cmd.PeerID)
		if err != nil {
			emitErr(err)
			return
		}
		emitData(data)
	case "remote.session.open":
		watchPresence := cmd.WatchPresence != nil && *cmd.WatchPresence
		data, err := rm.OpenSessionWithOptions(ctx, cmd.Channel, cmd.PeerID, cmd.SessionID, watchPresence)
		if err != nil {
			emitErr(err)
			return
		}
		emitData(data)
	case "remote.session.close":
		data, err := rm.CloseSession(ctx, cmd.Channel, cmd.PeerID, cmd.SessionID)
		if err != nil {
			emitErr(err)
			return
		}
		emitData(data)
	case "remote.session.presence":
		data, err := rm.SessionPresence(ctx, cmd.Channel, cmd.PeerID, cmd.SessionID, cmd.Watch)
		if err != nil {
			emitErr(err)
			return
		}
		emitData(data)
	case "remote.events.resume":
		if cmd.AfterSeq == nil {
			emitErr(errors.New("after_seq is required"))
			return
		}
		if err := rm.Resume(ctx, cmd.Channel, cmd.PeerID, cmd.SessionID, *cmd.AfterSeq); err != nil {
			emitErr(err)
			return
		}
		raw, _ := json.Marshal(map[string]any{"session_id": cmd.SessionID, "after_seq": *cmd.AfterSeq})
		emitData(raw)
	case "remote.events.ack":
		if cmd.Seq == nil {
			emitErr(errors.New("seq is required"))
			return
		}
		if err := rm.Acknowledge(cmd.Channel, cmd.PeerID, cmd.SessionID, *cmd.Seq); err != nil {
			emitErr(err)
			return
		}
		raw, _ := json.Marshal(map[string]any{"session_id": cmd.SessionID, "seq": *cmd.Seq})
		emitData(raw)
	case "remote.run.start":
		data, err := rm.StartRunWithOptions(ctx, cmd.Channel, cmd.PeerID, cmd.SessionID, cmd.RequestID, cmd.Text, remote.RequestOptions{
			Namespace:   cmd.Namespace,
			LinkOrigin:  cmd.LinkOrigin,
			ModeLimit:   cmd.ModeLimit,
			QueuePolicy: cmd.QueuePolicy,
		})
		if err != nil {
			emitErr(err)
			return
		}
		emitData(data)
	case "remote.run.cancel":
		data, err := rm.CancelRunWithOrigin(ctx, cmd.Channel, cmd.PeerID, cmd.SessionID, cmd.RunID, cmd.LinkOrigin)
		if err != nil {
			emitErr(err)
			return
		}
		emitData(data)
	case "remote.guest.request":
		data, err := rm.SubmitGuestRequest(ctx, cmd.Channel, cmd.PeerID, cmd.SessionID, cmd.RequestID, cmd.Text)
		if err != nil {
			emitErr(err)
			return
		}
		emitData(data)
	case "remote.guest.respond":
		data, err := rm.RespondGuestRequestWithOptions(ctx, cmd.Channel, cmd.PeerID, cmd.SessionID, cmd.GuestRequestID, cmd.Action, remote.GuestRespondOptions{
			Text:       cmd.Text,
			LinkOrigin: cmd.LinkOrigin,
			ModeLimit:  cmd.ModeLimit,
		})
		if err != nil {
			emitErr(err)
			return
		}
		emitData(data)
	case "remote.ui.respond":
		data, err := rm.RespondUI(ctx, cmd.Channel, cmd.PeerID, cmd.SessionID, cmd.RunID, cmd.UIID, remote.UIResponse{
			Confirmed: cmd.Confirmed,
			Value:     cmd.Value,
			Answers:   cmd.Answers,
			Cancelled: cmd.Cancelled,
		})
		if err != nil {
			emitErr(err)
			return
		}
		emitData(data)
	default:
		emitErr(fmt.Errorf("unknown remote command %q", cmd.Type))
	}
}

func remoteErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var closed *transport.ClosedError
	if errors.As(err, &closed) && closed.Reason != "" {
		return closed.Reason
	}
	var sig transport.SignalError
	if errors.As(err, &sig) {
		return string(sig)
	}
	switch err.Error() {
	case "unavailable", "tool_denied", "request_conflict", "snapshot_required", "snapshot_too_large", "invalid_request", "session_busy", "guest_request_limit":
		return err.Error()
	}
	return ""
}
