// Package remote implements multi-peer outbound PC-to-PC remote control over
// official (cn/global), self-hosted (self), and LAN channels while sharing the
// local desktop's device keys and pairnet pairing network.
package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/pairnet"
	"vanora-relay/protocol"
)

const (
	ChannelCN     = "cn"
	ChannelGlobal = "global"
	ChannelSelf   = "self"
	ChannelLAN    = "lan"
)

// OfficialChannel exposes one configured official relay site (CN or GLOBAL) to
// the outbound remote controller.
type OfficialChannel struct {
	Channel    string
	SignalURL  string
	Account    *account.Account
	Source     transport.IdentitySource
	LiveSocket func() *transport.Client
}

// SelfChannel exposes the local desktop's self-hosted relay state and vault.
type SelfChannel struct {
	SignalURL string
	Token     string
	Server    *selfrelay.Server
}

// LANChannel exposes the local desktop's LAN state and vault.
type LANChannel struct {
	Server *lan.Server
}

// Provider supplies shared desktop channel identities and active host sockets.
type Provider interface {
	DesktopName() string
	Official(channel string) (*OfficialChannel, error)
	Self() (*SelfChannel, error)
	LAN() (*LANChannel, error)
	ListOfficialChannels() []string
}

// PairOptions configures pairing this desktop with another desktop.
type PairOptions struct {
	Channel     string
	Input       string
	SignalURL   string
	SignalToken string
	GrantAccess string
}

// PeerInfo summarizes a known paired or connected remote desktop.
type PeerInfo struct {
	PeerID    string `json:"peer_id"`
	Channel   string `json:"channel"`
	Role      string `json:"role"`
	Name      string `json:"name,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Address   string `json:"address,omitempty"`
	SignalURL string `json:"signal_url,omitempty"`
	Online    *bool  `json:"online,omitempty"`
	State     string `json:"state"`
	Path      string `json:"path,omitempty"`
	Error     string `json:"error,omitempty"`
}

// UIResponse carries an answer to a remote desktop's approval or ask prompt.
type UIResponse struct {
	Confirmed *bool      `json:"confirmed,omitempty"`
	Value     *string    `json:"value,omitempty"`
	Answers   [][]string `json:"answers,omitempty"`
	Cancelled bool       `json:"cancelled,omitempty"`
}

type peerKey struct {
	channel string
	peerID  string
}

// Manager coordinates concurrent outbound control links to multiple remote
// desktops across official, self-hosted, and LAN channels.
type Manager struct {
	ctx      context.Context
	cancel   context.CancelFunc
	provider Provider
	observer func(map[string]any)

	mu          sync.Mutex
	peers       map[peerKey]*RemotePeer
	lastEmitted map[string]pairnet.Roster
}

// NewManager creates a remote desktop controller manager bound to provider.
func NewManager(ctx context.Context, provider Provider, observer func(map[string]any)) *Manager {
	mctx, cancel := context.WithCancel(ctx)
	return &Manager{
		ctx:         mctx,
		cancel:      cancel,
		provider:    provider,
		observer:    observer,
		peers:       make(map[peerKey]*RemotePeer),
		lastEmitted: make(map[string]pairnet.Roster),
	}
}

// Close terminates all active remote desktop connections and background
// reconnect loops.
func (m *Manager) Close() {
	m.cancel()
	m.mu.Lock()
	list := make([]*RemotePeer, 0, len(m.peers))
	for _, rp := range m.peers {
		list = append(list, rp)
	}
	clear(m.peers)
	m.mu.Unlock()
	for _, rp := range list {
		rp.Close()
	}
}

func (m *Manager) emit(ev map[string]any) {
	if m.observer != nil {
		m.observer(ev)
	}
}

func (m *Manager) desktopName() string {
	if m.provider != nil {
		if n := strings.TrimSpace(m.provider.DesktopName()); n != "" {
			return n
		}
	}
	return "Desktop"
}

// NewRequestID generates a unique idempotency key for session.create or run.start.
func NewRequestID() string { return protocol.NewID() }

// Pair pairs this desktop as a controller with a remote desktop via QR link,
// 16-character pairing code, or LAN link, synchronizes pairnet membership, and
// establishes an active connection.
func (m *Manager) Pair(ctx context.Context, opts PairOptions) (PeerInfo, error) {
	if m.provider == nil {
		return PeerInfo{}, errors.New("remote: provider required")
	}
	input := strings.TrimSpace(opts.Input)
	if input == "" {
		return PeerInfo{}, errors.New("remote: pairing link or code is required")
	}
	channel, err := m.detectPairChannel(opts.Channel, input, opts.SignalURL)
	if err != nil {
		return PeerInfo{}, err
	}
	grant := strings.ToLower(strings.TrimSpace(opts.GrantAccess))
	if grant != "" {
		if channel == ChannelCN || channel == ChannelGlobal {
			return PeerInfo{}, errors.New("remote: official relay permissions are configured by desktop resource ACL")
		}
		if grant != selfrelay.Read && grant != selfrelay.Control {
			return PeerInfo{}, errors.New("remote: grant_access must be read or control")
		}
	}

	switch channel {
	case ChannelLAN:
		return m.pairLAN(ctx, input, strings.TrimSpace(opts.SignalURL), grant)
	case ChannelSelf:
		return m.pairSelf(ctx, input, strings.TrimSpace(opts.SignalURL), strings.TrimSpace(opts.SignalToken), grant)
	case ChannelCN, ChannelGlobal:
		return m.pairOfficial(ctx, channel, input)
	default:
		return PeerInfo{}, fmt.Errorf("remote: unsupported channel %q", channel)
	}
}

func (m *Manager) detectPairChannel(rawChannel, input, rawSignalURL string) (string, error) {
	ch := strings.ToLower(strings.TrimSpace(rawChannel))
	if ch != "" {
		switch ch {
		case ChannelCN, ChannelGlobal, ChannelSelf, ChannelLAN:
			return ch, nil
		default:
			return "", fmt.Errorf("remote: unknown channel %q (want cn, global, self or lan)", ch)
		}
	}
	lower := strings.ToLower(input)
	switch {
	case strings.HasPrefix(lower, "vanora://pair/cn#"):
		return ChannelCN, nil
	case strings.HasPrefix(lower, "vanora://pair/global#"):
		return ChannelGlobal, nil
	case strings.Contains(input, "://"):
		u, err := url.Parse(input)
		if err != nil {
			return "", pairing.ErrInvalid
		}
		if u.Path == "/v1/lan" {
			return ChannelLAN, nil
		}
		if params, err := url.ParseQuery(u.Fragment); err == nil && params.Get("mode") == "self" {
			return ChannelSelf, nil
		}
		return "", pairing.ErrInvalid
	case strings.Contains(input, "@"):
		return ChannelLAN, nil
	}
	sig := strings.TrimSpace(rawSignalURL)
	if sig != "" {
		if ap, err := netip.ParseAddrPort(sig); err == nil && ap.Port() != 0 {
			return ChannelLAN, nil
		}
		return ChannelSelf, nil
	}
	officials := m.provider.ListOfficialChannels()
	if len(officials) == 1 {
		return officials[0], nil
	}
	return "", errors.New("remote: channel is required for pairing code (cn, global, self, or lan)")
}

func (m *Manager) pairLAN(ctx context.Context, input, address, grant string) (PeerInfo, error) {
	lanCh, err := m.provider.LAN()
	if err != nil || lanCh == nil || lanCh.Server == nil {
		if err == nil {
			err = errors.New("remote: LAN channel unavailable")
		}
		return PeerInfo{}, err
	}
	link := input
	if !strings.Contains(link, "://") {
		link, err = lan.ResolveCode(ctx, input, address, lanCh.Server.Seed())
		if err != nil {
			return PeerInfo{}, err
		}
	}
	target, err := lan.ParseTarget(link)
	if err != nil {
		return PeerInfo{}, err
	}
	if target.Pin == lanCh.Server.Pin() {
		return PeerInfo{}, errors.New("remote: cannot pair with self")
	}
	rp := m.getOrCreatePeer(ChannelLAN, target.Pin)
	if err := rp.pairLAN(ctx, target); err != nil {
		return PeerInfo{}, err
	}
	if grant != "" {
		if err := lanCh.Server.SetClientAccess(target.Pin, grant); err != nil {
			return PeerInfo{}, err
		}
	}
	m.notifyNetworkChanged(ChannelLAN, target.Pin)
	return rp.Info(), nil
}

func (m *Manager) pairSelf(ctx context.Context, input, rawSignalURL, rawToken, grant string) (PeerInfo, error) {
	selfCh, err := m.provider.Self()
	if err != nil || selfCh == nil || selfCh.Server == nil {
		if err == nil {
			err = errors.New("remote: self-hosted relay unavailable")
		}
		return PeerInfo{}, err
	}
	service := rawSignalURL
	if service == "" {
		service = strings.TrimSpace(selfCh.SignalURL)
	}
	if service == "" {
		service = strings.TrimSpace(selfCh.Server.Profile().Service)
	}
	if service != "" {
		service, err = selfrelay.NormalizeSignalURL(service)
		if err != nil {
			return PeerInfo{}, err
		}
	}
	link := input
	if !strings.Contains(link, "://") {
		if service == "" {
			return PeerInfo{}, errors.New("remote: self-hosted pairing code requires signal_url")
		}
		link, err = pairing.Resolve(ctx, service, input)
		if err != nil {
			return PeerInfo{}, err
		}
	}
	target, err := selfrelay.ParseTarget(link)
	if err != nil || target.Pair == "" {
		return PeerInfo{}, pairing.ErrInvalid
	}
	if service != "" && rawSignalURL != "" && service != target.SignalURL {
		return PeerInfo{}, pairing.ErrInvalid
	}
	if rawToken != "" {
		if err := selfrelay.ValidateRelayToken(rawToken); err != nil {
			return PeerInfo{}, err
		}
		target.Token = rawToken
	}
	if target.Token == "" {
		if tok := strings.TrimSpace(selfCh.Token); tok != "" {
			target.Token = tok
		} else if prof := selfCh.Server.Profile(); prof.Service == target.SignalURL && prof.Token != "" {
			target.Token = prof.Token
		}
	}
	if target.Token == "" {
		return PeerInfo{}, errors.New("remote: self-hosted relay token is required")
	}
	if target.Pin == selfCh.Server.Pin() {
		return PeerInfo{}, errors.New("remote: cannot pair with self")
	}
	rp := m.getOrCreatePeer(ChannelSelf, target.Pin)
	if err := rp.pairSelf(ctx, target); err != nil {
		return PeerInfo{}, err
	}
	if grant != "" {
		if err := selfCh.Server.SetPeerAccessFor(target.SignalURL, target.Pin, grant); err != nil {
			return PeerInfo{}, err
		}
	}
	m.notifyNetworkChanged(ChannelSelf, target.Pin)
	return rp.Info(), nil
}

func (m *Manager) pairOfficial(ctx context.Context, channel, input string) (PeerInfo, error) {
	occ, err := m.provider.Official(channel)
	if err != nil || occ == nil || occ.Account == nil || occ.SignalURL == "" {
		if err == nil {
			err = fmt.Errorf("remote: official channel %s is not configured", channel)
		}
		return PeerInfo{}, err
	}
	link := input
	if !strings.Contains(link, "://") {
		link, err = pairing.Resolve(ctx, occ.SignalURL, input)
		if err != nil {
			return PeerInfo{}, err
		}
	}
	target, err := pairing.ParseOfficial(link, occ.SignalURL)
	if err != nil {
		return PeerInfo{}, err
	}
	if target.Channel != channel {
		return PeerInfo{}, pairing.ErrInvalid
	}
	if occ.Account.DeviceID() != "" && target.Device == occ.Account.DeviceID() {
		return PeerInfo{}, errors.New("remote: cannot pair with self")
	}
	rp := m.getOrCreatePeer(channel, target.Device)
	if err := rp.pairOfficial(ctx, target); err != nil {
		return PeerInfo{}, err
	}
	m.notifyNetworkChanged(channel, target.Device)
	return rp.Info(), nil
}

// Connect connects to an already paired or pairnet-known remote desktop.
func (m *Manager) Connect(ctx context.Context, channel, peerID string) (PeerInfo, error) {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return PeerInfo{}, errors.New("remote: peer_id is required")
	}
	ch, err := m.resolveChannelForPeer(channel, peerID)
	if err != nil {
		return PeerInfo{}, err
	}
	rp := m.getOrCreatePeer(ch, peerID)
	if err := rp.ConnectExisting(ctx); err != nil {
		return PeerInfo{}, err
	}
	return rp.Info(), nil
}

// Disconnect closes the outbound connection to a remote desktop and disables
// automatic reconnect while keeping its pairing record.
func (m *Manager) Disconnect(channel, peerID string) error {
	rp, err := m.lookupPeer(channel, peerID)
	if err != nil {
		return err
	}
	rp.Disconnect()
	return nil
}

// Reconnect drops the current transport to peerID and dials immediately while
// preserving active session cursors.
func (m *Manager) Reconnect(ctx context.Context, channel, peerID string) (PeerInfo, error) {
	rp, err := m.lookupPeer(channel, peerID)
	if err != nil {
		return PeerInfo{}, err
	}
	if err := rp.Reconnect(ctx); err != nil {
		return rp.Info(), err
	}
	return rp.Info(), nil
}

// ListPeers returns all known paired remote desktops across the requested
// channel (or all channels when channelFilter is empty), merged with live
// connection state and optional official directory presence.
func (m *Manager) ListPeers(ctx context.Context, channelFilter string) ([]PeerInfo, error) {
	filter := strings.ToLower(strings.TrimSpace(channelFilter))
	if filter != "" && filter != ChannelCN && filter != ChannelGlobal && filter != ChannelSelf && filter != ChannelLAN {
		return nil, fmt.Errorf("remote: unknown channel %q", filter)
	}
	result := make(map[peerKey]PeerInfo)

	addMember := func(ch, signalURL string, mem pairnet.Member) {
		if mem.Role != "desktop" || !mem.Active() {
			return
		}
		k := peerKey{ch, mem.ID}
		info := result[k]
		info.PeerID = mem.ID
		info.Channel = ch
		info.Role = mem.Role
		if mem.Name != "" {
			info.Name = mem.Name
		}
		if mem.Owner != "" {
			info.Owner = mem.Owner
		}
		if mem.Address != "" {
			info.Address = mem.Address
		}
		if signalURL != "" {
			info.SignalURL = signalURL
		}
		if info.State == "" {
			info.State = "disconnected"
		}
		result[k] = info
	}

	// Official channels.
	for _, ch := range m.provider.ListOfficialChannels() {
		if filter != "" && filter != ch {
			continue
		}
		occ, err := m.provider.Official(ch)
		if err != nil || occ == nil || occ.Account == nil || occ.SignalURL == "" {
			continue
		}
		group, _ := occ.Account.PairingIdentity(occ.SignalURL, "desktop")
		if group != nil && group.Allows(group.Self()) {
			for _, mem := range group.Snapshot().Members() {
				if mem.ID == group.Self() {
					continue
				}
				addMember(ch, occ.SignalURL, mem)
			}
		}
		// Overlay live online presence when an official socket is open.
		if occ.LiveSocket != nil {
			if sock := occ.LiveSocket(); sock != nil {
				dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				devices, derr := sock.Devices(dctx)
				cancel()
				if derr == nil {
					onlineSet := make(map[string]string, len(devices))
					for _, d := range devices {
						onlineSet[d.DeviceID] = d.Name
					}
					for k, info := range result {
						if k.channel != ch {
							continue
						}
						if name, ok := onlineSet[k.peerID]; ok {
							t := true
							info.Online = &t
							if info.Name == "" {
								info.Name = name
							}
						} else {
							f := false
							info.Online = &f
						}
						result[k] = info
					}
				}
			}
		}
	}

	// Self-hosted channel.
	if filter == "" || filter == ChannelSelf {
		if selfCh, err := m.provider.Self(); err == nil && selfCh != nil && selfCh.Server != nil {
			sigURL := strings.TrimSpace(selfCh.SignalURL)
			if sigURL == "" {
				sigURL = strings.TrimSpace(selfCh.Server.Profile().Service)
			}
			var group *pairnet.Group
			if sigURL != "" {
				group, _, _ = selfCh.Server.GroupFor(sigURL, m.desktopName())
			} else {
				group = selfCh.Server.Network()
			}
			if group != nil && group.Allows(group.Self()) {
				for _, mem := range group.Snapshot().Members() {
					if mem.ID == group.Self() {
						continue
					}
					addMember(ChannelSelf, sigURL, mem)
				}
			}
		}
	}

	// LAN channel.
	if filter == "" || filter == ChannelLAN {
		if lanCh, err := m.provider.LAN(); err == nil && lanCh != nil && lanCh.Server != nil {
			group := lanCh.Server.Network()
			if group != nil && group.Allows(group.Self()) {
				for _, mem := range group.Snapshot().Members() {
					if mem.ID == group.Self() {
						continue
					}
					addMember(ChannelLAN, "", mem)
				}
			}
		}
	}

	// Overlay live outbound connection state.
	m.mu.Lock()
	for k, rp := range m.peers {
		if filter != "" && filter != k.channel {
			continue
		}
		live := rp.Info()
		if existing, ok := result[k]; ok {
			if live.Name == "" {
				live.Name = existing.Name
			}
			if live.Owner == "" {
				live.Owner = existing.Owner
			}
			if live.Address == "" {
				live.Address = existing.Address
			}
			if live.SignalURL == "" {
				live.SignalURL = existing.SignalURL
			}
			if live.Online == nil {
				live.Online = existing.Online
			}
		}
		result[k] = live
	}
	m.mu.Unlock()

	out := make([]PeerInfo, 0, len(result))
	for _, info := range result {
		out = append(out, info)
	}
	slices.SortFunc(out, func(a, b PeerInfo) int {
		if c := strings.Compare(a.Channel, b.Channel); c != 0 {
			return c
		}
		return strings.Compare(a.PeerID, b.PeerID)
	})
	return out, nil
}

// OnNetworkChanged propagates local or inbound pairing network changes to all
// outbound peers on channel, severing removed peers and pushing updated rosters
// to active peers.
func (m *Manager) OnNetworkChanged(channel string) {
	m.notifyNetworkChanged(channel, "")
}

func (m *Manager) notifyNetworkChanged(channel, skipInboundBroadcastFor string) {
	group := m.groupForChannel(channel)
	if group == nil {
		return
	}
	// If triggered from an outbound peer merge, also broadcast to inbound host peers.
	if skipInboundBroadcastFor != "" {
		switch channel {
		case ChannelLAN:
			if lanCh, err := m.provider.LAN(); err == nil && lanCh != nil && lanCh.Server != nil {
				lanCh.Server.BroadcastNetwork()
			}
		case ChannelSelf:
			if selfCh, err := m.provider.Self(); err == nil && selfCh != nil && selfCh.Server != nil {
				selfCh.Server.BroadcastNetwork()
			}
		case ChannelCN, ChannelGlobal:
			if occ, err := m.provider.Official(channel); err == nil && occ != nil && occ.LiveSocket != nil {
				if sock := occ.LiveSocket(); sock != nil {
					sock.NetworkChanged()
				}
			}
		}
	}

	m.mu.Lock()
	peers := make([]*RemotePeer, 0, len(m.peers))
	for k, rp := range m.peers {
		if k.channel == channel {
			peers = append(peers, rp)
		}
	}
	m.mu.Unlock()

	for _, rp := range peers {
		if skipInboundBroadcastFor != "" && rp.peerID == skipInboundBroadcastFor && group.Allows(rp.peerID) && group.Allows(group.Self()) {
			continue
		}
		rp.onNetworkChanged(group)
	}

	snap := group.Snapshot()
	m.mu.Lock()
	unchanged := maps.Equal(m.lastEmitted[channel], snap)
	if !unchanged {
		m.lastEmitted[channel] = snap
	}
	m.mu.Unlock()
	if unchanged {
		return
	}
	members := []pairnet.Member{}
	if group.Allows(group.Self()) {
		members = snap.Members()
	}
	m.emit(map[string]any{
		"type":    "remote.network.updated",
		"channel": channel,
		"self_id": group.Self(),
		"members": members,
	})
}

func (m *Manager) groupForChannel(channel string) *pairnet.Group {
	switch channel {
	case ChannelLAN:
		if lanCh, err := m.provider.LAN(); err == nil && lanCh != nil && lanCh.Server != nil {
			return lanCh.Server.Network()
		}
	case ChannelSelf:
		if selfCh, err := m.provider.Self(); err == nil && selfCh != nil && selfCh.Server != nil {
			if g := selfCh.Server.Network(); g != nil {
				return g
			}
			sig := strings.TrimSpace(selfCh.SignalURL)
			if sig == "" {
				sig = strings.TrimSpace(selfCh.Server.Profile().Service)
			}
			if sig != "" {
				g, _, _ := selfCh.Server.GroupFor(sig, m.desktopName())
				return g
			}
		}
	case ChannelCN, ChannelGlobal:
		if occ, err := m.provider.Official(channel); err == nil && occ != nil && occ.Account != nil && occ.SignalURL != "" {
			g, _ := occ.Account.PairingIdentity(occ.SignalURL, "desktop")
			return g
		}
	}
	return nil
}

func (m *Manager) getOrCreatePeer(channel, peerID string) *RemotePeer {
	k := peerKey{channel, peerID}
	m.mu.Lock()
	defer m.mu.Unlock()
	if rp := m.peers[k]; rp != nil {
		return rp
	}
	rp := newRemotePeer(m, channel, peerID)
	m.peers[k] = rp
	return rp
}

func (m *Manager) lookupPeer(channel, peerID string) (*RemotePeer, error) {
	ch := strings.ToLower(strings.TrimSpace(channel))
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return nil, errors.New("remote: peer_id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ch != "" {
		rp := m.peers[peerKey{ch, peerID}]
		if rp == nil {
			return nil, errors.New("remote: peer is not connected")
		}
		return rp, nil
	}
	var found *RemotePeer
	for k, rp := range m.peers {
		if k.peerID == peerID {
			if found != nil {
				return nil, errors.New("remote: ambiguous peer_id across channels; specify channel")
			}
			found = rp
		}
	}
	if found == nil {
		return nil, errors.New("remote: peer is not connected")
	}
	return found, nil
}

func (m *Manager) resolveChannelForPeer(rawChannel, peerID string) (string, error) {
	ch := strings.ToLower(strings.TrimSpace(rawChannel))
	if ch != "" {
		switch ch {
		case ChannelCN, ChannelGlobal, ChannelSelf, ChannelLAN:
			return ch, nil
		default:
			return "", fmt.Errorf("remote: unknown channel %q", ch)
		}
	}
	// Check active outbound peers first.
	m.mu.Lock()
	var matches []string
	for k := range m.peers {
		if k.peerID == peerID {
			matches = append(matches, k.channel)
		}
	}
	m.mu.Unlock()
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return "", errors.New("remote: ambiguous peer_id across channels; specify channel")
	}
	// Search pairing networks.
	candidates := append([]string{}, m.provider.ListOfficialChannels()...)
	candidates = append(candidates, ChannelSelf, ChannelLAN)
	for _, cand := range candidates {
		g := m.groupForChannel(cand)
		if g != nil && g.Allows(peerID) {
			if mem, ok := g.Get(peerID); ok && mem.Role == "desktop" && mem.ID != g.Self() {
				matches = append(matches, cand)
			}
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return "", errors.New("remote: peer exists in multiple channels; specify channel")
	}
	// Fallback to official direct bindings.
	for _, cand := range m.provider.ListOfficialChannels() {
		if occ, err := m.provider.Official(cand); err == nil && occ != nil && occ.Account != nil {
			if _, ok := occ.Account.PairedPeer(peerID); ok {
				return cand, nil
			}
		}
	}
	return "", pairing.ErrInvalid
}

// RPC forwarding helpers on Manager.

func (m *Manager) ListWorkspaces(ctx context.Context, channel, peerID string) (json.RawMessage, error) {
	rp, err := m.lookupPeer(channel, peerID)
	if err != nil {
		return nil, err
	}
	return rp.ListWorkspaces(ctx)
}

func (m *Manager) CreateSession(ctx context.Context, channel, peerID, workspaceID, requestID, title string) (json.RawMessage, error) {
	rp, err := m.lookupPeer(channel, peerID)
	if err != nil {
		return nil, err
	}
	return rp.CreateSession(ctx, workspaceID, requestID, title)
}

func (m *Manager) ListSessions(ctx context.Context, channel, peerID string) (json.RawMessage, error) {
	rp, err := m.lookupPeer(channel, peerID)
	if err != nil {
		return nil, err
	}
	return rp.ListSessions(ctx)
}

func (m *Manager) OpenSession(ctx context.Context, channel, peerID, sessionID string) (json.RawMessage, error) {
	rp, err := m.lookupPeer(channel, peerID)
	if err != nil {
		return nil, err
	}
	return rp.OpenSession(ctx, sessionID)
}

func (m *Manager) Resume(ctx context.Context, channel, peerID, sessionID string, afterSeq int64) error {
	rp, err := m.lookupPeer(channel, peerID)
	if err != nil {
		return err
	}
	return rp.Resume(ctx, sessionID, afterSeq)
}

func (m *Manager) Acknowledge(channel, peerID, sessionID string, seq int64) error {
	rp, err := m.lookupPeer(channel, peerID)
	if err != nil {
		return err
	}
	return rp.Acknowledge(sessionID, seq)
}

func (m *Manager) StartRun(ctx context.Context, channel, peerID, sessionID, requestID, text string) (json.RawMessage, error) {
	rp, err := m.lookupPeer(channel, peerID)
	if err != nil {
		return nil, err
	}
	return rp.StartRun(ctx, sessionID, requestID, text)
}

func (m *Manager) CancelRun(ctx context.Context, channel, peerID, sessionID, runID string) (json.RawMessage, error) {
	rp, err := m.lookupPeer(channel, peerID)
	if err != nil {
		return nil, err
	}
	return rp.CancelRun(ctx, sessionID, runID)
}

func (m *Manager) RespondUI(ctx context.Context, channel, peerID, sessionID, runID, uiID string, payload UIResponse) (json.RawMessage, error) {
	rp, err := m.lookupPeer(channel, peerID)
	if err != nil {
		return nil, err
	}
	return rp.RespondUI(ctx, sessionID, runID, uiID, payload)
}

func decodePin32(b64 string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return nil, pairing.ErrInvalid
	}
	return raw, nil
}
