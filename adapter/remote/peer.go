package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/cftunnel"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/pairnet"
	"vanora-relay/internal/routes"
	"vanora-relay/protocol"
)

var (
	errSnapshot    = errors.New("snapshot_required")
	errUnavailable = errors.New("unavailable")
)

type rpcReply struct {
	data json.RawMessage
	err  error
}

type sessionCursor struct {
	applied       int64
	delivered     int64
	watchPresence bool
}

type tunnelDialOptions struct {
	url        string
	headStart  time.Duration
	httpClient *http.Client
}

// RemotePeer maintains one authenticated outbound control connection to a
// single remote desktop, including reconnect, pairnet sync, RPC correlation,
// and per-session event cursors.
type RemotePeer struct {
	manager *Manager
	channel string
	peerID  string

	ctx  context.Context
	stop context.CancelFunc

	op sync.Mutex // serializes dial, reconnect, openSession, resume, disconnect

	mu             sync.Mutex
	owner          string
	name           string
	address        string
	signalURL      string
	lanTarget      *lan.Target
	selfTarget     *selfrelay.Target
	officialInvite *pairing.Official
	group          *pairnet.Group
	socket         *transport.Client
	ownsSocket     bool
	peer           transport.Peer
	wantReconnect  bool
	connState      string
	connPath       string
	connErr        string
	pending        map[string]chan rpcReply
	subscriptions  map[string]*sessionCursor
	lastSynced     pairnet.Roster
	altRoutes      []string
	routeTracker   *routes.Tracker

	generation    atomic.Uint64
	inboundFrames atomic.Uint64

	retry      chan struct{}
	retryNow   chan struct{}
	betterWake chan struct{}
}

func newRemotePeer(m *Manager, channel, peerID string) *RemotePeer {
	ctx, stop := context.WithCancel(m.ctx)
	rp := &RemotePeer{
		manager:       m,
		channel:       channel,
		peerID:        peerID,
		ctx:           ctx,
		stop:          stop,
		connState:     "disconnected",
		pending:       make(map[string]chan rpcReply),
		subscriptions: make(map[string]*sessionCursor),
		routeTracker:  routes.NewTracker(),
		retry:         make(chan struct{}, 1),
		retryNow:      make(chan struct{}, 1),
		betterWake:    make(chan struct{}, 1),
	}
	go rp.recoverLoop()
	go rp.maintainRoutes()
	return rp
}

// Info returns a snapshot of this peer's current metadata and connection state.
func (rp *RemotePeer) Info() PeerInfo {
	rp.mu.Lock()
	info := PeerInfo{
		PeerID:        rp.peerID,
		Channel:       rp.channel,
		Role:          "desktop",
		Name:          rp.name,
		Owner:         rp.owner,
		Address:       rp.address,
		SignalURL:     rp.signalURL,
		State:         rp.connState,
		Path:          rp.connPath,
		Error:         rp.connErr,
		Generation:    rp.generation.Load(),
		TransportHint: rp.routeTracker.TransportHint(time.Now()),
		Routes:        rp.routesLocked(),
	}
	p := rp.peer
	rp.mu.Unlock()
	if info.State == "connected" && p != nil {
		if live := peerPath(p); live != "" {
			info.Path = live
		}
	}
	return info
}

func (rp *RemotePeer) pairLAN(ctx context.Context, target lan.Target) error {
	rp.op.Lock()
	defer rp.op.Unlock()
	rp.dropLinkLocked()
	rp.mu.Lock()
	rp.owner = "lan"
	rp.address = target.Address
	rp.lanTarget = &target
	rp.wantReconnect = true
	rp.setStateLocked("connecting", "", "")
	rp.mu.Unlock()
	err := rp.connectLocked(ctx)
	if err != nil {
		if !rp.handleAuthError(err) {
			signalCh(rp.retry)
		}
		return err
	}
	return nil
}

func (rp *RemotePeer) pairSelf(ctx context.Context, target selfrelay.Target) error {
	rp.op.Lock()
	defer rp.op.Unlock()
	rp.dropLinkLocked()
	rp.mu.Lock()
	rp.owner = "self"
	rp.signalURL = target.SignalURL
	rp.selfTarget = &target
	rp.wantReconnect = true
	rp.setStateLocked("connecting", "", "")
	rp.mu.Unlock()
	err := rp.connectLocked(ctx)
	if err != nil {
		if !rp.handleAuthError(err) {
			signalCh(rp.retry)
		}
		return err
	}
	return nil
}

func (rp *RemotePeer) pairOfficial(ctx context.Context, target pairing.Official) error {
	rp.op.Lock()
	defer rp.op.Unlock()
	rp.dropLinkLocked()
	rp.mu.Lock()
	rp.owner = target.Owner
	rp.signalURL = target.Relay
	rp.officialInvite = &target
	rp.wantReconnect = true
	rp.setStateLocked("connecting", "", "")
	rp.mu.Unlock()
	err := rp.connectLocked(ctx)
	if err != nil {
		if !rp.handleAuthError(err) {
			signalCh(rp.retry)
		}
		return err
	}
	return nil
}

// ConnectExisting connects using stored pairing network credentials (without an
// invitation).
func (rp *RemotePeer) ConnectExisting(ctx context.Context) error {
	rp.op.Lock()
	defer rp.op.Unlock()
	rp.mu.Lock()
	if rp.peer != nil && rp.peer.Allows(false) {
		rp.mu.Unlock()
		return nil
	}
	rp.officialInvite = nil
	rp.wantReconnect = true
	rp.setStateLocked("connecting", "", "")
	rp.mu.Unlock()
	err := rp.connectLocked(ctx)
	if err != nil {
		if !rp.handleAuthError(err) {
			signalCh(rp.retry)
		}
		return err
	}
	return nil
}

// Reconnect drops the active link and immediately redials while keeping
// subscribed session cursors.
func (rp *RemotePeer) Reconnect(ctx context.Context) error {
	rp.op.Lock()
	defer rp.op.Unlock()
	rp.dropLinkLocked()
	rp.mu.Lock()
	rp.wantReconnect = true
	rp.setStateLocked("reconnecting", "", "")
	rp.mu.Unlock()
	err := rp.connectLocked(ctx)
	if err != nil {
		if !rp.handleAuthError(err) {
			signalCh(rp.retry)
		}
		return err
	}
	return nil
}

// Disconnect closes the connection and stops background reconnection.
func (rp *RemotePeer) Disconnect() {
	rp.op.Lock()
	defer rp.op.Unlock()
	rp.disconnectLocked()
}

// Close shuts down this peer permanently.
func (rp *RemotePeer) Close() {
	rp.stop()
	rp.Disconnect()
}

func (rp *RemotePeer) disconnectLocked() {
	rp.mu.Lock()
	rp.wantReconnect = false
	rp.officialInvite = nil
	oldPeer := rp.peer
	oldSock := rp.socket
	owns := rp.ownsSocket
	rp.socket = nil
	rp.ownsSocket = false
	rp.detachLocked()
	clear(rp.subscriptions)
	rp.setStateLocked("disconnected", "", "")
	rp.mu.Unlock()
	if oldPeer != nil {
		oldPeer.Close()
	}
	if owns && oldSock != nil {
		oldSock.Close()
	}
}

func (rp *RemotePeer) dropLinkLocked() {
	rp.mu.Lock()
	oldPeer := rp.peer
	oldSock := rp.socket
	owns := rp.ownsSocket
	rp.socket = nil
	rp.ownsSocket = false
	rp.detachLocked()
	rp.mu.Unlock()
	if oldPeer != nil {
		oldPeer.Close()
	}
	if owns && oldSock != nil {
		oldSock.Close()
	}
}

func (rp *RemotePeer) connectLocked(ctx context.Context) error {
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(rp.ctx, cancel)
	p, start, group, err := rp.dialPeer(dialCtx)
	stop()
	cancel()
	if err != nil {
		rp.mu.Lock()
		if rp.wantReconnect {
			rp.setStateLocked("reconnecting", "", err.Error())
		} else {
			rp.setStateLocked("disconnected", "", err.Error())
		}
		rp.mu.Unlock()
		return err
	}
	rp.mu.Lock()
	if !p.Allows(true) {
		rp.setStateLocked("reconnecting", "", "desktop authorization expired")
		rp.mu.Unlock()
		p.Close()
		return errors.New("desktop authorization expired")
	}
	rp.peer = p
	rp.generation.Add(1)
	rp.group = group
	activePath := peerPath(p)
	rp.routeTracker.RecordActivePath(activePath, time.Now())
	rp.setStateLocked("connected", activePath, "")
	resume := make(map[string]int64, len(rp.subscriptions))
	for id, cur := range rp.subscriptions {
		resume[id] = cur.applied
	}
	rp.mu.Unlock()

	if start != nil {
		start()
	}
	if !p.Allows(false) {
		p.Close()
		(*peerHandler)(rp).Closed(p)
		return transport.ErrPeerClosed
	}
	if group != nil {
		if err := rp.syncPeer(p, group); err != nil {
			p.Close()
			return err
		}
	}
	for id, seq := range resume {
		if _, err := rp.subscribe(ctx, p, id, seq); err != nil {
			if errors.Is(err, errSnapshot) || errors.Is(err, errUnavailable) || p.Allows(false) {
				rp.mu.Lock()
				delete(rp.subscriptions, id)
				rp.mu.Unlock()
				rp.emitSubError(id, err.Error())
				continue
			}
			p.Close()
			return err
		}
	}
	return nil
}

func (rp *RemotePeer) dialPeer(ctx context.Context) (transport.Peer, func(), *pairnet.Group, error) {
	switch rp.channel {
	case ChannelLAN:
		return rp.dialLAN(ctx)
	case ChannelSelf:
		return rp.dialSelf(ctx)
	case ChannelCN, ChannelGlobal:
		return rp.dialOfficial(ctx)
	default:
		return nil, nil, nil, fmt.Errorf("remote: unsupported channel %q", rp.channel)
	}
}

func (rp *RemotePeer) dialLAN(ctx context.Context) (transport.Peer, func(), *pairnet.Group, error) {
	lanCh, err := rp.manager.provider.LAN()
	if err != nil || lanCh == nil || lanCh.Server == nil {
		if err == nil {
			err = errors.New("remote: LAN channel unavailable")
		}
		return nil, nil, nil, err
	}
	group := lanCh.Server.Network()
	rp.mu.Lock()
	var target lan.Target
	if rp.lanTarget != nil {
		target = *rp.lanTarget
	}
	alt := slices.Clone(rp.altRoutes)
	rp.mu.Unlock()

	var learnedAddr string
	if mem, ok := group.Get(rp.peerID); ok {
		if target.Token == "" && !group.Allows(rp.peerID) {
			return nil, nil, nil, lan.ErrUnpaired
		}
		if mem.Address != "" {
			learnedAddr = mem.Address
		}
		if target.Pin == "" && mem.Role == "desktop" && group.Allows(rp.peerID) {
			target = lan.Target{Address: mem.Address, Pin: mem.Pin}
		}
	}
	if target.Pin == "" {
		return nil, nil, nil, lan.ErrUnpaired
	}

	localName := rp.manager.desktopName()
	localAddr := lanCh.Server.Address()
	invited := target.Token != ""

	var p transport.Peer
	var start func()
	if invited {
		p, start, err = lan.DialWithOptions(rp.ctx, target, lanCh.Server.Seed(), localName, "desktop", localAddr, (*peerHandler)(rp))
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		entries := routes.MergeOrdered(target.Address, alt, learnedAddr)
		if len(entries) == 0 {
			return nil, nil, nil, lan.ErrUnpaired
		}
		now := time.Now()
		var filtered []routes.Entry
		for _, e := range entries {
			if !rp.routeTracker.InCooldown(e.Address, now) {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) == 0 {
			filtered = entries
		}
		var lastErr error
		for _, cand := range filtered {
			candTarget := lan.Target{Address: cand.Address, Pin: target.Pin}
			dctx, cancel := context.WithTimeout(ctx, routes.DialTimeout(cand.Kind))
			// Bind the persistent peer reader to rp.ctx while bounding the initial dial via dctx:
			// probe first on dctx when multiple candidates exist so unreachable LAN IPs skip fast.
			if len(filtered) > 1 {
				if pErr := lan.ProbeTarget(dctx, candTarget, lanCh.Server.Seed(), routes.DialTimeout(cand.Kind)); pErr != nil {
					cancel()
					if errors.Is(pErr, lan.ErrUnpaired) {
						return nil, nil, nil, pErr
					}
					lastErr = pErr
					continue
				}
			}
			p, start, err = lan.DialWithOptions(rp.ctx, candTarget, lanCh.Server.Seed(), localName, "desktop", localAddr, (*peerHandler)(rp))
			cancel()
			if err == nil {
				if target.Address != "" && target.Address != cand.Address && !slices.Contains(alt, target.Address) {
					alt = append(alt, target.Address)
				}
				target.Address = cand.Address
				rp.routeTracker.RecordProbeSuccess(cand.Address)
				break
			}
			if errors.Is(err, lan.ErrUnpaired) {
				return nil, nil, nil, err
			}
			lastErr = err
		}
		if p == nil {
			return nil, nil, nil, lastErr
		}
	}

	localMem := pairnet.Member{ID: lanCh.Server.Pin(), Pin: lanCh.Server.Pin(), Role: "desktop", Name: localName, Address: localAddr}
	remoteMem := pairnet.Member{ID: target.Pin, Pin: target.Pin, Role: "desktop", Address: target.Address}
	if err := group.Admit(localMem, remoteMem, invited); err != nil {
		p.Close()
		return nil, nil, nil, err
	}
	target.Token = ""
	rp.mu.Lock()
	rp.owner = "lan"
	rp.address = target.Address
	rp.lanTarget = &target
	rp.altRoutes = alt
	if mem, ok := group.Get(rp.peerID); ok && mem.Name != "" {
		rp.name = mem.Name
	}
	rp.mu.Unlock()
	return p, start, group, nil
}

func (rp *RemotePeer) dialSelf(ctx context.Context) (transport.Peer, func(), *pairnet.Group, error) {
	selfCh, err := rp.manager.provider.Self()
	if err != nil || selfCh == nil || selfCh.Server == nil {
		if err == nil {
			err = errors.New("remote: self-hosted relay unavailable")
		}
		return nil, nil, nil, err
	}
	rp.mu.Lock()
	var target selfrelay.Target
	if rp.selfTarget != nil {
		target = *rp.selfTarget
	}
	rp.mu.Unlock()

	if target.SignalURL == "" {
		sig := strings.TrimSpace(selfCh.SignalURL)
		tok := strings.TrimSpace(selfCh.Token)
		prof := selfCh.Server.Profile()
		if sig == "" {
			sig = strings.TrimSpace(prof.Service)
		}
		if tok == "" && (prof.Service == "" || prof.Service == sig) {
			tok = strings.TrimSpace(prof.Token)
		}
		if sig == "" {
			return nil, nil, nil, selfrelay.ErrUnpaired
		}
		sig, err = selfrelay.NormalizeSignalURL(sig)
		if err != nil {
			return nil, nil, nil, err
		}
		target.SignalURL = sig
		target.Token = tok
	}
	if target.Token == "" {
		if tok := strings.TrimSpace(selfCh.Token); tok != "" {
			target.Token = tok
		} else if prof := selfCh.Server.Profile(); prof.Service == target.SignalURL && prof.Token != "" {
			target.Token = prof.Token
		}
	}
	group, localMem, err := selfCh.Server.GroupFor(target.SignalURL, rp.manager.desktopName())
	if err != nil {
		return nil, nil, nil, err
	}
	if target.Pin == "" {
		mem, ok := group.Get(rp.peerID)
		if !ok || mem.Role != "desktop" || !group.Allows(rp.peerID) {
			return nil, nil, nil, selfrelay.ErrUnpaired
		}
		target.Pin = mem.Pin
	} else if target.Pair == "" && !group.Allows(rp.peerID) {
		return nil, nil, nil, selfrelay.ErrUnpaired
	}

	localName := rp.manager.desktopName()
	seed := selfCh.Server.Seed()
	options := rp.manager.tunnel
	dialTarget := target
	webRTC := func(ctx context.Context) (cftunnel.Candidate, error) {
		peer, start, err := selfrelay.DialWithRoleFor(ctx, rp.ctx, dialTarget, seed, localName, "desktop", (*peerHandler)(rp))
		return cftunnel.Candidate{Peer: peer, Start: start}, err
	}
	var tunnel cftunnel.CandidateDial
	if target.Pair == "" {
		tunnel = func(ctx context.Context) (cftunnel.Candidate, error) {
			key, err := selfrelay.ClientPrivateKey(seed)
			if err != nil {
				return cftunnel.Candidate{}, err
			}
			pin, err := decodePin32(dialTarget.Pin)
			if err != nil {
				return cftunnel.Candidate{}, err
			}
			peer, start, err := cftunnel.ConnectSelfDeferred(ctx, cftunnel.SelfConnectOptions{
				SignalURL: dialTarget.SignalURL, SelfToken: dialTarget.Token, PrivateKey: key, HostPublicKey: pin,
				Role: "desktop", Handler: (*peerHandler)(rp), DialURL: options.url, HTTPClient: options.httpClient,
				Allows: func() bool { return rp.ctx.Err() == nil && group.Allows(rp.peerID) },
			})
			return cftunnel.Candidate{Peer: peer, Start: start}, err
		}
	}
	winner, err := cftunnel.DialFallback(ctx, rp.routeTracker, target.SignalURL, options.headStart, webRTC, tunnel)
	if err != nil {
		return nil, nil, nil, err
	}
	invited := target.Pair != ""
	remoteMem := pairnet.Member{ID: target.Pin, Pin: target.Pin, Role: "desktop"}
	if err := group.Admit(localMem, remoteMem, invited); err != nil {
		winner.Close()
		return nil, nil, nil, err
	}
	_ = selfCh.Server.SetProfile(pairnet.Profile{Service: target.SignalURL, Token: target.Token, Name: localName})
	target.Pair = ""
	rp.mu.Lock()
	rp.owner = "self"
	rp.signalURL = target.SignalURL
	rp.selfTarget = &target
	if mem, ok := group.Get(rp.peerID); ok && mem.Name != "" {
		rp.name = mem.Name
	}
	rp.mu.Unlock()
	return winner.Peer, winner.Start, group, nil
}

func (rp *RemotePeer) dialOfficial(ctx context.Context) (transport.Peer, func(), *pairnet.Group, error) {
	occ, err := rp.manager.provider.Official(rp.channel)
	if err != nil || occ == nil || occ.Account == nil || occ.SignalURL == "" {
		if err == nil {
			err = fmt.Errorf("remote: official channel %s is not configured", rp.channel)
		}
		return nil, nil, nil, err
	}
	group, localMem := occ.Account.PairingIdentity(occ.SignalURL, "desktop")
	localMem.Name = rp.manager.desktopName()

	rp.mu.Lock()
	invite := rp.officialInvite
	owner := rp.owner
	rp.mu.Unlock()

	var pin, token []byte
	if invite != nil {
		pin, token = invite.Pin, invite.Token
		owner = invite.Owner
	} else {
		var pinB64 string
		if group != nil {
			if mem, ok := group.Get(rp.peerID); ok {
				if mem.Role != "desktop" || !group.Allows(rp.peerID) {
					return nil, nil, nil, pairing.ErrInvalid
				}
				owner = mem.Owner
				pinB64 = mem.Pin
			}
		}
		if pinB64 == "" {
			bound, ok := occ.Account.PairedPeer(rp.peerID)
			if !ok {
				return nil, nil, nil, pairing.ErrInvalid
			}
			owner = bound.Owner
			pinB64 = bound.Pin
		}
		pin, err = decodePin32(pinB64)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	rp.mu.Lock()
	existing, ownsExisting := rp.socket, rp.ownsSocket
	rp.socket, rp.ownsSocket = nil, false
	rp.mu.Unlock()
	source := occ.Source
	if source == nil {
		source = occ.Account
	}
	name := localMem.Name
	webRTC := func(ctx context.Context) (cftunnel.Candidate, error) {
		socket, owns, err := rp.acquireOfficialSocket(ctx, occ, source, existing, ownsExisting)
		if err != nil {
			return cftunnel.Candidate{}, err
		}
		dialCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		defer stop()
		peer, start, err := socket.ConnectPairedDeferred(dialCtx, rp.peerID, owner, transport.ConnectOptions{
			Pin: pin, Token: token, Role: transport.RoleDesktop, Name: name, Handler: (*peerHandler)(rp),
		})
		return cftunnel.Candidate{Peer: peer, Start: start, Socket: socket, OwnsSocket: owns}, err
	}
	options := rp.manager.tunnel
	pinB64 := base64.RawURLEncoding.EncodeToString(pin)
	bound := account.PeerBinding{Owner: owner, Pin: pinB64}
	var tunnel cftunnel.CandidateDial
	if invite == nil {
		pairedGroup := group
		tunnel = func(ctx context.Context) (cftunnel.Candidate, error) {
			peer, start, err := cftunnel.ConnectOfficialDeferred(ctx, cftunnel.OfficialConnectOptions{
				SignalURL: occ.SignalURL, Channel: rp.channel, HostDeviceID: rp.peerID, HostPublicKey: pin, OwnerID: owner,
				Role: "desktop", CA: occ.Account.CA(), LeaseSource: source,
				Handler: (*peerHandler)(rp), DialURL: options.url, HTTPClient: options.httpClient,
				Allows: func() bool {
					if rp.ctx.Err() != nil {
						return false
					}
					if pairedGroup != nil {
						if member, known := pairedGroup.Get(rp.peerID); known {
							return pairedGroup.Allows(rp.peerID) && member.Role == "desktop" &&
								member.Owner == bound.Owner && member.Pin == bound.Pin
						}
						if local, known := pairedGroup.Get(pairedGroup.Self()); known && !local.Active() {
							return false
						}
					}
					current, ok := occ.Account.PairedPeer(rp.peerID)
					return ok && current == bound
				},
			})
			return cftunnel.Candidate{Peer: peer, Start: start}, err
		}
	}
	winner, err := cftunnel.DialFallback(ctx, rp.routeTracker, occ.SignalURL, options.headStart, webRTC, tunnel)
	if err != nil {
		return nil, nil, nil, err
	}

	// Re-fetch PairingIdentity in case enrollment finished during dial.
	if group == nil {
		group, localMem = occ.Account.PairingIdentity(occ.SignalURL, "desktop")
		localMem.Name = rp.manager.desktopName()
	}
	if group != nil {
		remoteMem := pairnet.Member{ID: rp.peerID, Pin: pinB64, Owner: owner, Role: "desktop"}
		if err := group.Admit(localMem, remoteMem, invite != nil); err != nil {
			winner.Close()
			return nil, nil, nil, err
		}
	}
	if err := occ.Account.BindNetworkPeer(group, rp.peerID, bound); err != nil {
		winner.Close()
		return nil, nil, nil, err
	}

	rp.mu.Lock()
	rp.socket = winner.Socket
	rp.ownsSocket = winner.OwnsSocket
	rp.owner = owner
	rp.signalURL = occ.SignalURL
	rp.officialInvite = nil
	if group != nil {
		if mem, ok := group.Get(rp.peerID); ok && mem.Name != "" {
			rp.name = mem.Name
		}
	}
	rp.mu.Unlock()
	return winner.Peer, winner.Start, group, nil
}

func (rp *RemotePeer) acquireOfficialSocket(ctx context.Context, occ *OfficialChannel, source transport.IdentitySource, existing *transport.Client, owns bool) (*transport.Client, bool, error) {
	if occ.LiveSocket != nil {
		if live := occ.LiveSocket(); live != nil {
			select {
			case <-live.Done():
			default:
				if existing != nil && existing != live && owns {
					existing.Close()
				}
				return live, false, nil
			}
		}
	}
	if owns && existing != nil {
		select {
		case <-existing.Done():
			existing.Close()
		default:
			return existing, true, nil
		}
	}
	sock, err := transport.DialDesktopControllerFor(ctx, occ.SignalURL, rp.peerID, source, (*peerHandler)(rp))
	if err != nil {
		return nil, false, err
	}
	return sock, true, nil
}

func (rp *RemotePeer) recoverLoop() {
	for {
		select {
		case <-rp.ctx.Done():
			return
		case <-rp.retry:
		case <-rp.retryNow:
		}
		for delay := time.Second; ; delay = min(delay*2, 15*time.Second) {
			timer := time.NewTimer(delay)
			select {
			case <-rp.ctx.Done():
				timer.Stop()
				return
			case <-rp.retryNow:
				timer.Stop()
				delay = time.Second
			case <-timer.C:
			}
			rp.op.Lock()
			rp.mu.Lock()
			want := rp.wantReconnect && rp.peer == nil
			rp.mu.Unlock()
			var err error
			if want {
				err = rp.connectLocked(rp.ctx)
			}
			rp.op.Unlock()
			if !want || err == nil || rp.handleAuthError(err) {
				break
			}
		}
	}
}

func (rp *RemotePeer) onNetworkChanged(group *pairnet.Group) {
	rp.mu.Lock()
	p := rp.peer
	if group != nil {
		rp.group = group
		if mem, ok := group.Get(rp.peerID); ok {
			if mem.Name != "" {
				rp.name = mem.Name
			}
			if mem.Address != "" {
				rp.address = mem.Address
			}
		}
	}
	rp.mu.Unlock()
	if group == nil {
		return
	}
	if !group.Allows(rp.peerID) || !group.Allows(group.Self()) {
		if p != nil {
			_ = rp.syncPeer(p, group)
		}
		rp.mu.Lock()
		rp.wantReconnect = false
		rp.mu.Unlock()
		if p != nil {
			p.Close()
		}
		return
	}
	if p != nil {
		_ = rp.syncPeer(p, group)
	}
}

func (rp *RemotePeer) syncPeer(p transport.Peer, g *pairnet.Group) error {
	snap := g.Snapshot()
	rp.mu.Lock()
	if rp.peer == p && maps.Equal(rp.lastSynced, snap) {
		rp.mu.Unlock()
		return nil
	}
	rp.lastSynced = snap
	rp.mu.Unlock()
	return p.Send(protocol.Encode(transport.NetworkFrame{Type: "pairnet.sync", Members: snap}), true)
}

func (rp *RemotePeer) detachLocked() {
	rp.peer = nil
	rp.lastSynced = nil
	for id, ch := range rp.pending {
		ch <- rpcReply{err: errors.New("connection lost")}
		delete(rp.pending, id)
	}
	for _, cur := range rp.subscriptions {
		cur.delivered = cur.applied
	}
}

func (rp *RemotePeer) setStateLocked(state, path, errMsg string) {
	if rp.connState == state && rp.connPath == path && rp.connErr == errMsg {
		return
	}
	rp.connState = state
	rp.connPath = path
	rp.connErr = errMsg
	owner := rp.owner
	name := rp.name
	rp.manager.emit(map[string]any{
		"type":    "remote.connection.state",
		"peer_id": rp.peerID,
		"channel": rp.channel,
		"owner":   owner,
		"name":    name,
		"state":   state,
		"path":    path,
		"error":   errMsg,
	})
}

func (rp *RemotePeer) handleAuthError(err error) bool {
	var closed *transport.ClosedError
	pairingRequired := errors.Is(err, lan.ErrUnpaired) || errors.Is(err, selfrelay.ErrUnpaired) ||
		errors.Is(err, pairing.ErrInvalid) || errors.Is(err, pairnet.ErrRemoved) ||
		errors.Is(err, transport.ErrUnauthorized) ||
		(errors.As(err, &closed) && (closed.Reason == "access_denied" || closed.Reason == "access_revoked"))
	relayTokenInvalid := errors.Is(err, selfrelay.ErrUnauthorized)
	loginRequired := isLoginRequiredError(err) || errors.Is(err, transport.ErrIdentityChanged)
	if !pairingRequired && !relayTokenInvalid && !loginRequired {
		return false
	}
	rp.mu.Lock()
	rp.wantReconnect = false
	rp.setStateLocked("disconnected", "", err.Error())
	rp.mu.Unlock()
	eventType, state := "remote.auth.state", "login_required"
	if pairingRequired {
		eventType, state = "remote.access.state", "pairing_required"
	} else if relayTokenInvalid {
		eventType, state = "remote.access.state", "relay_token_invalid"
	}
	rp.manager.emit(map[string]any{
		"type":    eventType,
		"peer_id": rp.peerID,
		"channel": rp.channel,
		"state":   state,
		"error":   err.Error(),
	})
	return true
}

func isLoginRequiredError(err error) bool {
	return errors.Is(err, account.ErrNotEnrolled) ||
		errors.Is(err, account.ErrExpired) ||
		errors.Is(err, account.ErrCredential) ||
		errors.Is(err, account.ErrStateInvalid) ||
		errors.Is(err, account.ErrAuthorityChanged) ||
		errors.Is(err, account.ErrAlreadyEnrolled)
}

func (rp *RemotePeer) emitSubError(sessionID, code string) {
	rp.manager.emit(map[string]any{
		"type":       "remote.subscription.error",
		"peer_id":    rp.peerID,
		"channel":    rp.channel,
		"session_id": sessionID,
		"code":       code,
	})
}

type peerHandler RemotePeer

func (h *peerHandler) Open(transport.Peer) {}

func (h *peerHandler) Closed(p transport.Peer) {
	rp := (*RemotePeer)(h)
	rp.mu.Lock()
	if rp.peer == p {
		rp.detachLocked()
		if rp.wantReconnect {
			rp.setStateLocked("reconnecting", "", "connection lost")
			signalCh(rp.retry)
		} else {
			rp.setStateLocked("disconnected", "", "")
		}
	}
	rp.mu.Unlock()
}

func (h *peerHandler) Message(p transport.Peer, b []byte) {
	rp := (*RemotePeer)(h)
	var m struct {
		Type     string          `json:"type"`
		ID       string          `json:"request_id"`
		Data     json.RawMessage `json:"data"`
		Code     string          `json:"code"`
		Session  string          `json:"session_id"`
		RunID    string          `json:"run_id"`
		Seq      int64           `json:"seq"`
		Kind     string          `json:"kind"`
		Members  pairnet.Roster  `json:"members"`
		Receiver bool            `json:"receiver"`
		Epoch    uint64          `json:"epoch"`
	}
	if json.Unmarshal(b, &m) != nil {
		p.Close()
		return
	}
	rp.mu.Lock()
	if rp.peer != p {
		rp.mu.Unlock()
		return
	}
	rp.inboundFrames.Add(1)
	group := rp.group
	switch m.Type {
	case "pairnet.state":
		rp.mu.Unlock()
		if group == nil {
			p.Close()
			return
		}
		changed, err := group.Merge(rp.peerID, m.Members)
		if err != nil || !group.Allows(rp.peerID) || !group.Allows(group.Self()) {
			rp.handleAuthError(pairnet.ErrRemoved)
			if changed {
				go rp.manager.notifyNetworkChanged(rp.channel, rp.peerID)
			}
			p.Close()
			return
		}
		if mem, ok := group.Get(rp.peerID); ok {
			rp.mu.Lock()
			if mem.Name != "" {
				rp.name = mem.Name
			}
			if mem.Address != "" {
				rp.address = mem.Address
			}
			rp.mu.Unlock()
		}
		if changed {
			signalCh(rp.betterWake)
			go rp.manager.notifyNetworkChanged(rp.channel, rp.peerID)
		}
		return
	case "pairnet.removed":
		rp.mu.Unlock()
		if group != nil {
			changed, _ := group.ReceiveRemoval(rp.peerID, m.Receiver, m.Epoch)
			if changed {
				go rp.manager.notifyNetworkChanged(rp.channel, rp.peerID)
			}
		}
		rp.handleAuthError(pairnet.ErrRemoved)
		p.Close()
		return
	case "result", "error":
		if ch := rp.pending[m.ID]; ch != nil {
			var err error
			if m.Type == "error" {
				err = errors.New(m.Code)
				switch m.Code {
				case "snapshot_required":
					err = errSnapshot
				case "unavailable":
					err = errUnavailable
				}
			}
			ch <- rpcReply{m.Data, err}
			delete(rp.pending, m.ID)
		}
		rp.mu.Unlock()
		return
	case "event":
		if m.Seq == 0 && m.Kind != "" && m.Session != "" {
			rp.mu.Unlock()
			ev := map[string]any{
				"type":       "remote.event",
				"peer_id":    rp.peerID,
				"channel":    rp.channel,
				"session_id": m.Session,
				"seq":        int64(0),
				"kind":       m.Kind,
			}
			if len(m.Data) > 0 {
				ev["data"] = m.Data
			}
			rp.manager.emit(ev)
			return
		}
		cur := rp.subscriptions[m.Session]
		if cur != nil && m.Seq > cur.delivered {
			if m.Seq != cur.delivered+1 {
				delete(rp.subscriptions, m.Session)
				rp.mu.Unlock()
				rp.emitSubError(m.Session, errSnapshot.Error())
				return
			}
			cur.delivered = m.Seq
			rp.mu.Unlock()
			ev := map[string]any{
				"type":       "remote.event",
				"peer_id":    rp.peerID,
				"channel":    rp.channel,
				"session_id": m.Session,
				"seq":        m.Seq,
				"kind":       m.Kind,
			}
			if m.RunID != "" {
				ev["run_id"] = m.RunID
			}
			if len(m.Data) > 0 {
				ev["data"] = m.Data
			}
			rp.manager.emit(ev)
			return
		}
		rp.mu.Unlock()
		return
	default:
		rp.mu.Unlock()
		p.Close()
	}
}

// Business RPC methods mirroring mobile/requests.go.

func (rp *RemotePeer) currentPeer() (transport.Peer, error) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if rp.peer == nil {
		return nil, errors.New("remote: desktop disconnected")
	}
	return rp.peer, nil
}

func (rp *RemotePeer) request(ctx context.Context, p transport.Peer, req map[string]any, online bool) (json.RawMessage, error) {
	return rp.requestWithTimeout(ctx, p, req, online, 20*time.Second)
}

func (rp *RemotePeer) requestWithTimeout(ctx context.Context, p transport.Peer, req map[string]any, online bool, timeout time.Duration) (json.RawMessage, error) {
	id, _ := req["request_id"].(string)
	if id == "" || len(id) > 128 {
		return nil, errors.New("request_id must be 1..128 bytes")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	ch := make(chan rpcReply, 1)
	rp.mu.Lock()
	if rp.peer != p || len(rp.pending) >= 32 || rp.pending[id] != nil {
		rp.mu.Unlock()
		return nil, errors.New("remote: desktop disconnected, busy, or request already pending")
	}
	rp.pending[id] = ch
	rp.mu.Unlock()
	defer func() {
		rp.mu.Lock()
		if rp.pending[id] == ch {
			delete(rp.pending, id)
		}
		rp.mu.Unlock()
	}()
	if err := p.Send(body, online); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-rp.ctx.Done():
		return nil, rp.ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("remote: desktop response timeout")
	case r := <-ch:
		return r.data, r.err
	}
}

func (rp *RemotePeer) subscribe(ctx context.Context, p transport.Peer, sessionID string, afterSeq int64) (json.RawMessage, error) {
	if afterSeq < 0 || sessionID == "" {
		return nil, errors.New("session_id and nonnegative after_seq required")
	}
	rp.mu.Lock()
	if len(rp.subscriptions) >= 64 && rp.subscriptions[sessionID] == nil {
		rp.mu.Unlock()
		return nil, errors.New("too many open sessions")
	}
	watch := false
	if existing := rp.subscriptions[sessionID]; existing != nil {
		watch = existing.watchPresence
	}
	rp.subscriptions[sessionID] = &sessionCursor{applied: afterSeq, delivered: afterSeq, watchPresence: watch}
	rp.mu.Unlock()
	req := map[string]any{
		"type":       "events.resume",
		"request_id": NewRequestID(),
		"session_id": sessionID,
		"after_seq":  afterSeq,
	}
	if watch {
		req["watch_presence"] = true
	}
	data, err := rp.request(ctx, p, req, false)
	if errors.Is(err, errSnapshot) || errors.Is(err, errUnavailable) {
		rp.mu.Lock()
		delete(rp.subscriptions, sessionID)
		rp.mu.Unlock()
	}
	return data, err
}

func (rp *RemotePeer) ListWorkspaces(ctx context.Context) (json.RawMessage, error) {
	p, err := rp.currentPeer()
	if err != nil {
		return nil, err
	}
	return rp.request(ctx, p, map[string]any{"type": "workspace.list", "request_id": NewRequestID()}, false)
}

func (rp *RemotePeer) CreateSession(ctx context.Context, workspaceID, requestID, title string) (json.RawMessage, error) {
	return rp.CreateSessionWithOptions(ctx, workspaceID, requestID, title, RequestOptions{})
}

func (rp *RemotePeer) CreateSessionWithOptions(ctx context.Context, workspaceID, requestID, title string, opts RequestOptions) (json.RawMessage, error) {
	p, err := rp.currentPeer()
	if err != nil {
		return nil, err
	}
	req := map[string]any{
		"type":         "session.create",
		"request_id":   ScopedRequestID(opts.Namespace, requestID),
		"workspace_id": workspaceID,
		"title":        title,
	}
	if strings.TrimSpace(opts.LinkOrigin) != "" {
		req["link_origin"] = strings.TrimSpace(opts.LinkOrigin)
	}
	if opts.ModeLimit != nil {
		req["mode_limit"] = opts.ModeLimit
	}
	return rp.request(ctx, p, req, true)
}

func (rp *RemotePeer) ListSessions(ctx context.Context) (json.RawMessage, error) {
	p, err := rp.currentPeer()
	if err != nil {
		return nil, err
	}
	return rp.request(ctx, p, map[string]any{"type": "session.list", "request_id": NewRequestID()}, false)
}

func (rp *RemotePeer) OpenSession(ctx context.Context, sessionID string) (json.RawMessage, error) {
	return rp.OpenSessionWithOptions(ctx, sessionID, false)
}

func (rp *RemotePeer) OpenSessionWithOptions(ctx context.Context, sessionID string, watchPresence bool) (json.RawMessage, error) {
	rp.op.Lock()
	defer rp.op.Unlock()
	p, err := rp.currentPeer()
	if err != nil {
		return nil, err
	}
	req := map[string]any{
		"type":       "session.open",
		"request_id": NewRequestID(),
		"session_id": sessionID,
	}
	if watchPresence {
		req["watch_presence"] = true
	}
	data, err := rp.request(ctx, p, req, false)
	if err != nil {
		return nil, err
	}
	var snapshot struct {
		Last *int64 `json:"last_seq"`
	}
	if json.Unmarshal(data, &snapshot) != nil || snapshot.Last == nil || *snapshot.Last < 0 {
		return nil, errors.New("remote: invalid desktop snapshot")
	}
	if watchPresence {
		rp.mu.Lock()
		if cur := rp.subscriptions[sessionID]; cur != nil {
			cur.watchPresence = true
		} else {
			rp.subscriptions[sessionID] = &sessionCursor{applied: *snapshot.Last, delivered: *snapshot.Last, watchPresence: true}
		}
		rp.mu.Unlock()
	}
	if _, err := rp.subscribe(ctx, p, sessionID, *snapshot.Last); err != nil {
		return nil, err
	}
	return data, nil
}

func (rp *RemotePeer) CloseSession(ctx context.Context, sessionID string) (json.RawMessage, error) {
	rp.op.Lock()
	defer rp.op.Unlock()
	p, err := rp.currentPeer()
	if err != nil {
		return nil, err
	}
	rp.mu.Lock()
	delete(rp.subscriptions, sessionID)
	rp.mu.Unlock()
	return rp.request(ctx, p, map[string]any{
		"type":       "session.close",
		"request_id": NewRequestID(),
		"session_id": sessionID,
	}, false)
}

func (rp *RemotePeer) SessionPresence(ctx context.Context, sessionID string, watch *bool) (json.RawMessage, error) {
	p, err := rp.currentPeer()
	if err != nil {
		return nil, err
	}
	req := map[string]any{
		"type":       "session.presence",
		"request_id": NewRequestID(),
		"session_id": sessionID,
	}
	if watch != nil {
		req["watch"] = *watch
	}
	data, err := rp.request(ctx, p, req, false)
	if err == nil && watch != nil {
		rp.mu.Lock()
		if cur := rp.subscriptions[sessionID]; cur != nil {
			cur.watchPresence = *watch
		}
		rp.mu.Unlock()
	}
	return data, err
}

func (rp *RemotePeer) Resume(ctx context.Context, sessionID string, afterSeq int64) error {
	rp.op.Lock()
	defer rp.op.Unlock()
	p, err := rp.currentPeer()
	if err != nil {
		return err
	}
	_, err = rp.subscribe(ctx, p, sessionID, afterSeq)
	return err
}

func (rp *RemotePeer) Acknowledge(sessionID string, seq int64) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	cur := rp.subscriptions[sessionID]
	if cur == nil || seq < 0 || seq > cur.delivered {
		return errors.New("cursor was not delivered")
	}
	cur.applied = max(cur.applied, seq)
	return nil
}

func (rp *RemotePeer) StartRun(ctx context.Context, sessionID, requestID, text string) (json.RawMessage, error) {
	return rp.StartRunWithOptions(ctx, sessionID, requestID, text, RequestOptions{})
}

func (rp *RemotePeer) StartRunWithOptions(ctx context.Context, sessionID, requestID, text string, opts RequestOptions) (json.RawMessage, error) {
	p, err := rp.currentPeer()
	if err != nil {
		return nil, err
	}
	req := map[string]any{
		"type":       "run.start",
		"request_id": ScopedRequestID(opts.Namespace, requestID),
		"session_id": sessionID,
		"text":       text,
	}
	if strings.TrimSpace(opts.LinkOrigin) != "" {
		req["link_origin"] = strings.TrimSpace(opts.LinkOrigin)
	}
	if opts.ModeLimit != nil {
		req["mode_limit"] = opts.ModeLimit
	}
	if strings.TrimSpace(opts.QueuePolicy) != "" {
		req["queue_policy"] = strings.TrimSpace(opts.QueuePolicy)
	}
	return rp.request(ctx, p, req, true)
}

func (rp *RemotePeer) CancelRun(ctx context.Context, sessionID, runID string) (json.RawMessage, error) {
	return rp.CancelRunWithOrigin(ctx, sessionID, runID, "")
}

func (rp *RemotePeer) CancelRunWithOrigin(ctx context.Context, sessionID, runID, linkOrigin string) (json.RawMessage, error) {
	p, err := rp.currentPeer()
	if err != nil {
		return nil, err
	}
	req := map[string]any{
		"type":       "run.cancel",
		"request_id": NewRequestID(),
		"session_id": sessionID,
		"run_id":     runID,
	}
	if strings.TrimSpace(linkOrigin) != "" {
		req["link_origin"] = strings.TrimSpace(linkOrigin)
	}
	return rp.request(ctx, p, req, true)
}

func (rp *RemotePeer) SubmitGuestRequest(ctx context.Context, sessionID, requestID, text string) (json.RawMessage, error) {
	p, err := rp.currentPeer()
	if err != nil {
		return nil, err
	}
	if requestID == "" {
		requestID = NewRequestID()
	}
	return rp.request(ctx, p, map[string]any{
		"type":       "guest.request",
		"request_id": requestID,
		"session_id": sessionID,
		"text":       text,
	}, false)
}

func (rp *RemotePeer) RespondGuestRequest(ctx context.Context, sessionID, guestRequestID, action string) (json.RawMessage, error) {
	return rp.RespondGuestRequestWithOptions(ctx, sessionID, guestRequestID, action, GuestRespondOptions{})
}

func (rp *RemotePeer) RespondGuestRequestWithOptions(ctx context.Context, sessionID, guestRequestID, action string, opts GuestRespondOptions) (json.RawMessage, error) {
	p, err := rp.currentPeer()
	if err != nil {
		return nil, err
	}
	req := map[string]any{
		"type":             "guest.respond",
		"request_id":       NewRequestID(),
		"session_id":       sessionID,
		"guest_request_id": guestRequestID,
		"action":           action,
	}
	if opts.Text != "" {
		req["text"] = opts.Text
	}
	if strings.TrimSpace(opts.LinkOrigin) != "" {
		req["link_origin"] = strings.TrimSpace(opts.LinkOrigin)
	}
	if opts.ModeLimit != nil {
		req["mode_limit"] = opts.ModeLimit
	}
	return rp.request(ctx, p, req, action == "approve")
}

func (rp *RemotePeer) RespondUI(ctx context.Context, sessionID, runID, uiID string, payload UIResponse) (json.RawMessage, error) {
	p, err := rp.currentPeer()
	if err != nil {
		return nil, err
	}
	req := map[string]any{
		"type":       "ui.respond",
		"request_id": NewRequestID(),
		"session_id": sessionID,
		"run_id":     runID,
		"ui_id":      uiID,
	}
	if payload.Cancelled {
		req["cancelled"] = true
	}
	if payload.Confirmed != nil {
		req["confirmed"] = *payload.Confirmed
	}
	if payload.Value != nil {
		req["value"] = *payload.Value
	}
	if payload.Answers != nil {
		req["answers"] = payload.Answers
	}
	return rp.request(ctx, p, req, true)
}

func peerPath(p transport.Peer) string {
	if pr, ok := p.(transport.PathReporter); ok {
		return pr.Path()
	}
	return "unknown"
}

func signalCh(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
