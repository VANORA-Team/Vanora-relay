package remote

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairnet"
	"vanora-relay/internal/routes"
)

const (
	silentSocketCheckAfter        = 300 * time.Millisecond
	silentSocketRecheck           = 400 * time.Millisecond
	remoteSilentSocketAfter       = 1400 * time.Millisecond
	longResumeRelaySilentFloor    = 900 * time.Millisecond
	longResumeProbeTimeout        = 1500 * time.Millisecond
	quickProbeTimeout             = 3000 * time.Millisecond
	remoteProbeTimeout            = 6000 * time.Millisecond
	tunnelWebRTCFailbackMinUptime = routes.BetterRouteCheckInterval
)

// Wakeup probes an established connection instead of blindly tearing it down,
// running a parallel silent-socket check so half-open sockets are replaced
// promptly while healthy sessions stay uninterrupted.
func (rp *RemotePeer) Wakeup(ctx context.Context, longResume bool) error {
	rp.routeTracker.Reset()
	rp.mu.Lock()
	p := rp.peer
	path := rp.connPath
	rp.mu.Unlock()
	if p != nil {
		if live := peerPath(p); live != "" {
			path = live
		}
	}

	if p == nil {
		rp.interruptDial()
		rp.op.Lock()
		defer rp.op.Unlock()
		rp.mu.Lock()
		if rp.peer != nil && rp.peer.Allows(false) {
			rp.mu.Unlock()
			return nil
		}
		rp.wantReconnect = true
		rp.setStateLocked("reconnecting", "", "")
		rp.mu.Unlock()
		err := rp.connectLocked(ctx)
		if err != nil && !rp.handleAuthError(err) {
			signalCh(rp.retryNow)
		}
		return err
	}

	if rp.probeWithSilentCheck(ctx, p, path, longResume) {
		signalCh(rp.betterWake)
		return nil
	}

	rp.interruptDial()
	rp.op.Lock()
	defer rp.op.Unlock()
	rp.mu.Lock()
	if rp.peer != p {
		rp.mu.Unlock()
		return nil
	}
	rp.mu.Unlock()
	rp.dropLinkLocked()
	rp.mu.Lock()
	rp.wantReconnect = true
	rp.setStateLocked("reconnecting", "", "silent or unresponsive socket")
	rp.mu.Unlock()
	err := rp.connectLocked(ctx)
	if err != nil && !rp.handleAuthError(err) {
		signalCh(rp.retryNow)
	}
	return err
}

// Probe performs an in-band liveness check over the active encrypted channel.
func (rp *RemotePeer) Probe(ctx context.Context, timeout time.Duration) (bool, error) {
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 3 * time.Second
	}
	p, err := rp.currentPeer()
	if err != nil {
		return false, err
	}
	return rp.pingPeer(ctx, p, timeout), nil
}

func (rp *RemotePeer) pingPeer(ctx context.Context, p transport.Peer, timeout time.Duration) bool {
	framesBefore := rp.inboundFrames.Load()
	_, err := rp.requestWithTimeout(ctx, p, map[string]any{
		"type":       "ping",
		"request_id": NewRequestID(),
	}, false, timeout)
	if err == nil {
		return true
	}
	if err.Error() == "invalid_request" || rp.inboundFrames.Load() > framesBefore {
		return true
	}
	return false
}

func (rp *RemotePeer) probeWithSilentCheck(ctx context.Context, p transport.Peer, path string, longResume bool) bool {
	timeout := remoteProbeTimeout
	if longResume {
		timeout = longResumeProbeTimeout
	} else if path == "lan" || path == "direct" {
		timeout = quickProbeTimeout
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	framesBefore := rp.inboundFrames.Load()
	probeCh := make(chan bool, 1)
	go func() {
		probeCh <- rp.pingPeer(pctx, p, timeout)
	}()

	silentCh := make(chan string, 1)
	go func() {
		started := time.Now()
		timer := time.NewTimer(silentSocketCheckAfter)
		defer timer.Stop()
		select {
		case <-pctx.Done():
			return
		case <-timer.C:
		}
		if rp.inboundFrames.Load() > framesBefore {
			silentCh <- "alive"
			return
		}
		for {
			if pctx.Err() != nil {
				return
			}
			if rp.checkHostReachable(pctx) {
				break
			}
			wait := time.NewTimer(silentSocketRecheck)
			select {
			case <-pctx.Done():
				wait.Stop()
				return
			case <-wait.C:
			}
		}
		floor := time.Duration(0)
		if !longResume && path != "lan" && path != "direct" {
			floor = remoteSilentSocketAfter
		} else if longResume && rp.channel != ChannelLAN {
			floor = longResumeRelaySilentFloor
		}
		if floor > 0 {
			if rem := floor - time.Since(started); rem > 0 {
				deadline := time.Now().Add(rem)
				for time.Now().Before(deadline) {
					if rp.inboundFrames.Load() > framesBefore {
						silentCh <- "alive"
						return
					}
					sleep := time.NewTimer(50 * time.Millisecond)
					select {
					case <-pctx.Done():
						sleep.Stop()
						return
					case <-sleep.C:
					}
				}
			}
		}
		if rp.inboundFrames.Load() == framesBefore {
			silentCh <- "silent"
		} else {
			silentCh <- "alive"
		}
	}()

	for {
		select {
		case ok := <-probeCh:
			return ok
		case sig := <-silentCh:
			if sig == "silent" {
				return false
			}
		case <-pctx.Done():
			return rp.inboundFrames.Load() > framesBefore
		}
	}
}

func (rp *RemotePeer) checkHostReachable(ctx context.Context) bool {
	switch rp.channel {
	case ChannelLAN:
		lanCh, err := rp.manager.provider.LAN()
		if err != nil || lanCh == nil || lanCh.Server == nil {
			return false
		}
		rp.mu.Lock()
		addr := rp.address
		rp.mu.Unlock()
		if addr == "" {
			return false
		}
		return lan.ProbeTarget(ctx, lan.Target{Address: addr, Pin: rp.peerID}, lanCh.Server.Seed(), 1200*time.Millisecond) == nil
	case ChannelSelf:
		rp.mu.Lock()
		var sigURL, tok string
		if rp.selfTarget != nil {
			sigURL, tok = rp.selfTarget.SignalURL, rp.selfTarget.Token
		} else {
			sigURL = rp.signalURL
		}
		rp.mu.Unlock()
		if sigURL == "" {
			return false
		}
		return routes.ProbeSignalHTTP(ctx, sigURL, tok, 1500*time.Millisecond) == nil
	case ChannelCN, ChannelGlobal:
		rp.mu.Lock()
		sigURL := rp.signalURL
		rp.mu.Unlock()
		if sigURL == "" {
			if occ, err := rp.manager.provider.Official(rp.channel); err == nil && occ != nil {
				sigURL = occ.SignalURL
			}
		}
		if sigURL == "" {
			return false
		}
		return routes.ProbeSignalHTTP(ctx, sigURL, "", 1500*time.Millisecond) == nil
	default:
		return false
	}
}

func (rp *RemotePeer) routesLocked() []routes.Entry {
	switch rp.channel {
	case ChannelLAN:
		var learned string
		if rp.group != nil {
			if mem, ok := rp.group.Get(rp.peerID); ok && mem.Active() && strings.TrimSpace(mem.Address) != "" {
				learned = mem.Address
			}
		}
		primary := rp.address
		if primary == "" && rp.lanTarget != nil {
			primary = rp.lanTarget.Address
		}
		return routes.MergeOrdered(primary, rp.altRoutes, learned)
	case ChannelSelf, ChannelCN, ChannelGlobal:
		if rp.signalURL != "" {
			entries := []routes.Entry{{Address: rp.signalURL, Kind: routes.KindRelay}}
			if (rp.channel == ChannelSelf && rp.selfTarget != nil && rp.selfTarget.Pair == "") ||
				(rp.channel != ChannelSelf && rp.officialInvite == nil) {
				entries = append(entries, routes.Entry{Address: rp.signalURL, Kind: routes.KindCFTunnel})
			}
			return entries
		}
	}
	return nil
}

// AddRoute adds an alternate private LAN or tailnet (100.64.0.0/10) IP:port
// route for this LAN peer.
func (rp *RemotePeer) AddRoute(address string) error {
	if rp.channel != ChannelLAN {
		return errors.New("remote: alternate IP routes require channel lan")
	}
	norm, _, err := routes.ClassifyAddress(address)
	if err != nil {
		return err
	}
	rp.op.Lock()
	defer rp.op.Unlock()
	rp.mu.Lock()
	if rp.address == "" {
		rp.address = norm
	} else if rp.address != norm && !slices.Contains(rp.altRoutes, norm) {
		rp.altRoutes = append(rp.altRoutes, norm)
	}
	if rp.lanTarget != nil && rp.lanTarget.Address == "" {
		rp.lanTarget.Address = norm
	}
	rp.mu.Unlock()
	rp.routeTracker.Reset()
	signalCh(rp.betterWake)
	return nil
}

// RemoveRoute removes an alternate IP:port route from this LAN peer.
func (rp *RemotePeer) RemoveRoute(address string) error {
	if rp.channel != ChannelLAN {
		return errors.New("remote: alternate IP routes require channel lan")
	}
	norm, _, err := routes.ClassifyAddress(address)
	if err != nil {
		return err
	}
	rp.op.Lock()
	defer rp.op.Unlock()
	rp.mu.Lock()
	defer rp.mu.Unlock()
	all := rp.routesLocked()
	if len(all) <= 1 {
		return errors.New("remote: cannot remove the last route")
	}
	rp.altRoutes = slices.DeleteFunc(rp.altRoutes, func(a string) bool { return a == norm })
	if rp.address == norm {
		for _, entry := range all {
			if entry.Address != norm {
				rp.address = entry.Address
				if rp.lanTarget != nil {
					rp.lanTarget.Address = entry.Address
				}
				break
			}
		}
	}
	return nil
}

func (rp *RemotePeer) maintainRoutes() {
	ticker := time.NewTicker(routes.BetterRouteCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-rp.ctx.Done():
			return
		case <-ticker.C:
		case <-rp.betterWake:
		}
		rp.checkBetterRoutes()
	}
}

func (rp *RemotePeer) checkBetterRoutes() {
	rp.mu.Lock()
	p := rp.peer
	connectedAt := rp.connectedAt
	activeAddr := rp.address
	hasLANToken := rp.lanTarget != nil && rp.lanTarget.Token != ""
	entries := rp.routesLocked()
	rp.mu.Unlock()
	if p == nil {
		return
	}

	if rp.channel == ChannelLAN {
		if activeAddr == "" || hasLANToken {
			return
		}
		lanCh, err := rp.manager.provider.LAN()
		if err != nil || lanCh == nil || lanCh.Server == nil {
			return
		}
		_, activeKind, err := routes.ClassifyAddress(activeAddr)
		if err != nil {
			return
		}
		localName := rp.manager.desktopName()
		localAddr := lanCh.Server.Address()
		now := time.Now()
		for _, cand := range entries {
			if cand.Address == activeAddr || routes.Rank(cand.Kind) >= routes.Rank(activeKind) {
				continue
			}
			if !rp.routeTracker.ShouldProbe(cand.Address, now) {
				continue
			}
			dctx, cancel := context.WithTimeout(rp.ctx, routes.DialTimeout(cand.Kind))
			nextPeer, start, err := lan.DialWithOptionsFor(dctx, rp.ctx, lan.Target{Address: cand.Address, Pin: rp.peerID}, lanCh.Server.Seed(), localName, "desktop", localAddr, (*peerHandler)(rp))
			cancel()
			if err != nil {
				if errors.Is(err, lan.ErrUnpaired) {
					return
				}
				rp.routeTracker.RecordProbeMiss(cand.Address, now)
				continue
			}
			rp.routeTracker.RecordProbeSuccess(cand.Address)
			rp.adoptBetterLANPeer(p, nextPeer, start, activeAddr, cand.Address)
			return
		}
		return
	}

	if peerPath(p) == "cf_tunnel" && time.Since(connectedAt) >= tunnelWebRTCFailbackMinUptime {
		rp.tryFailbackToWebRTC(p)
	}
}

func (rp *RemotePeer) adoptBetterLANPeer(oldPeer, nextPeer transport.Peer, start func(), prevAddr, betterAddr string) {
	rp.op.Lock()
	defer rp.op.Unlock()
	rp.mu.Lock()
	if rp.peer != oldPeer || rp.address == betterAddr {
		rp.mu.Unlock()
		nextPeer.Close()
		return
	}
	if prevAddr != "" && !slices.Contains(rp.altRoutes, prevAddr) {
		rp.altRoutes = append(rp.altRoutes, prevAddr)
	}
	rp.address = betterAddr
	if rp.lanTarget != nil {
		rp.lanTarget.Address = betterAddr
	}
	group := rp.group
	rp.swapPeerLocked(nextPeer)
	resume := rp.resumeSnapshotLocked()
	rp.mu.Unlock()
	oldPeer.Close()
	rp.finishSwappedPeer(nextPeer, start, group, resume, betterAddr)
}

func (rp *RemotePeer) tryFailbackToWebRTC(oldPeer transport.Peer) {
	rp.mu.Lock()
	owner := rp.owner
	invite := rp.officialInvite
	var selfT *selfrelay.Target
	if rp.selfTarget != nil {
		cp := *rp.selfTarget
		selfT = &cp
	}
	sigURL := rp.signalURL
	rp.mu.Unlock()
	if invite != nil || (selfT != nil && selfT.Pair != "") {
		return
	}

	probeKey := "webrtc:" + sigURL + "\x00" + rp.peerID
	if selfT != nil && selfT.SignalURL != "" {
		probeKey = "webrtc:" + selfT.SignalURL + "\x00" + selfT.Pin
	}
	now := time.Now()
	if !rp.routeTracker.ShouldProbe(probeKey, now) {
		return
	}

	dctx, cancel := context.WithTimeout(rp.ctx, 8*time.Second)
	defer cancel()

	var nextPeer transport.Peer
	var start func()
	var nextSock *transport.Client
	var ownsNext bool
	var err error

	switch rp.channel {
	case ChannelSelf:
		if selfT == nil || selfT.SignalURL == "" || selfT.Pin == "" {
			return
		}
		selfCh, sErr := rp.manager.provider.Self()
		if sErr != nil || selfCh == nil || selfCh.Server == nil {
			return
		}
		nextPeer, start, err = selfrelay.DialWithRoleFor(dctx, rp.ctx, *selfT, selfCh.Server.Seed(), rp.manager.desktopName(), "desktop", (*peerHandler)(rp))
	case ChannelCN, ChannelGlobal:
		occ, oErr := rp.manager.provider.Official(rp.channel)
		if oErr != nil || occ == nil || occ.Account == nil || occ.SignalURL == "" {
			return
		}
		var pinB64 string
		if group, _ := occ.Account.PairingIdentity(occ.SignalURL, "desktop"); group != nil {
			if mem, ok := group.Get(rp.peerID); ok && mem.Role == "desktop" && group.Allows(rp.peerID) {
				owner = mem.Owner
				pinB64 = mem.Pin
			}
		}
		if pinB64 == "" {
			bound, ok := occ.Account.PairedPeer(rp.peerID)
			if !ok {
				return
			}
			owner = bound.Owner
			pinB64 = bound.Pin
		}
		pin, decErr := decodePin32(pinB64)
		if decErr != nil {
			return
		}
		source := occ.Source
		if source == nil {
			source = occ.Account
		}
		nextSock, ownsNext, err = rp.acquireOfficialSocket(dctx, occ, source, nil, false)
		if err == nil {
			nextPeer, start, err = nextSock.ConnectPairedDeferred(dctx, rp.peerID, owner, transport.ConnectOptions{
				Pin: pin, Role: transport.RoleDesktop, Name: rp.manager.desktopName(), Handler: (*peerHandler)(rp),
			})
			if err != nil && ownsNext {
				nextSock.Close()
				nextSock = nil
				ownsNext = false
			}
		}
	default:
		return
	}

	if err != nil || nextPeer == nil || !nextPeer.Allows(true) {
		if nextPeer != nil {
			nextPeer.Close()
		}
		if ownsNext && nextSock != nil {
			nextSock.Close()
		}
		rp.routeTracker.RecordProbeMiss(probeKey, now)
		return
	}
	rp.routeTracker.RecordProbeSuccess(probeKey)

	rp.op.Lock()
	defer rp.op.Unlock()
	rp.mu.Lock()
	if rp.peer != oldPeer {
		rp.mu.Unlock()
		nextPeer.Close()
		if ownsNext && nextSock != nil {
			nextSock.Close()
		}
		return
	}
	oldSock, ownsOld := rp.socket, rp.ownsSocket
	rp.socket, rp.ownsSocket = nextSock, ownsNext
	group := rp.group
	rp.swapPeerLocked(nextPeer)
	resume := rp.resumeSnapshotLocked()
	rp.mu.Unlock()
	oldPeer.Close()
	if ownsOld && oldSock != nil && oldSock != nextSock {
		oldSock.Close()
	}
	rp.finishSwappedPeer(nextPeer, start, group, resume, probeKey)
}

func (rp *RemotePeer) swapPeerLocked(nextPeer transport.Peer) {
	rp.detachLocked()
	rp.peer = nextPeer
	rp.connectedAt = time.Now()
	rp.generation.Add(1)
	activePath := peerPath(nextPeer)
	rp.routeTracker.RecordActivePath(activePath, time.Now())
	rp.setStateLocked("connected", activePath, "")
}

func (rp *RemotePeer) resumeSnapshotLocked() map[string]int64 {
	resume := make(map[string]int64, len(rp.subscriptions))
	for id, cur := range rp.subscriptions {
		resume[id] = cur.applied
	}
	return resume
}

func (rp *RemotePeer) finishSwappedPeer(p transport.Peer, start func(), group *pairnet.Group, resume map[string]int64, routeKey string) {
	if start != nil {
		start()
	}
	if !p.Allows(false) {
		rp.routeTracker.RecordSwitchFailure(routeKey, time.Now())
		p.Close()
		(*peerHandler)(rp).Closed(p)
		return
	}
	if group != nil {
		if err := rp.syncPeer(p, group); err != nil {
			rp.routeTracker.RecordSwitchFailure(routeKey, time.Now())
			p.Close()
			return
		}
	}
	for id, seq := range resume {
		if _, err := rp.subscribe(rp.ctx, p, id, seq); err != nil {
			if errors.Is(err, errSnapshot) || errors.Is(err, errUnavailable) || p.Allows(false) {
				rp.mu.Lock()
				delete(rp.subscriptions, id)
				rp.mu.Unlock()
				rp.emitSubError(id, err.Error())
				continue
			}
			rp.routeTracker.RecordSwitchFailure(routeKey, time.Now())
			p.Close()
			return
		}
	}
}
