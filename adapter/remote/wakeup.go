package remote

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/routes"
)

const (
	silentSocketCheckAfter  = 300 * time.Millisecond
	silentSocketRecheck     = 400 * time.Millisecond
	remoteSilentSocketAfter = 1400 * time.Millisecond
	longResumeProbeTimeout  = 1500 * time.Millisecond
	quickProbeTimeout       = 3000 * time.Millisecond
	remoteProbeTimeout      = 6000 * time.Millisecond
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

	if p == nil {
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
		if !longResume && path != "lan" && path != "direct" {
			if rem := remoteSilentSocketAfter - time.Since(started); rem > 0 {
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
			return []routes.Entry{{Address: rp.signalURL, Kind: routes.KindRelay}}
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
	if rp.channel != ChannelLAN {
		return
	}
	lanCh, err := rp.manager.provider.LAN()
	if err != nil || lanCh == nil || lanCh.Server == nil {
		return
	}
	rp.mu.Lock()
	if rp.peer == nil || rp.address == "" || (rp.lanTarget != nil && rp.lanTarget.Token != "") {
		rp.mu.Unlock()
		return
	}
	activeAddr := rp.address
	entries := rp.routesLocked()
	rp.mu.Unlock()

	_, activeKind, err := routes.ClassifyAddress(activeAddr)
	if err != nil {
		return
	}
	now := time.Now()
	for _, cand := range entries {
		if cand.Address == activeAddr || routes.Rank(cand.Kind) >= routes.Rank(activeKind) {
			continue
		}
		if !rp.routeTracker.ShouldProbe(cand.Address, now) {
			continue
		}
		if err := lan.ProbeTarget(rp.ctx, lan.Target{Address: cand.Address, Pin: rp.peerID}, lanCh.Server.Seed(), 2*time.Second); err != nil {
			rp.routeTracker.RecordProbeMiss(cand.Address, now)
			continue
		}
		rp.routeTracker.RecordProbeSuccess(cand.Address)
		rp.switchToBetterRoute(activeAddr, cand.Address)
		return
	}
}

func (rp *RemotePeer) switchToBetterRoute(prevAddr, betterAddr string) {
	rp.op.Lock()
	defer rp.op.Unlock()
	rp.mu.Lock()
	if rp.address == betterAddr {
		rp.mu.Unlock()
		return
	}
	if prevAddr != "" && !slices.Contains(rp.altRoutes, prevAddr) {
		rp.altRoutes = append(rp.altRoutes, prevAddr)
	}
	rp.address = betterAddr
	if rp.lanTarget != nil {
		rp.lanTarget.Address = betterAddr
	}
	rp.mu.Unlock()
	rp.dropLinkLocked()
	rp.mu.Lock()
	rp.wantReconnect = true
	rp.setStateLocked("reconnecting", "", "")
	rp.mu.Unlock()
	if err := rp.connectLocked(rp.ctx); err != nil {
		rp.routeTracker.RecordSwitchFailure(betterAddr, time.Now())
		rp.mu.Lock()
		rp.address = prevAddr
		if rp.lanTarget != nil {
			rp.lanTarget.Address = prevAddr
		}
		rp.mu.Unlock()
		if err2 := rp.connectLocked(rp.ctx); err2 != nil && !rp.handleAuthError(err2) {
			signalCh(rp.retryNow)
		}
	}
}
