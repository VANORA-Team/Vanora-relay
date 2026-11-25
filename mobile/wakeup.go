package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
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

// Wakeup notifies the client that the app returned to the foreground or the
// device network changed. Unlike Reconnect, Wakeup probes an established
// connection first instead of blindly tearing down a healthy socket, while
// running a parallel silent-socket check so half-open suspended sockets are
// replaced within ~1.5s.
func (c *Client) Wakeup(longResume bool) error {
	c.routeTracker.Reset()
	c.mu.Lock()
	device := c.device
	p := c.peer
	path := c.connPath
	c.mu.Unlock()
	if device == "" {
		return errors.New("no desktop selected")
	}
	if p == nil {
		c.op.Lock()
		defer c.op.Unlock()
		c.mu.Lock()
		stillNil := c.peer == nil && c.device != ""
		if stillNil {
			c.setStateLocked("reconnecting", "", "")
		}
		c.mu.Unlock()
		if !stillNil {
			return nil
		}
		err := c.connectLocked()
		if err != nil && !c.handleAuthError(err) {
			signal(c.retryNow)
		}
		return err
	}

	alive := c.probeWithSilentCheck(p, path, longResume)
	if alive {
		signal(c.betterWake)
		return nil
	}

	c.op.Lock()
	defer c.op.Unlock()
	c.mu.Lock()
	if c.device == "" {
		c.mu.Unlock()
		return errors.New("no desktop selected")
	}
	if c.peer != p {
		// Another goroutine already replaced the connection while we probed.
		c.mu.Unlock()
		return nil
	}
	c.detachLocked()
	c.setStateLocked("reconnecting", "", "silent or unresponsive socket")
	c.mu.Unlock()
	p.Close()
	if c.socket != nil {
		c.socket.Close()
		c.socket = nil
	}
	err := c.connectLocked()
	if err != nil && !c.handleAuthError(err) {
		signal(c.retryNow)
	}
	return err
}

// Probe performs an in-band liveness check over the active encrypted channel.
func (c *Client) Probe(timeoutMillis int64) (bool, error) {
	if timeoutMillis <= 0 || timeoutMillis > 30000 {
		timeoutMillis = 3000
	}
	p, err := c.currentPeer()
	if err != nil {
		return false, err
	}
	return c.pingPeer(p, time.Duration(timeoutMillis)*time.Millisecond), nil
}

func (c *Client) pingPeer(p transport.Peer, timeout time.Duration) bool {
	framesBefore := c.inboundFrames.Load()
	_, err := c.requestWithTimeout(p, map[string]any{
		"type":       "ping",
		"request_id": NewRequestID(),
	}, false, timeout)
	if err == nil {
		return true
	}
	// An older desktop that rejects "ping" with invalid_request still proved
	// bidirectional frame delivery over the encrypted channel.
	if err.Error() == "invalid_request" || c.inboundFrames.Load() > framesBefore {
		return true
	}
	return false
}

func (c *Client) probeWithSilentCheck(p transport.Peer, path string, longResume bool) bool {
	timeout := remoteProbeTimeout
	if longResume {
		timeout = longResumeProbeTimeout
	} else if path == "lan" || path == "direct" {
		timeout = quickProbeTimeout
	}

	pctx, cancel := context.WithTimeout(c.ctx, timeout)
	defer cancel()

	framesBefore := c.inboundFrames.Load()
	type outcome struct {
		alive bool
	}
	probeCh := make(chan outcome, 1)
	go func() {
		ok := c.pingPeer(p, timeout)
		probeCh <- outcome{alive: ok}
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
		if c.inboundFrames.Load() > framesBefore {
			silentCh <- "alive"
			return
		}
		for {
			if pctx.Err() != nil {
				return
			}
			if c.checkHostReachable(pctx) {
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
					if c.inboundFrames.Load() > framesBefore {
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
		if c.inboundFrames.Load() == framesBefore {
			silentCh <- "silent"
		} else {
			silentCh <- "alive"
		}
	}()

	for {
		select {
		case res := <-probeCh:
			return res.alive
		case sig := <-silentCh:
			if sig == "silent" {
				// Host answered a fresh out-of-band check while the socket stayed
				// completely silent: half-open dead socket detected early.
				return false
			}
		case <-pctx.Done():
			return c.inboundFrames.Load() > framesBefore
		}
	}
}

func (c *Client) checkHostReachable(ctx context.Context) bool {
	c.mu.Lock()
	var lanT *lan.Target
	if c.lanTarget != nil {
		cp := *c.lanTarget
		lanT = &cp
	}
	var selfURL, selfTok string
	if c.selfTarget != nil {
		selfURL, selfTok = c.selfTarget.SignalURL, c.selfTarget.Token
	}
	sigURL := c.url
	c.mu.Unlock()

	switch {
	case lanT != nil:
		return lan.ProbeTarget(ctx, *lanT, c.lanKey, 1200*time.Millisecond) == nil
	case selfURL != "":
		return routes.ProbeSignalHTTP(ctx, selfURL, selfTok, 1500*time.Millisecond) == nil
	case sigURL != "":
		return routes.ProbeSignalHTTP(ctx, sigURL, "", 1500*time.Millisecond) == nil
	default:
		return false
	}
}

// AddRoute adds an alternate private LAN or tailnet (100.64.0.0/10) IP:port
// route for the currently paired LAN desktop, preserving its pinned public key.
func (c *Client) AddRoute(address string) error {
	norm, _, err := routes.ClassifyAddress(address)
	if err != nil {
		return err
	}
	c.op.Lock()
	defer c.op.Unlock()
	if c.lanKey == "" || c.lanTarget == nil {
		return errors.New("alternate IP routes require a paired LAN/tailnet desktop")
	}
	c.mu.Lock()
	if c.lanTarget.Address != norm && !slices.Contains(c.altLANRoutes, norm) {
		c.altLANRoutes = append(c.altLANRoutes, norm)
	}
	c.mu.Unlock()
	c.routeTracker.Reset()
	signal(c.betterWake)
	return nil
}

// RemoveRoute removes a previously added alternate IP:port route.
func (c *Client) RemoveRoute(address string) error {
	norm, _, err := routes.ClassifyAddress(address)
	if err != nil {
		return err
	}
	c.op.Lock()
	defer c.op.Unlock()
	if c.lanTarget == nil {
		return errors.New("no paired LAN/tailnet desktop")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	all := c.lanCandidateEntriesLocked()
	if len(all) <= 1 {
		return errors.New("cannot remove the last route")
	}
	c.altLANRoutes = slices.DeleteFunc(c.altLANRoutes, func(a string) bool { return a == norm })
	if c.lanTarget.Address == norm {
		for _, entry := range all {
			if entry.Address != norm {
				c.lanTarget.Address = entry.Address
				break
			}
		}
	}
	return nil
}

// Routes returns a JSON array of ordered candidate routes for the selected desktop.
func (c *Client) Routes() string {
	c.mu.Lock()
	var list []routes.Entry
	switch {
	case c.lanTarget != nil:
		list = c.lanCandidateEntriesLocked()
	case c.selfTarget != nil:
		list = []routes.Entry{{Address: c.selfTarget.SignalURL, Kind: routes.KindRelay}}
	case c.device != "" && c.url != "":
		list = []routes.Entry{{Address: c.url, Kind: routes.KindRelay}}
	default:
		list = []routes.Entry{}
	}
	c.mu.Unlock()
	b, _ := json.Marshal(list)
	return string(b)
}

func (c *Client) lanCandidateEntriesLocked() []routes.Entry {
	if c.lanTarget == nil {
		return nil
	}
	var learned string
	if c.group != nil {
		if mem, ok := c.group.Get(c.lanTarget.Pin); ok && mem.Active() && strings.TrimSpace(mem.Address) != "" {
			learned = mem.Address
		}
	}
	return routes.MergeOrdered(c.lanTarget.Address, c.altLANRoutes, learned)
}

func (c *Client) dialLANPeer() (transport.Peer, func(), error) {
	c.mu.Lock()
	base := *c.lanTarget
	entries := c.lanCandidateEntriesLocked()
	c.mu.Unlock()
	if len(entries) == 0 {
		entries = []routes.Entry{{Address: base.Address, Kind: routes.KindLAN}}
	}
	// First-time pairing with a one-time token must only go to the exact invited address.
	if base.Token != "" {
		p, start, err := lan.Dial(c.ctx, base, c.lanKey, c.lanName, (*handler)(c))
		if err == nil {
			c.lanTarget.Token = ""
		}
		return p, start, err
	}

	now := time.Now()
	var filtered []routes.Entry
	for _, e := range entries {
		if !c.routeTracker.InCooldown(e.Address, now) {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == 0 {
		filtered = entries
	}

	var lastErr error
	for _, cand := range filtered {
		t := lan.Target{Address: cand.Address, Pin: base.Pin}
		if len(filtered) > 1 {
			dctx, cancel := context.WithTimeout(c.ctx, routes.DialTimeout(cand.Kind))
			pErr := lan.ProbeTarget(dctx, t, c.lanKey, routes.DialTimeout(cand.Kind))
			cancel()
			if pErr != nil {
				if errors.Is(pErr, lan.ErrUnpaired) {
					return nil, nil, pErr
				}
				lastErr = pErr
				continue
			}
		}
		p, start, err := lan.Dial(c.ctx, t, c.lanKey, c.lanName, (*handler)(c))
		if err == nil {
			c.mu.Lock()
			if c.lanTarget != nil && c.lanTarget.Pin == base.Pin {
				if c.lanTarget.Address != cand.Address && !slices.Contains(c.altLANRoutes, c.lanTarget.Address) {
					c.altLANRoutes = append(c.altLANRoutes, c.lanTarget.Address)
				}
				c.lanTarget.Address = cand.Address
			}
			c.mu.Unlock()
			c.routeTracker.RecordProbeSuccess(cand.Address)
			return p, start, nil
		}
		if errors.Is(err, lan.ErrUnpaired) {
			return nil, nil, err
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

func (c *Client) maintainRoutes() {
	ticker := time.NewTicker(routes.BetterRouteCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		case <-c.betterWake:
		}
		c.checkBetterRoutes()
	}
}

func (c *Client) checkBetterRoutes() {
	c.mu.Lock()
	if c.lanTarget == nil || c.peer == nil || c.lanTarget.Token != "" {
		c.mu.Unlock()
		return
	}
	activeAddr := c.lanTarget.Address
	pin := c.lanTarget.Pin
	entries := c.lanCandidateEntriesLocked()
	c.mu.Unlock()

	_, activeKind, err := routes.ClassifyAddress(activeAddr)
	if err != nil {
		return
	}
	now := time.Now()
	for _, cand := range entries {
		if cand.Address == activeAddr || routes.Rank(cand.Kind) >= routes.Rank(activeKind) {
			continue
		}
		if !c.routeTracker.ShouldProbe(cand.Address, now) {
			continue
		}
		err := lan.ProbeTarget(c.ctx, lan.Target{Address: cand.Address, Pin: pin}, c.lanKey, 2*time.Second)
		if err != nil {
			c.routeTracker.RecordProbeMiss(cand.Address, now)
			continue
		}
		c.routeTracker.RecordProbeSuccess(cand.Address)
		c.switchToBetterLANRoute(pin, activeAddr, cand.Address)
		return
	}
}

func (c *Client) switchToBetterLANRoute(pin, prevAddr, betterAddr string) {
	c.op.Lock()
	defer c.op.Unlock()
	c.mu.Lock()
	if c.lanTarget == nil || c.lanTarget.Pin != pin || c.lanTarget.Address == betterAddr {
		c.mu.Unlock()
		return
	}
	if !slices.Contains(c.altLANRoutes, prevAddr) {
		c.altLANRoutes = append(c.altLANRoutes, prevAddr)
	}
	c.lanTarget.Address = betterAddr
	oldPeer := c.peer
	c.detachLocked()
	c.setStateLocked("reconnecting", "", "")
	c.mu.Unlock()
	if oldPeer != nil {
		oldPeer.Close()
	}
	if err := c.connectLocked(); err != nil {
		// Better route answered probe but failed setup; cool it down for 5 minutes.
		c.routeTracker.RecordSwitchFailure(betterAddr, time.Now())
		c.mu.Lock()
		if c.lanTarget != nil && c.lanTarget.Pin == pin {
			c.lanTarget.Address = prevAddr
		}
		c.mu.Unlock()
		if err2 := c.connectLocked(); err2 != nil && !c.handleAuthError(err2) {
			signal(c.retryNow)
		}
	}
}

// PollActivity queries the configured relay over HTTP(S) for redacted,
// content-free session attention states of the selected desktop without
// opening a WebRTC DataChannel (suitable for background OS tasks and widgets).
func (c *Client) PollActivity() (string, error) {
	c.mu.Lock()
	var selfT *selfrelay.Target
	if c.selfTarget != nil {
		cp := *c.selfTarget
		selfT = &cp
	}
	selfSeed := c.selfKey
	sigURL := c.url
	targetDevice := c.device
	source := c.source
	c.mu.Unlock()

	now := time.Now()
	pctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()

	var rawEndpoint string
	var bearerToken string
	var pubKeyHeader string
	var proofHeader string

	switch {
	case selfSeed != "" && selfT != nil && selfT.SignalURL != "" && selfT.Pin != "":
		pubB64, devID, proofB64, err := selfrelay.SignActivityPoll(selfSeed, selfT.Pin, now)
		if err != nil {
			return "", err
		}
		rawEndpoint = selfT.SignalURL
		targetDevice = devID
		bearerToken = selfT.Token
		pubKeyHeader = pubB64
		proofHeader = proofB64
	case source != nil && sigURL != "" && targetDevice != "":
		creds, _, err := source.Current(pctx)
		if err != nil {
			return "", err
		}
		proofB64, err := creds.SignActivityPoll(targetDevice, now)
		if err != nil {
			return "", err
		}
		rawEndpoint = sigURL
		proofHeader = proofB64
	default:
		return "", errors.New("activity polling requires a selected official or self-hosted relay desktop")
	}

	u, err := url.Parse(strings.TrimSpace(rawEndpoint))
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	q := u.Query()
	q.Set("activity", targetDevice)
	u.RawQuery = q.Encode()
	u.Fragment = ""

	req, err := http.NewRequestWithContext(pctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	if pubKeyHeader != "" {
		req.Header.Set("X-Vanora-Public-Key", pubKeyHeader)
	}
	req.Header.Set("X-Vanora-Activity-Proof", proofHeader)

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return "", errors.New(msg)
	}
	return string(body), nil
}
