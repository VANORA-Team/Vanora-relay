// Package routes implements multi-route classification, priority ordering,
// out-of-band reachability probing, exponential silent-route backoff, and
// anti-flap switchover cooldowns inspired by T3 Code's connection runtime.
package routes

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Kind classifies how a client reaches a target desktop.
type Kind string

const (
	KindLoopback Kind = "loopback"
	KindLAN      Kind = "lan"
	KindTailnet  Kind = "tailnet"
	KindDirect   Kind = "direct"
	KindRelay    Kind = "relay"
	KindCFTunnel Kind = "cf_tunnel"
)

const (
	BetterRouteCheckInterval = 60 * time.Second
	SilentRouteBackoffMax    = 30 * time.Minute
	BetterRouteCooldown      = 5 * time.Minute
	NearbyDialTimeout        = 2500 * time.Millisecond
	TailnetDialTimeout       = 8 * time.Second
	CFTunnelHeadStart        = 4 * time.Second
	CFTunnelFastHeadStart    = 500 * time.Millisecond
)

var tailnetPrefix = netip.MustParsePrefix("100.64.0.0/10")

// IsTailnetAddr reports whether addr belongs to RFC 6598 Shared Address Space
// (100.64.0.0/10), used by Tailscale, Headscale, and WireGuard tailnets.
func IsTailnetAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.Is4() && tailnetPrefix.Contains(addr)
}

// Rank returns the speed preference order (lower is faster/preferred).
func Rank(k Kind) int {
	switch k {
	case KindLoopback:
		return 0
	case KindLAN:
		return 1
	case KindTailnet:
		return 2
	case KindDirect:
		return 3
	case KindRelay:
		return 4
	case KindCFTunnel:
		return 5
	default:
		return 6
	}
}

// ClassifyAddress parses and classifies a private/loopback/tailnet IP:port.
func ClassifyAddress(raw string) (string, Kind, error) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(raw))
	if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" {
		return "", "", errors.New("routes: invalid IP:port address")
	}
	addr := ap.Addr().Unmap()
	var kind Kind
	switch {
	case addr.IsLoopback():
		kind = KindLoopback
	case IsTailnetAddr(addr):
		kind = KindTailnet
	case addr.IsPrivate():
		kind = KindLAN
	default:
		return "", "", errors.New("routes: address must be loopback, private LAN, or tailnet (100.64.0.0/10)")
	}
	return netip.AddrPortFrom(addr, ap.Port()).String(), kind, nil
}

// DialTimeout returns a bounded setup timeout appropriate for k so unreachable
// nearby LAN addresses fail fast when away from home without starving tailnet
// or DERP paths.
func DialTimeout(k Kind) time.Duration {
	switch k {
	case KindLoopback, KindLAN:
		return NearbyDialTimeout
	default:
		return TailnetDialTimeout
	}
}

// Entry represents one candidate address for reaching a pinned desktop.
type Entry struct {
	Address string `json:"address"`
	Kind    Kind   `json:"kind"`
	Learned bool   `json:"learned,omitempty"`
}

// MergeOrdered builds a deduplicated, rank-ordered route slice from primary,
// saved alternates, and an optional learned address reported over pairnet.
func MergeOrdered(primary string, saved []string, learned string) []Entry {
	seen := make(map[string]int)
	var list []Entry
	add := func(raw string, isLearned bool) {
		norm, kind, err := ClassifyAddress(raw)
		if err != nil {
			return
		}
		if idx, exists := seen[norm]; exists {
			if !isLearned && list[idx].Learned {
				list[idx].Learned = false
			}
			return
		}
		entry := Entry{Address: norm, Kind: kind, Learned: isLearned}
		// Insert ahead of strictly slower kinds (preserving caller order within same kind).
		pos := len(list)
		for i, cur := range list {
			if Rank(cur.Kind) > Rank(kind) {
				pos = i
				break
			}
		}
		list = slices.Insert(list, pos, entry)
		for k, v := range seen {
			if v >= pos {
				seen[k] = v + 1
			}
		}
		seen[norm] = pos
	}
	if primary != "" {
		add(primary, false)
	}
	for _, s := range saved {
		add(s, false)
	}
	if learned != "" {
		add(learned, true)
	}
	return list
}

type silentState struct {
	failures int
	until    time.Time
}

// Tracker manages silent-route exponential backoff and flaky-route switchover
// cooldowns for one logical peer.
type Tracker struct {
	mu          sync.Mutex
	silent      map[string]silentState
	tunnels     map[string]silentState
	tunnelWins  map[string]int
	cooldowns   map[string]time.Time
	relayStalls int
	lastRelayAt time.Time
}

func NewTracker() *Tracker {
	return &Tracker{
		silent:     make(map[string]silentState),
		tunnels:    make(map[string]silentState),
		tunnelWins: make(map[string]int),
		cooldowns:  make(map[string]time.Time),
	}
}

// Reset clears silent-route backoffs (e.g. after a network change or explicit wakeup).
func (t *Tracker) Reset() {
	t.mu.Lock()
	clear(t.silent)
	clear(t.tunnels)
	clear(t.tunnelWins)
	t.mu.Unlock()
}

// ShouldProbe reports whether addr is eligible for a background better-route probe at now.
func (t *Tracker) ShouldProbe(addr string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if until, ok := t.cooldowns[addr]; ok && now.Before(until) {
		return false
	}
	if st, ok := t.silent[addr]; ok && now.Before(st.until) {
		return false
	}
	return true
}

// InCooldown reports whether addr recently answered a probe yet failed full connection setup.
func (t *Tracker) InCooldown(addr string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	until, ok := t.cooldowns[addr]
	return ok && now.Before(until)
}

// RecordProbeMiss backs off addr exponentially up to SilentRouteBackoffMax.
func (t *Tracker) RecordProbeMiss(addr string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.silent[addr] = nextBackoff(t.silent[addr], now)
}

func nextBackoff(previous silentState, now time.Time) silentState {
	failures := min(previous.failures+1, 10)
	delay := min(SilentRouteBackoffMax, BetterRouteCheckInterval*time.Duration(1<<(failures-1)))
	return silentState{failures: failures, until: now.Add(delay)}
}

func (t *Tracker) ShouldAttemptTunnel(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !now.Before(t.tunnels[key].until)
}

func (t *Tracker) RecordTunnelUnavailable(key string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tunnels[key] = nextBackoff(t.tunnels[key], now)
}

func (t *Tracker) RecordTunnelSuccess(key string) {
	t.mu.Lock()
	delete(t.tunnels, key)
	t.tunnelWins[key]++
	t.mu.Unlock()
}

// RecordWebRTCSuccess clears consecutive tunnel-win head-start adaptation for key.
func (t *Tracker) RecordWebRTCSuccess(key string) {
	t.mu.Lock()
	delete(t.tunnelWins, key)
	t.mu.Unlock()
}

// TunnelHeadStart returns an adapted WebRTC head-start duration. After repeated
// consecutive tunnel wins on the current network (e.g. UDP/TURN blocked), it
// shortens the wait so reconnects and wakeups do not pay the full 4s penalty.
func (t *Tracker) TunnelHeadStart(key string, base time.Duration) time.Duration {
	if base <= 0 {
		base = CFTunnelHeadStart
	}
	t.mu.Lock()
	wins := t.tunnelWins[key]
	t.mu.Unlock()
	if wins >= 2 && base > CFTunnelFastHeadStart {
		return CFTunnelFastHeadStart
	}
	return base
}

// RecordProbeSuccess clears silent-route backoff for addr.
func (t *Tracker) RecordProbeSuccess(addr string) {
	t.mu.Lock()
	delete(t.silent, addr)
	t.mu.Unlock()
}

// RecordSwitchFailure places addr on a 5-minute cooldown so a flaky LAN cannot bounce the session.
func (t *Tracker) RecordSwitchFailure(addr string, now time.Time) {
	t.mu.Lock()
	t.cooldowns[addr] = now.Add(BetterRouteCooldown)
	t.mu.Unlock()
}

// RecordActivePath tracks whether WebRTC connections repeatedly land on TURN
// relay vs direct P2P so callers can inspect adaptive path hints.
func (t *Tracker) RecordActivePath(path string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch path {
	case "relay", "cf_tunnel":
		t.relayStalls++
		t.lastRelayAt = now
	case "direct", "lan", "tailnet":
		t.relayStalls = 0
	}
}

// TransportHint returns "relay_preferred" when recent WebRTC attempts on the
// current network consistently required TURN, or "direct_preferred" otherwise.
func (t *Tracker) TransportHint(now time.Time) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.relayStalls >= 3 && now.Sub(t.lastRelayAt) < 24*time.Hour {
		return "relay_preferred"
	}
	return "direct_preferred"
}

// ProbeSignalHTTP checks whether a signaling HTTP(S) origin answers ?probe=1
// without following redirects or consuming pre-auth WebSocket slots.
func ProbeSignalHTTP(ctx context.Context, signalWSURL, bearerToken string, timeout time.Duration) error {
	u, err := url.Parse(strings.TrimSpace(signalWSURL))
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	case "http", "https":
	default:
		return errors.New("routes: unsupported signal scheme")
	}
	q := u.Query()
	q.Set("probe", "1")
	u.RawQuery = q.Encode()
	u.Fragment = ""

	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if strings.TrimSpace(bearerToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearerToken))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return errors.New("routes: signal probe rejected")
	}
	return nil
}
