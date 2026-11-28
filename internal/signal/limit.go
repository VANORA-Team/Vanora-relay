package signal

import (
	"container/list"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	// unauthRefillPerSecond is the sustained per-IP request rate allowed on
	// the tokenless HTTP surfaces (pairing lookup/deposit, activity poll and
	// publish). Legitimate clients need well under one request per second;
	// the limit exists to keep anonymous floods off the hub mutex.
	unauthRefillPerSecond = 16.0
	// unauthBurst is the refill bucket size: one QR redemption plus a wake
	// storm of a few phones fits comfortably; sustained floods do not.
	unauthBurst = 64.0

	// tokenFailWindow bounds how quickly failed bearer-token attempts from
	// one IP escalate to tokenFailThreshold.
	tokenFailWindow = 15 * time.Second
	// tokenFailThreshold is the number of failed bearer attempts within
	tokenFailThreshold = 24
	// tokenLockout is the base lockout applied to an IP that burned through
	// the failure budget. Each consecutive lockout doubles it so persistent
	// guessing degrades to near-zero throughput without operator action.
	tokenLockout    = 15 * time.Second
	tokenLockoutMax = 5 * time.Minute

	gateMaxEntries = 8192
)

type gateState struct {
	tokens  float64
	last    time.Time
	fails   int
	failAt  time.Time
	locked  time.Time
	lockout time.Duration
	recent  *list.Element
}

// unauthGate throttles tokenless HTTP surfaces per client IP and locks out
// IPs that hammer the bearer-token check with repeated failures. It is
// deliberately cheap: one mutex, one map lookup and a couple of float adds
// per request, taken before any hub-level lock.
type unauthGate struct {
	mu     sync.Mutex
	byIP   map[string]*gateState
	recent list.List
}

func newUnauthGate() *unauthGate {
	return &unauthGate{byIP: make(map[string]*gateState)}
}

func (g *unauthGate) stateFor(ip string, now time.Time) *gateState {
	st, ok := g.byIP[ip]
	if !ok {
		if len(g.byIP) >= gateMaxEntries {
			oldest := g.recent.Back()
			delete(g.byIP, g.recent.Remove(oldest).(string))
		}
		st = &gateState{tokens: unauthBurst, last: now, recent: g.recent.PushFront(ip)}
		g.byIP[ip] = st
	} else {
		g.recent.MoveToFront(st.recent)
	}
	return st
}

// allowRequest consumes one unauth-surface request credit for ip. It reports
// whether the request may proceed toward the actual handlers.
func (g *unauthGate) allowRequest(ip string, now time.Time) bool {
	if ip == "" {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.stateFor(ip, now)
	st.tokens += now.Sub(st.last).Seconds() * unauthRefillPerSecond
	if st.tokens > unauthBurst {
		st.tokens = unauthBurst
	}
	st.last = now
	if st.tokens < 1 {
		return false
	}
	st.tokens--
	return true
}

// tokenLocked reports whether ip is currently locked out after repeated
// failed bearer attempts.
func (g *unauthGate) tokenLocked(ip string, now time.Time) bool {
	if ip == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.byIP[ip]
	if ok {
		g.recent.MoveToFront(st.recent)
		return now.Before(st.locked)
	}
	return false
}

// recordTokenFailure registers a failed bearer-token attempt for ip. It
// returns true when the caller is now locked out and should answer 429
// instead of probing the token again.
func (g *unauthGate) recordTokenFailure(ip string, now time.Time) bool {
	if ip == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.stateFor(ip, now)
	if now.Before(st.locked) {
		return true
	}
	if now.Sub(st.failAt) > tokenFailWindow {
		st.fails = 0
	}
	st.failAt = now
	st.fails++
	if st.fails >= tokenFailThreshold {
		st.lockout = min(tokenLockoutMax, max(tokenLockout, 2*st.lockout))
		st.locked = now.Add(st.lockout)
		st.fails = 0
		return true
	}
	return false
}

// lockRemaining reports how long ip stays locked out after repeated failed
// bearer attempts.
func (g *unauthGate) lockRemaining(ip string, now time.Time) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if st, ok := g.byIP[ip]; ok && now.Before(st.locked) {
		return st.locked.Sub(now)
	}
	return 0
}

// limitResponse writes the 429 used when a gate rejects an anonymous request.
func limitResponse(w http.ResponseWriter, retry time.Duration) {
	if retry > 0 {
		secs := int(retry.Round(time.Second) / time.Second)
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
}
