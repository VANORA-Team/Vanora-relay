package cftunnel

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

func (cfg Config) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	remote = remote.Unmap()
	if !cfg.trustsProxy(remote) {
		return remote.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for idx := len(hops) - 1; idx >= 0; idx-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[idx]))
		if err != nil || hop.Zone() != "" {
			return remote.String()
		}
		hop = hop.Unmap()
		if !cfg.trustsProxy(hop) {
			return hop.String()
		}
	}
	return remote.String()
}

func (cfg Config) trustsProxy(addr netip.Addr) bool {
	for _, prefix := range cfg.TrustedProxies {
		if prefix.Contains(addr) || addr.Is4() && prefix.Contains(netip.AddrFrom16(addr.As16())) {
			return true
		}
	}
	return false
}

type httpLimit struct {
	mu      sync.Mutex
	entries map[string]*httpLimitEntry
	swept   time.Time
}

type httpLimitEntry struct {
	challenges *rate.Limiter
	seen       time.Time
	failureAt  time.Time
	failures   int
	locked     time.Time
}

func (g *httpLimit) check(ip string, now time.Time, challenge, badBearer bool) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Sub(g.swept) >= time.Minute {
		for key, entry := range g.entries {
			if now.Sub(entry.seen) >= 10*time.Minute {
				delete(g.entries, key)
			}
		}
		g.swept = now
	}
	entry := g.entries[ip]
	if entry == nil {
		if !challenge && !badBearer {
			return 0
		}
		if len(g.entries) >= 8192 {
			return time.Second
		}
		entry = &httpLimitEntry{challenges: rate.NewLimiter(8, 32)}
		g.entries[ip] = entry
	}
	entry.seen = now
	if now.Before(entry.locked) {
		return entry.locked.Sub(now)
	}
	if badBearer {
		if now.Sub(entry.failureAt) >= 15*time.Second {
			entry.failureAt, entry.failures = now, 0
		}
		entry.failures++
		if entry.failures >= 24 {
			entry.locked = now.Add(15 * time.Second)
			entry.failures = 0
			return entry.locked.Sub(now)
		}
	}
	if challenge && !entry.challenges.AllowN(now, 1) {
		return time.Second
	}
	return 0
}
