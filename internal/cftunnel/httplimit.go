package cftunnel

import (
	"container/list"
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
	recent  list.List
}

const httpLimitMaxEntries = 8192

type httpLimitEntry struct {
	challenges *rate.Limiter
	requests   *rate.Limiter
	recent     *list.Element
	failureAt  time.Time
	failures   int
	locked     time.Time
}

func (g *httpLimit) check(ip string, now time.Time, challenge, badBearer bool) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	entry := g.entries[ip]
	if entry == nil {
		if len(g.entries) >= httpLimitMaxEntries {
			delete(g.entries, g.recent.Remove(g.recent.Back()).(string))
		}
		entry = &httpLimitEntry{
			challenges: rate.NewLimiter(8, 32),
			requests:   rate.NewLimiter(32, 64),
			recent:     g.recent.PushFront(ip),
		}
		g.entries[ip] = entry
	} else {
		g.recent.MoveToFront(entry.recent)
	}
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
	limiter := entry.requests
	if challenge {
		limiter = entry.challenges
	}
	if !limiter.AllowN(now, 1) {
		return time.Second
	}
	return 0
}
