package cftunnel

import (
	"context"
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type PauseStore interface {
	LoadPause(ctx context.Context, scopeID, accountID string) (time.Time, error)
	ExtendPause(ctx context.Context, scopeID, accountID string, until time.Time) error
}

type GatedCloudflare struct {
	client          Cloudflare
	inline          bool
	store           PauseStore
	scope, account  string
	clock           func() time.Time
	metrics         *Metrics
	limiter         *rate.Limiter
	background      *rate.Limiter
	slots           chan struct{}
	backgroundSlots chan struct{}
	mu              sync.Mutex
	pausedUntil     time.Time
	cacheUntil      time.Time
}

var _ Cloudflare = (*GatedCloudflare)(nil)

func NewGatedCloudflare(client Cloudflare, store PauseStore, scope Scope, limits RateConfig, clock func() time.Time, metrics *Metrics) *GatedCloudflare {
	perSecond, burst, concurrency := limits.PerSecond, limits.Burst, limits.Concurrency
	if perSecond <= 0 {
		perSecond = 3
	}
	if burst <= 0 {
		burst = 4
	}
	if concurrency <= 0 {
		concurrency = 4
	}
	if clock == nil {
		clock = time.Now
	}
	if metrics == nil {
		metrics = new(Metrics)
	}
	gate := &GatedCloudflare{client: client, store: store, scope: scope.ID, account: scope.AccountID, clock: clock, metrics: metrics,
		limiter:    rate.NewLimiter(rate.Limit(perSecond), burst),
		background: rate.NewLimiter(rate.Limit(float64(perSecond)/2), max(1, burst/2)),
		slots:      make(chan struct{}, concurrency), backgroundSlots: make(chan struct{}, max(1, concurrency-1))}
	if rest, ok := client.(*CFClient); ok {
		copy := *rest
		copy.gate = gate
		gate.client, gate.inline = &copy, true
	}
	return gate
}

type backgroundCFKey struct{}

func backgroundCF(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundCFKey{}, true)
}

func (g *GatedCloudflare) checkPause(ctx context.Context) error {
	g.mu.Lock()
	now := g.clock()
	if g.pausedUntil.After(now) {
		wait := g.pausedUntil.Sub(now)
		g.mu.Unlock()
		return CFRateLimitError{RetryAfter: wait}
	}
	if g.cacheUntil.After(now) || g.store == nil {
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()
	until, err := g.store.LoadPause(ctx, g.scope, g.account)
	g.mu.Lock()
	defer g.mu.Unlock()
	now = g.clock()
	if err == nil {
		g.cacheUntil = now.Add(5 * time.Second)
		if until.After(g.pausedUntil) {
			g.pausedUntil = until
			g.metrics.pause(until, false)
		}
	}
	if g.pausedUntil.After(now) {
		return CFRateLimitError{RetryAfter: g.pausedUntil.Sub(now)}
	}
	return nil
}

func boundedTimeAdd(now time.Time, delay time.Duration) time.Time {
	limit := time.Unix(0, math.MaxInt64)
	if delay > limit.Sub(now) {
		return limit
	}
	return now.Add(delay)
}

func (g *GatedCloudflare) do(ctx context.Context, op string, call func() error) error {
	if err := g.checkPause(ctx); err != nil {
		return err
	}
	if ctx.Value(backgroundCFKey{}) == true {
		select {
		case g.backgroundSlots <- struct{}{}:
			defer func() { <-g.backgroundSlots }()
		case <-ctx.Done():
			return CFTransientError{}
		}
		if err := g.background.Wait(ctx); err != nil {
			return CFTransientError{}
		}
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	case <-ctx.Done():
		return CFTransientError{}
	}
	if err := g.limiter.Wait(ctx); err != nil {
		return CFTransientError{}
	}
	if err := g.checkPause(ctx); err != nil {
		return err
	}
	err := call()
	if delay, limited := cfRateDelay(err); limited {
		until := boundedTimeAdd(g.clock(), delay)
		g.mu.Lock()
		if until.After(g.pausedUntil) {
			g.pausedUntil = until
		}
		g.mu.Unlock()
		g.metrics.pause(until, true)
		if g.store != nil {
			persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			_ = g.store.ExtendPause(persist, g.scope, g.account, until)
			cancel()
		}
	}
	g.metrics.api(op, err)
	return err
}

func gatedCall[T any](ctx context.Context, g *GatedCloudflare, op string, call func() (T, error)) (result T, err error) {
	if g.inline {
		return call()
	}
	err = g.do(ctx, op, func() error {
		result, err = call()
		return err
	})
	return result, err
}

func (g *GatedCloudflare) write(ctx context.Context, op string, call func() error) error {
	if g.inline {
		return call()
	}
	return g.do(ctx, op, call)
}

func (g *GatedCloudflare) CreateTunnel(ctx context.Context, name string, secret []byte) (Tunnel, error) {
	return gatedCall(ctx, g, "create_tunnel", func() (Tunnel, error) { return g.client.CreateTunnel(ctx, name, secret) })
}

func (g *GatedCloudflare) GetTunnel(ctx context.Context, id string) (Tunnel, error) {
	return gatedCall(ctx, g, "get_tunnel", func() (Tunnel, error) { return g.client.GetTunnel(ctx, id) })
}

func (g *GatedCloudflare) ListTunnels(ctx context.Context, query TunnelListQuery) (TunnelListPage, error) {
	return gatedCall(ctx, g, "list_tunnels", func() (TunnelListPage, error) { return g.client.ListTunnels(ctx, query) })
}

func (g *GatedCloudflare) GetConfiguration(ctx context.Context, id string) (IngressConfig, error) {
	return gatedCall(ctx, g, "get_configuration", func() (IngressConfig, error) { return g.client.GetConfiguration(ctx, id) })
}

func (g *GatedCloudflare) PutConfiguration(ctx context.Context, id string, cfg IngressConfig) error {
	return g.write(ctx, "put_configuration", func() error { return g.client.PutConfiguration(ctx, id, cfg) })
}

func (g *GatedCloudflare) GetToken(ctx context.Context, id string) (string, error) {
	return gatedCall(ctx, g, "get_token", func() (string, error) { return g.client.GetToken(ctx, id) })
}

func (g *GatedCloudflare) RotateSecret(ctx context.Context, id string, secret []byte) error {
	return g.write(ctx, "rotate_secret", func() error { return g.client.RotateSecret(ctx, id, secret) })
}

func (g *GatedCloudflare) ListConnections(ctx context.Context, id string) ([]Connection, error) {
	return gatedCall(ctx, g, "list_connections", func() ([]Connection, error) { return g.client.ListConnections(ctx, id) })
}

func (g *GatedCloudflare) DisconnectAll(ctx context.Context, id string) error {
	return g.write(ctx, "disconnect_all", func() error { return g.client.DisconnectAll(ctx, id) })
}

func (g *GatedCloudflare) DeleteTunnel(ctx context.Context, id string) error {
	return g.write(ctx, "delete_tunnel", func() error { return g.client.DeleteTunnel(ctx, id) })
}

func (g *GatedCloudflare) GetZone(ctx context.Context) (Zone, error) {
	return gatedCall(ctx, g, "get_zone", func() (Zone, error) { return g.client.GetZone(ctx) })
}

func (g *GatedCloudflare) ListDNSRecords(ctx context.Context, hostname string) ([]DNSRecord, error) {
	return gatedCall(ctx, g, "list_dns_records", func() ([]DNSRecord, error) { return g.client.ListDNSRecords(ctx, hostname) })
}

func (g *GatedCloudflare) ListMarkedDNSRecords(ctx context.Context, page, perPage int) (DNSListPage, error) {
	return gatedCall(ctx, g, "list_dns_records", func() (DNSListPage, error) { return g.client.ListMarkedDNSRecords(ctx, page, perPage) })
}

func (g *GatedCloudflare) CreateDNSRecord(ctx context.Context, record DNSRecord) (DNSRecord, error) {
	return gatedCall(ctx, g, "create_dns_record", func() (DNSRecord, error) { return g.client.CreateDNSRecord(ctx, record) })
}

func (g *GatedCloudflare) PatchDNSRecord(ctx context.Context, record DNSRecord) (DNSRecord, error) {
	return gatedCall(ctx, g, "patch_dns_record", func() (DNSRecord, error) { return g.client.PatchDNSRecord(ctx, record) })
}

func (g *GatedCloudflare) DeleteDNSRecord(ctx context.Context, id string) error {
	return g.write(ctx, "delete_dns_record", func() error { return g.client.DeleteDNSRecord(ctx, id) })
}
