package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vanora-relay/internal/cftunnel"
	"vanora-relay/internal/cftunnel/sqlstore"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/membership"
	relay "vanora-relay/internal/signal"
	"vanora-relay/protocol"
)

type relayNetwork interface {
	Config(connectionID, visitor string, until time.Time) ([]ice.ICEServer, error)
	Revoke(connectionID string)
	Close() error
}

type relayStartup struct {
	key                      ed25519.PublicKey
	keys                     []ed25519.PublicKey
	allowedIssuer, selfToken string
	membership               *membership.Client
	pushURL, pushToken       string
	metricsToken             string
	maxSlots, workers        int
	startupCtx               context.Context
	openStore                func(context.Context, cftunnel.Config) (cftunnel.Store, error)
	newCloudflare            func(cftunnel.Config) (cftunnel.Cloudflare, error)
	newNetwork               func() (relayNetwork, error)
	canaryClient             *http.Client
}

type relayServer struct {
	http.Handler
	hub      *relay.Hub
	cancel   context.CancelFunc
	draining atomic.Bool
}

func (s *relayServer) drain(ctx context.Context) {
	s.draining.Store(true)
	if s.hub != nil {
		s.hub.Drain(ctx)
	}
}

func (s *relayServer) ready(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.draining.Load() {
		http.Error(w, "draining", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "ok")
}

func (s *relayServer) metricsHandler(metrics *cftunnel.Metrics, token string) http.HandlerFunc {
	tokenHash := sha256.Sum256([]byte(token))
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		remote, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remote = r.RemoteAddr
		}
		addr, _ := netip.ParseAddr(remote)
		local := addr.Unmap().IsLoopback() &&
			len(r.Header.Values("X-Forwarded-For")) == 0 && len(r.Header.Values("Forwarded")) == 0 &&
			len(r.Header.Values("X-Real-IP")) == 0 && len(r.Header.Values("CF-Connecting-IP")) == 0
		if !local {
			raw, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			presented := sha256.Sum256([]byte(raw))
			if token == "" || !bearer || subtle.ConstantTimeCompare(tokenHash[:], presented[:]) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		data := struct {
			Tunnel cftunnel.MetricsSnapshot `json:"tunnel"`
			Signal relay.MetricsSnapshot    `json:"signal"`
		}{Tunnel: metrics.Snapshot()}
		if s.hub != nil {
			data.Signal = s.hub.Metrics()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(data)
	}
}

func openTunnelStore(ctx context.Context, cfg cftunnel.Config) (cftunnel.Store, error) {
	if cfg.Store == cftunnel.StorePostgres {
		return sqlstore.OpenPostgres(ctx, cfg.PostgresDSN, sqlstore.Options{})
	}
	return sqlstore.OpenSQLite(ctx, cfg.SQLitePath, sqlstore.Options{})
}

func buildServer(parent context.Context, cfg cftunnel.Config, opts relayStartup) (*relayServer, func(), error) {
	if cfg.Process == cftunnel.ProcessControl && (cfg.Mode == cftunnel.ModeOff || cfg.Store != cftunnel.StorePostgres) {
		return nil, nil, errors.New("RELAY_TUNNEL_PROCESS=control requires enabled tunnels and PostgreSQL")
	}
	ctx, cancel := context.WithCancel(parent)
	startupCtx := opts.startupCtx
	if startupCtx == nil {
		startupCtx = ctx
	}
	server := &relayServer{cancel: cancel}
	var tasks sync.WaitGroup
	var store cftunnel.Store
	var network relayNetwork
	var closeOnce sync.Once
	closeServer := func() {
		closeOnce.Do(func() {
			cancel()
			tasks.Wait()
			if network != nil {
				_ = network.Close()
			}
			if store != nil {
				_ = store.Close()
			}
		})
	}
	started := false
	defer func() {
		if !started {
			closeServer()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", server.ready)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	})

	var hub *relay.Hub
	var service *cftunnel.Service
	if cfg.Mode != cftunnel.ModeOff {
		memberURL := ""
		if opts.membership != nil {
			memberURL = opts.membership.URL
		}
		scope, err := cfg.BuildScope(opts.key, opts.allowedIssuer, memberURL)
		if err != nil {
			return nil, nil, fmt.Errorf("configure tunnel scope: %w", err)
		}
		if opts.openStore == nil {
			opts.openStore = openTunnelStore
		}
		opened, err := opts.openStore(startupCtx, cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("open tunnel store: %w", err)
		}
		store = opened
		if err := store.EnsureScope(startupCtx, scope); err != nil {
			return nil, nil, fmt.Errorf("verify stored tunnel scope: %w", err)
		}
		crypto, err := cftunnel.NewCrypto(cfg.MasterKey, cfg.EdgeKey, cfg.EdgePrevKey)
		if err != nil {
			return nil, nil, err
		}
		if opts.newCloudflare == nil {
			opts.newCloudflare = func(cfg cftunnel.Config) (cftunnel.Cloudflare, error) {
				return cftunnel.NewCFClient(cfg, cftunnel.CFClientOptions{})
			}
		}
		client, err := opts.newCloudflare(cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("configure Cloudflare client: %w", err)
		}
		cf := cftunnel.NewGatedCloudflare(client, store, scope, cfg.CloudflareRate, nil, nil)
		serviceOpts := cftunnel.ServiceOptions{}
		if opts.membership != nil {
			serviceOpts.Membership = opts.membership
		}
		if cfg.Process != cftunnel.ProcessControl {
			serviceOpts.RuntimeChecker = func(ctx context.Context, deviceID, keyHash, runtimeID string, now time.Time) bool {
				return ctx.Err() == nil && hub != nil && hub.HasActiveTunnelRuntime(deviceID, keyHash, runtimeID, now)
			}
		}
		service, err = cftunnel.NewService(cfg, scope, store, cf, crypto, serviceOpts)
		if err != nil {
			return nil, nil, err
		}
		if err := service.PreflightZone(startupCtx); err != nil {
			return nil, nil, fmt.Errorf("verify Cloudflare zone: %w", err)
		}
		if err := service.PreflightEdgeCanary(startupCtx, opts.canaryClient); err != nil {
			return nil, nil, err
		}
	}

	caKeys := opts.keys
	if len(caKeys) == 0 && len(opts.key) > 0 {
		caKeys = []ed25519.PublicKey{opts.key}
	}
	if cfg.Process != cftunnel.ProcessControl {
		if opts.newNetwork == nil {
			opts.newNetwork = func() (relayNetwork, error) { return ice.FromEnvForChannel(string(cfg.Channel)) }
		}
		opened, err := opts.newNetwork()
		if err != nil {
			return nil, nil, fmt.Errorf("start STUN/TURN: %w", err)
		}
		network = opened
		if cfg.Channel.IsSelfHosted() {
			hub = relay.NewSelfHosted(opts.selfToken, network)
		} else {
			hub = relay.New(opts.key, opts.membership, network)
			if len(caKeys) > 0 {
				hub.ConfigureTrustedKeys(caKeys)
			}
			if opts.allowedIssuer != "" {
				hub.RequireIssuer(opts.allowedIssuer)
			}
		}
		hub.ConfigureClientIP(cfg.ClientIP)
		hub.ConfigureMaxSlots(opts.maxSlots)
		if opts.pushURL != "" {
			if err := hub.ConfigurePushWebhook(opts.pushURL, opts.pushToken, false); err != nil {
				return nil, nil, err
			}
		}
		mux.Handle("GET /v1/signal", hub)
		mux.Handle("POST /v1/signal", hub)
		mux.HandleFunc("GET /v1/probe", hub.ServeProbe)
		mux.HandleFunc("GET /v1/pairing", hub.ServePairing)
		mux.HandleFunc("POST /v1/pairing", hub.ServePairing)
		mux.HandleFunc("GET /v1/activity", hub.ServeActivity)
		mux.HandleFunc("POST /v1/activity", hub.ServeActivity)
	}

	var handler http.Handler = mux
	metrics := new(cftunnel.Metrics)
	if service != nil {
		metrics = service.Metrics()
		if hub != nil {
			hub.ConfigureTunnel(tunnelController{service})
		}
		api := cftunnel.NewHTTPHandlerWithKeys(service, caKeys, opts.selfToken)
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/tunnels" || strings.HasPrefix(r.URL.Path, "/v1/tunnels/") {
				api.ServeHTTP(w, r)
				return
			}
			mux.ServeHTTP(w, r)
		})
		workers := opts.workers
		if workers == 0 {
			workers = defaultTunnelWorkers(cfg.Store)
		}
		for range workers {
			tasks.Go(func() { _ = service.RunWorker(ctx, protocol.NewID()) })
		}
		if cfg.Reaper.Mode != cftunnel.ReaperOff {
			reaper := cftunnel.NewReaper(service)
			tasks.Go(func() { _ = reaper.Run(ctx) })
		}
		tasks.Go(func() { pruneTunnelStore(ctx, store, service.ScopeID()) })
	}
	if hub != nil {
		tasks.Go(func() { hub.Run(ctx) })
	}
	server.Handler, server.hub = handler, hub
	mux.HandleFunc("GET /metrics", server.metricsHandler(metrics, opts.metricsToken))
	started = true
	return server, closeServer, nil
}

func defaultTunnelWorkers(store cftunnel.StoreKind) int {
	if store == cftunnel.StorePostgres {
		return 4
	}
	return 2
}

func pruneTunnelStore(ctx context.Context, store cftunnel.Store, scopeID string) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := store.PruneExpired(ctx, scopeID, now); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "tunnel store pruning failed", "error_code", cftunnel.CodeOf(err))
			}
		}
	}
}

type tunnelController struct{ *cftunnel.Service }

func (c tunnelController) AuthorizeVisitor(ctx context.Context, req relay.TunnelAccessRequest) (string, time.Time, error) {
	return c.Service.AuthorizeVisitor(ctx, visitorRequest(req))
}

func (c tunnelController) RefreshVisitorAccess(ctx context.Context, req relay.TunnelAccessRequest) (string, time.Time, error) {
	return c.Service.RefreshVisitorAccess(ctx, visitorRequest(req))
}

func visitorRequest(req relay.TunnelAccessRequest) cftunnel.VisitorRequest {
	return cftunnel.VisitorRequest{Host: req.Host, Visitor: req.Visitor, HostLease: req.HostLease, VisitorLease: req.VisitorLease,
		Generation: req.Generation, Incarnation: req.Incarnation, Paired: true}
}
