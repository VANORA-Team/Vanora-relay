package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
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
	allowedIssuer, selfToken string
	membership               *membership.Client
	pushURL, pushToken       string
	openStore                func(context.Context, cftunnel.Config) (cftunnel.Store, error)
	newCloudflare            func(cftunnel.Config) (cftunnel.Cloudflare, error)
	newNetwork               func() (relayNetwork, error)
	canaryClient             *http.Client
}

func openTunnelStore(ctx context.Context, cfg cftunnel.Config) (cftunnel.Store, error) {
	if cfg.Store == cftunnel.StorePostgres {
		return sqlstore.OpenPostgres(ctx, cfg.PostgresDSN, sqlstore.Options{})
	}
	return sqlstore.OpenSQLite(ctx, cfg.SQLitePath, sqlstore.Options{})
}

func buildServer(parent context.Context, cfg cftunnel.Config, opts relayStartup) (http.Handler, func(), error) {
	if cfg.Process == cftunnel.ProcessControl && (cfg.Mode == cftunnel.ModeOff || cfg.Store != cftunnel.StorePostgres) {
		return nil, nil, errors.New("RELAY_TUNNEL_PROCESS=control requires enabled tunnels and PostgreSQL")
	}
	ctx, cancel := context.WithCancel(parent)
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
		opened, err := opts.openStore(ctx, cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("open tunnel store: %w", err)
		}
		store = opened
		if err := store.EnsureScope(ctx, scope); err != nil {
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
		if err := service.PreflightZone(ctx); err != nil {
			return nil, nil, fmt.Errorf("verify Cloudflare zone: %w", err)
		}
		if err := service.PreflightEdgeCanary(ctx, opts.canaryClient); err != nil {
			return nil, nil, err
		}
	}

	if cfg.Process != cftunnel.ProcessControl {
		if opts.newNetwork == nil {
			opts.newNetwork = func() (relayNetwork, error) { return ice.FromEnv() }
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
			if opts.allowedIssuer != "" {
				hub.RequireIssuer(opts.allowedIssuer)
			}
		}
		if opts.pushURL != "" {
			if err := hub.ConfigurePushWebhook(opts.pushURL, opts.pushToken, false); err != nil {
				return nil, nil, err
			}
		}
		mux.Handle("GET /v1/signal", hub)
		mux.Handle("POST /v1/signal", hub)
	}

	var handler http.Handler = mux
	if service != nil {
		if hub != nil {
			hub.ConfigureTunnelClientIP(cfg.ClientIP)
			hub.ConfigureTunnel(tunnelController{service})
		}
		api := cftunnel.NewHTTPHandler(service, opts.key, opts.selfToken)
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/tunnels" || strings.HasPrefix(r.URL.Path, "/v1/tunnels/") {
				api.ServeHTTP(w, r)
				return
			}
			mux.ServeHTTP(w, r)
		})
		tasks.Go(func() { _ = service.RunWorker(ctx, protocol.NewID()) })
		if cfg.Reaper.Mode != cftunnel.ReaperOff {
			reaper := cftunnel.NewReaper(service)
			tasks.Go(func() { _ = reaper.Run(ctx) })
		}
		tasks.Go(func() { pruneTunnelStore(ctx, store, service.ScopeID()) })
	}
	if hub != nil {
		tasks.Go(func() { hub.Run(ctx) })
	}
	started = true
	return handler, closeServer, nil
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
