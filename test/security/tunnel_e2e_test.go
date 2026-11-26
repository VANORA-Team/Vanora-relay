package security_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	managed "vanora-relay/adapter/cftunnel"
	"vanora-relay/adapter/desktop"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/cftunnel"
	"vanora-relay/internal/cftunnel/sqlstore"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/internal/membership"
	"vanora-relay/internal/pairnet"
	"vanora-relay/internal/signal"
	"vanora-relay/protocol"
)

type testCloudflare struct {
	mu     sync.Mutex
	tunnel cftunnel.Tunnel
	config cftunnel.IngressConfig
	dns    cftunnel.DNSRecord
}

func (cf *testCloudflare) CreateTunnel(_ context.Context, name string, _ []byte) (cftunnel.Tunnel, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	cf.tunnel = cftunnel.Tunnel{ID: protocol.NewID(), Name: name, Status: cftunnel.TunnelInactive,
		ConfigSrc: "cloudflare", CreatedAt: time.Now()}
	return cf.tunnel, nil
}

func (cf *testCloudflare) GetTunnel(_ context.Context, id string) (cftunnel.Tunnel, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	if cf.tunnel.ID != id {
		return cftunnel.Tunnel{}, cftunnel.ErrCFNotFound
	}
	return cf.tunnel, nil
}

func (cf *testCloudflare) ListTunnels(_ context.Context, query cftunnel.TunnelListQuery) (cftunnel.TunnelListPage, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	page := cftunnel.TunnelListPage{TotalPages: 1}
	if cf.tunnel.ID != "" && (query.Name == "" || cf.tunnel.Name == query.Name) {
		page.Tunnels, page.TotalCount = []cftunnel.Tunnel{cf.tunnel}, 1
	}
	return page, nil
}

func (cf *testCloudflare) GetConfiguration(context.Context, string) (cftunnel.IngressConfig, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	if cf.config.Ingress == nil {
		return cftunnel.IngressConfig{}, cftunnel.ErrCFConfigNotFound
	}
	return cf.config, nil
}

func (cf *testCloudflare) PutConfiguration(_ context.Context, _ string, cfg cftunnel.IngressConfig) error {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	cf.config = cfg
	return nil
}

func (cf *testCloudflare) RotateSecret(context.Context, string, []byte) error { return nil }
func (cf *testCloudflare) GetToken(context.Context, string) (string, error) {
	return "connector-fixture-value", nil
}
func (cf *testCloudflare) ListConnections(context.Context, string) ([]cftunnel.Connection, error) {
	return nil, nil
}
func (cf *testCloudflare) DisconnectAll(context.Context, string) error { return nil }
func (cf *testCloudflare) DeleteTunnel(context.Context, string) error {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	cf.tunnel, cf.config = cftunnel.Tunnel{}, cftunnel.IngressConfig{}
	return nil
}
func (cf *testCloudflare) GetZone(context.Context) (cftunnel.Zone, error) {
	return cftunnel.Zone{}, errors.New("unexpected zone query")
}
func (cf *testCloudflare) ListDNSRecords(_ context.Context, host string) ([]cftunnel.DNSRecord, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	if cf.dns.ID != "" && cf.dns.Hostname == host {
		return []cftunnel.DNSRecord{cf.dns}, nil
	}
	return nil, nil
}
func (cf *testCloudflare) ListMarkedDNSRecords(context.Context, int, int) (cftunnel.DNSListPage, error) {
	return cftunnel.DNSListPage{}, errors.New("unexpected DNS inventory")
}
func (cf *testCloudflare) CreateDNSRecord(_ context.Context, rec cftunnel.DNSRecord) (cftunnel.DNSRecord, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	rec.ID = protocol.NewID()
	cf.dns = rec
	return rec, nil
}
func (cf *testCloudflare) PatchDNSRecord(_ context.Context, rec cftunnel.DNSRecord) (cftunnel.DNSRecord, error) {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	cf.dns = rec
	return rec, nil
}
func (cf *testCloudflare) DeleteDNSRecord(context.Context, string) error {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	cf.dns = cftunnel.DNSRecord{}
	return nil
}

type managedE2E struct {
	signalURL, controlOrigin string
	edgeURL                  string
	edge                     *testTunnelEdge
}

type testTunnelEdge struct {
	crypto *cftunnel.Crypto
	route  atomic.Pointer[managed.ConnectorOptions]
	mu     sync.Mutex
	wire   bytes.Buffer
}

func (edge *testTunnelEdge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route := edge.route.Load()
	ticket, jti := r.Header.Get("Vanora-Edge-Ticket"), r.Header.Get("Vanora-Ticket-ID")
	if route == nil || r.Host != route.PinnedHostname || r.URL.Path != "/v1/tunnel/ws" ||
		!edge.crypto.VerifyEdgeTicket(ticket, r.Host, r.URL.Path, jti, time.Now()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	front, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{managed.Subprotocol}})
	if err != nil {
		return
	}
	defer front.CloseNow()
	headers := http.Header{"Vanora-Ticket-Id": {jti}, "Vanora-Client-Proof": {r.Header.Get("Vanora-Client-Proof")}}
	back, _, err := websocket.Dial(r.Context(), "ws://"+route.PinnedOrigin+r.URL.Path, &websocket.DialOptions{
		Host: r.Host, Subprotocols: []string{managed.Subprotocol}, HTTPHeader: headers,
	})
	if err != nil {
		return
	}
	defer back.CloseNow()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	forward := func(src, dst *websocket.Conn) {
		defer cancel()
		src.SetReadLimit(64 << 10)
		for {
			kind, data, err := src.Read(ctx)
			if err != nil || kind != websocket.MessageBinary {
				return
			}
			edge.mu.Lock()
			_, _ = edge.wire.Write(data)
			edge.mu.Unlock()
			if dst.Write(ctx, kind, data) != nil {
				return
			}
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		forward(front, back)
	}()
	forward(back, front)
	<-done
}

type testConnector struct {
	stop func()
}

func (c testConnector) Stop() { c.stop() }

func (edge *testTunnelEdge) start(_ context.Context, opts managed.ConnectorOptions) (managed.ConnectorProcess, error) {
	route := &managed.ConnectorOptions{PinnedOrigin: opts.PinnedOrigin, PinnedHostname: opts.PinnedHostname}
	if opts.Token != "connector-fixture-value" || route.PinnedOrigin == "" || !edge.route.CompareAndSwap(nil, route) {
		return nil, errors.New("invalid test connector")
	}
	opts.Observe(managed.ConnectorEvent{State: "ready"})
	return testConnector{stop: func() { edge.route.CompareAndSwap(route, nil) }}, nil
}

func newManagedE2E(t *testing.T, cfg cftunnel.Config, hub *signal.Hub, ca ed25519.PublicKey, token string, membership tunnelLookup) managedE2E {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	mustOK(t, err)
	cfg.ControlOrigin = "http://" + listener.Addr().String()
	cfg.Mode, cfg.AccountCap, cfg.FreeSlots, cfg.PaidDefaultSlots = cftunnel.ModeManaged, 8, 1, 3
	cfg.AccountID, cfg.ZoneID = strings.Repeat("a", 32), strings.Repeat("b", 32)
	cfg.BaseDomain, cfg.Namespace = "edge.example", "adapter-e2e"
	cfg.MasterKey, cfg.EdgeKey, cfg.EdgeGate = bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{9}, 32), cftunnel.EdgeWorkerHMAC
	var issuer, membershipOrigin string
	if cfg.Channel != cftunnel.ChannelSelf {
		issuer, membershipOrigin = tunnelIssuer, "https://membership.example"
		cfg.SiteManifest = &cftunnel.SiteManifest{Channel: cfg.Channel, CAPublicKeySHA256: tunnelDigest(ca),
			AllowedIssuer: issuer, MembershipOrigin: membershipOrigin, ControlOrigin: cfg.ControlOrigin,
			AccountID: cfg.AccountID, ZoneID: cfg.ZoneID, BaseDomain: cfg.BaseDomain, Namespace: cfg.Namespace}
		hub.RequireIssuer(issuer)
	}
	scope, err := cfg.BuildScope(ca, issuer, membershipOrigin)
	mustOK(t, err)
	store, err := sqlstore.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "tunnel.db"), sqlstore.Options{})
	mustOK(t, err)
	t.Cleanup(func() { mustOK(t, store.Close()) })
	mustOK(t, store.EnsureScope(t.Context(), scope))
	crypto, err := cftunnel.NewCrypto(cfg.MasterKey, cfg.EdgeKey, nil)
	mustOK(t, err)
	service, err := cftunnel.NewService(cfg, scope, store, &testCloudflare{}, crypto, cftunnel.ServiceOptions{
		Membership: membership,
		RuntimeChecker: func(_ context.Context, device, key, runtime string, now time.Time) bool {
			return hub.HasActiveTunnelRuntime(device, key, runtime, now)
		},
	})
	mustOK(t, err)
	hub.ConfigureTunnel(tunnelSecurityController{service})
	mux := http.NewServeMux()
	mux.Handle("/v1/signal", hub)
	mux.Handle("/v1/tunnels/", cftunnel.NewHTTPHandler(service, ca, token))
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go hub.Run(ctx)
	go func() {
		defer close(done)
		_ = service.RunWorker(ctx, "adapter-e2e-worker")
	}()
	t.Cleanup(func() { cancel(); <-done })
	edge := &testTunnelEdge{crypto: crypto}
	proxy := httptest.NewServer(edge)
	t.Cleanup(proxy.Close)
	return managedE2E{"ws://" + listener.Addr().String() + "/v1/signal", cfg.ControlOrigin, "ws" + strings.TrimPrefix(proxy.URL, "http"), edge}
}

type tunnelRPCHandler struct {
	noopTransportHandler
	opened   atomic.Int32
	messages chan []byte
	closed   chan struct{}
}

func newTunnelRPCHandler() *tunnelRPCHandler {
	return &tunnelRPCHandler{messages: make(chan []byte, 16), closed: make(chan struct{})}
}

func (h *tunnelRPCHandler) Open(transport.Peer) { h.opened.Add(1) }

func (h *tunnelRPCHandler) Closed(transport.Peer) { close(h.closed) }
func (h *tunnelRPCHandler) Message(_ transport.Peer, raw []byte) {
	h.messages <- raw
}

func (h *tunnelRPCHandler) workspaceList(t *testing.T, peer transport.Peer) {
	t.Helper()
	const id = "encrypted-workspace-request"
	mustOK(t, peer.Send(protocol.Encode(map[string]any{"type": "workspace.list", "request_id": id}), false))
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case raw := <-h.messages:
			var msg struct {
				Type  string `json:"type"`
				ID    string `json:"request_id"`
				Error string `json:"error"`
			}
			mustOK(t, json.Unmarshal(raw, &msg))
			if msg.ID != id {
				continue
			}
			if msg.Error != "" || !bytes.Contains(raw, []byte(`"workspace_id":"tunnel-workspace"`)) {
				t.Fatalf("desktop rejected workspace.list (%s)", msg.Type)
			}
			return
		case <-h.closed:
			t.Fatal("peer closed during workspace.list")
		case <-timeout.C:
			t.Fatal("desktop did not return a workspace.list response")
		}
	}
}

func discardDeferredTunnel(t *testing.T, host *managed.HostManager, handler *tunnelRPCHandler, peer transport.Peer, start func()) {
	t.Helper()
	peer.Close()
	start()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for host.Status().ActivePeers != 0 {
		select {
		case <-deadline.C:
			t.Fatal("discarded visitor did not close the host connection")
		case <-tick.C:
		}
	}
	select {
	case <-handler.closed:
		t.Fatal("discarded visitor received Closed")
	default:
	}
	if handler.opened.Load() != 0 || len(handler.messages) != 0 {
		t.Fatal("discarded visitor received Open or Message")
	}
}

func waitTunnelState(t *testing.T, host *managed.HostManager, state string, ready bool) {
	t.Helper()
	deadline := time.NewTimer(16 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(15 * time.Millisecond)
	defer ticker.Stop()
	for {
		status := host.Status()
		if status.State == state && status.ConnectorReady == ready {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("want %s (ready=%t), got %+v", state, ready, status)
		case <-ticker.C:
		}
	}
}

func newTunnelDesktop(t *testing.T, owner string, self bool, users []desktop.Grant) *desktop.Adapter {
	t.Helper()
	executable, err := os.Executable()
	mustOK(t, err)
	app, err := desktop.New(&desktop.Config{Executable: executable, Workspaces: []desktop.WorkspaceConfig{
		{ID: "tunnel-workspace", Owner: owner, WorkingDir: t.TempDir(), SelfAccess: self, Users: users, FencePeerSessions: !self},
	}}, filepath.Join(t.TempDir(), "state"))
	mustOK(t, err)
	t.Cleanup(func() { mustOK(t, app.Close()) })
	return app
}

func TestManagedTunnelSelfEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	app := newTunnelDesktop(t, desktop.LocalOwner, true, nil)
	srv, err := selfrelay.OpenServer(&lanMemStore{}, app)
	mustOK(t, err)
	app.SetSelfAuthority(srv.Allows)
	relayToken := strings.Repeat("e2e-self-relay-", 4)
	hub := signal.NewSelfHosted(relayToken, nil)
	rig := newManagedE2E(t, cftunnel.Config{Channel: cftunnel.ChannelSelf,
		SelfDevices: map[string]struct{}{srv.DeviceID(): {}}}, hub, nil, relayToken, nil)
	hostKey := srv.PrivateKey().Public().(ed25519.PublicKey)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	clientID := base64.RawURLEncoding.EncodeToString(pub)
	group, local, err := srv.GroupFor(rig.signalURL, "Self desktop")
	mustOK(t, err)
	mustOK(t, group.Admit(local, pairnet.Member{ID: clientID, Pin: clientID, Role: "desktop", Name: "Visitor"}, true))
	mustOK(t, srv.SetPeerAccessFor(rig.signalURL, clientID, selfrelay.Control))
	var active atomic.Pointer[managed.HostManager]
	started := make(chan error, 1)
	srv.SetTunnelHooks(selfrelay.TunnelHooks{
		OnSessionStart: func(ctx context.Context, scope, _, token string, send func(protocol.Message) error) {
			host, err := managed.NewHostManager(managed.HostOptions{Channel: "self", Scope: scope, ControlOrigin: rig.controlOrigin,
				DeviceID: srv.DeviceID(), OwnerID: srv.DeviceID(), PrivateKey: srv.PrivateKey(), SelfToken: token,
				SendSignal: send, Handler: srv.TunnelHandler(), StartConnector: rig.edge.start, PinnedConnector: true,
				AuthorizeOffer: func(req managed.OfferRequest) (managed.OfferDecision, error) {
					_, user, ok := srv.AuthorizePairedTunnel(req.Principal.PublicKey, req.Role)
					if !ok {
						return managed.OfferDecision{}, transport.ErrUnauthorized
					}
					return managed.OfferDecision{UserID: user, Allows: func() bool { return srv.Allows(user) }}, nil
				}})
			if err == nil {
				active.Store(host)
				err = host.Start(ctx)
			}
			started <- err
		},
		OnMessage: func(m protocol.Message) {
			if host := active.Load(); host != nil {
				host.HandleSignal(m)
			}
		},
		OnRevokeClient: func(id string) {
			if host := active.Load(); host != nil {
				host.RevokeUser("self:control:" + id)
			}
		},
	})
	mustOK(t, srv.Connect(ctx, rig.signalURL, relayToken, "Self desktop"))
	defer srv.Stop()
	select {
	case err := <-started:
		mustOK(t, err)
	case <-ctx.Done():
		t.Fatal("self host session did not start")
	}
	host := active.Load()
	defer host.Stop()
	waitTunnelState(t, host, "ready", true)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http"+strings.TrimPrefix(rig.edgeURL, "ws")+"/v1/tunnel/ws", nil)
	mustOK(t, err)
	req.Host = host.Status().Hostname
	resp, err := http.DefaultClient.Do(req)
	mustOK(t, err)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("edge accepted an unticketed request: %d", resp.StatusCode)
	}

	handler := newTunnelRPCHandler()
	opts := managed.SelfConnectOptions{SignalURL: rig.signalURL, SelfToken: relayToken, PrivateKey: key,
		HostPublicKey: hostKey, DialURL: rig.edgeURL, Handler: handler, Role: "desktop"}
	discarded := newTunnelRPCHandler()
	opts.Handler = discarded
	unstarted, start, err := managed.ConnectSelfDeferred(ctx, opts)
	mustOK(t, err)
	discardDeferredTunnel(t, host, discarded, unstarted, start)
	opts.Handler = handler
	peer, err := managed.ConnectSelf(ctx, opts)
	mustOK(t, err)
	defer peer.Close()
	handler.workspaceList(t, peer)
	rig.edge.mu.Lock()
	opaque := bytes.Contains(rig.edge.wire.Bytes(), []byte{0x17, 0x03, 0x03}) &&
		!bytes.Contains(rig.edge.wire.Bytes(), []byte("workspace.list")) &&
		!bytes.Contains(rig.edge.wire.Bytes(), []byte("tunnel-workspace")) &&
		!bytes.Contains(rig.edge.wire.Bytes(), []byte("encrypted-workspace-request"))
	rig.edge.mu.Unlock()
	if !opaque {
		t.Fatal("edge did not observe exclusively encrypted RPC traffic")
	}
	_, _, err = srv.Invite(selfrelay.Control, false)
	mustOK(t, err)
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	opts.PrivateKey = stranger
	if _, err := managed.ConnectSelf(ctx, opts); !errors.Is(err, transport.SignalError("device_unavailable")) {
		t.Fatalf("unpaired device received %v", err)
	}
	if len(srv.Status().Invitations) != 1 {
		t.Fatal("tunnel negotiation changed pending invitations")
	}
	mustOK(t, srv.RevokeClients(clientID))
	if host.Status().ActivePeers != 0 {
		t.Fatal("self-relay revocation left a live desktop peer")
	}
	select {
	case <-handler.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("visitor peer survived local revocation")
	}
}

type tunnelHostObserver struct {
	transport.Handler
	open chan transport.Peer
}

func (h tunnelHostObserver) Open(peer transport.Peer) {
	h.Handler.Open(peer)
	h.open <- peer
}

func TestManagedTunnelOfficialEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	ca := identitytest.NewAuthority(0)
	hostSource := makeStaticSource(t, ca, tunnelIssuer, "owner")
	owner := makeStaticSource(t, ca, tunnelIssuer, "owner")
	freeGuest := makeStaticSource(t, ca, tunnelIssuer, "free-guest")
	paidGuest := makeStaticSource(t, ca, tunnelIssuer, "paid-guest")
	hub := signal.New(ca.PublicKey(), nil, nil)
	rig := newManagedE2E(t, cftunnel.Config{Channel: cftunnel.ChannelCN}, hub, ca.PublicKey(), "",
		func(_ context.Context, _, subject string) (membership.Entitlement, error) {
			switch subject {
			case "owner":
				allow := true
				return membership.Entitlement{TunnelAllowed: &allow}, nil
			case "paid-guest":
				return membership.Entitlement{RelayAllowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
			default:
				return membership.Entitlement{}, nil
			}
		})
	ownerID := hostSource.creds.UserID()
	app := newTunnelDesktop(t, ownerID, false, []desktop.Grant{
		{UserID: freeGuest.creds.UserID(), Read: true, Tools: true}, {UserID: paidGuest.creds.UserID(), Read: true, Tools: true},
	})
	app.SetOfficialOwner(ownerID)
	app.AuthorityUntil(time.Now().Add(55 * time.Second))
	opened := make(chan transport.Peer, 8)
	socket, err := transport.DialPairedDesktopWithRole(ctx, rig.signalURL, hostSource, tunnelHostObserver{app, opened},
		func(_ string, principal identity.Principal, role, _ string, proof []byte) bool {
			if role != "mobile" || proof != nil {
				return false
			}
			for _, known := range []*staticSource{owner, freeGuest, paidGuest} {
				if known.creds.DeviceID() == principal.DeviceID && known.creds.PublicKey().Equal(principal.PublicKey) {
					return true
				}
			}
			return false
		})
	mustOK(t, err)
	defer socket.Close()
	mustOK(t, socket.Publish(ctx, "Official Desktop", []string{freeGuest.creds.UserID(), paidGuest.creds.UserID()}))
	host, err := managed.NewHostManager(managed.HostOptions{
		Channel: "cn", Scope: socket.TunnelScope(), ControlOrigin: rig.controlOrigin, DeviceID: socket.DeviceID(), OwnerID: socket.UserID(),
		PrivateKey: hostSource.creds.PrivateKey(), CA: ca.PublicKey(), Handler: socket.TunnelHandler(), SendSignal: socket.SendTunnel,
		PinnedConnector: true, StartConnector: rig.edge.start,
		LeaseSource: func(ctx context.Context) (endpoint.LeaseProof, error) {
			_, proof, err := socket.CurrentLease(ctx)
			return proof, err
		},
		AuthorizeOffer: func(req managed.OfferRequest) (managed.OfferDecision, error) {
			allows := func() bool { return socket.AuthorizePairedTunnel(req.ConnectionID, req.Principal, req.Role) }
			if !allows() {
				return managed.OfferDecision{}, transport.ErrUnauthorized
			}
			return managed.OfferDecision{UserID: req.Principal.RemoteUserID(), Allows: allows}, nil
		},
	})
	mustOK(t, err)
	socket.SetTunnelHooks(transport.TunnelHooks{OnMessage: host.HandleSignal, OnLeaseUpdated: host.UpdateLocalLease,
		OnAuthorityLost: host.AuthorityLost, OnRevokeUser: host.RevokeUser, OnRevokeDevice: host.RevokeVisitor})
	mustOK(t, host.Start(ctx))
	defer host.Stop()
	waitTunnelState(t, host, "ready", true)
	connect := func(source *staticSource, handler transport.Handler) (transport.Peer, error) {
		return managed.ConnectOfficial(ctx, managed.OfficialConnectOptions{SignalURL: rig.signalURL, Channel: "cn", OwnerID: ownerID,
			HostDeviceID: socket.DeviceID(), HostPublicKey: socket.PublicKey(), CA: ca.PublicKey(), LeaseSource: source,
			Handler: handler, DialURL: rig.edgeURL})
	}
	discarded := newTunnelRPCHandler()
	unstarted, start, err := managed.ConnectOfficialDeferred(ctx, managed.OfficialConnectOptions{
		SignalURL: rig.signalURL, Channel: "cn", OwnerID: ownerID, HostDeviceID: socket.DeviceID(), HostPublicKey: socket.PublicKey(),
		CA: ca.PublicKey(), LeaseSource: owner, Handler: discarded, DialURL: rig.edgeURL,
	})
	mustOK(t, err)
	select {
	case <-opened:
	case <-ctx.Done():
		t.Fatal("desktop did not open the deferred visitor")
	}
	discardDeferredTunnel(t, host, discarded, unstarted, start)
	ownerHandler := newTunnelRPCHandler()
	ownerPeer, err := connect(owner, ownerHandler)
	mustOK(t, err)
	defer ownerPeer.Close()
	ownerHandler.workspaceList(t, ownerPeer)
	if _, err := connect(freeGuest, nil); !errors.Is(err, transport.SignalError("device_unavailable")) {
		t.Fatalf("unpaid guest received %v", err)
	}
	paidHandler := newTunnelRPCHandler()
	paidPeer, err := connect(paidGuest, paidHandler)
	mustOK(t, err)
	defer paidPeer.Close()
	paidHandler.workspaceList(t, paidPeer)

	var desktopPeer transport.Peer
	select {
	case desktopPeer = <-opened:
	case <-ctx.Done():
		t.Fatal("desktop peer did not open")
	}
	if !desktopPeer.Allows(true) {
		t.Fatal("online authority did not authorize the established peer")
	}
	host.AuthorityLost()
	if desktopPeer.Allows(true) || !desktopPeer.Allows(false) {
		t.Fatal("authority loss did not disable online work while preserving read access")
	}
	mustOK(t, host.Disconnect(ctx))
	waitTunnelState(t, host, "suspended", false)
	if !host.Status().ManualResumeRequired || host.Status().ActivePeers != 0 {
		t.Fatal("disconnect failed to suspend the allocation and close all peers")
	}
	for _, handler := range []*tunnelRPCHandler{paidHandler, ownerHandler} {
		select {
		case <-handler.closed:
		case <-time.After(2 * time.Second):
			t.Fatal("visitor survived disconnect")
		}
	}
	if _, err := connect(owner, nil); !errors.Is(err, transport.SignalError("device_unavailable")) {
		t.Fatalf("suspended host received %v", err)
	}
	mustOK(t, host.Resume(ctx))
	waitTunnelState(t, host, "ready", true)
	restored := newTunnelRPCHandler()
	peer, err := connect(owner, restored)
	mustOK(t, err)
	defer peer.Close()
	restored.workspaceList(t, peer)
}
