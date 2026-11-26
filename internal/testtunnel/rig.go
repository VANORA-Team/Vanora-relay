// Package testtunnel provides loopback integration fixtures for managed tunnel clients.
package testtunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/cftunnel"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	relaytunnel "vanora-relay/internal/cftunnel"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/internal/membership"
	"vanora-relay/internal/signal"
	"vanora-relay/protocol"
)

const (
	hostname = "host.edge.example"
	scope    = "test-tunnel-scope"
	tunnelWS = "/v1/tunnel/ws"
)

type Store struct {
	mu    sync.Mutex
	value string
}

func (s *Store) Load() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value, nil
}

func (s *Store) Save(value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value = value
	return nil
}

type Rig struct {
	SignalURL, EdgeURL, Origin, Token, CAHex string
	FailICE, StallRTC, TURNSuppressed        atomic.Bool
	Offers, StalledOffers, ClosedStalled     atomic.Int32
	EdgeConnections                          atomic.Int32
	hub                                      *signal.Hub
	crypto                                   *relaytunnel.Crypto
	authority                                *identitytest.Authority
	entitlement                              membership.Entitlement
	challenges                               sync.Map
	origin                                   atomic.Pointer[string]
	listening                                atomic.Bool
	blackholed                               atomic.Int32
}

func New(t *testing.T, channel string) *Rig {
	t.Helper()
	rig := &Rig{Token: strings.Repeat("local-fixture-", 4)}
	crypto, err := relaytunnel.NewCrypto(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), nil)
	Must(t, err)
	rig.crypto = crypto
	if channel == "self" {
		rig.hub = signal.NewSelfHosted(rig.Token, rig)
	} else {
		allowed, slots := true, 1
		rig.entitlement = membership.Entitlement{TunnelAllowed: &allowed, MaxTunnels: &slots}
		rig.authority = identitytest.NewAuthority(0)
		rig.CAHex = hex.EncodeToString(rig.authority.PublicKey())
		rig.hub = signal.New(rig.authority.PublicKey(), rig, rig)
	}
	rig.hub.ConfigureTunnel(rig)
	go rig.hub.Run(t.Context())
	upstream := httptest.NewServer(rig.hub)
	t.Cleanup(upstream.Close)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/signal", func(w http.ResponseWriter, r *http.Request) {
		if rig.StallRTC.Load() && r.URL.Query().Get("probe") == "" {
			rig.stallVisitor(w, r, wsURL(upstream.URL)+"/v1/signal")
			return
		}
		rig.hub.ServeHTTP(w, r)
	})
	mux.HandleFunc("/v1/tunnels/", rig.control)
	mux.HandleFunc("/v1/identity/", rig.serveIdentity)
	mux.HandleFunc(tunnelWS, rig.edge)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	rig.Origin, rig.EdgeURL = server.URL, wsURL(server.URL)
	rig.SignalURL = rig.EdgeURL + "/v1/signal"
	return rig
}

func wsURL(origin string) string { return "ws" + strings.TrimPrefix(origin, "http") }

func (r *Rig) DisableTunnels() { r.hub.ConfigureTunnel(nil) }

func (r *Rig) BlackholeLatestEdge() { r.blackholed.Store(r.EdgeConnections.Load()) }

func (r *Rig) Config(_ string, _ string, until time.Time) ([]ice.ICEServer, error) {
	r.TURNSuppressed.Store(until.IsZero())
	if r.FailICE.Load() {
		return nil, errors.New("fixture ICE unavailable")
	}
	return []ice.ICEServer{}, nil
}

func (*Rig) Revoke(string) {}

func (*Rig) Check(context.Context, string, string) (time.Time, error) {
	return time.Time{}, errors.New("fixture TURN entitlement denied")
}

func (*Rig) ScopeID() string { return scope }

func (r *Rig) RecordHostPresence(_ context.Context, _ identity.Principal, _, _, phase string, _, _, _ int64, _ bool) error {
	r.listening.Store(phase == "listening")
	return nil
}

func (r *Rig) AuthorizeVisitor(_ context.Context, request signal.TunnelAccessRequest) (string, time.Time, error) {
	r.Offers.Add(1)
	now := time.Now()
	if r.authority != nil {
		quota := relaytunnel.EvaluateOwnerPolicy(r.entitlement, now, 1, 3, nil)
		if !quota.Allowed || quota.MaxTunnels != 1 ||
			!relaytunnel.EvaluateVisitorConnect(r.entitlement, now, request.Host.RemoteUserID() == request.Visitor.RemoteUserID()).Allowed {
			return "", time.Time{}, errors.New("fixture tunnel entitlement denied")
		}
	}
	return hostname, now.Add(55 * time.Second), nil
}

func (r *Rig) RefreshVisitorAccess(ctx context.Context, request signal.TunnelAccessRequest) (string, time.Time, error) {
	return r.AuthorizeVisitor(ctx, request)
}

func (r *Rig) MintEdgeTicket(_ context.Context, _ identity.Principal, _, _ int64, host, jti string) (string, error) {
	return r.crypto.MintEdgeTicket(host, tunnelWS, jti, time.Now())
}

func (*Rig) ReleasedForOwner(context.Context, identity.Principal, string) bool { return false }

func (r *Rig) control(w http.ResponseWriter, request *http.Request) {
	device := path.Base(path.Dir(request.URL.Path))
	switch path.Base(request.URL.Path) {
	case "challenge":
		writeJSON(w, map[string]any{"challenge": protocol.NewID(), "expires_at": time.Now().Add(30 * time.Second)})
	case "status", "origin":
		writeJSON(w, cftunnel.AllocationView{DeviceID: device, State: "ready", Generation: 1, Incarnation: 1, Hostname: hostname})
	case "token":
		writeJSON(w, cftunnel.ConnectorToken{Generation: 1, Incarnation: 1, Hostname: hostname, TunnelID: "fixture-tunnel", ConnectorToken: "fixture-token"})
	default:
		http.NotFound(w, request)
	}
}

func (r *Rig) edge(w http.ResponseWriter, request *http.Request) {
	origin := r.origin.Load()
	ticket, jti := request.Header.Get("Vanora-Edge-Ticket"), request.Header.Get("Vanora-Ticket-ID")
	if origin == nil || request.Host != hostname || !r.crypto.VerifyEdgeTicket(ticket, request.Host, tunnelWS, jti, time.Now()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	front, err := websocket.Accept(w, request, &websocket.AcceptOptions{Subprotocols: []string{cftunnel.Subprotocol}})
	if err != nil {
		return
	}
	defer front.CloseNow()
	headers := http.Header{"Vanora-Ticket-Id": {jti}, "Vanora-Client-Proof": {request.Header.Get("Vanora-Client-Proof")}}
	back, _, err := websocket.Dial(request.Context(), "ws://"+*origin+tunnelWS, &websocket.DialOptions{
		Host: hostname, Subprotocols: []string{cftunnel.Subprotocol}, HTTPHeader: headers,
	})
	if err != nil {
		return
	}
	defer back.CloseNow()
	front.SetReadLimit(64 << 10)
	back.SetReadLimit(64 << 10)
	connection := r.EdgeConnections.Add(1)
	drop := func([]byte) bool { return r.blackholed.Load() == connection }
	bridge(request.Context(), front, back, drop, drop)
}

func (r *Rig) stallVisitor(w http.ResponseWriter, request *http.Request, target string) {
	front, err := websocket.Accept(w, request, nil)
	if err != nil {
		return
	}
	defer front.CloseNow()
	headers := http.Header{"Authorization": request.Header.Values("Authorization")}
	back, _, err := websocket.Dial(request.Context(), target, &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		return
	}
	defer back.CloseNow()
	front.SetReadLimit(192 << 10)
	back.SetReadLimit(192 << 10)
	var sawOffer bool
	bridge(request.Context(), front, back, func(raw []byte) bool {
		var message protocol.Message
		_ = json.Unmarshal(raw, &message)
		switch message.Type {
		case "rtc.offer":
			sawOffer = true
			r.StalledOffers.Add(1)
			return true
		case "rtc.candidate":
			return true
		default:
			return false
		}
	}, func([]byte) bool { return false })
	if sawOffer {
		r.ClosedStalled.Add(1)
	}
}

func bridge(ctx context.Context, front, back *websocket.Conn, dropRequest, dropResponse func([]byte) bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	forward := func(from, to *websocket.Conn, drop func([]byte) bool) {
		defer cancel()
		for {
			kind, raw, err := from.Read(ctx)
			if err != nil {
				return
			}
			if !drop(raw) && to.Write(ctx, kind, raw) != nil {
				return
			}
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		forward(front, back, dropRequest)
	}()
	forward(back, front, dropResponse)
	<-done
}

type connector struct{ stop func() }

func (c connector) Stop() { c.stop() }

func (r *Rig) startConnector(_ context.Context, opts cftunnel.ConnectorOptions) (cftunnel.ConnectorProcess, error) {
	origin := &opts.PinnedOrigin
	r.origin.Store(origin)
	opts.Observe(cftunnel.ConnectorEvent{State: "ready"})
	return connector{stop: func() { r.origin.CompareAndSwap(origin, nil) }}, nil
}

func (r *Rig) StartSelfHost(t *testing.T, server *selfrelay.Server) {
	t.Helper()
	var host atomic.Pointer[cftunnel.HostManager]
	started := make(chan error, 1)
	server.SetTunnelHooks(selfrelay.TunnelHooks{
		OnSessionStart: func(ctx context.Context, scope, _, token string, send func(protocol.Message) error) {
			manager, err := cftunnel.NewHostManager(cftunnel.HostOptions{
				Channel: "self", Scope: scope, ControlOrigin: r.Origin, DeviceID: server.DeviceID(), OwnerID: server.DeviceID(),
				PrivateKey: server.PrivateKey(), SelfToken: token, Handler: server.TunnelHandler(), SendSignal: send,
				StartConnector: r.startConnector, PinnedConnector: true,
				AuthorizeOffer: func(req cftunnel.OfferRequest) (cftunnel.OfferDecision, error) {
					_, user, ok := server.AuthorizePairedTunnel(req.Principal.PublicKey, req.Role)
					if !ok {
						return cftunnel.OfferDecision{}, transport.ErrUnauthorized
					}
					return cftunnel.OfferDecision{UserID: user, Allows: func() bool { return server.Allows(user) }}, nil
				},
			})
			if err == nil {
				host.Store(manager)
				err = manager.Start(ctx)
			}
			select {
			case started <- err:
			case <-ctx.Done():
			}
		},
		OnMessage: func(msg protocol.Message) {
			if manager := host.Load(); manager != nil {
				manager.HandleSignal(msg)
			}
		},
	})
	Must(t, server.Connect(t.Context(), r.SignalURL, r.Token, "Test desktop"))
	t.Cleanup(server.Stop)
	Must(t, Await(t, started))
	t.Cleanup(host.Load().Stop)
	Wait(t, r.listening.Load)
}

func (r *Rig) NewAccount(t *testing.T) *account.Account {
	t.Helper()
	result, err := account.New(r.Origin, r.CAHex, &Store{})
	Must(t, err)
	Must(t, result.Enroll(t.Context(), "fixture-enrollment"))
	return result
}

func (r *Rig) StartOfficialHost(t *testing.T, source *account.Account, handler transport.Handler, paired endpoint.PairRoleAuthorizer) *transport.Client {
	t.Helper()
	socket, err := transport.DialPairedDesktopWithRole(t.Context(), r.SignalURL, source, handler, paired)
	Must(t, err)
	t.Cleanup(socket.Close)
	Must(t, socket.Publish(t.Context(), "Test desktop", nil))
	credentials, _, err := source.Current(t.Context())
	Must(t, err)
	host, err := cftunnel.NewHostManager(cftunnel.HostOptions{
		Channel: "cn", Scope: socket.TunnelScope(), ControlOrigin: r.Origin, DeviceID: socket.DeviceID(), OwnerID: socket.UserID(),
		PrivateKey: credentials.PrivateKey(), CA: source.CA(), Handler: socket.TunnelHandler(), SendSignal: socket.SendTunnel,
		PinnedConnector: true, StartConnector: r.startConnector,
		LeaseSource: func(ctx context.Context) (endpoint.LeaseProof, error) {
			_, proof, err := socket.CurrentLease(ctx)
			return proof, err
		},
		AuthorizeOffer: func(req cftunnel.OfferRequest) (cftunnel.OfferDecision, error) {
			allows := func() bool { return socket.AuthorizePairedTunnel(req.ConnectionID, req.Principal, req.Role) }
			if !allows() {
				return cftunnel.OfferDecision{}, transport.ErrUnauthorized
			}
			return cftunnel.OfferDecision{UserID: req.Principal.RemoteUserID(), Allows: allows}, nil
		},
	})
	Must(t, err)
	socket.SetTunnelHooks(transport.TunnelHooks{OnMessage: host.HandleSignal, OnLeaseUpdated: host.UpdateLocalLease, OnAuthorityLost: host.AuthorityLost})
	Must(t, host.Start(t.Context()))
	t.Cleanup(host.Stop)
	Wait(t, r.listening.Load)
	return socket
}

func (r *Rig) serveIdentity(w http.ResponseWriter, request *http.Request) {
	var input struct {
		PublicKey   string `json:"public_key"`
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
		Certificate string `json:"certificate"`
		Signature   string `json:"signature"`
	}
	if r.authority == nil || json.NewDecoder(request.Body).Decode(&input) != nil {
		http.Error(w, "invalid identity fixture request", http.StatusBadRequest)
		return
	}
	now := time.Now()
	switch path.Base(request.URL.Path) {
	case "challenges":
		id := protocol.NewID()
		r.challenges.Store(id, input.PublicKey)
		writeJSON(w, map[string]any{"challenge_id": id, "nonce": id, "expires_at": now.Add(time.Minute).Unix()})
	case "enroll":
		stored, ok := r.challenges.LoadAndDelete(input.ChallengeID)
		if ok {
			key, _ := base64.RawURLEncoding.DecodeString(stored.(string))
			proof, _ := base64.RawURLEncoding.DecodeString(input.Signature)
			if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, identity.ProofMessage(input.ChallengeID, input.ChallengeID, "enroll", key), proof) {
				cert, err := r.authority.IssueWithKey("https://fixture.example", "owner", key, now)
				if err == nil {
					principal, err := identity.VerifyCertificate(cert, r.authority.PublicKey(), now)
					if err == nil {
						writeJSON(w, map[string]any{"certificate": cert, "device_id": principal.DeviceID,
							"remote_user_id": principal.RemoteUserID(), "expires_at": principal.Expires.Unix()})
						return
					}
				}
			}
		}
		http.Error(w, "fixture enrollment denied", http.StatusUnauthorized)
	case "lease":
		principal, err := identity.VerifyCertificate(input.Certificate, r.authority.PublicKey(), now)
		proof, _ := base64.RawURLEncoding.DecodeString(input.Signature)
		if err == nil && ed25519.Verify(principal.PublicKey, identity.LeaseProofMessage(input.Nonce, input.Certificate), proof) {
			lease, expiry, err := r.authority.IssueLease(principal, input.Certificate, input.Nonce, now, 60*time.Second)
			if err == nil {
				writeJSON(w, map[string]any{"lease": lease, "device_id": principal.DeviceID, "remote_user_id": principal.RemoteUserID(),
					"issued_at": now.Unix(), "expires_at": expiry.Unix()})
				return
			}
		}
		http.Error(w, "fixture lease denied", http.StatusUnauthorized)
	default:
		http.NotFound(w, request)
	}
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func Must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func Await[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fixture event")
		var zero T
		return zero
	}
}

func Wait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-deadline:
			t.Fatal("fixture condition did not become true")
		case <-tick.C:
		}
	}
}
