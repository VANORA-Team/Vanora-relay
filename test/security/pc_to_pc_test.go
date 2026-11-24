package security_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/internal/signal"
	"vanora-relay/protocol"
)

type staticSource struct {
	creds *endpoint.Credentials
	proof endpoint.LeaseProof
}

func (s *staticSource) Current(context.Context) (*endpoint.Credentials, endpoint.LeaseProof, error) {
	return s.creds, s.proof, nil
}

func makeStaticSource(t *testing.T, auth *identitytest.Authority, iss, sub string) *staticSource {
	t.Helper()
	now := time.Now()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	cert, err := auth.IssueWithKey(iss, sub, pub, now)
	mustOK(t, err)
	p, err := identity.VerifyCertificate(cert, auth.PublicKey(), now)
	mustOK(t, err)
	nonceBytes := make([]byte, 16)
	_, err = rand.Read(nonceBytes)
	mustOK(t, err)
	lease, _, err := auth.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonceBytes), now, 55*time.Second)
	mustOK(t, err)
	creds, err := endpoint.OpenCredentials(cert, priv, auth.PublicKey(), now)
	mustOK(t, err)
	return &staticSource{creds: creds, proof: endpoint.LeaseProof{Certificate: cert, Lease: lease}}
}

type noopTransportHandler struct{}

func (noopTransportHandler) Open(transport.Peer)            {}
func (noopTransportHandler) Message(transport.Peer, []byte) {}
func (noopTransportHandler) Closed(transport.Peer)          {}

type staticEntitlement struct {
	mu      sync.Mutex
	allowed map[string]time.Time
	checked []string
}

func (e *staticEntitlement) Check(_ context.Context, _, subject string) (time.Time, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.checked = append(e.checked, subject)
	return e.allowed[subject], nil
}

type recordingICE struct {
	mu       sync.Mutex
	visitors map[string]bool
}

func (r *recordingICE) Config(_ string, visitor string, until time.Time) ([]ice.ICEServer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.visitors == nil {
		r.visitors = make(map[string]bool)
	}
	r.visitors[visitor] = until.After(time.Now())
	if until.After(time.Now()) {
		return []ice.ICEServer{{URLs: []string{"turn:127.0.0.1:3478"}, Username: "u", Credential: "c"}}, nil
	}
	return []ice.ICEServer{}, nil
}
func (r *recordingICE) Revoke(string) {}

func TestSecurityDesktopSelfDialRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 1. Official relay + endpoint + transport self-dial rejection.
	auth := identitytest.NewAuthority(10 * time.Minute)
	src := makeStaticSource(t, auth, "https://cn-auth.example.com/realms/vanora", "owner-self")
	hub := signal.New(auth.PublicKey(), nil, &recordingICE{})
	go hub.Run(ctx)
	srv := httptest.NewServer(hub)
	defer srv.Close()
	sigURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	if _, _, err := src.creds.RequestPairedWithMeta(src.creds.DeviceID(), src.creds.UserID(), src.creds.PublicKey(), nil, endpoint.ConnectRequestMeta{Role: "desktop"}); err == nil {
		t.Fatal("endpoint.RequestPairedWithMeta allowed dialing self")
	}

	desk, err := transport.DialPairedDesktopWithRole(ctx, sigURL, src, noopTransportHandler{}, func(string, endpoint.PeerIdentity, string, string, []byte) bool {
		return true
	})
	mustOK(t, err)
	defer desk.Close()
	mustOK(t, desk.Publish(ctx, "SelfDesk", nil))

	if _, err := desk.ConnectPairedWithOptions(ctx, src.creds.DeviceID(), src.creds.UserID(), transport.ConnectOptions{Role: transport.RoleDesktop}); err == nil {
		t.Fatal("transport.Client allowed desktop self-dial")
	}
	if _, err := transport.DialDesktopControllerFor(ctx, sigURL, src.creds.DeviceID(), src, noopTransportHandler{}); err == nil {
		t.Fatal("signal hub allowed scoped desktop self-dial socket")
	}
	devices, err := desk.Devices(ctx)
	mustOK(t, err)
	for _, d := range devices {
		if d.DeviceID == src.creds.DeviceID() {
			t.Fatal("devices.list returned the calling desktop itself")
		}
	}

	// 2. Self-hosted relay self-dial rejection.
	relayToken := strings.Repeat("self-selfdial-", 4)
	selfHub := signal.NewSelfHosted(relayToken, &recordingICE{})
	go selfHub.Run(ctx)
	selfSrv := httptest.NewServer(selfHub)
	defer selfSrv.Close()
	selfURL := "ws" + strings.TrimPrefix(selfSrv.URL, "http")

	selfDesk, err := selfrelay.OpenServer(&lanMemStore{}, noopTransportHandler{})
	mustOK(t, err)
	onlineCh := make(chan bool, 2)
	selfDesk.SetObserver(func(on bool, _ string) {
		if on {
			select {
			case onlineCh <- true:
			default:
			}
		}
	})
	mustOK(t, selfDesk.Connect(ctx, selfURL, relayToken, "SelfNode"))
	defer selfDesk.Stop()
	<-onlineCh

	_, selfLink, err := selfDesk.Invite(selfrelay.Control, true)
	mustOK(t, err)
	selfTarget, err := selfrelay.ParseTarget(selfLink)
	mustOK(t, err)
	if _, _, err := selfrelay.DialWithRole(ctx, selfTarget, selfDesk.Seed(), "SelfNode", "desktop", noopTransportHandler{}); err == nil {
		t.Fatal("selfrelay.DialWithRole allowed desktop self-dial")
	}

	// 3. LAN self-dial rejection.
	lanDesk, err := lan.OpenServer(&lanMemStore{}, noopTransportHandler{})
	mustOK(t, err)
	mustOK(t, lanDesk.Listen(ctx, "127.0.0.1:0"))
	defer lanDesk.Stop()
	_, lanLink, err := lanDesk.Invite(lan.Control)
	mustOK(t, err)
	lanTarget, err := lan.ParseTarget(lanLink)
	mustOK(t, err)
	if _, _, err := lan.DialWithOptions(ctx, lanTarget, lanDesk.Seed(), "SelfLAN", "desktop", lanDesk.Address(), noopTransportHandler{}); err == nil {
		t.Fatal("lan.DialWithOptions allowed desktop self-dial")
	}
}

func TestSecurityDesktopCrossAccountTURNEntitlementAttribution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	auth := identitytest.NewAuthority(10 * time.Minute)
	srcNoTurn := makeStaticSource(t, auth, "https://cn-auth.example.com/realms/vanora", "user-no-turn")
	srcWithTurn := makeStaticSource(t, auth, "https://cn-auth.example.com/realms/vanora", "user-with-turn")

	ent := &staticEntitlement{
		allowed: map[string]time.Time{
			"user-with-turn": time.Now().Add(time.Hour),
		},
	}
	iceRec := &recordingICE{}
	hub := signal.New(auth.PublicKey(), ent, iceRec)
	go hub.Run(ctx)
	srv := httptest.NewServer(hub)
	defer srv.Close()
	sigURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	deskNoTurn, err := transport.DialPairedDesktopWithRole(ctx, sigURL, srcNoTurn, noopTransportHandler{}, func(string, endpoint.PeerIdentity, string, string, []byte) bool {
		return true
	})
	mustOK(t, err)
	defer deskNoTurn.Close()
	mustOK(t, deskNoTurn.Publish(ctx, "DeskNoTurn", []string{srcWithTurn.creds.UserID()}))

	deskWithTurn, err := transport.DialPairedDesktopWithRole(ctx, sigURL, srcWithTurn, noopTransportHandler{}, func(string, endpoint.PeerIdentity, string, string, []byte) bool {
		return true
	})
	mustOK(t, err)
	defer deskWithTurn.Close()
	mustOK(t, deskWithTurn.Publish(ctx, "DeskWithTurn", []string{srcNoTurn.creds.UserID()}))

	// Case 1: Unentitled desktop connects to entitled desktop -> caller must NOT unlock TURN.
	p1, err := deskNoTurn.ConnectPairedWithOptions(ctx, srcWithTurn.creds.DeviceID(), srcWithTurn.creds.UserID(), transport.ConnectOptions{
		Pin:     srcWithTurn.creds.PublicKey(),
		Role:    transport.RoleDesktop,
		Name:    "DeskNoTurn",
		Handler: noopTransportHandler{},
	})
	mustOK(t, err)
	defer p1.Close()

	iceRec.mu.Lock()
	gotNoTurn := iceRec.visitors[srcNoTurn.creds.UserID()]
	iceRec.mu.Unlock()
	if gotNoTurn {
		t.Fatal("host's TURN entitlement leaked to unentitled desktop caller")
	}

	// Case 2: Entitled desktop connects to unentitled desktop -> caller DOES get TURN.
	p2, err := deskWithTurn.ConnectPairedWithOptions(ctx, srcNoTurn.creds.DeviceID(), srcNoTurn.creds.UserID(), transport.ConnectOptions{
		Pin:     srcNoTurn.creds.PublicKey(),
		Role:    transport.RoleDesktop,
		Name:    "DeskWithTurn",
		Handler: noopTransportHandler{},
	})
	mustOK(t, err)
	defer p2.Close()

	iceRec.mu.Lock()
	gotWithTurn := iceRec.visitors[srcWithTurn.creds.UserID()]
	iceRec.mu.Unlock()
	if !gotWithTurn {
		t.Fatal("entitled desktop caller did not receive TURN credentials")
	}
}

func TestSecurityDesktopPairedReadCannotUpgradeViaControlInvite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Verify on selfrelay that an already-paired Read desktop presenting a Control
	// invite stays Read and does NOT consume the Control invite.
	relayToken := strings.Repeat("self-noupgrade-", 4)
	hub := signal.NewSelfHosted(relayToken, &recordingICE{})
	go hub.Run(ctx)
	srv := httptest.NewServer(hub)
	defer srv.Close()
	sigURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	hostHandler := newLANRecordingHandler()
	host, err := selfrelay.OpenServer(&lanMemStore{}, hostHandler)
	mustOK(t, err)
	onlineCh := make(chan bool, 2)
	host.SetObserver(func(on bool, _ string) {
		if on {
			select {
			case onlineCh <- true:
			default:
			}
		}
	})
	mustOK(t, host.Connect(ctx, sigURL, relayToken, "HostPC"))
	defer host.Stop()
	<-onlineCh

	// Pair a Read-only desktop peer.
	_, readLink, err := host.Invite(selfrelay.Read, true)
	mustOK(t, err)
	readTarget, err := selfrelay.ParseTarget(readLink)
	mustOK(t, err)
	callerDesk, err := selfrelay.OpenServer(&lanMemStore{}, noopTransportHandler{})
	mustOK(t, err)

	p1, start1, err := selfrelay.DialWithRole(ctx, readTarget, callerDesk.Seed(), "ReaderPC", "desktop", noopTransportHandler{})
	mustOK(t, err)
	start1()
	hPeer1 := <-hostHandler.opened
	if got := selfrelay.Access(hPeer1.UserID()); got != selfrelay.Read {
		t.Fatalf("initial access = %q, want %q", got, selfrelay.Read)
	}
	p1.Close()
	<-hostHandler.closed

	// Create a Control invite and dial with the already-paired Read desktop key.
	ctrlInv, ctrlLink, err := host.Invite(selfrelay.Control, true)
	mustOK(t, err)
	ctrlTarget, err := selfrelay.ParseTarget(ctrlLink)
	mustOK(t, err)

	p2, start2, err := selfrelay.DialWithRole(ctx, ctrlTarget, callerDesk.Seed(), "ReaderPC", "desktop", noopTransportHandler{})
	mustOK(t, err)
	start2()
	defer p2.Close()

	hPeer2 := <-hostHandler.opened
	if got := selfrelay.Access(hPeer2.UserID()); got != selfrelay.Read {
		t.Fatalf("already-paired read desktop escalated to %q via control invite", got)
	}

	foundCtrl := false
	for _, inv := range host.Status().Invitations {
		if inv.ID == ctrlInv.ID {
			foundCtrl = true
		}
	}
	if !foundCtrl {
		t.Fatal("selfrelay control invitation was consumed by already-paired read desktop")
	}

	// Verify another unpaired desktop can still use that unconsumed control invite.
	otherDesk, err := selfrelay.OpenServer(&lanMemStore{}, noopTransportHandler{})
	mustOK(t, err)
	p3, start3, err := selfrelay.DialWithRole(ctx, ctrlTarget, otherDesk.Seed(), "ControllerPC", "desktop", noopTransportHandler{})
	mustOK(t, err)
	start3()
	defer p3.Close()
	hPeer3 := <-hostHandler.opened
	if got := selfrelay.Access(hPeer3.UserID()); got != selfrelay.Control {
		t.Fatalf("fresh desktop access = %q, want %q", got, selfrelay.Control)
	}
}

func TestSecurityDesktopScopedSocketCannotPublishOnline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	auth := identitytest.NewAuthority(10 * time.Minute)
	srcA := makeStaticSource(t, auth, "https://cn-auth.example.com/realms/vanora", "owner-a")
	srcB := makeStaticSource(t, auth, "https://cn-auth.example.com/realms/vanora", "owner-a")

	hub := signal.New(auth.PublicKey(), nil, &recordingICE{})
	go hub.Run(ctx)
	srv := httptest.NewServer(hub)
	defer srv.Close()
	sigURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	hostA, err := transport.DialPairedDesktopWithRole(ctx, sigURL, srcA, noopTransportHandler{}, func(string, endpoint.PeerIdentity, string, string, []byte) bool {
		return true
	})
	mustOK(t, err)
	defer hostA.Close()
	mustOK(t, hostA.Publish(ctx, "HostA", nil))

	// Connect raw WebSocket for B with role="desktop" and desktop=A.DeviceID (scoped outbound socket).
	ws, _, err := websocket.Dial(ctx, sigURL, nil)
	mustOK(t, err)
	defer ws.CloseNow()
	_, rawCh, err := ws.Read(ctx)
	mustOK(t, err)
	var ch protocol.Message
	mustOK(t, json.Unmarshal(rawCh, &ch))
	login, err := srcB.creds.LoginFor(ch, "desktop", srcB.proof.Lease, srcA.creds.DeviceID())
	mustOK(t, err)
	mustOK(t, ws.Write(ctx, websocket.MessageText, protocol.Encode(login)))
	_, rawOK, err := ws.Read(ctx)
	mustOK(t, err)
	var okMsg protocol.Message
	mustOK(t, json.Unmarshal(rawOK, &okMsg))
	if okMsg.Type != "auth.ok" {
		t.Fatalf("expected auth.ok, got %s", rawOK)
	}

	// Attempt to send device.online on the target-scoped socket -> must be rejected!
	onlineMsg, err := srcB.creds.Online("SpoofHost", nil)
	mustOK(t, err)
	mustOK(t, ws.Write(ctx, websocket.MessageText, protocol.Encode(onlineMsg)))
	_, rawReply, err := ws.Read(ctx)
	mustOK(t, err)
	var reply protocol.Message
	mustOK(t, json.Unmarshal(rawReply, &reply))
	if reply.Type != "error" || !strings.Contains(string(reply.Data), "invalid_device") {
		t.Fatalf("scoped desktop socket was allowed to publish device.online: %s", rawReply)
	}
}
