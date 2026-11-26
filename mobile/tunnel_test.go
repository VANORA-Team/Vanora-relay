package mobile

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/cftunnel"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/routes"
	"vanora-relay/internal/testtunnel"
)

func assertTunnelPath(t *testing.T, client *Client, signalURL string) {
	t.Helper()
	if state := client.ConnectionState(); !strings.Contains(state, `"path":"cf_tunnel"`) {
		t.Fatalf("expected managed tunnel, got %s", state)
	}
	var list []routes.Entry
	must(t, json.Unmarshal([]byte(client.Routes()), &list))
	want := []routes.Entry{{Address: signalURL, Kind: routes.KindRelay}, {Address: signalURL, Kind: routes.KindCFTunnel}}
	if !slices.Equal(list, want) {
		t.Fatalf("unexpected routes: %+v", list)
	}
}

func acknowledgeFixtureEvent(t *testing.T, client *Client, session string, seq int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := client.NextEvent(100)
		must(t, err)
		var event struct {
			Session string `json:"session_id"`
			Seq     int64  `json:"seq"`
		}
		if json.Unmarshal([]byte(raw), &event) == nil && event.Session == session && event.Seq == seq {
			must(t, client.Acknowledge(session, seq))
			return
		}
	}
	t.Fatalf("did not receive session event %d", seq)
}

func TestSelfManagedTunnelFallbackAndCursor(t *testing.T) {
	rig := testtunnel.New(t, "self")
	desktop := testtunnel.NewDesktop()
	host, err := selfrelay.OpenServer(&testtunnel.Store{}, desktop)
	must(t, err)
	rig.StartSelfHost(t, host)
	client, err := NewSelfRelayClient(&testtunnel.Store{})
	must(t, err)
	t.Cleanup(client.Close)
	client.tunnel = tunnelDialOptions{url: rig.EdgeURL, headStart: 25 * time.Millisecond}

	_, invite, err := host.Invite(selfrelay.Control, true)
	must(t, err)
	rig.FailICE.Store(true)
	var closed *transport.ClosedError
	if err := client.Pair(invite, "", "", "Test mobile"); !errors.As(err, &closed) || closed.Reason != "ice_unavailable" {
		t.Fatalf("first-time pairing did not return WebRTC failure: %v", err)
	}
	if rig.Offers.Load() != 0 {
		t.Fatal("a first-time invitation attempted a tunnel")
	}

	rig.FailICE.Store(false)
	_, invite, err = host.Invite(selfrelay.Control, true)
	must(t, err)
	must(t, client.Pair(invite, "", "", "Test mobile"))
	if rig.Offers.Load() != 0 || client.SelfRelayTarget() == "" || client.UserID() != "" {
		t.Fatal("account-free WebRTC pairing did not complete cleanly")
	}
	rig.FailICE.Store(true)
	must(t, client.Reconnect())
	assertTunnelPath(t, client, rig.SignalURL)
	workspaces, err := client.ListWorkspaces()
	must(t, err)
	if !strings.Contains(workspaces, "tunnel-workspace") {
		t.Fatalf("workspace RPC failed over tunnel: %s", workspaces)
	}
	desktop.AwaitRequest(t, "workspace.list", "cf_tunnel")
	const session = "self-fixture-session"
	_, err = client.OpenSession(session)
	must(t, err)
	desktop.AwaitRequest(t, "session.open", "cf_tunnel")
	if request := desktop.AwaitRequest(t, "events.resume", "cf_tunnel"); request.After != 0 {
		t.Fatalf("initial cursor = %d", request.After)
	}
	acknowledgeFixtureEvent(t, client, session, 1)

	rig.FailICE.Store(false)
	client.tunnel.headStart = 8 * time.Second
	must(t, client.Reconnect())
	if request := desktop.AwaitRequest(t, "events.resume", "direct"); request.After != 1 {
		t.Fatalf("WebRTC resume cursor = %d", request.After)
	}
	acknowledgeFixtureEvent(t, client, session, 2)

	rig.FailICE.Store(true)
	must(t, client.Reconnect())
	if request := desktop.AwaitRequest(t, "events.resume", "cf_tunnel"); request.After != 2 {
		t.Fatalf("tunnel resume cursor = %d", request.After)
	}
}

func TestOfficialManagedTunnelFreeOwnerWakeupAndRace(t *testing.T) {
	rig := testtunnel.New(t, "cn")
	desktop := testtunnel.NewDesktop()
	client, err := NewChannelClient("cn", rig.Origin, rig.SignalURL, rig.CAHex, &testtunnel.Store{})
	must(t, err)
	t.Cleanup(client.Close)
	client.tunnel = tunnelDialOptions{url: rig.EdgeURL, headStart: 750 * time.Millisecond}
	must(t, client.Enroll("fixture-enrollment"))
	host := rig.NewAccount(t)
	testtunnel.AdmitOfficial(t, rig.SignalURL, host, client.identity, "mobile")
	socket := rig.StartOfficialHost(t, host, desktop,
		func(_ string, principal identity.Principal, role, _ string, _ []byte) bool {
			return principal.DeviceID == client.DeviceID() && (role == "mobile" || role == "")
		})
	must(t, client.identity.BindPeer(socket.DeviceID(), account.PeerBinding{
		Owner: socket.UserID(), Pin: base64.RawURLEncoding.EncodeToString(socket.PublicKey()),
	}))

	wrongSite := pairing.NewOfficial("global", rig.SignalURL, socket.DeviceID(), socket.UserID(), socket.PublicKey())
	if err := client.Pair(wrongSite.Link(), "", "", "Test mobile"); !errors.Is(err, pairing.ErrInvalid) {
		t.Fatalf("cross-site invite returned %v", err)
	}
	rig.FailICE.Store(true)
	invite := pairing.NewOfficial("cn", rig.SignalURL, socket.DeviceID(), socket.UserID(), socket.PublicKey())
	var closed *transport.ClosedError
	if err := client.Pair(invite.Link(), "", "", "Test mobile"); !errors.As(err, &closed) || closed.Reason != "ice_unavailable" {
		t.Fatalf("first-time official pairing returned %v", err)
	}
	if rig.Offers.Load() != 0 {
		t.Fatal("an official invite attempted a tunnel")
	}
	must(t, client.Connect(socket.DeviceID(), socket.UserID()))
	assertTunnelPath(t, client, rig.SignalURL)
	if !rig.TURNSuppressed.Load() {
		t.Fatal("free account was granted TURN credentials")
	}
	generation := client.generation.Load()
	must(t, client.Wakeup(true))
	desktop.AwaitRequest(t, "ping", "cf_tunnel")
	if client.generation.Load() != generation || rig.EdgeConnections.Load() != 1 {
		t.Fatal("wakeup replaced a healthy tunnel")
	}

	rig.BlackholeLatestEdge()
	client.routeTracker.RecordTunnelUnavailable(rig.SignalURL, time.Now())
	started := time.Now()
	must(t, client.Wakeup(false))
	assertTunnelPath(t, client, rig.SignalURL)
	if client.generation.Load() != generation+1 || time.Since(started) > remoteProbeTimeout || rig.EdgeConnections.Load() != 2 {
		t.Fatal("wakeup did not promptly replace a silent tunnel")
	}

	rig.FailICE.Store(false)
	rig.StallRTC.Store(true)
	must(t, client.Reconnect())
	assertTunnelPath(t, client, rig.SignalURL)
	testtunnel.Wait(t, func() bool { return rig.ClosedStalled.Load() == 1 })
	if rig.StalledOffers.Load() != 1 || rig.EdgeConnections.Load() != 3 || client.generation.Load() != generation+2 {
		t.Fatal("the head-start race failed to select a single tunnel and close stalled WebRTC signaling")
	}
}

type tunnelRoundTripper func(*http.Request) (*http.Response, error)

func (rt tunnelRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return rt(r) }

func TestDisabledManagedTunnelPreservesWebRTCAndAuthErrors(t *testing.T) {
	rig := testtunnel.New(t, "self")
	host, err := selfrelay.OpenServer(&testtunnel.Store{}, testtunnel.NewDesktop())
	must(t, err)
	rig.StartSelfHost(t, host)
	client, err := NewSelfRelayClient(&testtunnel.Store{})
	must(t, err)
	t.Cleanup(client.Close)
	if err := client.SetChannel("cn"); err == nil {
		t.Fatal("self-hosted client accepted an official channel")
	}
	var attempts atomic.Int32
	client.tunnel = tunnelDialOptions{
		url: rig.EdgeURL, httpClient: &http.Client{Transport: tunnelRoundTripper(func(request *http.Request) (*http.Response, error) {
			attempts.Add(1)
			return http.DefaultTransport.RoundTrip(request)
		})},
	}
	_, invite, err := host.Invite(selfrelay.Control, true)
	must(t, err)
	must(t, client.Pair(invite, "", "", "Test mobile"))
	rig.DisableTunnels()
	must(t, client.Reconnect())
	if !strings.Contains(client.ConnectionState(), `"path":"direct"`) {
		t.Fatal("disabled tunnels broke WebRTC")
	}
	rig.FailICE.Store(true)
	for range 2 {
		var closed *transport.ClosedError
		if err := client.Reconnect(); !errors.As(err, &closed) || closed.Reason != "ice_unavailable" {
			t.Fatalf("expected primary WebRTC error, got %v", err)
		}
	}
	if attempts.Load() != 1 || client.handleAuthError(cftunnel.ErrTunnelUnavailable) {
		t.Fatal("disabled tunnel was retried or classified as an authentication error")
	}
	client.routeTracker.Reset()
	target, err := selfrelay.ParseTarget(client.SelfRelayTarget())
	must(t, err)
	target.Token = strings.Repeat("different-fixture-token-", 3)
	if err := client.ConnectSelfRelay(target.Link(), "Test mobile"); !errors.Is(err, selfrelay.ErrUnauthorized) {
		t.Fatalf("wrong relay token returned %v", err)
	}
	if attempts.Load() != 1 {
		t.Fatal("definitive WebRTC authorization failure attempted a tunnel")
	}
}
