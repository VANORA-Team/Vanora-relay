package mobile

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vanora-relay/adapter/desktop"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/internal/ice"
	signalserver "vanora-relay/internal/signal"
)

func TestWakeupPreservesHealthySocketAndReplacesSilentSocket(t *testing.T) {
	t.Setenv("VANORA_MOBILE_FAKE_CLI", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	dir := t.TempDir()
	exe, err := os.Executable()
	must(t, err)
	service, err := desktop.New(&desktop.Config{
		Executable: exe,
		Workspaces: []desktop.WorkspaceConfig{{
			ID: "shared", WorkingDir: dir, SessionDir: filepath.Join(dir, "sessions"),
			Owner: "local", LANAccess: true, Tools: []string{"read"}, ApprovalPolicy: "remote",
		}},
	}, filepath.Join(dir, "state"))
	must(t, err)
	defer service.Close()

	server, err := lan.OpenServer(&lanTestStore{}, service)
	must(t, err)
	defer server.Stop()
	service.SetLANAuthority(server.Allows)
	must(t, server.Listen(ctx, "127.0.0.1:0"))

	// Place a controllable TCP proxy in front of the LAN server so we can blackhole
	// the active WebSocket while keeping fresh probe connections working.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer proxyLn.Close()

	var mu sync.Mutex
	blackholeFirst := false
	connIndex := 0
	go func() {
		for {
			cli, err := proxyLn.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			idx := connIndex
			connIndex++
			mu.Unlock()
			upstream, err := net.Dial("tcp", server.Address())
			if err != nil {
				_ = cli.Close()
				continue
			}
			go func(first bool) {
				buf := make([]byte, 8192)
				for {
					n, err := cli.Read(buf)
					if err != nil {
						_ = upstream.Close()
						return
					}
					mu.Lock()
					drop := first && blackholeFirst
					mu.Unlock()
					if drop {
						continue
					}
					if _, err := upstream.Write(buf[:n]); err != nil {
						return
					}
				}
			}(idx == 0)
			go func(first bool) {
				buf := make([]byte, 8192)
				for {
					n, err := upstream.Read(buf)
					if err != nil {
						_ = cli.Close()
						return
					}
					mu.Lock()
					drop := first && blackholeFirst
					mu.Unlock()
					if drop {
						continue
					}
					if _, err := cli.Write(buf[:n]); err != nil {
						return
					}
				}
			}(idx == 0)
		}
	}()
	_ = io.Discard

	_, inviteLink, err := server.Invite(lan.Control)
	must(t, err)
	proxiedInvite := strings.Replace(inviteLink, server.Address(), proxyLn.Addr().String(), 1)

	client, err := NewLANClient(&lanTestStore{})
	must(t, err)
	defer client.Close()
	must(t, client.ConnectLAN(proxiedInvite, "Phone"))

	var state1 map[string]string
	must(t, json.Unmarshal([]byte(client.ConnectionState()), &state1))
	gen1 := state1["generation"]
	if gen1 != "1" {
		t.Fatalf("initial generation = %q, want 1", gen1)
	}

	// Healthy link: Wakeup probes in-band and preserves the existing socket without reconnecting!
	must(t, client.Wakeup(false))
	var state2 map[string]string
	must(t, json.Unmarshal([]byte(client.ConnectionState()), &state2))
	if state2["generation"] != gen1 {
		t.Fatalf("Wakeup tore down healthy socket: generation %q -> %q", gen1, state2["generation"])
	}

	// Now blackhole the first TCP socket while the proxy still accepts fresh probes.
	mu.Lock()
	blackholeFirst = true
	mu.Unlock()

	start := time.Now()
	must(t, client.Wakeup(false))
	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Fatalf("silent-socket Wakeup took %s, expected fast replacement (<3s)", elapsed)
	}
	var state3 map[string]string
	must(t, json.Unmarshal([]byte(client.ConnectionState()), &state3))
	if state3["generation"] == gen1 || state3["state"] != "connected" {
		t.Fatalf("expected reconnected generation > %q, got %+v", gen1, state3)
	}
}

func TestMultiRouteFailoverAndPollActivityAndGuestRequests(t *testing.T) {
	t.Setenv("VANORA_MOBILE_FAKE_CLI", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Multi-route LAN + Tailnet candidate management on mobile.Client.
	dir := t.TempDir()
	exe, err := os.Executable()
	must(t, err)
	sessionFile := filepath.Join(dir, "guest-sess.jsonl")
	writeJSON(t, sessionFile, map[string]any{
		"type":      "session",
		"version":   3,
		"id":        "guest-sess",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"cwd":       dir,
	})

	service, err := desktop.New(&desktop.Config{
		Executable:      exe,
		PublishActivity: true,
		Sessions: []desktop.SessionConfig{{
			ID:                 "shared-read",
			Title:              "Shared Read",
			WorkingDir:         dir,
			SessionFile:        sessionFile,
			Owner:              "local",
			LANAccess:          true,
			SelfAccess:         true,
			Tools:              []string{"bash"},
			ApprovalPolicy:     "remote",
			AllowGuestRequests: true,
		}},
	}, filepath.Join(dir, "state"))
	must(t, err)
	defer service.Close()

	lanServer, err := lan.OpenServer(&lanTestStore{}, service)
	must(t, err)
	defer lanServer.Stop()
	service.SetLANAuthority(lanServer.Allows)
	must(t, lanServer.Listen(ctx, "127.0.0.1:0"))

	_, readInvite, err := lanServer.Invite(lan.Read)
	must(t, err)
	reader, err := NewLANClient(&lanTestStore{})
	must(t, err)
	defer reader.Close()
	must(t, reader.ConnectLAN(readInvite, "Guest Phone"))

	// Add a Tailnet route and verify ordering (loopback < tailnet).
	must(t, reader.AddRoute("100.100.10.20:9443"))
	var routeList []struct {
		Address string `json:"address"`
		Kind    string `json:"kind"`
	}
	must(t, json.Unmarshal([]byte(reader.Routes()), &routeList))
	if len(routeList) != 2 || routeList[0].Kind != "loopback" || routeList[1].Kind != "tailnet" {
		t.Fatalf("unexpected routes: %+v", routeList)
	}
	must(t, reader.RemoveRoute("100.100.10.20:9443"))

	// 2. Self-hosted relay PollActivity + GuestRequest end-to-end.
	t.Setenv("STUN_URLS", "local")
	t.Setenv("TURN_PUBLIC_IP", "127.0.0.1")
	t.Setenv("TURN_BIND_IP", "127.0.0.1")
	t.Setenv("TURN_TCP", "false")
	t.Setenv("TURN_PORT", "0")
	t.Setenv("TURN_RELAY_MIN_PORT", "0")
	t.Setenv("TURN_RELAY_MAX_PORT", "0")
	turnNet, err := ice.FromEnv()
	must(t, err)
	defer turnNet.Close()

	relayToken := strings.Repeat("R", 40)
	hub := signalserver.NewSelfHosted(relayToken, turnNet)
	go hub.Run(ctx)
	relaySrv := httptest.NewServer(hub)
	defer relaySrv.Close()
	wsRelayURL := "ws" + strings.TrimPrefix(relaySrv.URL, "http") + "/v1/signal"

	selfHost, err := selfrelay.OpenServer(&lanTestStore{}, service)
	must(t, err)
	defer selfHost.Stop()
	service.SetSelfAuthority(selfHost.Allows)

	pub := desktop.NewActivityPublisher(ctx, func() (string, string, string) {
		st := selfHost.Status()
		if !st.Online {
			return "", "", ""
		}
		return wsRelayURL, st.DeviceID, selfHost.PairingTicket()
	})
	defer pub.Close()
	service.SetActivitySink(pub.Enqueue)

	must(t, selfHost.Connect(ctx, wsRelayURL, relayToken, "Workstation"))
	deadline := time.Now().Add(5 * time.Second)
	for !selfHost.Status().Online {
		if time.Now().After(deadline) {
			t.Fatal("selfHost did not come online")
		}
		time.Sleep(20 * time.Millisecond)
	}

	_, display, err := selfHost.InvitePairing(ctx, selfrelay.Read, true)
	must(t, err)

	selfPhone, err := NewSelfRelayClient(&lanTestStore{})
	must(t, err)
	defer selfPhone.Close()
	must(t, selfPhone.Pair(display.Link, "", "", "Self Guest Phone"))

	// Reader submits guest.request -> desktop publishes awaiting_guest_approval to relay -> PollActivity sees it!
	guestRaw, err := selfPhone.SubmitGuestRequest("shared-read", NewRequestID(), "Check deployment status")
	must(t, err)
	var guestSubmitted struct {
		GuestRequestID string `json:"guest_request_id"`
		Status         string `json:"status"`
	}
	must(t, json.Unmarshal([]byte(guestRaw), &guestSubmitted))
	if guestSubmitted.Status != "pending" || guestSubmitted.GuestRequestID == "" {
		t.Fatalf("unexpected guest request reply: %s", guestRaw)
	}

	deadline = time.Now().Add(5 * time.Second)
	for {
		polledRaw, err := selfPhone.PollActivity()
		must(t, err)
		if strings.Contains(polledRaw, `"phase":"awaiting_guest_approval"`) {
			if strings.Contains(polledRaw, "Check deployment status") {
				t.Fatalf("PollActivity leaked guest prompt text: %s", polledRaw)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("PollActivity did not observe awaiting_guest_approval; last=%s", polledRaw)
		}
		time.Sleep(30 * time.Millisecond)
	}

	// Dismiss locally on host and verify PollActivity clears it.
	_, err = service.RespondGuestLocal("shared-read", guestSubmitted.GuestRequestID, "dismiss")
	must(t, err)
	deadline = time.Now().Add(5 * time.Second)
	for {
		polledRaw, err := selfPhone.PollActivity()
		must(t, err)
		if !strings.Contains(polledRaw, `"awaiting_guest_approval"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("PollActivity did not clear dismissed guest request: %s", polledRaw)
		}
		time.Sleep(30 * time.Millisecond)
	}
}
