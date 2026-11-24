package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
	"vanora-relay/adapter/account"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/remote"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/signal"
	"vanora-relay/mobile"
	"vanora-relay/protocol"
)

// fakeDesktopService simulates a real desktop.Adapter over a DataChannel:
// it supports workspace.list, session.create, session.list, session.open,
// events.resume, run.start (emitting text.delta, ui.request, and run.completed),
// ui.respond, and run.cancel, while enforcing read vs control access for LAN/self.
type fakeDesktopService struct {
	name string

	mu          sync.Mutex
	seq         int64
	subscribers map[transport.Peer]map[string]bool
	pendingUI   map[string]chan bool
}

func newFakeDesktopService(name string) *fakeDesktopService {
	return &fakeDesktopService{
		name:        name,
		subscribers: make(map[transport.Peer]map[string]bool),
		pendingUI:   make(map[string]chan bool),
	}
}

func (f *fakeDesktopService) Open(transport.Peer) {}
func (f *fakeDesktopService) Closed(p transport.Peer) {
	f.mu.Lock()
	delete(f.subscribers, p)
	f.mu.Unlock()
}

func (f *fakeDesktopService) canRun(userID string) bool {
	if a := lan.Access(userID); a != "" {
		return a == lan.Control
	}
	if a := selfrelay.Access(userID); a != "" {
		return a == selfrelay.Control
	}
	return true
}

func (f *fakeDesktopService) Message(p transport.Peer, raw []byte) {
	var req struct {
		Type        string `json:"type"`
		RequestID   string `json:"request_id"`
		SessionID   string `json:"session_id"`
		WorkspaceID string `json:"workspace_id"`
		Title       string `json:"title"`
		Text        string `json:"text"`
		RunID       string `json:"run_id"`
		UIID        string `json:"ui_id"`
		Confirmed   *bool  `json:"confirmed"`
		AfterSeq    *int64 `json:"after_seq"`
	}
	if json.Unmarshal(raw, &req) != nil {
		return
	}
	sendResult := func(data any) {
		_ = p.Send(protocol.Encode(map[string]any{
			"type":       "result",
			"request_id": req.RequestID,
			"data":       data,
		}), false)
	}
	sendErr := func(code string) {
		_ = p.Send(protocol.Encode(map[string]any{
			"type":       "error",
			"request_id": req.RequestID,
			"code":       code,
		}), false)
	}
	switch req.Type {
	case "workspace.list":
		if !f.canRun(p.UserID()) {
			sendResult(map[string]any{"workspaces": []any{}})
			return
		}
		sendResult(map[string]any{
			"workspaces": []map[string]any{
				{"workspace_id": "ws-" + f.name, "title": "Workspace " + f.name, "tools_enabled": true},
			},
		})
	case "session.create":
		if !f.canRun(p.UserID()) {
			sendErr("unavailable")
			return
		}
		sendResult(map[string]any{
			"session_id":    "created-" + f.name,
			"workspace_id":  req.WorkspaceID,
			"title":         req.Title,
			"can_run_tools": true,
			"tools_enabled": true,
		})
	case "session.list":
		sendResult(map[string]any{
			"sessions": []map[string]any{
				{
					"session_id":      "sess-" + f.name,
					"title":           "Session " + f.name,
					"can_run_tools":   f.canRun(p.UserID()),
					"tools_enabled":   f.canRun(p.UserID()),
					"approval_policy": "remote",
				},
			},
		})
	case "session.open":
		f.mu.Lock()
		last := f.seq
		if f.subscribers[p] == nil {
			f.subscribers[p] = make(map[string]bool)
		}
		f.subscribers[p][req.SessionID] = true
		f.mu.Unlock()
		sendResult(map[string]any{
			"messages": []any{},
			"last_seq": last,
		})
	case "events.resume":
		f.mu.Lock()
		if f.subscribers[p] == nil {
			f.subscribers[p] = make(map[string]bool)
		}
		f.subscribers[p][req.SessionID] = true
		f.mu.Unlock()
		after := int64(0)
		if req.AfterSeq != nil {
			after = *req.AfterSeq
		}
		sendResult(map[string]any{"session_id": req.SessionID, "after_seq": after})
	case "run.start":
		if !f.canRun(p.UserID()) {
			sendErr("tool_denied")
			return
		}
		runID := "run-" + f.name + "-" + req.RequestID[:6]
		uiID := "ui-" + runID
		uiCh := make(chan bool, 1)
		f.mu.Lock()
		f.pendingUI[uiID] = uiCh
		f.mu.Unlock()
		sendResult(map[string]any{"run_id": runID})
		go func() {
			emit := func(kind string, data any) {
				f.mu.Lock()
				f.seq++
				seq := f.seq
				f.mu.Unlock()
				_ = p.Send(protocol.Encode(map[string]any{
					"type":       "event",
					"session_id": req.SessionID,
					"run_id":     runID,
					"seq":        seq,
					"kind":       kind,
					"data":       data,
				}), false)
			}
			emit("text.delta", map[string]string{"text": f.name + ":" + req.Text})
			if strings.Contains(req.Text, "[approve]") {
				emit("ui.request", map[string]any{
					"ui_id":  uiID,
					"method": "confirm",
					"title":  "Approve on " + f.name,
				})
				select {
				case ok := <-uiCh:
					status := "responded"
					if !ok {
						status = "cancelled"
					}
					emit("ui.resolved", map[string]string{"ui_id": uiID, "status": status})
				case <-time.After(5 * time.Second):
					emit("ui.resolved", map[string]string{"ui_id": uiID, "status": "timeout"})
				}
			}
			emit("run.completed", map[string]string{"status": "completed"})
		}()
	case "ui.respond":
		if !f.canRun(p.UserID()) {
			sendErr("unavailable")
			return
		}
		f.mu.Lock()
		ch := f.pendingUI[req.UIID]
		delete(f.pendingUI, req.UIID)
		f.mu.Unlock()
		if ch == nil {
			sendErr("unavailable")
			return
		}
		confirmed := req.Confirmed != nil && *req.Confirmed
		ch <- confirmed
		sendResult(map[string]string{"ui_id": req.UIID, "status": "responded"})
	case "run.cancel":
		sendResult(map[string]string{"run_id": req.RunID, "status": "cancelling"})
	default:
		sendErr("invalid_request")
	}
}

type desktopNode struct {
	name      string
	channel   string
	manager   *accessManager
	events    chan map[string]any
	invite    func(access string) pairing.Display
	selfID    func() string
	closeNode func()
}

func newPCNode(t *testing.T, ctx context.Context, channel, name, service, selfToken, issuerURL, caHex, authToken string, vault *memVault) *desktopNode {
	t.Helper()
	evCh := make(chan map[string]any, 256)
	svc := newFakeDesktopService(name)
	var outBuf syncBuffer
	emitter := &jsonEmitter{out: &chanWriter{ch: evCh, buf: &outBuf}}

	am := &accessManager{
		ctx:           ctx,
		name:          name,
		emitter:       emitter,
		slots:         make(map[string]*officialSlot),
		activeChannel: channel,
	}
	if channel == "lan" {
		am.activeChannel = ""
	}
	am.initRemote()

	var inviteFn func(string) pairing.Display
	var selfIDFn func() string
	var closeFn func()

	switch channel {
	case "lan":
		srv := requireNetwork(lan.OpenServer(vault, svc))
		srv.SetNetworkObserver(func() { am.onNetworkChanged("lan") })
		if err := srv.Listen(ctx, "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		am.local = srv
		inviteFn = func(access string) pairing.Display {
			if access == "" {
				access = lan.Control
			}
			_, disp, err := srv.InvitePairing(access)
			return requireNetwork(disp, err)
		}
		selfIDFn = srv.Pin
		closeFn = func() {
			am.close()
		}
	case "self":
		srv := requireNetwork(selfrelay.OpenServer(vault, svc))
		srv.SetNetworkObserver(func() { am.onNetworkChanged("self") })
		if err := srv.Connect(ctx, service, selfToken, name); err != nil {
			t.Fatal(err)
		}
		awaitNetwork(t, func() bool { return srv.Status().Online })
		am.selfServer = srv
		am.selfURL = service
		am.selfToken = selfToken
		inviteFn = func(access string) pairing.Display {
			if access == "" {
				access = selfrelay.Control
			}
			_, disp, err := srv.InvitePairing(ctx, access, true)
			return requireNetwork(disp, err)
		}
		selfIDFn = srv.Pin
		closeFn = func() {
			am.close()
		}
	case "cn", "global":
		acc := requireNetwork(account.New(issuerURL, caHex, vault))
		if acc.UserID() == "" {
			if err := acc.Enroll(ctx, authToken); err != nil {
				t.Fatal(err)
			}
		}
		slot := &officialSlot{name: channel, desktopName: name, url: service, account: acc}
		socket := requireNetwork(transport.DialPairedDesktopWithRole(ctx, service, acc, svc, slot.authorize))
		socket.SetNetworkChangedHook(func() { am.onNetworkChanged(channel) })
		if err := socket.Publish(ctx, name, nil); err != nil {
			t.Fatal(err)
		}
		slot.socket.Store(socket)
		slot.online.Store(true)
		am.slots[channel] = slot
		am.activeSlot = slot
		inviteFn = func(string) pairing.Display {
			_, disp, err := slot.invite(ctx)
			return requireNetwork(disp, err)
		}
		selfIDFn = acc.DeviceID
		closeFn = func() {
			socket.Close()
			am.close()
		}
	}
	t.Cleanup(closeFn)
	return &desktopNode{
		name:      name,
		channel:   channel,
		manager:   am,
		events:    evCh,
		invite:    inviteFn,
		selfID:    selfIDFn,
		closeNode: closeFn,
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

type chanWriter struct {
	ch  chan map[string]any
	buf *syncBuffer
}

func (w *chanWriter) Write(p []byte) (int, error) {
	w.buf.mu.Lock()
	w.buf.buf.Write(p)
	for {
		line, err := w.buf.buf.ReadBytes('\n')
		if err != nil {
			w.buf.buf.Write(line)
			break
		}
		var ev map[string]any
		if json.Unmarshal(bytes.TrimSpace(line), &ev) == nil {
			select {
			case w.ch <- ev:
			default:
			}
		}
	}
	w.buf.mu.Unlock()
	return len(p), nil
}

func waitEvent(t *testing.T, ch <-chan map[string]any, match func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev := <-ch:
			if match(ev) {
				return ev
			}
		case <-deadline:
			t.Fatal("timed out waiting for expected sidecar event")
		}
	}
}

func TestDesktopToDesktopMutualControlAllChannels(t *testing.T) {
	for _, channel := range []string{"lan", "self", "cn", "global"} {
		t.Run(channel, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()

			var service, issuerURL, caHex string
			selfToken := strings.Repeat("pc2pc-self-", 4)
			const authToken = "owner-token"

			switch channel {
			case "self":
				hub := signal.NewSelfHosted(selfToken, directICE{})
				go hub.Run(ctx)
				srv := httptest.NewServer(hub)
				t.Cleanup(srv.Close)
				service = "ws" + strings.TrimPrefix(srv.URL, "http")
			case "cn", "global":
				issuer, auth := newTestTokenAuthority(t, map[string]string{authToken: "owner-user"})
				issuerURL = issuer.URL
				caHex = hex.EncodeToString(auth.PublicKey())
				hub := signal.New(auth.PublicKey(), nil, directICE{})
				go hub.Run(ctx)
				srv := httptest.NewServer(hub)
				t.Cleanup(srv.Close)
				service = "ws" + strings.TrimPrefix(srv.URL, "http")
			}

			vaultA, vaultB := &memVault{}, &memVault{}
			alpha := newPCNode(t, ctx, channel, "Alpha", service, selfToken, issuerURL, caHex, authToken, vaultA)
			beta := newPCNode(t, ctx, channel, "Beta", service, selfToken, issuerURL, caHex, authToken, vaultB)

			// 1. Beta pairs with Alpha using Alpha's 16-char pairing code.
			// On self/lan, Beta intentionally omits grant_access first so Alpha's
			// reverse access on Beta starts fail-safe as read-only.
			invA := alpha.invite("control")
			pairOpts := remote.PairOptions{
				Channel: channel,
				Input:   invA.Code,
			}
			if channel == "self" {
				pairOpts.SignalURL = service
			}
			pairedInfo, err := beta.manager.remoteManager().Pair(ctx, pairOpts)
			if err != nil {
				t.Fatalf("Beta pair Alpha: %v", err)
			}
			if pairedInfo.PeerID != alpha.selfID() || pairedInfo.State != "connected" {
				t.Fatalf("unexpected paired info: %+v", pairedInfo)
			}

			// Wait until pairnet converges on both sides so Alpha knows Beta.
			awaitNetwork(t, func() bool {
				peers, err := alpha.manager.remoteManager().ListPeers(ctx, channel)
				return err == nil && len(peers) == 1 && peers[0].PeerID == beta.selfID()
			})

			// 2. Alpha connects back to Beta WITHOUT any second invitation.
			backInfo, err := alpha.manager.remoteManager().Connect(ctx, channel, beta.selfID())
			if err != nil {
				t.Fatalf("Alpha reverse-connect Beta: %v", err)
			}
			if backInfo.PeerID != beta.selfID() || backInfo.State != "connected" {
				t.Fatalf("unexpected reverse connect info: %+v", backInfo)
			}

			// 3. On self/lan, verify fail-safe read-only default on reverse link,
			// then dynamically promote Alpha to control via access.client.access.set.
			if channel == "lan" || channel == "self" {
				if _, err := alpha.manager.remoteManager().ListSessions(ctx, channel, beta.selfID()); err != nil {
					t.Fatalf("Alpha read-only session.list on Beta failed: %v", err)
				}
				if _, err := alpha.manager.remoteManager().StartRun(ctx, channel, beta.selfID(), "sess-Beta", remote.NewRequestID(), "should-fail"); err == nil || err.Error() != "tool_denied" {
					t.Fatalf("expected tool_denied for default read-only reverse peer, got %v", err)
				}
				// Dynamically grant Alpha control on Beta via Sidecar command.
				beta.manager.command(accessCommand{
					Type:      "access.client.access.set",
					RequestID: "grant-alpha",
					Channel:   channel,
					ID:        alpha.selfID(),
					Access:    "control",
				})
				waitEvent(t, beta.events, func(ev map[string]any) bool {
					return ev["type"] == "access.ok" && ev["request_id"] == "grant-alpha"
				})
				// Reconnect Alpha to pick up the elevated UserID permission.
				awaitNetwork(t, func() bool {
					_, err := alpha.manager.remoteManager().Reconnect(ctx, channel, beta.selfID())
					return err == nil
				})
			}

			// 4. Simultaneous bidirectional mutual control (A controls B AND B controls A
			// concurrently, including streaming deltas + remote approval ui.respond).
			runMutual := func(caller, target *desktopNode, prompt string) error {
				rm := caller.manager.remoteManager()
				peerID := target.selfID()
				if _, err := rm.ListWorkspaces(ctx, channel, peerID); err != nil {
					return fmt.Errorf("%s->%s workspace.list: %w", caller.name, target.name, err)
				}
				sessID := "sess-" + target.name
				if _, err := rm.OpenSession(ctx, channel, peerID, sessID); err != nil {
					return fmt.Errorf("%s->%s session.open: %w", caller.name, target.name, err)
				}
				resRaw, err := rm.StartRun(ctx, channel, peerID, sessID, remote.NewRequestID(), prompt)
				if err != nil {
					return fmt.Errorf("%s->%s run.start: %w", caller.name, target.name, err)
				}
				var started struct {
					RunID string `json:"run_id"`
				}
				if json.Unmarshal(resRaw, &started) != nil || started.RunID == "" {
					return fmt.Errorf("%s->%s invalid run_id: %s", caller.name, target.name, string(resRaw))
				}

				gotText := false
				gotCompleted := false
				deadline := time.After(10 * time.Second)
				for !gotCompleted {
					select {
					case ev := <-caller.events:
						if ev["type"] != "remote.event" || ev["peer_id"] != peerID || ev["run_id"] != started.RunID {
							continue
						}
						if seq, ok := ev["seq"].(float64); ok && seq > 0 {
							_ = rm.Acknowledge(channel, peerID, sessID, int64(seq))
						}
						switch ev["kind"] {
						case "text.delta":
							gotText = true
						case "ui.request":
							rawData, _ := json.Marshal(ev["data"])
							var uiReq struct {
								UIID string `json:"ui_id"`
							}
							_ = json.Unmarshal(rawData, &uiReq)
							yes := true
							if _, err := rm.RespondUI(ctx, channel, peerID, sessID, started.RunID, uiReq.UIID, remote.UIResponse{Confirmed: &yes}); err != nil {
								return fmt.Errorf("%s->%s ui.respond: %w", caller.name, target.name, err)
							}
						case "run.completed":
							gotCompleted = true
						}
					case <-deadline:
						return fmt.Errorf("%s->%s timed out waiting for completion", caller.name, target.name)
					}
				}
				if !gotText {
					return fmt.Errorf("%s->%s missing text.delta", caller.name, target.name)
				}
				return nil
			}

			errCh := make(chan error, 2)
			go func() { errCh <- runMutual(alpha, beta, "hello-beta [approve]") }()
			go func() { errCh <- runMutual(beta, alpha, "hello-alpha [approve]") }()
			for range 2 {
				if err := <-errCh; err != nil {
					t.Fatal(err)
				}
			}

			// 5. Bidirectional revocation: Alpha removes Beta from pairnet.
			// Both inbound (Beta->Alpha) and outbound (Alpha->Beta) must sever and
			// prevent reconnection.
			alpha.manager.command(accessCommand{
				Type:      "access.network.remove",
				RequestID: "rm-beta",
				Channel:   channel,
				ID:        beta.selfID(),
			})
			waitEvent(t, alpha.events, func(ev map[string]any) bool {
				return ev["type"] == "access.network" && ev["request_id"] == "rm-beta"
			})
			awaitNetwork(t, func() bool {
				_, errA := alpha.manager.remoteManager().ListSessions(ctx, channel, beta.selfID())
				_, errB := beta.manager.remoteManager().ListSessions(ctx, channel, alpha.selfID())
				return errA != nil && errB != nil
			})
			if _, err := beta.manager.remoteManager().Connect(ctx, channel, alpha.selfID()); err == nil {
				t.Fatal("removed Beta unexpectedly reconnected to Alpha")
			}
			if _, err := alpha.manager.remoteManager().Connect(ctx, channel, beta.selfID()); err == nil {
				t.Fatal("Alpha unexpectedly reconnected to removed Beta")
			}
		})
	}
}

func TestDesktopToDesktopGrantControlOnPairAndTransitiveViaPhone(t *testing.T) {
	for _, channel := range []string{"lan", "self", "cn", "global"} {
		t.Run(channel, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()

			var service, issuerURL, caHex string
			selfToken := strings.Repeat("pc2pc-mesh-", 4)
			const authToken = "mesh-owner"
			var newPhone func() *mobile.Client

			switch channel {
			case "lan":
				newPhone = func() *mobile.Client { return requireNetwork(mobile.NewLANClient(&memVault{})) }
			case "self":
				hub := signal.NewSelfHosted(selfToken, directICE{})
				go hub.Run(ctx)
				srv := httptest.NewServer(hub)
				t.Cleanup(srv.Close)
				service = "ws" + strings.TrimPrefix(srv.URL, "http")
				newPhone = func() *mobile.Client { return requireNetwork(mobile.NewSelfRelayClient(&memVault{})) }
			case "cn", "global":
				issuer, auth := newTestTokenAuthority(t, map[string]string{authToken: "mesh-user"})
				issuerURL = issuer.URL
				caHex = hex.EncodeToString(auth.PublicKey())
				hub := signal.New(auth.PublicKey(), nil, directICE{})
				go hub.Run(ctx)
				srv := httptest.NewServer(hub)
				t.Cleanup(srv.Close)
				service = "ws" + strings.TrimPrefix(srv.URL, "http")
				newPhone = func() *mobile.Client {
					c := requireNetwork(mobile.NewClient(issuerURL, service, caHex, &memVault{}))
					if err := c.Enroll(authToken); err != nil {
						t.Fatal(err)
					}
					return c
				}
			}

			// Part A: Transitive discovery via Phone (Phone pairs with Alpha and Beta;
			// Alpha and Beta never scan each other directly, yet can connect via pairnet).
			alpha := newPCNode(t, ctx, channel, "Alpha", service, selfToken, issuerURL, caHex, authToken, &memVault{})
			beta := newPCNode(t, ctx, channel, "Beta", service, selfToken, issuerURL, caHex, authToken, &memVault{})
			phone := newPhone()
			defer phone.Close()

			if err := phone.Pair(alpha.invite("control").Code, service, "", "Phone"); err != nil {
				t.Fatalf("phone pair Alpha: %v", err)
			}
			if err := phone.Pair(beta.invite("control").Code, service, "", "Phone"); err != nil {
				t.Fatalf("phone pair Beta: %v", err)
			}

			awaitNetwork(t, func() bool {
				peersA, errA := alpha.manager.remoteManager().ListPeers(ctx, channel)
				peersB, errB := beta.manager.remoteManager().ListPeers(ctx, channel)
				return errA == nil && errB == nil && len(peersA) == 1 && peersA[0].PeerID == beta.selfID() &&
					len(peersB) == 1 && peersB[0].PeerID == alpha.selfID()
			})

			if _, err := alpha.manager.remoteManager().Connect(ctx, channel, beta.selfID()); err != nil {
				t.Fatalf("transitive Alpha->Beta connect: %v", err)
			}
			if _, err := alpha.manager.remoteManager().ListSessions(ctx, channel, beta.selfID()); err != nil {
				t.Fatalf("transitive Alpha->Beta session.list: %v", err)
			}

			// Part B: On lan/self, verify one-step grant_access="control" during direct remote.pair
			// grants immediate bidirectional control without a separate access.client.access.set call.
			if channel == "lan" || channel == "self" {
				gamma := newPCNode(t, ctx, channel, "Gamma", service, selfToken, issuerURL, caHex, authToken, &memVault{})
				delta := newPCNode(t, ctx, channel, "Delta", service, selfToken, issuerURL, caHex, authToken, &memVault{})
				_, err := delta.manager.remoteManager().Pair(ctx, remote.PairOptions{
					Channel:     channel,
					Input:       gamma.invite("control").Link,
					SignalURL:   service,
					GrantAccess: "control",
				})
				if err != nil {
					t.Fatalf("Delta pair Gamma with grant_access=control: %v", err)
				}
				awaitNetwork(t, func() bool {
					peers, err := gamma.manager.remoteManager().ListPeers(ctx, channel)
					return err == nil && len(peers) == 1 && peers[0].PeerID == delta.selfID()
				})
				if _, err := gamma.manager.remoteManager().Connect(ctx, channel, delta.selfID()); err != nil {
					t.Fatalf("Gamma connect Delta: %v", err)
				}
				if _, err := gamma.manager.remoteManager().StartRun(ctx, channel, delta.selfID(), "sess-Delta", remote.NewRequestID(), "immediate-control"); err != nil {
					t.Fatalf("Gamma run.start on Delta after grant_access=control failed: %v", err)
				}
			}
		})
	}
}

func TestDesktopSidecarRemoteJSONLCommands(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	alpha := newPCNode(t, ctx, "lan", "Alpha", "", "", "", "", "", &memVault{})
	beta := newPCNode(t, ctx, "lan", "Beta", "", "", "", "", "", &memVault{})

	// Pair Beta -> Alpha via Sidecar remote.pair command.
	go beta.manager.remoteCommand(accessCommand{
		Type:        "remote.pair",
		RequestID:   "req-pair",
		Channel:     "lan",
		Input:       alpha.invite("control").Code,
		GrantAccess: "control",
	})
	pairedEv := waitEvent(t, beta.events, func(ev map[string]any) bool {
		return ev["type"] == "remote.paired" && ev["request_id"] == "req-pair"
	})
	peerObj, _ := pairedEv["peer"].(map[string]any)
	if peerObj["peer_id"] != alpha.selfID() || peerObj["state"] != "connected" {
		t.Fatalf("unexpected remote.paired event: %+v", pairedEv)
	}

	// List peers via Sidecar remote.peers.list.
	go beta.manager.remoteCommand(accessCommand{
		Type:      "remote.peers.list",
		RequestID: "req-peers",
		Channel:   "lan",
	})
	peersEv := waitEvent(t, beta.events, func(ev map[string]any) bool {
		return ev["type"] == "remote.peers" && ev["request_id"] == "req-peers"
	})
	peersList, _ := peersEv["peers"].([]any)
	if len(peersList) != 1 {
		t.Fatalf("expected 1 peer in remote.peers, got %+v", peersEv)
	}

	// Run session.list via Sidecar remote.session.list.
	go beta.manager.remoteCommand(accessCommand{
		Type:      "remote.session.list",
		RequestID: "req-list",
		Channel:   "lan",
		PeerID:    alpha.selfID(),
	})
	listEv := waitEvent(t, beta.events, func(ev map[string]any) bool {
		return ev["type"] == "remote.result" && ev["request_id"] == "req-list"
	})
	if listEv["peer_id"] != alpha.selfID() {
		t.Fatalf("unexpected remote.result: %+v", listEv)
	}

	// Disconnect via Sidecar remote.disconnect.
	go beta.manager.remoteCommand(accessCommand{
		Type:      "remote.disconnect",
		RequestID: "req-disc",
		Channel:   "lan",
		PeerID:    alpha.selfID(),
	})
	waitEvent(t, beta.events, func(ev map[string]any) bool {
		return ev["type"] == "remote.disconnected" && ev["request_id"] == "req-disc"
	})
}

func TestDesktopCtlSubcommand(t *testing.T) {
	keyring.MockInit()
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()

	alpha := newPCNode(t, ctx, "lan", "Alpha", "", "", "", "", "", &memVault{})
	stateDir := t.TempDir()

	if err := runCtl([]string{
		"pair", "-channel", "lan", "-state-dir", stateDir, "-name", "BetaCLI",
		"-input", alpha.invite("control").Code, "-grant-access", "control", "-json",
	}); err != nil {
		t.Fatalf("ctl pair: %v", err)
	}
	if err := runCtl([]string{
		"peers", "-channel", "lan", "-state-dir", stateDir, "-json",
	}); err != nil {
		t.Fatalf("ctl peers: %v", err)
	}
	if err := runCtl([]string{
		"workspaces", "-channel", "lan", "-state-dir", stateDir, "-name", "BetaCLI", "-peer", alpha.selfID(), "-json",
	}); err != nil {
		t.Fatalf("ctl workspaces: %v", err)
	}
	if err := runCtl([]string{
		"sessions", "-channel", "lan", "-state-dir", stateDir, "-name", "BetaCLI", "-peer", alpha.selfID(), "-json",
	}); err != nil {
		t.Fatalf("ctl sessions: %v", err)
	}
	if err := runCtl([]string{
		"run", "-channel", "lan", "-state-dir", stateDir, "-name", "BetaCLI", "-peer", alpha.selfID(),
		"-session", "sess-Alpha", "-text", "hello-from-ctl", "-json",
	}); err != nil {
		t.Fatalf("ctl run: %v", err)
	}

	awaitNetwork(t, func() bool {
		peers, err := alpha.manager.remoteManager().ListPeers(ctx, "lan")
		return err == nil && len(peers) == 1 && peers[0].Name == "BetaCLI"
	})
}
