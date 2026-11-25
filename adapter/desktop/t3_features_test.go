package desktop

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPingRPC(t *testing.T) {
	env := newTestEnv(t, []Grant{{UserID: "viewer", Read: true}}, nil)
	a, p := newTestAdapter(t, env, "viewer")

	reqID := sendRequest(t, a, p, map[string]any{"type": "ping"})
	data := resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == reqID
	}))
	if pong, _ := data["pong"].(bool); !pong {
		t.Fatalf("expected pong=true, got %+v", data)
	}
}

func TestActivityPublisherCoalescingAndRedaction(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Vanora-Desktop") != "dev-1" || r.Header.Get("Authorization") != "Bearer ticket-1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pub := NewActivityPublisher(ctx, func() (string, string, string) {
		return "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/signal", "dev-1", "ticket-1"
	})
	defer pub.Close()

	env := newTestEnv(t, nil, []string{"read"})
	env.cfg.PublishActivity = true
	env.cfg.Sessions[0].ApprovalPolicy = "remote"
	env.extMode = "confirm"
	a, p := newTestAdapter(t, env, "owner")
	a.SetActivitySink(pub.Enqueue)
	subscribeSession(t, a, p)

	startID := sendRequest(t, a, p, map[string]any{
		"type":       "run.start",
		"session_id": "main",
		"text":       "SUPER-SECRET-PROMPT-DO-NOT-LEAK",
	})
	started := resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == startID
	}))
	runID, _ := started["run_id"].(string)

	uiEv := p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == "ui.request"
	})
	uiData, _ := uiEv["data"].(map[string]any)
	uiID, _ := uiData["ui_id"].(string)

	respID := sendRequest(t, a, p, map[string]any{
		"type":       "ui.respond",
		"session_id": "main",
		"run_id":     runID,
		"ui_id":      uiID,
		"confirmed":  true,
	})
	_ = p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == respID
	})
	waitRunStatus(t, a, runID, statusCompleted)

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(bodies)
		lastCompleted := n > 0 && strings.Contains(bodies[n-1], `"phase":"completed"`)
		mu.Unlock()
		if lastCompleted {
			break
		}
		if time.Now().After(deadline) {
			mu.Lock()
			t.Fatalf("timed out waiting for completed activity; got %v", bodies)
			mu.Unlock()
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, b := range bodies {
		if strings.Contains(b, "SUPER-SECRET-PROMPT") || strings.Contains(b, "SECRET-") || strings.Contains(b, "part-0") {
			t.Fatalf("activity payload leaked sensitive content: %s", b)
		}
	}
}

func TestPeerSessionFenceAndModeLimitNarrowing(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	hostSession := filepath.Join(dir, "host.jsonl")
	header, _ := json.Marshal(map[string]any{
		"type":      "session",
		"version":   3,
		"id":        "host-sess",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"cwd":       work,
	})
	if err := os.WriteFile(hostSession, append(header, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Executable: os.Args[0],
		Sessions: []SessionConfig{{
			ID:                "host",
			Title:             "Host Session",
			WorkingDir:        work,
			SessionFile:       hostSession,
			Owner:             "owner",
			Tools:             []string{"read", "bash"},
			FencePeerSessions: true,
			Users: []Grant{
				{UserID: "peer-a", Read: true, Tools: true},
				{UserID: "peer-b", Read: true, Tools: true},
			},
		}},
		Workspaces: []WorkspaceConfig{{
			ID:                "ws",
			Title:             "Fenced Workspace",
			WorkingDir:        work,
			SessionDir:        filepath.Join(dir, "sessions"),
			Owner:             "owner",
			Tools:             []string{"read", "grep"},
			FencePeerSessions: true,
			Users: []Grant{
				{UserID: "peer-a", Read: true, Tools: true},
				{UserID: "peer-b", Read: true, Tools: true},
			},
		}},
	}

	a, err := New(cfg, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	a.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	a.AuthorityUntil(time.Now().Add(time.Hour))

	var cmdMu sync.Mutex
	var lastTools []string
	var lastLinkOriginEnv string
	a.buildCommand = func(s *normalizedSession) (*exec.Cmd, error) {
		defaultCmd, err := a.defaultCommand(s)
		if err != nil {
			return nil, err
		}
		cmdMu.Lock()
		lastTools = slices.Clone(s.tools)
		cmdMu.Unlock()
		_ = defaultCmd
		cmd := exec.Command(os.Args[0], "-test.run=^TestFakeVanora$")
		cmd.Dir = s.workDir
		cmd.Env = append(os.Environ(), "VANORA_FAKE_PROCESS=1", "FAKE_DELAY_MS=120", "FAKE_HANDLED=true")
		return cmd, nil
	}
	t.Cleanup(func() { _ = a.Close() })

	peerA := newFakePeer("peer-a")
	peerB := newFakePeer("peer-b")
	ownerPeer := newFakePeer("owner")
	a.Open(peerA)
	a.Open(peerB)
	a.Open(ownerPeer)
	t.Cleanup(func() {
		a.Closed(peerA)
		a.Closed(peerB)
		a.Closed(ownerPeer)
	})

	// 1. Fenced peer-a cannot run on pre-existing unfenced host session.
	denyHostID := sendRequest(t, a, peerA, map[string]any{
		"type":       "run.start",
		"session_id": "host",
		"text":       "try mutate host",
	})
	denyHost := peerA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["request_id"] == denyHostID
	})
	if denyHost["type"] != "error" || denyHost["code"] != codeToolDenied {
		t.Fatalf("expected fenced peer denial on host session, got %+v", denyHost)
	}

	// 2. peer-a creates a fenced session with mode_limit attempting to request ["read", "bash"]
	// where workspace only allows ["read", "grep"] -> monotonically intersected to ["read"]!
	createID := sendRequest(t, a, peerA, map[string]any{
		"type":         "session.create",
		"workspace_id": "ws",
		"title":        "Agent A Task",
		"link_origin":  "agent-1",
		"mode_limit": map[string]any{
			"tools": []string{"read", "bash"},
		},
	})
	created := resultData(t, peerA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == createID
	}))
	sessID, _ := created["session_id"].(string)
	if gotOrigin, _ := created["link_origin"].(string); gotOrigin != "peer-a/agent-1" {
		t.Fatalf("link_origin = %q, want peer-a/agent-1", gotOrigin)
	}

	// 3. peer-b cannot run in peer-a's fenced session.
	denyCrossID := sendRequest(t, a, peerB, map[string]any{
		"type":        "run.start",
		"session_id":  sessID,
		"link_origin": "agent-1",
		"text":        "hijack peer-a",
	})
	denyCross := peerB.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["request_id"] == denyCrossID
	})
	if denyCross["type"] != "error" || denyCross["code"] != codeToolDenied {
		t.Fatalf("expected cross-peer fence denial, got %+v", denyCross)
	}

	// 4. peer-a with mode_limit read_only=true is denied on run.start.
	denyROID := sendRequest(t, a, peerA, map[string]any{
		"type":        "run.start",
		"session_id":  sessID,
		"link_origin": "agent-1",
		"text":        "blocked by read_only",
		"mode_limit":  map[string]any{"read_only": true},
	})
	denyRO := peerA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["request_id"] == denyROID
	})
	if denyRO["type"] != "error" || denyRO["code"] != codeToolDenied {
		t.Fatalf("expected read_only mode_limit denial, got %+v", denyRO)
	}

	// 5. peer-a runs with matching link_origin; tools are narrowed to ["read"] and VANORA_LINK_ORIGIN is set.
	runReqID := sendRequest(t, a, peerA, map[string]any{
		"type":        "run.start",
		"session_id":  sessID,
		"link_origin": "agent-1",
		"text":        "execute safely",
	})
	runStarted := resultData(t, peerA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == runReqID
	}))
	runID, _ := runStarted["run_id"].(string)

	a.mu.Lock()
	r := a.runs[runID]
	if r != nil && r.handle != nil && r.handle.cmd != nil {
		for _, kv := range r.handle.cmd.Env {
			if after, ok := strings.CutPrefix(kv, "VANORA_LINK_ORIGIN="); ok {
				lastLinkOriginEnv = after
			}
		}
	}
	a.mu.Unlock()

	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		rec := a.sessions[sessID].ps.Runs[runID]
		a.mu.Unlock()
		if rec.Status == statusCompleted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fenced run status = %q", rec.Status)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cmdMu.Lock()
	gotTools := slices.Clone(lastTools)
	cmdMu.Unlock()
	if !slices.Equal(gotTools, []string{"read"}) {
		t.Fatalf("effective narrowed tools = %v, want [read]", gotTools)
	}
	if lastLinkOriginEnv != "peer-a/agent-1" {
		t.Fatalf("VANORA_LINK_ORIGIN = %q, want peer-a/agent-1", lastLinkOriginEnv)
	}
}

func TestOwnerGatedGuestRequests(t *testing.T) {
	env := newTestEnv(t, []Grant{
		{UserID: "guest-1", Read: true},
		{UserID: "guest-2", Read: true},
	}, nil)
	env.handled = true
	env.cfg.Sessions[0].AllowGuestRequests = true

	a, ownerPeer := newTestAdapter(t, env, "owner")
	guest1 := newFakePeer("guest-1")
	guest2 := newFakePeer("guest-2")
	a.Open(guest1)
	a.Open(guest2)
	t.Cleanup(func() {
		a.Closed(guest1)
		a.Closed(guest2)
	})

	subscribeSession(t, a, ownerPeer)
	subscribeSession(t, a, guest1)
	subscribeSession(t, a, guest2)

	// Direct run.start by read-only guest-1 is still strictly denied.
	directID := sendRequest(t, a, guest1, map[string]any{
		"type":       "run.start",
		"session_id": "main",
		"text":       "direct attempt",
	})
	directResp := guest1.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["request_id"] == directID
	})
	if directResp["type"] != "error" || directResp["code"] != codeToolDenied {
		t.Fatalf("expected direct run.start denial, got %+v", directResp)
	}

	// guest-1 submits an owner-gated guest.request.
	gReqID := sendRequest(t, a, guest1, map[string]any{
		"type":       "guest.request",
		"session_id": "main",
		"text":       "Please summarize the architecture",
	})
	gRes := resultData(t, guest1.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == gReqID
	}))
	guestItemID, _ := gRes["guest_request_id"].(string)
	if guestItemID == "" || gRes["status"] != "pending" {
		t.Fatalf("unexpected guest.request result: %+v", gRes)
	}

	// Owner receives guest.request event; guest-2 receives redacted sync placeholder!
	_ = ownerPeer.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindGuestRequest
	})
	syncEv := guest2.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindSync
	})
	if syncEv["data"] != nil {
		t.Fatalf("expected redacted sync event for other guest, got %+v", syncEv)
	}

	// Non-owner guest-2 cannot approve guest-1's request.
	spoofApproveID := sendRequest(t, a, guest2, map[string]any{
		"type":             "guest.respond",
		"session_id":       "main",
		"guest_request_id": guestItemID,
		"action":           "approve",
	})
	spoofResp := guest2.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["request_id"] == spoofApproveID
	})
	if spoofResp["type"] != "error" || spoofResp["code"] != codeToolDenied {
		t.Fatalf("expected non-owner guest.respond denial, got %+v", spoofResp)
	}

	// Owner approves via guest.respond -> spawns run and completes!
	approveID := sendRequest(t, a, ownerPeer, map[string]any{
		"type":             "guest.respond",
		"session_id":       "main",
		"guest_request_id": guestItemID,
		"action":           "approve",
	})
	approved := resultData(t, ownerPeer.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == approveID
	}))
	runID, _ := approved["run_id"].(string)
	if approved["status"] != "approved" || runID == "" {
		t.Fatalf("unexpected approve result: %+v", approved)
	}
	waitRunStatus(t, a, runID, statusCompleted)

	// Submit a second guest request and dismiss locally via RespondGuestLocal.
	gReq2ID := sendRequest(t, a, guest1, map[string]any{
		"type":       "guest.request",
		"session_id": "main",
		"text":       "Dismiss me",
	})
	gRes2 := resultData(t, guest1.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == gReq2ID
	}))
	guestItem2ID, _ := gRes2["guest_request_id"].(string)
	localRes, err := a.RespondGuestLocal("main", guestItem2ID, "dismiss")
	if err != nil || localRes.Status != "dismissed" {
		t.Fatalf("RespondGuestLocal dismiss = (%+v, %v)", localRes, err)
	}
}
