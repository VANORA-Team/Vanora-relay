package desktop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

func testLANUserID(access, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "lan:" + access + ":" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestMultiUserRealTimeRunStartedAndActiveRunSnapshot(t *testing.T) {
	env := newTestEnv(t, []Grant{
		{UserID: "collab", Read: true, Tools: true},
		{UserID: "viewer", Read: true},
	}, []string{"read"})
	env.delay = 250

	a, owner := newTestAdapter(t, env, "owner")
	collab := newFakePeer("collab")
	viewer := newFakePeer("viewer")
	a.Open(collab)
	a.Open(viewer)
	defer a.Closed(collab)
	defer a.Closed(viewer)

	subscribeSession(t, a, owner)
	subscribeSession(t, a, collab)
	subscribeSession(t, a, viewer)

	// Collaborator starts a run; all subscribers must receive run.started with
	// author & prompt text before any assistant text.delta.
	startID := sendRequest(t, a, collab, map[string]any{
		"type":       "run.start",
		"session_id": "main",
		"text":       "check deployment status",
	})
	started := resultData(t, collab.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == startID
	}))
	runID, _ := started["run_id"].(string)
	if runID == "" || started["status"] != statusRunning {
		t.Fatalf("unexpected run.start result: %+v", started)
	}

	// Viewer immediately receives run.started event with user_id & text.
	vStarted := viewer.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunStarted && f["run_id"] == runID
	})
	vData, _ := vStarted["data"].(map[string]any)
	if vData["user_id"] != "collab" || vData["text"] != "check deployment status" {
		t.Fatalf("unexpected viewer run.started payload: %+v", vStarted)
	}

	// Mid-run session.open returns active_run and participants.
	openID := sendRequest(t, a, owner, map[string]any{
		"type":       "session.open",
		"session_id": "main",
	})
	snap := resultData(t, owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == openID
	}))
	activeRun, _ := snap["active_run"].(map[string]any)
	if activeRun == nil || activeRun["run_id"] != runID || activeRun["user_id"] != "collab" || activeRun["status"] != statusRunning {
		t.Fatalf("session.open active_run = %+v", snap["active_run"])
	}
	participants, _ := snap["participants"].([]any)
	if len(participants) != 3 {
		t.Fatalf("expected 3 participants in snapshot, got %+v", participants)
	}

	// session.list exposes active_run_id, active_run_user_id, and viewer_count.
	listID := sendRequest(t, a, viewer, map[string]any{"type": "session.list"})
	listData := resultData(t, viewer.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == listID
	}))
	sessions, _ := listData["sessions"].([]any)
	summary, _ := sessions[0].(map[string]any)
	if summary["active_run_id"] != runID || summary["active_run_user_id"] != "collab" || summary["viewer_count"] != float64(3) {
		t.Fatalf("unexpected session.list collaboration summary: %+v", summary)
	}

	// Wait for completion and verify ordering: viewer saw run.started before text.delta.
	viewer.waitFrame(t, 5*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCompleted && f["run_id"] == runID
	})
	var startedSeq, deltaSeq float64
	viewer.mu.Lock()
	for _, raw := range viewer.frames {
		var f map[string]any
		if json.Unmarshal(raw, &f) == nil && f["type"] == "event" && f["run_id"] == runID {
			if f["kind"] == kindRunStarted && startedSeq == 0 {
				startedSeq, _ = f["seq"].(float64)
			}
			if f["kind"] == kindTextDelta && deltaSeq == 0 {
				deltaSeq, _ = f["seq"].(float64)
			}
		}
	}
	viewer.mu.Unlock()
	if startedSeq == 0 || deltaSeq == 0 || startedSeq >= deltaSeq {
		t.Fatalf("expected run.started (seq=%.0f) before text.delta (seq=%.0f)", startedSeq, deltaSeq)
	}

	// Post-run session.open preserves user_id attribution on user message.
	openAfterID := sendRequest(t, a, owner, map[string]any{"type": "session.open", "session_id": "main"})
	snapAfter := resultData(t, owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == openAfterID
	}))
	msgs, _ := snapAfter["messages"].([]any)
	foundAttr := false
	for _, rawMsg := range msgs {
		m, _ := rawMsg.(map[string]any)
		if m["role"] == "user" && m["user_id"] == "collab" {
			foundAttr = true
		}
	}
	if !foundAttr {
		t.Fatalf("expected user message attribution for collab in %+v", msgs)
	}
}

func TestMultiUserTurnQueueFIFOAndSecurity(t *testing.T) {
	env := newTestEnv(t, []Grant{
		{UserID: "guestA", Read: true, Tools: true},
		{UserID: "guestB", Read: true, Tools: true},
	}, []string{"read"})
	env.delay = 450

	a, owner := newTestAdapter(t, env, "owner")
	guestA := newFakePeer("guestA")
	guestB := newFakePeer("guestB")
	a.Open(guestA)
	a.Open(guestB)
	defer a.Closed(guestA)
	defer a.Closed(guestB)

	subscribeSession(t, a, owner)
	subscribeSession(t, a, guestA)
	subscribeSession(t, a, guestB)

	// 1. Owner starts active run 1.
	r1Req := sendRequest(t, a, owner, map[string]any{
		"type": "run.start", "session_id": "main", "text": "turn-1",
	})
	r1ID, _ := resultData(t, owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == r1Req
	}))["run_id"].(string)

	// 2. Guest B with queue_policy="reject" receives session_busy immediately.
	rejectReq := sendRequest(t, a, guestB, map[string]any{
		"type": "run.start", "session_id": "main", "text": "no-queue", "queue_policy": "reject",
	})
	rejectErr := guestB.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == rejectReq
	})
	if rejectErr["code"] != codeSessionBusy {
		t.Fatalf("queue_policy=reject error = %+v, want %s", rejectErr, codeSessionBusy)
	}

	// 3. Guest A enqueues turn 2 (default policy) with stable request_id.
	qAReq := sendRequest(t, a, guestA, map[string]any{
		"type": "run.start", "request_id": "q-a-1", "session_id": "main", "text": "turn-2-from-A",
	})
	qAData := resultData(t, guestA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == qAReq
	}))
	runAID, _ := qAData["run_id"].(string)
	if runAID == "" || qAData["status"] != statusQueued || qAData["queue_position"] != float64(1) {
		t.Fatalf("unexpected guestA queue result: %+v", qAData)
	}

	// Idempotent retry returns the same queued run_id and position.
	qARetry := sendRequest(t, a, guestA, map[string]any{
		"type": "run.start", "request_id": "q-a-1", "session_id": "main", "text": "turn-2-from-A",
	})
	qARetryData := resultData(t, guestA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == qARetry
	}))
	if qARetryData["run_id"] != runAID || qARetryData["status"] != statusQueued {
		t.Fatalf("idempotent queued retry = %+v", qARetryData)
	}

	// 4. Guest B enqueues turn 3 (position 2).
	qBReq := sendRequest(t, a, guestB, map[string]any{
		"type": "run.start", "session_id": "main", "text": "turn-3-from-B",
	})
	qBData := resultData(t, guestB.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == qBReq
	}))
	runBID, _ := qBData["run_id"].(string)
	if runBID == "" || qBData["status"] != statusQueued || qBData["queue_position"] != float64(2) {
		t.Fatalf("unexpected guestB queue result: %+v", qBData)
	}

	// Owner receives run.queued events for both queued turns.
	owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunQueued && f["run_id"] == runAID
	})
	owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunQueued && f["run_id"] == runBID
	})

	// 5. Cross-guest cancel on queued run is strictly denied (VR-SEC-10).
	spoofCancel := sendRequest(t, a, guestB, map[string]any{
		"type": "run.cancel", "session_id": "main", "run_id": runAID,
	})
	spoofErr := guestB.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == spoofCancel
	})
	if spoofErr["code"] != codeUnavailable {
		t.Fatalf("cross-guest queued cancel = %+v, want %s", spoofErr, codeUnavailable)
	}

	// 6. Guest B cancels their own queued run immediately.
	selfCancel := sendRequest(t, a, guestB, map[string]any{
		"type": "run.cancel", "session_id": "main", "run_id": runBID,
	})
	selfRes := resultData(t, guestB.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == selfCancel
	}))
	if selfRes["status"] != statusCancelled {
		t.Fatalf("queued self cancel = %+v, want cancelled", selfRes)
	}
	owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCancelled && f["run_id"] == runBID
	})

	// 7. When owner's turn finishes, guestA's queued turn auto-promotes and completes!
	waitRunStatus(t, a, r1ID, statusCompleted)
	owner.waitFrame(t, 5*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunStarted && f["run_id"] == runAID
	})
	waitRunStatus(t, a, runAID, statusCompleted)
}

func TestQueuedRunCancelledOnACLRevocationAndPerUserCap(t *testing.T) {
	env := newTestEnv(t, []Grant{
		{UserID: "guestA", Read: true, Tools: true},
		{UserID: "guestB", Read: true, Tools: true},
	}, []string{"read"})
	env.delay = 2000

	a, owner := newTestAdapter(t, env, "owner")
	guestA := newFakePeer("guestA")
	guestB := newFakePeer("guestB")
	a.Open(guestA)
	a.Open(guestB)
	defer a.Closed(guestA)
	defer a.Closed(guestB)
	subscribeSession(t, a, owner)

	// Start active run from owner.
	r1Req := sendRequest(t, a, owner, map[string]any{
		"type": "run.start", "session_id": "main", "text": "hold-slot",
	})
	_ = resultData(t, owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == r1Req
	}))

	// Guest A fills their per-user cap (3), 4th is rejected with session_busy,
	// while Guest B can still enqueue!
	var guestARuns []string
	for i := range maxQueuedRunsPerUser {
		reqID := sendRequest(t, a, guestA, map[string]any{
			"type": "run.start", "session_id": "main", "text": "a-" + string(rune('0'+i)),
		})
		res := resultData(t, guestA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
			return f["type"] == "result" && f["request_id"] == reqID
		}))
		guestARuns = append(guestARuns, res["run_id"].(string))
	}
	overCapReq := sendRequest(t, a, guestA, map[string]any{
		"type": "run.start", "session_id": "main", "text": "a-overflow",
	})
	overCapErr := guestA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == overCapReq
	})
	if overCapErr["code"] != codeSessionBusy {
		t.Fatalf("per-user queue cap error = %+v, want %s", overCapErr, codeSessionBusy)
	}

	bReq := sendRequest(t, a, guestB, map[string]any{
		"type": "run.start", "session_id": "main", "text": "b-ok",
	})
	bRes := resultData(t, guestB.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == bReq
	}))
	if bRes["status"] != statusQueued {
		t.Fatalf("guestB should still enqueue when guestA hits per-user cap: %+v", bRes)
	}

	// Revoke guestA via ReloadACL -> all guestA queued runs immediately cancelled,
	// while guestB's queued run remains queued!
	if err := a.ReloadACL(env.reload([]Grant{{UserID: "guestB", Read: true, Tools: true}})); err != nil {
		t.Fatal(err)
	}
	for _, rid := range guestARuns {
		waitRunStatus(t, a, rid, statusCancelled)
	}
	a.mu.Lock()
	bRec := a.sessions["main"].ps.Runs[bRes["run_id"].(string)]
	a.mu.Unlock()
	if bRec.Status != statusQueued {
		t.Fatalf("guestB queued run unexpectedly changed to %q", bRec.Status)
	}
}

func TestCollaboratorPresenceWatchAndSessionClose(t *testing.T) {
	env := newTestEnv(t, []Grant{
		{UserID: "guest-1", Read: true},
		{UserID: "guest-2", Read: true, Tools: true},
	}, nil)

	a, owner := newTestAdapter(t, env, "owner")
	g1 := newFakePeer("guest-1")
	g2 := newFakePeer("guest-2")
	a.Open(g1)
	a.Open(g2)
	defer a.Closed(g1)
	defer a.Closed(g2)

	// Owner opens with watch_presence=true.
	openOwner := sendRequest(t, a, owner, map[string]any{
		"type":           "session.open",
		"session_id":     "main",
		"watch_presence": true,
	})
	snapOwner := resultData(t, owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == openOwner
	}))
	if parts, _ := snapOwner["participants"].([]any); len(parts) != 1 {
		t.Fatalf("expected 1 participant initially, got %+v", parts)
	}

	// Guest 1 subscribes -> owner receives live ephemeral presence.updated (seq=0) with 2 participants.
	subscribeSession(t, a, g1)
	presEv := owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		if f["type"] != "event" || f["kind"] != kindPresenceUpdated {
			return false
		}
		d, _ := f["data"].(map[string]any)
		parts, _ := d["participants"].([]any)
		return len(parts) == 2
	})
	if seq, _ := presEv["seq"].(float64); seq != 0 {
		t.Fatalf("expected ephemeral seq=0 for presence.updated, got %v", presEv["seq"])
	}

	// Guest 2 queries session.presence explicitly with watch=true.
	presReq := sendRequest(t, a, g2, map[string]any{
		"type":       "session.presence",
		"session_id": "main",
		"watch":      true,
	})
	presRes := resultData(t, g2.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == presReq
	}))
	if parts, _ := presRes["participants"].([]any); len(parts) != 2 {
		t.Fatalf("session.presence participants = %+v, want 2", parts)
	}

	// Guest 1 closes session -> both owner and g2 receive presence.updated with 1 participant.
	closeReq := sendRequest(t, a, g1, map[string]any{
		"type":       "session.close",
		"session_id": "main",
	})
	closeRes := resultData(t, g1.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == closeReq
	}))
	if closed, _ := closeRes["closed"].(bool); !closed {
		t.Fatalf("session.close result = %+v", closeRes)
	}

	owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		if f["type"] != "event" || f["kind"] != kindPresenceUpdated {
			return false
		}
		d, _ := f["data"].(map[string]any)
		parts, _ := d["participants"].([]any)
		return len(parts) == 1
	})

	// CollaborationSnapshot exposes live participants to the local host Sidecar.
	collabSnap := a.CollaborationSnapshot("main")
	if len(collabSnap) != 1 || len(collabSnap[0].Participants) != 1 || collabSnap[0].Participants[0].UserID != "owner" {
		t.Fatalf("unexpected CollaborationSnapshot: %+v", collabSnap)
	}
}

func TestGuestRequestCapsSelfCancelEditNarrowAndQueueApprove(t *testing.T) {
	env := newTestEnv(t, []Grant{
		{UserID: "guest-1", Read: true},
		{UserID: "guest-2", Read: true},
	}, []string{"read", "bash"})
	env.delay = 350
	env.cfg.Sessions[0].AllowGuestRequests = true

	var mu sync.Mutex
	var recordedTools [][]string
	a, err := New(env.cfg, env.state)
	if err != nil {
		t.Fatal(err)
	}
	a.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	a.AuthorityUntil(time.Now().Add(time.Hour))
	a.buildCommand = func(s *normalizedSession) (*exec.Cmd, error) {
		mu.Lock()
		recordedTools = append(recordedTools, slices.Clone(s.tools))
		mu.Unlock()
		cmd := exec.Command(os.Args[0], "-test.run=^TestFakeVanora$")
		cmd.Dir = s.workDir
		cmd.Env = append(os.Environ(), "VANORA_FAKE_PROCESS=1", "FAKE_DELAY_MS=300", "FAKE_HANDLED=true")
		return cmd, nil
	}
	defer a.Close()

	owner := newFakePeer("owner")
	g1 := newFakePeer("guest-1")
	g2 := newFakePeer("guest-2")
	a.Open(owner)
	a.Open(g1)
	a.Open(g2)
	defer a.Closed(owner)
	defer a.Closed(g1)
	defer a.Closed(g2)

	subscribeSession(t, a, owner)
	subscribeSession(t, a, g1)
	subscribeSession(t, a, g2)

	// 1. Per-user pending guest request cap (4), 5th rejected with guest_request_limit,
	// while guest-2 can still submit!
	var g1IDs []string
	for i := range maxPendingGuestPerUser {
		req := sendRequest(t, a, g1, map[string]any{
			"type": "guest.request", "session_id": "main", "text": "q-" + string(rune('0'+i)),
		})
		res := resultData(t, g1.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
			return f["type"] == "result" && f["request_id"] == req
		}))
		g1IDs = append(g1IDs, res["guest_request_id"].(string))
	}
	overReq := sendRequest(t, a, g1, map[string]any{
		"type": "guest.request", "session_id": "main", "text": "q-overflow",
	})
	overErr := g1.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == overReq
	})
	if overErr["code"] != codeGuestLimit {
		t.Fatalf("expected %s, got %+v", codeGuestLimit, overErr)
	}

	g2Req := sendRequest(t, a, g2, map[string]any{
		"type": "guest.request", "session_id": "main", "text": "g2-question",
	})
	g2Res := resultData(t, g2.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == g2Req
	}))
	g2ID := g2Res["guest_request_id"].(string)

	// 2. Guest-2 cannot cancel guest-1's request; guest-1 can cancel their own!
	badCancel := sendRequest(t, a, g2, map[string]any{
		"type": "guest.respond", "session_id": "main", "guest_request_id": g1IDs[0], "action": "cancel",
	})
	badErr := g2.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == badCancel
	})
	if badErr["code"] != codeToolDenied {
		t.Fatalf("cross-guest cancel = %+v, want %s", badErr, codeToolDenied)
	}

	selfCancel := sendRequest(t, a, g1, map[string]any{
		"type": "guest.respond", "session_id": "main", "guest_request_id": g1IDs[0], "action": "cancel",
	})
	selfRes := resultData(t, g1.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == selfCancel
	}))
	if selfRes["status"] != "cancelled" {
		t.Fatalf("guest self cancel = %+v", selfRes)
	}

	// 3. Owner starts an active run, then approves guest-1's second request WITH
	// edited text and narrowed mode_limit (tools: ["read"]) -> smoothly enqueues!
	activeReq := sendRequest(t, a, owner, map[string]any{
		"type": "run.start", "session_id": "main", "text": "owner-turn",
	})
	activeRunID := resultData(t, owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == activeReq
	}))["run_id"].(string)

	approveReq := sendRequest(t, a, owner, map[string]any{
		"type":             "guest.respond",
		"session_id":       "main",
		"guest_request_id": g1IDs[1],
		"action":           "approve",
		"text":             "refined prompt for read-only check",
		"mode_limit":       map[string]any{"tools": []string{"read"}},
	})
	approveRes := resultData(t, owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == approveReq
	}))
	queuedRunID, _ := approveRes["run_id"].(string)
	if approveRes["status"] != "approved" || approveRes["queued"] != true || approveRes["queue_position"] != float64(1) || queuedRunID == "" {
		t.Fatalf("unexpected busy guest approve result: %+v", approveRes)
	}

	// Wait for both active run and promoted guest run to complete.
	waitRunStatus(t, a, activeRunID, statusCompleted)
	waitRunStatus(t, a, queuedRunID, statusCompleted)

	// Verify promoted guest run emitted run.started with refined text and requested_by=guest-1.
	startedEv := owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunStarted && f["run_id"] == queuedRunID
	})
	sData, _ := startedEv["data"].(map[string]any)
	if sData["text"] != "refined prompt for read-only check" || sData["requested_by"] != "guest-1" || sData["guest_request_id"] != g1IDs[1] {
		t.Fatalf("unexpected promoted guest run.started: %+v", startedEv)
	}

	mu.Lock()
	gotTools := slices.Clone(recordedTools)
	mu.Unlock()
	if len(gotTools) != 2 || !slices.Equal(gotTools[1], []string{"read"}) {
		t.Fatalf("expected narrowed tools [read] for approved guest run, got %v", gotTools)
	}

	// 4. ReloadACL removing guest-2 automatically prunes guest-2's pending guest request!
	if pending := a.PendingGuestRequests("main"); !slices.ContainsFunc(pending, func(g GuestRequestInfo) bool { return g.GuestRequestID == g2ID }) {
		t.Fatalf("expected guest-2 request in PendingGuestRequests, got %+v", pending)
	}
	if err := a.ReloadACL(env.reload([]Grant{{UserID: "guest-1", Read: true}})); err != nil {
		t.Fatal(err)
	}
	if pending := a.PendingGuestRequests("main"); slices.ContainsFunc(pending, func(g GuestRequestInfo) bool { return g.GuestRequestID == g2ID }) {
		t.Fatalf("revoked guest-2 request survived ReloadACL: %+v", pending)
	}
}

func TestLANGuestManagementAndLocalApprovalOfflineOfficialAuthority(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	sessionFile := filepath.Join(dir, "session.jsonl")
	header, _ := json.Marshal(map[string]any{
		"type":      "session",
		"version":   3,
		"id":        "lan-sess",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"cwd":       work,
	})
	if err := os.WriteFile(sessionFile, append(header, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Executable: os.Args[0],
		Sessions: []SessionConfig{{
			ID:                 "main",
			Title:              "LAN Shared",
			WorkingDir:         work,
			SessionFile:        sessionFile,
			Owner:              LocalOwner,
			LANAccess:          true,
			Tools:              []string{"bash"},
			ApprovalPolicy:     approvalRemote,
			AllowGuestRequests: true,
		}},
	}
	a, err := New(cfg, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	// Official authority intentionally OFFLINE (pure account-free LAN mode)!
	a.SetLANAuthority(func(string) bool { return true })
	a.buildCommand = func(s *normalizedSession) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFakeVanora$")
		cmd.Dir = s.workDir
		cmd.Env = append(os.Environ(), "VANORA_FAKE_PROCESS=1", "FAKE_EXTENSION_MODE=confirm")
		return cmd, nil
	}

	lanControl := newFakePeer(testLANUserID("control", "controller-device"))
	lanReader1 := newFakePeer(testLANUserID("read", "reader-1"))
	lanReader2 := newFakePeer(testLANUserID("read", "reader-2"))
	a.Open(lanControl)
	a.Open(lanReader1)
	a.Open(lanReader2)
	defer a.Closed(lanControl)
	defer a.Closed(lanReader1)
	defer a.Closed(lanReader2)

	subscribeSession(t, a, lanControl)
	subscribeSession(t, a, lanReader1)
	subscribeSession(t, a, lanReader2)

	// 1. LAN reader-1 submits a guest request; LAN controller sees it, reader-2 gets sync only!
	gReq := sendRequest(t, a, lanReader1, map[string]any{
		"type": "guest.request", "session_id": "main", "text": "run diagnostic via LAN",
	})
	gRes := resultData(t, lanReader1.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == gReq
	}))
	guestReqID := gRes["guest_request_id"].(string)

	lanControl.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindGuestRequest
	})
	syncFrame := lanReader2.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindSync
	})
	if syncFrame["data"] != nil {
		t.Fatalf("reader-2 leaked LAN guest request data: %+v", syncFrame)
	}

	// session.list shows pending_guest_count=1 for controller & reader-1, 0 for reader-2.
	listR2 := sendRequest(t, a, lanReader2, map[string]any{"type": "session.list"})
	r2Sessions := resultData(t, lanReader2.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == listR2
	}))["sessions"].([]any)
	if _, leaked := r2Sessions[0].(map[string]any)["pending_guest_count"]; leaked {
		t.Fatalf("reader-2 saw other guest pending count: %+v", r2Sessions[0])
	}

	// 2. LAN controller approves guest request -> hits ui.request -> controller confirms -> completes!
	approveReq := sendRequest(t, a, lanControl, map[string]any{
		"type": "guest.respond", "session_id": "main", "guest_request_id": guestReqID, "action": "approve",
	})
	approveData := resultData(t, lanControl.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == approveReq
	}))
	runID := approveData["run_id"].(string)
	lanControl.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindUIRequest && f["run_id"] == runID
	})
	uiReq := sendRequest(t, a, lanControl, map[string]any{
		"type": "ui.respond", "session_id": "main", "run_id": runID, "ui_id": "ext-1", "confirmed": true,
	})
	_ = resultData(t, lanControl.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == uiReq
	}))
	waitRunStatus(t, a, runID, statusCompleted)

	// 3. Local host approves a second guest request while official authority is OFFLINE:
	// tool approval must NOT be auto-cancelled and LAN controller can answer ui.respond!
	gReq2 := sendRequest(t, a, lanReader1, map[string]any{
		"type": "guest.request", "session_id": "main", "text": "locally approved lan run",
	})
	guestReq2ID := resultData(t, lanReader1.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == gReq2
	}))["guest_request_id"].(string)

	localRes, err := a.RespondGuestLocal("main", guestReq2ID, "approve")
	if err != nil || localRes.RunID == "" {
		t.Fatalf("RespondGuestLocal approve = (%+v, %v)", localRes, err)
	}
	lanControl.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindUIRequest && f["run_id"] == localRes.RunID
	})
	uiReq2 := sendRequest(t, a, lanControl, map[string]any{
		"type": "ui.respond", "session_id": "main", "run_id": localRes.RunID, "ui_id": "ext-1", "confirmed": true,
	})
	_ = resultData(t, lanControl.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == uiReq2
	}))
	waitRunStatus(t, a, localRes.RunID, statusCompleted)
}
