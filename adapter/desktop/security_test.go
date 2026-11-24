package desktop

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func secFinding(t *testing.T, id, format string, args ...any) {
	t.Helper()
	t.Logf("FINDING %s: "+format, append([]any{id}, args...)...)
	v := strings.TrimSpace(os.Getenv("VANORA_SECURITY_STRICT"))
	if v == "1" || strings.EqualFold(v, "true") {
		t.Fatalf("FINDING %s: "+format, append([]any{id}, args...)...)
	}
	t.Skipf("FINDING %s: "+format, append([]any{id}, args...)...)
}

func TestSecurityEventsResumeDoesNotLeakOtherGuestApproval(t *testing.T) {
	env := newTestEnv(t, []Grant{
		{UserID: "guestA", Read: true, Tools: true, Approve: true},
		{UserID: "guestB", Read: true, Tools: true, Approve: true},
	}, []string{"bash"})
	env.cfg.Sessions[0].ApprovalPolicy = approvalRemote
	env.extMode = "confirm"

	a, _ := newTestAdapter(t, env, "owner")
	guestA := newFakePeer("guestA")
	guestB := newFakePeer("guestB")
	a.Open(guestA)
	defer a.Closed(guestA)
	a.Open(guestB)
	defer a.Closed(guestB)

	subscribeSession(t, a, guestA)

	// Guest A starts a run that emits an interactive remote approval prompt (ui.request).
	startID := sendRequest(t, a, guestA, map[string]any{
		"type":       "run.start",
		"session_id": "main",
		"text":       "secret command for guestA",
	})
	runID, _ := resultData(t, guestA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == startID
	}))["run_id"].(string)

	reqFrame := guestA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindUIRequest && f["run_id"] == runID
	})
	reqSeq, _ := reqFrame["seq"].(float64)

	// Guest B resolves nothing; Guest A approves so ui.resolved is also recorded.
	okID := sendRequest(t, a, guestA, map[string]any{
		"type":       "ui.respond",
		"session_id": "main",
		"run_id":     runID,
		"ui_id":      "ext-1",
		"confirmed":  true,
	})
	_ = resultData(t, guestA.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == okID
	}))
	guestA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindUIResolved && f["run_id"] == runID
	})
	guestA.waitFrame(t, 5*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCompleted && f["run_id"] == runID
	})

	// Control guest B resumes from seq 0 on the same session.
	// Secure behavior: guest A's ui.request and ui.resolved must be masked as "sync"
	// just like live delivery in adapter.go:442.
	resumeID := sendRequest(t, a, guestB, map[string]any{
		"type":       "events.resume",
		"session_id": "main",
		"after_seq":  0,
	})
	_ = resultData(t, guestB.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == resumeID
	}))
	guestB.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCompleted && f["run_id"] == runID
	})

	var leaked []string
	guestB.mu.Lock()
	for _, raw := range guestB.frames {
		var f map[string]any
		if json.Unmarshal(raw, &f) != nil || f["type"] != "event" {
			continue
		}
		kind, _ := f["kind"].(string)
		if (kind == kindUIRequest || kind == kindUIResolved) && f["run_id"] == runID {
			leaked = append(leaked, string(raw))
		}
	}
	guestB.mu.Unlock()

	if len(leaked) > 0 {
		secFinding(t, "VR-SEC-01", "events.resume replayed %d approval frame(s) (seq %.0f+) to another control guest B: %s (state.go:73-79, adapter.go:1106-1113, protocol.go:459-485)", len(leaked), reqSeq, leaked[0])
	}
}

func TestSecurityCrossGuestRunCancelAndUIRespondRejected(t *testing.T) {
	env := newTestEnv(t, []Grant{
		{UserID: "guestA", Read: true, Tools: true, Approve: true},
		{UserID: "guestB", Read: true, Tools: true, Approve: true},
	}, []string{"bash"})
	env.cfg.Sessions[0].ApprovalPolicy = approvalRemote
	env.extMode = "confirm"

	a, _ := newTestAdapter(t, env, "owner")
	guestA := newFakePeer("guestA")
	guestB := newFakePeer("guestB")
	a.Open(guestA)
	defer a.Closed(guestA)
	a.Open(guestB)
	defer a.Closed(guestB)

	subscribeSession(t, a, guestA)
	subscribeSession(t, a, guestB)

	startID := sendRequest(t, a, guestA, map[string]any{
		"type":       "run.start",
		"session_id": "main",
		"text":       "wait for approval",
	})
	runID, _ := resultData(t, guestA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == startID
	}))["run_id"].(string)

	guestA.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindUIRequest && f["run_id"] == runID
	})

	// While guestA's run is live, guestB must NOT see ui.request live.
	time.Sleep(50 * time.Millisecond)
	guestB.mu.Lock()
	for _, raw := range guestB.frames {
		var f map[string]any
		if json.Unmarshal(raw, &f) == nil && f["type"] == "event" && f["kind"] == kindUIRequest {
			guestB.mu.Unlock()
			t.Fatalf("live approval prompt leaked to guestB: %s", raw)
		}
	}
	guestB.mu.Unlock()

	// Guest B cannot cancel Guest A's active run.
	cancelID := sendRequest(t, a, guestB, map[string]any{
		"type":       "run.cancel",
		"session_id": "main",
		"run_id":     runID,
	})
	cancelErr := guestB.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == cancelID
	})
	if cancelErr["code"] != codeUnavailable {
		t.Fatalf("cross-guest run.cancel = %v, want %s", cancelErr, codeUnavailable)
	}

	// Guest B cannot respond to Guest A's approval prompt.
	respID := sendRequest(t, a, guestB, map[string]any{
		"type":       "ui.respond",
		"session_id": "main",
		"run_id":     runID,
		"ui_id":      "ext-1",
		"confirmed":  true,
	})
	respErr := guestB.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == respID
	})
	if respErr["code"] != codeUnavailable {
		t.Fatalf("cross-guest ui.respond = %v, want %s", respErr, codeUnavailable)
	}

	// Guest A approves and completes normally.
	okID := sendRequest(t, a, guestA, map[string]any{
		"type":       "ui.respond",
		"session_id": "main",
		"run_id":     runID,
		"ui_id":      "ext-1",
		"confirmed":  true,
	})
	_ = resultData(t, guestA.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == okID
	}))
	guestA.waitFrame(t, 5*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCompleted && f["run_id"] == runID
	})
	waitRunStatus(t, a, runID, statusCompleted)

	// Post-completion run.cancel by another guest must also return unavailable
	// rather than disclosing the finished run's persisted status (VR-SEC-10).
	postCancelID := sendRequest(t, a, guestB, map[string]any{
		"type":       "run.cancel",
		"session_id": "main",
		"run_id":     runID,
	})
	postFrame := guestB.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return (f["type"] == "result" || f["type"] == "error") && f["request_id"] == postCancelID
	})
	if postFrame["type"] != "error" || postFrame["code"] != codeUnavailable {
		secFinding(t, "VR-SEC-10", "post-completion run.cancel by guestB leaked status: %v (protocol.go:603-606)", postFrame)
	}
}
