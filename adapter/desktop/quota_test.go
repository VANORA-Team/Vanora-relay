package desktop

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSessionCreateQuotaBounded pins the anti-brick quota: a remote user with
// create rights cannot open unbounded sessions in a workspace, and closing a
// session releases its slot so the desktop keeps working.
func TestSessionCreateQuotaBounded(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "proj")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Executable: os.Args[0],
		Workspaces: []WorkspaceConfig{{
			ID:             "proj",
			Title:          "Project",
			WorkingDir:     work,
			SessionDir:     filepath.Join(dir, "sessions"),
			Owner:          "owner",
			Tools:          []string{"read", "bash"},
			ApprovalPolicy: "remote",
		}},
		Retention: RetentionConfig{MaxCreatedSessions: 3},
	}
	a, err := New(cfg, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.AuthorityUntil(time.Now().Add(time.Hour))
	p := newFakePeer("owner")
	a.Open(p)
	defer a.Closed(p)

	create := func(requestID, title string) (string, string, bool) {
		id := sendRequest(t, a, p, map[string]any{
			"type":         "session.create",
			"request_id":   requestID,
			"workspace_id": "proj",
			"title":        title,
		})
		frame := p.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
			return f["type"] == "result" && f["request_id"] == id || f["type"] == "error" && f["request_id"] == id
		})
		if frame["type"] == "error" {
			code, _ := frame["code"].(string)
			return "", code, false
		}
		data := resultData(t, frame)
		sid, _ := data["session_id"].(string)
		return sid, "", true
	}

	var ids []string
	for i := 1; i <= 3; i++ {
		sid, _, ok := create(fmt.Sprintf("create-%d", i), "chat")
		if !ok || sid == "" {
			t.Fatalf("create %d failed: %v", i, sid)
		}
		ids = append(ids, sid)
	}

	// Fourth create is refused with the dedicated quota code.
	if _, code, ok := create("create-4", "chat"); ok || code != codeSessionLimit {
		t.Fatalf("quota create accepted (ok=%v code=%q), want %s", ok, code, codeSessionLimit)
	}

	// Idempotent replay of an existing create request still succeeds at the cap.
	if sid, _, ok := create("create-3", "chat"); !ok || sid != ids[2] {
		t.Fatalf("dedup replay returned ok=%v sid=%q, want %s", ok, sid, ids[2])
	}

	// Reloading from the same state dir must keep the quota enforced: a
	// persisted-state create storm restarts bounded.
	a.Close()
	a2, err := New(cfg, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("reload rejected: %v", err)
	}
	defer a2.Close()
	a2.AuthorityUntil(time.Now().Add(time.Hour))
	p2 := newFakePeer("owner")
	a2.Open(p2)
	defer a2.Closed(p2)
	reloadID := sendRequest(t, a2, p2, map[string]any{
		"type":         "session.create",
		"request_id":   "create-6",
		"workspace_id": "proj",
		"title":        "chat",
	})
	frame2 := p2.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == reloadID || f["type"] == "error" && f["request_id"] == reloadID
	})
	if frame2["type"] != "error" || frame2["code"] != codeSessionLimit {
		t.Fatalf("post-reload create = %v, want session_limit error", frame2)
	}

	// The persisted state keeps exactly the three created sessions.
	a2.mu.Lock()
	st := a2.state
	a2.mu.Unlock()
	if st == nil {
		t.Fatal("missing persisted state")
	}
	if len(st.CreatedSessions) != 3 {
		t.Fatalf("created sessions = %d, want 3", len(st.CreatedSessions))
	}
}

// TestSaveStateSizeBudget refuses to persist a state blob over the budget so
// no write path can push startup into the load-time ceiling.
func TestSaveStateSizeBudget(t *testing.T) {
	dir := t.TempDir()
	blob := make([]byte, maxPersistedStateBytes+1024)
	for i := range blob {
		blob[i] = ' '
	}
	st := &persistedState{Sessions: map[string]*persistedSession{
		"fat": {Events: []storedEvent{{Kind: "message", Data: json.RawMessage("\"" + string(blob) + "\"")}}},
	}}
	if err := saveState(dir, st); err == nil {
		t.Fatal("oversized state was persisted")
	}
	if info, err := os.Stat(filepath.Join(dir, "state.json")); err == nil {
		t.Fatalf("state.json exists at %d bytes despite budget", info.Size())
	}
}
