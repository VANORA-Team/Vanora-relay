package desktop

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFakeVanora(t *testing.T) {
	if os.Getenv("VANORA_FAKE_PROCESS") != "1" {
		return
	}
	if err := runFakeVanora(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

// runFakeVanora is a tiny JSONL RPC peer used in place of the real CLI. It
// emits the same records the adapter consumes and refuses to finish when an
// extension dialog is not cancelled locally.
func runFakeVanora() error {
	delay := envInt("FAKE_DELAY_MS", 0)
	deltas := envInt("FAKE_DELTAS", 1)
	ext := os.Getenv("FAKE_EXTENSION") == "1" || os.Getenv("FAKE_EXTENSION") == "true"
	extMode := os.Getenv("FAKE_EXTENSION_MODE")
	handled := os.Getenv("FAKE_HANDLED") == "1" || os.Getenv("FAKE_HANDLED") == "true"

	rd := bufio.NewReader(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return nil
		}
		var cmd struct {
			Type    string `json:"type"`
			ID      string `json:"id"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(line), &cmd); err != nil {
			return err
		}
		if cmd.Type == "abort" {
			return nil
		}
		if cmd.Type != "prompt" {
			continue
		}
		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
		disposition := "started"
		if handled {
			disposition = "handled"
		}
		if err := enc.Encode(map[string]any{
			"id":      cmd.ID,
			"type":    "response",
			"command": "prompt",
			"success": true,
			"data":    map[string]any{"disposition": disposition},
		}); err != nil {
			return err
		}
		if handled {
			_ = enc.Encode(map[string]any{"type": "agent_settled", "aborted": false})
			continue
		}
		if ext || extMode != "" {
			req := map[string]any{
				"type":    "extension_ui_request",
				"id":      "ext-1",
				"method":  "confirm",
				"title":   "Allow?",
				"message": "Run bash?",
			}
			if extMode == "ask" {
				req = map[string]any{
					"type":   "extension_ui_request",
					"id":     "ext-1",
					"method": "ask",
					"questions": []map[string]any{{
						"question": "Which DB?",
						"header":   "DB",
						"options":  []map[string]any{{"label": "SQLite"}, {"label": "Postgres"}},
					}},
				}
			}
			if err := enc.Encode(req); err != nil {
				return err
			}
			for {
				responseLine, err := rd.ReadString('\n')
				if err != nil {
					return errors.New("extension dialog was not answered")
				}
				var response struct {
					Type      string     `json:"type"`
					ID        string     `json:"id"`
					Confirmed *bool      `json:"confirmed"`
					Answers   [][]string `json:"answers"`
					Cancelled bool       `json:"cancelled"`
				}
				if err := json.Unmarshal([]byte(responseLine), &response); err != nil {
					return err
				}
				if response.Type == "extension_ui_response" && response.ID == "ext-1" {
					switch extMode {
					case "confirm":
						if response.Confirmed == nil || !*response.Confirmed {
							return errors.New("confirm dialog was not approved")
						}
					case "ask":
						if len(response.Answers) != 1 || len(response.Answers[0]) != 1 || response.Answers[0][0] != "Postgres" {
							return fmt.Errorf("unexpected ask answers: %v", response.Answers)
						}
					case "expect_cancel":
						if !response.Cancelled {
							return errors.New("expected cancelled dialog")
						}
						_ = enc.Encode(map[string]any{"type": "agent_settled", "aborted": true})
						return nil
					default:
						if !response.Cancelled {
							return errors.New("extension dialog received an answer")
						}
					}
					break
				}
			}
		}
		_ = enc.Encode(map[string]any{
			"type": "message_start",
			"message": map[string]any{
				"role":      "user",
				"content":   cmd.Message,
				"timestamp": 1,
			},
		})
		_ = enc.Encode(map[string]any{
			"type": "message_start",
			"message": map[string]any{
				"role":      "assistant",
				"content":   []any{},
				"timestamp": 2,
			},
		})
		for i := 0; i < deltas; i++ {
			_ = enc.Encode(map[string]any{
				"type": "message_update",
				"assistantMessageEvent": map[string]any{
					"type":  "text_delta",
					"delta": fmt.Sprintf("part-%d", i),
				},
			})
			_ = enc.Encode(map[string]any{
				"type": "message_update",
				"assistantMessageEvent": map[string]any{
					"type":  "thinking_delta",
					"delta": "SECRET-THINKING",
				},
			})
			_ = enc.Encode(map[string]any{
				"type": "message_update",
				"assistantMessageEvent": map[string]any{
					"type": "toolcall_end",
					"toolCall": map[string]any{
						"id":        "call-1",
						"name":      "secret_tool",
						"arguments": map[string]any{"token": "SECRET-TOOL"},
					},
				},
			})
			_ = enc.Encode(map[string]any{
				"type":       "tool_execution_start",
				"toolCallId": "call-1",
				"toolName":   "secret_tool",
				"args":       map[string]any{"token": "SECRET-TOOL"},
			})
			_ = enc.Encode(map[string]any{
				"type":       "tool_execution_update",
				"toolCallId": "call-1",
				"toolName":   "secret_tool",
				"partialResult": map[string]any{
					"updateMode": "delta",
					"content":    []map[string]any{{"type": "text", "text": "SECRET-STREAM"}},
				},
			})
			_ = enc.Encode(map[string]any{
				"type":       "tool_execution_end",
				"toolCallId": "call-1",
				"toolName":   "secret_tool",
				"result": map[string]any{
					"content": []map[string]any{{"type": "text", "text": "SECRET-RESULT"}},
				},
				"isError":    false,
				"durationMs": 12,
			})
		}
		text := ""
		for i := 0; i < deltas; i++ {
			text += fmt.Sprintf("part-%d", i)
		}
		_ = enc.Encode(map[string]any{
			"type": "message_end",
			"message": map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{"type": "thinking", "thinking": "SECRET-THINKING"},
					map[string]any{"type": "text", "text": text},
					map[string]any{"type": "toolCall", "id": "call-1", "name": "secret_tool", "arguments": map[string]any{"token": "SECRET-TOOL"}},
				},
				"timestamp":  3,
				"stopReason": "stop",
			},
		})
		_ = enc.Encode(map[string]any{"type": "agent_settled", "aborted": false})
	}
}

func envInt(name string, fallback int) int {
	n, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return fallback
	}
	return n
}

type fakePeer struct {
	user     string
	mu       sync.Mutex
	frames   [][]byte
	allows   atomic.Bool
	failSend atomic.Bool
	closed   atomic.Bool
}

func newFakePeer(user string) *fakePeer {
	p := &fakePeer{user: user}
	p.allows.Store(true)
	return p
}

func (p *fakePeer) UserID() string { return p.user }

func (p *fakePeer) Allows(bool) bool { return p.allows.Load() }

func (p *fakePeer) Send(data []byte, _ bool) error {
	if p.failSend.Load() {
		return errors.New("send failed")
	}
	p.mu.Lock()
	p.frames = append(p.frames, append([]byte(nil), data...))
	p.mu.Unlock()
	return nil
}

func (p *fakePeer) Close() { p.closed.Store(true) }

func (p *fakePeer) waitFrame(t *testing.T, timeout time.Duration, pred func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		p.mu.Lock()
		for _, raw := range p.frames {
			var frame map[string]any
			if json.Unmarshal(raw, &frame) == nil && pred(frame) {
				p.mu.Unlock()
				return frame
			}
		}
		p.mu.Unlock()
		if time.Now().After(deadline) {
			p.mu.Lock()
			var dump []string
			for _, raw := range p.frames {
				dump = append(dump, string(raw))
			}
			p.mu.Unlock()
			t.Fatalf("timed out waiting for frame; got %v", dump)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type testEnv struct {
	dir       string
	work      string
	session   string
	state     string
	cfg       *Config
	delay     int
	deltas    int
	extension bool
	extMode   string
	handled   bool
}

func newTestEnv(t *testing.T, users []Grant, tools []string) *testEnv {
	t.Helper()
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	session := filepath.Join(dir, "session.jsonl")
	header, _ := json.Marshal(map[string]any{
		"type":      "session",
		"version":   3,
		"id":        "session-1",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"cwd":       work,
	})
	if err := os.WriteFile(session, append(header, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	env := &testEnv{
		dir:     dir,
		work:    work,
		session: session,
		state:   filepath.Join(dir, "state"),
		deltas:  1,
	}
	env.cfg = &Config{
		Executable: os.Args[0],
		Sessions: []SessionConfig{{
			ID:          "main",
			Title:       "Main",
			WorkingDir:  work,
			SessionFile: session,
			Owner:       "owner",
			Tools:       tools,
			Users:       users,
		}},
	}
	return env
}

func (e *testEnv) reload(users []Grant) *Config {
	cfg := *e.cfg
	cfg.Sessions = append([]SessionConfig(nil), e.cfg.Sessions...)
	cfg.Sessions[0].Users = users
	return &cfg
}

func newTestAdapter(t *testing.T, env *testEnv, user string) (*Adapter, *fakePeer) {
	t.Helper()
	a, err := New(env.cfg, env.state)
	if err != nil {
		t.Fatal(err)
	}
	a.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	a.AuthorityUntil(time.Now().Add(time.Hour))
	a.buildCommand = func(s *normalizedSession) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFakeVanora$")
		cmd.Dir = s.workDir
		cmd.Env = append(os.Environ(),
			"VANORA_FAKE_PROCESS=1",
			fmt.Sprintf("FAKE_DELAY_MS=%d", env.delay),
			fmt.Sprintf("FAKE_DELTAS=%d", env.deltas),
			fmt.Sprintf("FAKE_EXTENSION=%t", env.extension),
			fmt.Sprintf("FAKE_EXTENSION_MODE=%s", env.extMode),
			fmt.Sprintf("FAKE_HANDLED=%t", env.handled),
		)
		return cmd, nil
	}
	t.Cleanup(func() { _ = a.Close() })
	p := newFakePeer(user)
	a.Open(p)
	t.Cleanup(func() { a.Closed(p) })
	return a, p
}

func subscribeSession(t *testing.T, a *Adapter, p *fakePeer) {
	t.Helper()
	id := sendRequest(t, a, p, map[string]any{"type": "session.open", "session_id": "main"})
	_ = resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == id
	}))
}

func waitRunStatus(t *testing.T, a *Adapter, runID, status string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		sr := a.sessions["main"]
		var got string
		if sr != nil {
			if rec, ok := sr.ps.Runs[runID]; ok {
				got = rec.Status
			}
		}
		a.mu.Unlock()
		if got == status {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("run %s status = %q, want %q", runID, got, status)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func sendRequest(t *testing.T, a *Adapter, p *fakePeer, req map[string]any) string {
	t.Helper()
	id, _ := req["request_id"].(string)
	if id == "" {
		id = fmt.Sprintf("req-%d", time.Now().UnixNano())
		req["request_id"] = id
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	a.Message(p, raw)
	return id
}

func resultData(t *testing.T, frame map[string]any) map[string]any {
	t.Helper()
	if frame["type"] != "result" {
		t.Fatalf("expected result, got %v", frame)
	}
	data, _ := frame["data"].(map[string]any)
	if data == nil {
		t.Fatalf("result has no data: %v", frame)
	}
	return data
}

func TestDefaultCommandForcesTextOnlyWithoutTools(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	nc, err := normalizeConfig(env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{cfg: nc, now: time.Now}
	cmd, err := a.defaultCommand(nc.sessions[0])
	if err != nil {
		t.Fatal(err)
	}
	args := cmd.Args
	for _, want := range []string{
		"--no-tools", "--no-extensions", "--no-mcp", "--no-skills",
		"--no-prompt-templates", "--no-approve", "--mode", "rpc",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("args %v missing %q", args, want)
		}
	}
	if !slices.Contains(args, "--session") || args[len(args)-1] != env.session {
		t.Fatalf("session argument not last: %v", args)
	}

	withTools := newTestEnv(t, nil, []string{"read", "grep"})
	nc2, err := normalizeConfig(withTools.cfg)
	if err != nil {
		t.Fatal(err)
	}
	a2 := &Adapter{cfg: nc2, now: time.Now}
	cmd2, err := a2.defaultCommand(nc2.sessions[0])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(cmd2.Args, "--tools") || !slices.Contains(cmd2.Args, "read,grep") {
		t.Fatalf("tools args not selected: %v", cmd2.Args)
	}
	if slices.Contains(cmd2.Args, "--no-tools") {
		t.Fatalf("both tool and no-tool flags: %v", cmd2.Args)
	}
}

func TestResumeLargeBacklogRequestsSnapshotWithoutClosingPeer(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	a, p := newTestAdapter(t, env, "owner")
	a.mu.Lock()
	sr := a.sessions["main"]
	for i := 0; i < maxReplayEvents+1; i++ {
		a.appendEventLocked(sr, "run-1", "text.delta", map[string]string{"text": "x"}, false)
	}
	a.mu.Unlock()
	subscribeSession(t, a, p)

	id := sendRequest(t, a, p, map[string]any{
		"type":       "events.resume",
		"session_id": "main",
		"after_seq":  int64(0),
	})
	frame := p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == id
	})
	if frame["code"] != "snapshot_required" {
		t.Fatalf("resume error = %v, want snapshot_required", frame)
	}
	if p.closed.Load() {
		t.Fatal("large replay closed the peer")
	}
	// The rejected resume must leave the session unsubscribed, but the peer
	// must still serve a fresh snapshot.
	subscribeSession(t, a, p)
	if p.closed.Load() {
		t.Fatal("peer closed after snapshot reopen")
	}
}

func TestReloadACLAbortsPeerWithPendingList(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	a, p := newTestAdapter(t, env, "owner")
	a.mu.Lock()
	a.peers[p].pendingLists.Add(1)
	a.mu.Unlock()
	if err := a.ReloadACL(env.reload(nil)); err != nil {
		t.Fatal(err)
	}
	if !p.closed.Load() {
		t.Fatal("peer with a list authorized under the old ACL stayed open")
	}
}

func TestLoadConfigReadsLocalJSON(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	path := filepath.Join(env.dir, "config.json")
	raw, err := json.Marshal(env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sessions) != 1 || cfg.Sessions[0].ID != "main" {
		t.Fatalf("loaded config = %+v", cfg)
	}
	if err := os.WriteFile(path, append(raw, []byte("\n{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("trailing config data was accepted")
	}
	var withUnknown map[string]any
	_ = json.Unmarshal(raw, &withUnknown)
	withUnknown["bogus"] = true
	unknown, _ := json.Marshal(withUnknown)
	if err := os.WriteFile(path, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown config field was accepted")
	}
	if _, err := LoadConfig("https://example.com/config.json"); err == nil {
		t.Fatal("remote config URL was accepted")
	}
}

func TestSessionListDistinguishesTextOnlyRun(t *testing.T) {
	env := newTestEnv(t, []Grant{{UserID: "guest", Read: true, Tools: true}}, nil)
	a, p := newTestAdapter(t, env, "guest")
	id := sendRequest(t, a, p, map[string]any{"type": "session.list"})
	frame := p.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == id
	})
	data, ok := frame["data"].(map[string]any)
	if !ok {
		t.Fatalf("session.list data missing: %v", frame)
	}
	sessions, ok := data["sessions"].([]any)
	if !ok || len(sessions) != 1 {
		t.Fatalf("sessions = %v", data["sessions"])
	}
	session, ok := sessions[0].(map[string]any)
	if !ok {
		t.Fatalf("session = %v", sessions[0])
	}
	if session["can_run_tools"] != true || session["tools_enabled"] != false {
		t.Fatalf("text-only session summary = %v", session)
	}
}

func TestLauncherAndArgumentAllowlist(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	node := filepath.Join(env.dir, "node.exe")
	if err := os.WriteFile(node, []byte("stub"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(env.dir, "cli.js")
	if err := os.WriteFile(script, []byte("// stub\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := *env.cfg
	cfg.Executable = node
	cfg.LauncherArgs = []string{script}
	cfg.Arguments = []string{"--provider", "local", "--model", "test:high"}
	nc, err := normalizeConfig(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{cfg: nc, now: time.Now}
	cmd, err := a.defaultCommand(nc.sessions[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Args) < 2 || cmd.Args[0] != node || cmd.Args[1] != script {
		t.Fatalf("launcher prefix missing: %v", cmd.Args)
	}
	if !slices.Contains(cmd.Args, "--provider") || !slices.Contains(cmd.Args, "local") {
		t.Fatalf("separated provider args missing: %v", cmd.Args)
	}

	bad := cfg
	bad.Arguments = []string{"--extension=evil"}
	if _, err := normalizeConfig(&bad); err == nil {
		t.Fatal("extension argument was accepted")
	}
	bad = cfg
	bad.LauncherArgs = []string{script, script}
	if _, err := normalizeConfig(&bad); err == nil {
		t.Fatal("multiple launcher scripts were accepted")
	}
}

func TestReadOnlyCannotStartAndSnapshotFiltersInternalContent(t *testing.T) {
	env := newTestEnv(t, []Grant{{UserID: "reader", Read: true}}, nil)
	entry := func(id string, parent any, message map[string]any) {
		line, _ := json.Marshal(map[string]any{
			"type":      "message",
			"id":        id,
			"parentId":  parent,
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			"message":   message,
		})
		f, err := os.OpenFile(env.session, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(append(line, '\n'))
		_ = f.Close()
	}
	entry("u1", nil, map[string]any{"role": "user", "content": "hello", "timestamp": 1})
	entry("a1", "u1", map[string]any{
		"role": "assistant",
		"content": []any{
			map[string]any{"type": "thinking", "thinking": "SECRET-THINKING"},
			map[string]any{"type": "text", "text": "answer"},
			map[string]any{"type": "toolCall", "name": "x", "arguments": map[string]any{"token": "SECRET-TOOL"}},
		},
		"timestamp": 2,
	})
	entry("t1", "a1", map[string]any{"role": "toolResult", "toolCallId": "x", "content": "SECRET-RESULT"})

	a, p := newTestAdapter(t, env, "reader")
	id := sendRequest(t, a, p, map[string]any{"type": "session.open", "session_id": "main"})
	data := resultData(t, p.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == id
	}))
	messages, _ := data["messages"].([]any)
	if len(messages) != 2 {
		t.Fatalf("expected two exposed messages, got %v", messages)
	}
	blob, _ := json.Marshal(messages)
	if strings.Contains(string(blob), "SECRET") {
		t.Fatalf("internal content leaked: %s", blob)
	}

	startID := sendRequest(t, a, p, map[string]any{
		"type": "run.start", "session_id": "main", "text": "hi",
	})
	errFrame := p.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == startID
	})
	if errFrame["code"] != codeToolDenied {
		t.Fatalf("read-only run got %v", errFrame)
	}
}

func TestRunCompletionEventsAndIdempotency(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	a, p := newTestAdapter(t, env, "owner")
	subscribeSession(t, a, p)
	startID := sendRequest(t, a, p, map[string]any{
		"type": "run.start", "session_id": "main", "text": "hello", "request_id": "same-request",
	})
	data := resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == startID
	}))
	runID, _ := data["run_id"].(string)
	if runID == "" {
		t.Fatal("missing run id")
	}
	p.waitFrame(t, 5*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCompleted && f["run_id"] == runID
	})
	for _, raw := range p.frames {
		if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "secret_tool") {
			t.Fatalf("internal record leaked: %s", raw)
		}
	}

	again := sendRequest(t, a, p, map[string]any{
		"type": "run.start", "session_id": "main", "text": "hello", "request_id": "same-request",
	})
	data = resultData(t, p.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == again
	}))
	if data["run_id"] != runID {
		t.Fatalf("idempotent retry returned %v, want %v", data["run_id"], runID)
	}

	conflictID := sendRequest(t, a, p, map[string]any{
		"type": "run.start", "session_id": "main", "text": "different", "request_id": "same-request",
	})
	conflict := p.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == conflictID
	})
	if conflict["code"] != codeRequestConflict {
		t.Fatalf("conflict code = %v", conflict)
	}
}

func TestIdempotencySurvivesRestart(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	a, p := newTestAdapter(t, env, "owner")
	subscribeSession(t, a, p)
	id := sendRequest(t, a, p, map[string]any{
		"type": "run.start", "session_id": "main", "text": "hello", "request_id": "durable-request",
	})
	data := resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == id
	}))
	runID, _ := data["run_id"].(string)
	waitRunStatus(t, a, runID, statusCompleted)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	a2, p2 := newTestAdapter(t, env, "owner")
	subscribeSession(t, a2, p2)
	again := sendRequest(t, a2, p2, map[string]any{
		"type": "run.start", "session_id": "main", "text": "hello", "request_id": "durable-request",
	})
	data = resultData(t, p2.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == again
	}))
	if data["run_id"] != runID {
		t.Fatalf("restart retry returned %v, want %v", data["run_id"], runID)
	}
}

func TestDisconnectDoesNotCancelAcceptedRun(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.delay = 1500
	a, p := newTestAdapter(t, env, "owner")
	subscribeSession(t, a, p)
	id := sendRequest(t, a, p, map[string]any{"type": "run.start", "session_id": "main", "text": "slow"})
	data := resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == id
	}))
	runID, _ := data["run_id"].(string)
	p.allows.Store(false)
	time.Sleep(1200 * time.Millisecond)
	a.mu.Lock()
	r := a.runs[runID]
	stillRunning := r != nil && !r.terminal
	a.mu.Unlock()
	if !stillRunning {
		t.Fatal("phone disconnect cancelled the run")
	}
	waitRunStatus(t, a, runID, statusCompleted)
	p.allows.Store(true)
	resumeID := sendRequest(t, a, p, map[string]any{
		"type": "events.resume", "session_id": "main", "after_seq": 0,
	})
	_ = resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == resumeID
	}))
	p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCompleted && f["run_id"] == runID
	})
}

func TestAuthorityRestoreRequiresValidatedDeadline(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	a, err := New(env.cfg, env.state)
	if err != nil {
		t.Fatal(err)
	}
	a.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { _ = a.Close() })
	state := func() (bool, time.Time) {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.effectiveOnlineLocked(), a.authorityUntil
	}
	if online, _ := state(); online {
		t.Fatal("adapter started with unbounded authority")
	}
	a.AuthorityRestored()
	if online, _ := state(); online {
		t.Fatal("restore without a deadline granted authority")
	}
	deadline := time.Now().Add(time.Hour)
	a.AuthorityUntil(deadline)
	if online, until := state(); !online || !until.Equal(deadline) {
		t.Fatalf("AuthorityUntil: online=%v until=%v", online, until)
	}
	a.AuthorityLost()
	if online, until := state(); online || !until.Equal(deadline) {
		t.Fatalf("AuthorityLost: online=%v until=%v", online, until)
	}
	a.AuthorityRestored()
	if online, until := state(); !online || !until.Equal(deadline) {
		t.Fatalf("AuthorityRestored: online=%v until=%v", online, until)
	}
	a.AuthorityUntil(time.Time{})
	if online, _ := state(); online {
		t.Fatal("zero deadline granted authority")
	}
	a.AuthorityRestored()
	if online, _ := state(); online {
		t.Fatal("restore after expiry granted authority")
	}
}

func TestAuthorityLossCancelsWithoutPeerConnectivity(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.delay = 5000
	a, p := newTestAdapter(t, env, "owner")
	subscribeSession(t, a, p)
	id := sendRequest(t, a, p, map[string]any{"type": "run.start", "session_id": "main", "text": "slow"})
	data := resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == id
	}))
	runID, _ := data["run_id"].(string)
	p.allows.Store(false)
	a.AuthorityLost()
	waitRunStatus(t, a, runID, statusCancelled)
	p.allows.Store(true)
	resumeID := sendRequest(t, a, p, map[string]any{
		"type": "events.resume", "session_id": "main", "after_seq": 0,
	})
	_ = resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == resumeID
	}))
	p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCancelled && f["run_id"] == runID
	})
}

func TestAuthorityDeadlineCancelsWithoutLink(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.delay = 5000
	a, p := newTestAdapter(t, env, "owner")
	subscribeSession(t, a, p)
	a.AuthorityUntil(time.Now().Add(time.Second))
	id := sendRequest(t, a, p, map[string]any{"type": "run.start", "session_id": "main", "text": "slow"})
	data := resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == id
	}))
	runID, _ := data["run_id"].(string)
	p.allows.Store(false)
	waitRunStatus(t, a, runID, statusCancelled)
	p.allows.Store(true)
	resumeID := sendRequest(t, a, p, map[string]any{
		"type": "events.resume", "session_id": "main", "after_seq": 0,
	})
	_ = resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == resumeID
	}))
	p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCancelled && f["run_id"] == runID
	})
}

func TestACLRevokeCancelsJob(t *testing.T) {
	env := newTestEnv(t, []Grant{{UserID: "guest", Read: true, Tools: true}}, nil)
	env.delay = 5000
	a, p := newTestAdapter(t, env, "guest")
	id := sendRequest(t, a, p, map[string]any{"type": "run.start", "session_id": "main", "text": "slow"})
	data := resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == id
	}))
	runID, _ := data["run_id"].(string)
	if err := a.ReloadACL(env.reload(nil)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		rec := a.sessions["main"].ps.Runs[runID]
		a.mu.Unlock()
		if rec.Status == statusCancelled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run status = %q", rec.Status)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestExtensionDialogCancelledLocally(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.extension = true
	a, p := newTestAdapter(t, env, "owner")
	subscribeSession(t, a, p)
	id := sendRequest(t, a, p, map[string]any{"type": "run.start", "session_id": "main", "text": "hello"})
	_ = resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == id
	}))
	p.waitFrame(t, 5*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCompleted
	})
	for _, raw := range p.frames {
		if strings.Contains(string(raw), "extension_ui") || strings.Contains(string(raw), "Allow?") {
			t.Fatalf("extension dialog leaked: %s", raw)
		}
	}
}

func TestSendFailureClosesPeer(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	a, p := newTestAdapter(t, env, "owner")
	p.failSend.Store(true)
	sendRequest(t, a, p, map[string]any{"type": "session.list"})
	deadline := time.Now().Add(2 * time.Second)
	for !p.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("peer was not closed after send failure")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = a
}

func TestSnapshotTooLargeIsBounded(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.cfg.MaxSnapshotBytes = 64
	line, _ := json.Marshal(map[string]any{
		"type": "message", "id": "u1", "parentId": nil,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"message":   map[string]any{"role": "user", "content": strings.Repeat("x", 200), "timestamp": 1},
	})
	f, _ := os.OpenFile(env.session, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()
	a, p := newTestAdapter(t, env, "owner")
	id := sendRequest(t, a, p, map[string]any{"type": "session.open", "session_id": "main"})
	frame := p.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == id
	})
	if frame["code"] != codeSnapshotLarge {
		t.Fatalf("oversized snapshot code = %v", frame)
	}
}

func TestEventsResumeRetention(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.cfg.Retention.MaxEvents = 2
	env.deltas = 4
	a, p := newTestAdapter(t, env, "owner")
	subscribeSession(t, a, p)
	id := sendRequest(t, a, p, map[string]any{"type": "run.start", "session_id": "main", "text": "hello"})
	_ = resultData(t, p.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == id
	}))
	p.waitFrame(t, 5*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCompleted
	})
	resumeID := sendRequest(t, a, p, map[string]any{
		"type": "events.resume", "session_id": "main", "after_seq": 0,
	})
	frame := p.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == resumeID
	})
	if frame["code"] != codeSnapshotNeeded {
		t.Fatalf("resume code = %v", frame)
	}
}

func TestUnknownSessionErrorIsDelivered(t *testing.T) {
	env := newTestEnv(t, []Grant{{UserID: "outsider", Read: true}}, nil)
	a, p := newTestAdapter(t, env, "outsider")
	id := sendRequest(t, a, p, map[string]any{"type": "session.open", "session_id": "nope"})
	frame := p.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == id
	})
	if frame["code"] != codeUnavailable {
		t.Fatalf("unknown session code = %v", frame)
	}
	if _, attached := frame["session_id"]; attached {
		t.Fatalf("error disclosed session id: %v", frame)
	}
}

func TestZeroSessionsAndApprovalGuardCommand(t *testing.T) {
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
			ShowThinking:   true,
			ShowTools:      true,
			ApprovalPolicy: "remote",
		}},
	}
	a, err := New(cfg, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("zero-session config rejected: %v", err)
	}
	defer a.Close()

	// Create a session through the workspace and inspect defaultCommand.
	a.AuthorityUntil(time.Now().Add(time.Hour))
	p := newFakePeer("owner")
	a.Open(p)
	defer a.Closed(p)
	createID := sendRequest(t, a, p, map[string]any{
		"type":         "session.create",
		"workspace_id": "proj",
		"title":        "New Chat",
	})
	data := resultData(t, p.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == createID
	}))
	sid, _ := data["session_id"].(string)
	if sid == "" {
		t.Fatalf("missing session_id: %v", data)
	}
	a.mu.Lock()
	sr := a.sessions[sid]
	a.mu.Unlock()
	cmd, err := a.defaultCommand(sr.cfg)
	if err != nil {
		t.Fatal(err)
	}
	idxExt := slices.Index(cmd.Args, "-e")
	if idxExt < 0 || idxExt+1 >= len(cmd.Args) || !strings.HasSuffix(cmd.Args[idxExt+1], "approval-guard.mjs") {
		t.Fatalf("expected embedded approval-guard.mjs in args: %v", cmd.Args)
	}
	if _, err := os.Stat(cmd.Args[idxExt+1]); err != nil {
		t.Fatalf("materialized guard extension missing: %v", err)
	}
	if cmd.Args[len(cmd.Args)-2] != "--session" || cmd.Args[len(cmd.Args)-1] != sr.cfg.sessionFile {
		t.Fatalf("--session must remain last: %v", cmd.Args)
	}
}

func TestWorkspaceCreatePersistenceAndReload(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "proj")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Executable: os.Args[0],
		Workspaces: []WorkspaceConfig{{
			ID:         "proj",
			Title:      "Project",
			WorkingDir: work,
			SessionDir: filepath.Join(dir, "vanora-sessions"),
			Owner:      "owner",
			Tools:      []string{"read"},
		}},
	}
	stateDir := filepath.Join(dir, "state")
	a, err := New(cfg, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	a.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	a.AuthorityUntil(time.Now().Add(time.Hour))

	owner := newFakePeer("owner")
	guest := newFakePeer("guest")
	a.Open(owner)
	a.Open(guest)

	// Owner sees workspace, guest sees none.
	wOwner := sendRequest(t, a, owner, map[string]any{"type": "workspace.list"})
	wData := resultData(t, owner.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == wOwner
	}))
	if list, _ := wData["workspaces"].([]any); len(list) != 1 {
		t.Fatalf("owner workspaces = %v", wData)
	}
	wGuest := sendRequest(t, a, guest, map[string]any{"type": "workspace.list"})
	wgData := resultData(t, guest.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == wGuest
	}))
	if list, _ := wgData["workspaces"].([]any); len(list) != 0 {
		t.Fatalf("guest workspaces = %v", wgData)
	}

	// Guest cannot create session.
	gCreate := sendRequest(t, a, guest, map[string]any{
		"type": "session.create", "workspace_id": "proj", "title": "Nope",
	})
	gErr := guest.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == gCreate
	})
	if gErr["code"] != codeUnavailable {
		t.Fatalf("guest create = %v", gErr)
	}

	// Owner creates session with idempotency and conflict check.
	c1 := sendRequest(t, a, owner, map[string]any{
		"type": "session.create", "request_id": "create-1", "workspace_id": "proj", "title": "Sprint 1",
	})
	c1Data := resultData(t, owner.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == c1
	}))
	sid, _ := c1Data["session_id"].(string)
	if sid == "" || c1Data["title"] != "Sprint 1" {
		t.Fatalf("unexpected create result: %v", c1Data)
	}
	c2 := sendRequest(t, a, owner, map[string]any{
		"type": "session.create", "request_id": "create-1", "workspace_id": "proj", "title": "Sprint 1",
	})
	c2Data := resultData(t, owner.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == c2
	}))
	if c2Data["session_id"] != sid {
		t.Fatalf("idempotent create returned %v, want %v", c2Data["session_id"], sid)
	}
	cConflict := sendRequest(t, a, owner, map[string]any{
		"type": "session.create", "request_id": "create-1", "workspace_id": "proj", "title": "Other",
	})
	conflictFrame := owner.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "error" && f["request_id"] == cConflict
	})
	if conflictFrame["code"] != codeRequestConflict {
		t.Fatalf("conflict = %v", conflictFrame)
	}
	a.Closed(owner)
	a.Closed(guest)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart adapter and verify created session persisted and is listed.
	a2, err := New(cfg, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()
	a2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	a2.AuthorityUntil(time.Now().Add(time.Hour))
	owner2 := newFakePeer("owner")
	a2.Open(owner2)
	defer a2.Closed(owner2)
	listID := sendRequest(t, a2, owner2, map[string]any{"type": "session.list"})
	listData := resultData(t, owner2.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == listID
	}))
	sessions, _ := listData["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("expected persisted session after restart, got %v", listData)
	}

	// Removing workspace via ReloadACL removes created session.
	cfgNoWS := &Config{Executable: os.Args[0]}
	if err := a2.ReloadACL(cfgNoWS); err != nil {
		t.Fatal(err)
	}
	a2.mu.Lock()
	remaining := len(a2.sessions)
	a2.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("created session survived workspace removal: %d", remaining)
	}
}

func TestRichThinkingToolsAndMixedGuestIsolation(t *testing.T) {
	env := newTestEnv(t, []Grant{{UserID: "guest", Read: true}}, []string{"read"})
	env.cfg.Sessions[0].ShowThinking = true
	env.cfg.Sessions[0].ShowTools = true
	a, owner := newTestAdapter(t, env, "owner")
	guest := newFakePeer("guest")
	a.Open(guest)
	defer a.Closed(guest)

	subscribeSession(t, a, owner)
	subscribeSession(t, a, guest)

	startID := sendRequest(t, a, owner, map[string]any{
		"type": "run.start", "session_id": "main", "text": "inspect",
	})
	runID, _ := resultData(t, owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == startID
	}))["run_id"].(string)

	owner.waitFrame(t, 5*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCompleted && f["run_id"] == runID
	})
	guest.waitFrame(t, 5*time.Second, func(f map[string]any) bool {
		return f["type"] == "event" && f["kind"] == kindRunCompleted && f["run_id"] == runID
	})

	// Owner saw thinking + tool lifecycle events.
	ownerKinds := map[string]bool{}
	owner.mu.Lock()
	for _, raw := range owner.frames {
		var f map[string]any
		if json.Unmarshal(raw, &f) == nil && f["type"] == "event" {
			ownerKinds[fmt.Sprint(f["kind"])] = true
		}
	}
	owner.mu.Unlock()
	for _, want := range []string{kindThinkingDelta, kindToolCall, kindToolStart, kindToolUpdate, kindToolEnd, kindTextDelta, kindRunCompleted} {
		if !ownerKinds[want] {
			t.Fatalf("owner missing event kind %q; saw %v", want, ownerKinds)
		}
	}

	// Guest saw ZERO secret content and strictly contiguous seq numbers (1..N).
	var lastSeq int64
	guest.mu.Lock()
	for _, raw := range guest.frames {
		if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "secret_tool") {
			guest.mu.Unlock()
			t.Fatalf("guest frame leaked internal data: %s", raw)
		}
		var f struct {
			Type string `json:"type"`
			Seq  int64  `json:"seq"`
		}
		if json.Unmarshal(raw, &f) == nil && f.Type == "event" {
			if f.Seq != lastSeq+1 {
				guest.mu.Unlock()
				t.Fatalf("guest seq gap: got %d after %d", f.Seq, lastSeq)
			}
			lastSeq = f.Seq
		}
	}
	guest.mu.Unlock()

	// Snapshots also respect visibility: owner gets thinking + tools, guest gets text only.
	oOpen := sendRequest(t, a, owner, map[string]any{"type": "session.open", "session_id": "main"})
	oSnap := resultData(t, owner.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == oOpen
	}))
	oBlob, _ := json.Marshal(oSnap)
	if !strings.Contains(string(oBlob), "SECRET-THINKING") || !strings.Contains(string(oBlob), "SECRET-RESULT") {
		t.Fatalf("owner snapshot missing thinking/tool result: %s", oBlob)
	}

	gOpen := sendRequest(t, a, guest, map[string]any{"type": "session.open", "session_id": "main"})
	gSnap := resultData(t, guest.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
		return f["type"] == "result" && f["request_id"] == gOpen
	}))
	gBlob, _ := json.Marshal(gSnap)
	if strings.Contains(string(gBlob), "SECRET") {
		t.Fatalf("guest snapshot leaked internal content: %s", gBlob)
	}
}

func TestRemoteApprovalAndAskDialogFlow(t *testing.T) {
	t.Run("confirm approved by owner and rejected for guest", func(t *testing.T) {
		env := newTestEnv(t, []Grant{{UserID: "guest", Read: true, Tools: true}}, []string{"bash"})
		env.cfg.Sessions[0].ApprovalPolicy = "remote"
		env.extMode = "confirm"
		a, owner := newTestAdapter(t, env, "owner")
		guest := newFakePeer("guest")
		a.Open(guest)
		defer a.Closed(guest)
		subscribeSession(t, a, owner)

		startID := sendRequest(t, a, owner, map[string]any{
			"type": "run.start", "session_id": "main", "text": "run cmd",
		})
		runID, _ := resultData(t, owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
			return f["type"] == "result" && f["request_id"] == startID
		}))["run_id"].(string)

		reqFrame := owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
			return f["type"] == "event" && f["kind"] == kindUIRequest && f["run_id"] == runID
		})
		reqData, _ := reqFrame["data"].(map[string]any)
		if reqData["ui_id"] != "ext-1" || reqData["method"] != "confirm" {
			t.Fatalf("unexpected ui.request: %v", reqFrame)
		}

		// Reopening session while pending includes pending_ui for owner, not guest.
		oOpen := sendRequest(t, a, owner, map[string]any{"type": "session.open", "session_id": "main"})
		oSnap := resultData(t, owner.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
			return f["type"] == "result" && f["request_id"] == oOpen
		}))
		if pui, _ := oSnap["pending_ui"].([]any); len(pui) != 1 {
			t.Fatalf("owner snapshot missing pending_ui: %v", oSnap)
		}
		gOpen := sendRequest(t, a, guest, map[string]any{"type": "session.open", "session_id": "main"})
		gSnap := resultData(t, guest.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
			return f["type"] == "result" && f["request_id"] == gOpen
		}))
		if _, leaked := gSnap["pending_ui"]; leaked {
			t.Fatalf("guest snapshot leaked pending_ui: %v", gSnap)
		}

		// Guest without approve grant cannot respond.
		gResp := sendRequest(t, a, guest, map[string]any{
			"type": "ui.respond", "session_id": "main", "run_id": runID, "ui_id": "ext-1", "confirmed": true,
		})
		gErr := guest.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
			return f["type"] == "error" && f["request_id"] == gResp
		})
		if gErr["code"] != codeUnavailable {
			t.Fatalf("guest respond = %v", gErr)
		}

		// Owner approves and run completes.
		okID := sendRequest(t, a, owner, map[string]any{
			"type": "ui.respond", "session_id": "main", "run_id": runID, "ui_id": "ext-1", "confirmed": true,
		})
		_ = resultData(t, owner.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
			return f["type"] == "result" && f["request_id"] == okID
		}))
		owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
			return f["type"] == "event" && f["kind"] == kindUIResolved && f["run_id"] == runID
		})
		owner.waitFrame(t, 5*time.Second, func(f map[string]any) bool {
			return f["type"] == "event" && f["kind"] == kindRunCompleted && f["run_id"] == runID
		})
	})

	t.Run("ask dialog answered remotely", func(t *testing.T) {
		env := newTestEnv(t, nil, []string{"ask"})
		env.cfg.Sessions[0].ApprovalPolicy = "remote"
		env.extMode = "ask"
		a, owner := newTestAdapter(t, env, "owner")
		subscribeSession(t, a, owner)

		startID := sendRequest(t, a, owner, map[string]any{
			"type": "run.start", "session_id": "main", "text": "pick db",
		})
		runID, _ := resultData(t, owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
			return f["type"] == "result" && f["request_id"] == startID
		}))["run_id"].(string)

		owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
			return f["type"] == "event" && f["kind"] == kindUIRequest && f["run_id"] == runID
		})
		ansID := sendRequest(t, a, owner, map[string]any{
			"type": "ui.respond", "session_id": "main", "run_id": runID, "ui_id": "ext-1",
			"answers": [][]string{{"Postgres"}},
		})
		_ = resultData(t, owner.waitFrame(t, 2*time.Second, func(f map[string]any) bool {
			return f["type"] == "result" && f["request_id"] == ansID
		}))
		owner.waitFrame(t, 5*time.Second, func(f map[string]any) bool {
			return f["type"] == "event" && f["kind"] == kindRunCompleted && f["run_id"] == runID
		})
	})

	t.Run("authority loss cancels pending approval", func(t *testing.T) {
		env := newTestEnv(t, nil, []string{"bash"})
		env.cfg.Sessions[0].ApprovalPolicy = "remote"
		env.extMode = "expect_cancel"
		a, owner := newTestAdapter(t, env, "owner")
		subscribeSession(t, a, owner)

		startID := sendRequest(t, a, owner, map[string]any{
			"type": "run.start", "session_id": "main", "text": "danger",
		})
		runID, _ := resultData(t, owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
			return f["type"] == "result" && f["request_id"] == startID
		}))["run_id"].(string)
		owner.waitFrame(t, 3*time.Second, func(f map[string]any) bool {
			return f["type"] == "event" && f["kind"] == kindUIRequest && f["run_id"] == runID
		})
		a.AuthorityLost()
		waitRunStatus(t, a, runID, statusCancelled)
	})
}
