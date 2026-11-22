package mobile

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vanora-relay/adapter/desktop"
	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/internal/membership"
	signalserver "vanora-relay/internal/signal"
)

func TestMain(m *testing.M) {
	if os.Getenv("VANORA_MOBILE_FAKE_CLI") == "1" {
		if err := runFakeMobileCLI(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runFakeMobileCLI() error {
	// Verify the desktop adapter attached the built-in approval guard extension
	// via `--no-extensions -e .../approval-guard.mjs`.
	idx := slices.Index(os.Args, "-e")
	if idx < 0 || idx+1 >= len(os.Args) || !strings.HasSuffix(os.Args[idx+1], "approval-guard.mjs") {
		return fmt.Errorf("missing approval-guard extension flag in args: %v", os.Args)
	}
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
		if json.Unmarshal([]byte(line), &cmd) != nil {
			continue
		}
		if cmd.Type == "abort" {
			return nil
		}
		if cmd.Type != "prompt" {
			continue
		}
		_ = enc.Encode(map[string]any{
			"id": cmd.ID, "type": "response", "command": "prompt", "success": true,
			"data": map[string]any{"disposition": "started"},
		})
		_ = enc.Encode(map[string]any{
			"type": "message_start",
			"message": map[string]any{"role": "user", "content": cmd.Message, "timestamp": 1},
		})
		_ = enc.Encode(map[string]any{
			"type": "message_start",
			"message": map[string]any{"role": "assistant", "content": []any{}, "timestamp": 2},
		})
		_ = enc.Encode(map[string]any{
			"type": "message_update",
			"assistantMessageEvent": map[string]any{"type": "thinking_delta", "delta": "plan step"},
		})
		_ = enc.Encode(map[string]any{
			"type": "extension_ui_request", "id": "approve-1", "method": "confirm",
			"title": "Allow tool \"bash\"?", "message": "echo hi",
		})
		for {
			respLine, err := rd.ReadString('\n')
			if err != nil {
				return io.EOF
			}
			var resp struct {
				Type      string `json:"type"`
				ID        string `json:"id"`
				Confirmed *bool  `json:"confirmed"`
			}
			if json.Unmarshal([]byte(respLine), &resp) == nil && resp.Type == "extension_ui_response" && resp.ID == "approve-1" {
				if resp.Confirmed == nil || !*resp.Confirmed {
					return fmt.Errorf("tool was not approved")
				}
				break
			}
		}
		_ = enc.Encode(map[string]any{
			"type": "tool_execution_start", "toolCallId": "call-1", "toolName": "bash",
			"args": map[string]any{"command": "echo hi"},
		})
		_ = enc.Encode(map[string]any{
			"type": "tool_execution_end", "toolCallId": "call-1", "toolName": "bash",
			"result": map[string]any{"content": []map[string]any{{"type": "text", "text": "hi"}}},
			"isError": false, "durationMs": 5,
		})
		_ = enc.Encode(map[string]any{
			"type": "message_update",
			"assistantMessageEvent": map[string]any{"type": "text_delta", "delta": "done!"},
		})
		_ = enc.Encode(map[string]any{
			"type": "message_end",
			"message": map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{"type": "thinking", "thinking": "plan step"},
					map[string]any{"type": "text", "text": "done!"},
				},
				"timestamp": 3, "stopReason": "stop",
			},
		})
		_ = enc.Encode(map[string]any{"type": "agent_settled", "aborted": false})
	}
}

type testIdentity struct {
	creds   *endpoint.Credentials
	key     ed25519.PrivateKey
	signer  *identitytest.Authority
	subject string
}

func issue(t *testing.T, s *identitytest.Authority, subject string) *testIdentity {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	id := &testIdentity{key: k, signer: s, subject: subject}
	id.creds, _, err = id.Current(context.Background())
	must(t, err)
	return id
}
func (s *testIdentity) Current(context.Context) (*endpoint.Credentials, endpoint.LeaseProof, error) {
	now := time.Now()
	cert, err := s.signer.IssueWithKey("https://issuer.example", s.subject, s.key.Public().(ed25519.PublicKey), now)
	if err != nil {
		return nil, endpoint.LeaseProof{}, err
	}
	p, err := identity.VerifyCertificate(cert, s.signer.PublicKey(), now)
	if err != nil {
		return nil, endpoint.LeaseProof{}, err
	}
	nonce := make([]byte, 24)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, endpoint.LeaseProof{}, err
	}
	lease, _, err := s.signer.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
	if err != nil {
		return nil, endpoint.LeaseProof{}, err
	}
	c, err := endpoint.OpenCredentials(cert, s.key, s.signer.PublicKey(), now)
	return c, endpoint.LeaseProof{Certificate: cert, Lease: lease}, err
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	must(t, os.WriteFile(path, append(b, '\n'), 0600))
}

func TestNativeAdapters(t *testing.T) { exerciseAdapters(t, "") }

// Set VANORA_TEST_CLI to the installed upstream dist/cli.js. Only the model's
// HTTP endpoint is simulated; real Vanora handles prompts, sessions and RPC lifecycle.
func TestUpstreamVanoraRunAfterNetworkLoss(t *testing.T) {
	cli := os.Getenv("VANORA_TEST_CLI")
	if cli == "" {
		t.Skip("requires installed Vanora CLI; set VANORA_TEST_CLI")
	}
	exerciseAdapters(t, cli)
}
func exerciseAdapters(t *testing.T, cli string) {
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	dir := t.TempDir()
	_, ca, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	signer, err := identitytest.NewAuthorityWithKey(ca, 10*time.Minute)
	must(t, err)
	host := issue(t, signer, "owner")
	phone := issue(t, signer, "visitor")
	t.Setenv("STUN_URLS", "local")
	t.Setenv("TURN_PUBLIC_IP", "127.0.0.1")
	t.Setenv("TURN_BIND_IP", "127.0.0.1")
	t.Setenv("TURN_TCP", "false")
	t.Setenv("TURN_PORT", "0")
	t.Setenv("TURN_RELAY_MIN_PORT", "0")
	t.Setenv("TURN_RELAY_MAX_PORT", "0")
	network, err := ice.FromEnv()
	must(t, err)
	defer network.Close()
	hub := signalserver.New(signer.PublicKey(), &membership.Client{}, network)
	go hub.Run(ctx)
	srv := httptest.NewServer(hub)
	defer srv.Close()
	signalURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	sessionFile := filepath.Join(dir, "shared.jsonl")
	writeJSON(t, sessionFile, map[string]any{"type": "session", "version": 3, "id": "aa53b049-ce76-4dfc-b346-12896c2a0111", "timestamp": "2026-01-01T00:00:00Z", "cwd": dir})
	// Keep the session nonempty, as it would be after a locally started chat.
	f, err := os.OpenFile(sessionFile, os.O_APPEND|os.O_WRONLY, 0600)
	must(t, err)
	historyText := strings.Repeat("desktop history ", 1600)
	_, err = fmt.Fprintf(f, `{"type":"message","id":"00112233","parentId":null,"timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":[{"type":"text","text":%q}],"timestamp":1767225600000}}`+"\n", historyText)
	must(t, err)
	must(t, f.Close())
	executable, err := os.Executable()
	must(t, err)
	cfg := map[string]any{"executable": executable, "sessions": []any{map[string]any{"id": "shared", "title": "Shared project", "working_dir": dir, "session_file": sessionFile, "owner": host.creds.UserID(), "users": []any{map[string]any{"user_id": phone.creds.UserID(), "read": true, "tools": cli != ""}}}}}
	requested := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	releaseModel := func() { once.Do(func() { close(release) }) }
	var modelCalls atomic.Int32
	if cli != "" {
		model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if !strings.HasSuffix(r.URL.Path, "/chat/completions") || !strings.Contains(string(body), "test reconnect") {
				http.Error(w, "invalid test prompt", 400)
				return
			}
			modelCalls.Add(1)
			select {
			case requested <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			case <-ctx.Done():
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"chat1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"tiny\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"desktop replied\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"chat1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"tiny\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
		}))
		defer model.Close()
		defer releaseModel()
		node, err := exec.LookPath("node")
		must(t, err)
		cfg["executable"] = node
		cfg["launcher_args"] = []string{cli}
		t.Setenv("VANORA_AGENT_DIR", dir)
		t.Setenv("VANORA_OFFLINE", "1")
		writeJSON(t, filepath.Join(dir, "models.json"), map[string]any{"providers": map[string]any{"fixture": map[string]any{"api": "openai-completions", "baseUrl": model.URL + "/v1", "apiKey": "test-only", "models": []any{map[string]any{"id": "tiny", "name": "tiny"}}}}})
		writeJSON(t, filepath.Join(dir, "settings.json"), map[string]any{"defaultProvider": "fixture", "defaultModel": "tiny"})
	}
	cfgPath := filepath.Join(dir, "config.json")
	writeJSON(t, cfgPath, cfg)
	dc, err := desktop.LoadConfig(cfgPath)
	must(t, err)
	service, err := desktop.New(dc, filepath.Join(dir, "state"))
	must(t, err)
	defer service.Close()
	service.AuthorityUntil(time.Now().Add(time.Minute))
	desktopConn, err := transport.Dial(ctx, signalURL, "desktop", host, service)
	must(t, err)
	defer desktopConn.Close()
	must(t, desktopConn.Publish(ctx, "Office", []string{phone.creds.UserID()}))
	c := newClient(signalURL, phone)
	defer c.Close()
	directory, err := c.Devices()
	must(t, err)
	if !strings.Contains(directory, host.creds.DeviceID()) {
		t.Fatalf("incorrect directory %s", directory)
	}
	must(t, c.Connect(host.creds.DeviceID(), host.creds.UserID()))
	sessions, err := c.ListSessions()
	must(t, err)
	if !strings.Contains(sessions, "Shared project") {
		t.Fatalf("unexpected sessions %s", sessions)
	}
	if _, err = c.OpenSession("other"); err == nil || err.Error() != "unavailable" {
		t.Fatalf("unshared session: %v", err)
	}
	if err := c.Resume("shared", 9999); err == nil || err.Error() != "snapshot_required" {
		t.Fatalf("invalid resume cursor: %v", err)
	}
	snapshot, err := c.OpenSession("shared")
	must(t, err)
	if !strings.Contains(snapshot, strings.TrimSpace(historyText)) {
		t.Fatal("missing fragmented Vanora history")
	}
	requestID := NewRequestID()
	run, err := c.StartRun("shared", requestID, "test reconnect")
	if cli == "" {
		if err == nil || err.Error() != "tool_denied" {
			t.Fatalf("read-only guest run: %v", err)
		}
		return
	}
	must(t, err)
	select {
	case <-requested:
	case <-ctx.Done():
		t.Fatal("Vanora did not reach local model")
	}
	p, err := c.currentPeer()
	must(t, err)
	p.Close()
	releaseModel()
	foundText := false
	for {
		if ctx.Err() != nil {
			t.Fatal("timed out recovering run")
		}
		raw, err := c.NextEvent(1000)
		must(t, err)
		if raw == "" {
			continue
		}
		var ev struct {
			Kind string `json:"kind"`
			Seq  int64  `json:"seq"`
		}
		must(t, json.Unmarshal([]byte(raw), &ev))
		if ev.Kind == "text.delta" && strings.Contains(raw, "desktop replied") {
			foundText = true
		}
		if ev.Seq > 0 {
			must(t, c.Acknowledge("shared", ev.Seq))
		}
		if ev.Kind == "run.failed" || ev.Kind == "run.cancelled" {
			t.Fatal(raw)
		}
		if ev.Kind == "run.completed" {
			break
		}
	}
	if !foundText {
		t.Fatal("missing recovered text")
	}
	retried, err := c.StartRun("shared", requestID, "test reconnect")
	must(t, err)
	if retried != run || modelCalls.Load() != 1 {
		t.Fatalf("duplicate execution: %s / %s, model calls %d", run, retried, modelCalls.Load())
	}
}

func TestMobileEmbeddedCapabilities(t *testing.T) {
	t.Setenv("VANORA_MOBILE_FAKE_CLI", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	dir := t.TempDir()
	work := filepath.Join(dir, "repo")
	must(t, os.MkdirAll(work, 0o700))

	_, ca, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	signer, err := identitytest.NewAuthorityWithKey(ca, 10*time.Minute)
	must(t, err)
	// Same account on desktop and mobile (owner flow).
	host := issue(t, signer, "owner")
	phone := issue(t, signer, "owner")

	t.Setenv("STUN_URLS", "local")
	t.Setenv("TURN_PUBLIC_IP", "127.0.0.1")
	t.Setenv("TURN_BIND_IP", "127.0.0.1")
	t.Setenv("TURN_TCP", "false")
	t.Setenv("TURN_PORT", "0")
	t.Setenv("TURN_RELAY_MIN_PORT", "0")
	t.Setenv("TURN_RELAY_MAX_PORT", "0")
	network, err := ice.FromEnv()
	must(t, err)
	defer network.Close()

	hub := signalserver.New(signer.PublicKey(), &membership.Client{}, network)
	go hub.Run(ctx)
	srv := httptest.NewServer(hub)
	defer srv.Close()
	signalURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	executable, err := os.Executable()
	must(t, err)
	cfg := &desktop.Config{
		Executable: executable,
		Workspaces: []desktop.WorkspaceConfig{{
			ID:             "repo",
			Title:          "My Repo",
			WorkingDir:     work,
			SessionDir:     filepath.Join(dir, "vanora-sessions"),
			Owner:          host.creds.UserID(),
			Tools:          []string{"read", "bash"},
			ShowThinking:   true,
			ShowTools:      true,
			ApprovalPolicy: "remote",
		}},
	}
	service, err := desktop.New(cfg, filepath.Join(dir, "state"))
	must(t, err)
	defer service.Close()
	service.AuthorityUntil(time.Now().Add(time.Minute))

	desktopConn, err := transport.Dial(ctx, signalURL, "desktop", host, service)
	must(t, err)
	defer desktopConn.Close()
	must(t, desktopConn.Publish(ctx, "Workstation", nil))

	c := newClient(signalURL, phone)
	defer c.Close()

	must(t, c.Connect(host.creds.DeviceID(), host.creds.UserID()))
	var stateSnap map[string]string
	must(t, json.Unmarshal([]byte(c.ConnectionState()), &stateSnap))
	if stateSnap["state"] != "connected" || stateSnap["path"] != "direct" {
		t.Fatalf("unexpected ConnectionState: %v", stateSnap)
	}

	wsJSON, err := c.ListWorkspaces()
	must(t, err)
	if !strings.Contains(wsJSON, `"workspace_id":"repo"`) {
		t.Fatalf("unexpected workspaces: %s", wsJSON)
	}

	createReq := NewRequestID()
	createdJSON, err := c.CreateSession("repo", createReq, "Remote Session")
	must(t, err)
	var created struct {
		SessionID string `json:"session_id"`
	}
	must(t, json.Unmarshal([]byte(createdJSON), &created))
	if created.SessionID == "" {
		t.Fatalf("empty session_id: %s", createdJSON)
	}
	// Idempotent retry returns the same session.
	createdAgain, err := c.CreateSession("repo", createReq, "Remote Session")
	must(t, err)
	if !strings.Contains(createdAgain, created.SessionID) {
		t.Fatalf("non-idempotent CreateSession: %s vs %s", createdAgain, createdJSON)
	}

	_, err = c.OpenSession(created.SessionID)
	must(t, err)

	runJSON, err := c.StartRun(created.SessionID, NewRequestID(), "run bash")
	must(t, err)
	var started struct {
		RunID string `json:"run_id"`
	}
	must(t, json.Unmarshal([]byte(runJSON), &started))

	var sawConnState, sawThinking, sawToolStart, sawToolEnd, sawUIReq, sawText bool
	for {
		if ctx.Err() != nil {
			t.Fatal("timed out waiting for embedded run events")
		}
		raw, err := c.NextEvent(1000)
		must(t, err)
		if raw == "" {
			continue
		}
		var ev struct {
			Type  string          `json:"type"`
			State string          `json:"state"`
			Kind  string          `json:"kind"`
			Seq   int64           `json:"seq"`
			RunID string          `json:"run_id"`
			Data  json.RawMessage `json:"data"`
		}
		must(t, json.Unmarshal([]byte(raw), &ev))
		if ev.Type == "connection.state" && ev.State == "connected" {
			sawConnState = true
			continue
		}
		if ev.Seq > 0 {
			must(t, c.Acknowledge(created.SessionID, ev.Seq))
		}
		switch ev.Kind {
		case "thinking.delta":
			if strings.Contains(string(ev.Data), "plan step") {
				sawThinking = true
			}
		case "ui.request":
			sawUIReq = true
			var uiReq struct {
				UIID string `json:"ui_id"`
			}
			must(t, json.Unmarshal(ev.Data, &uiReq))
			_, err := c.RespondUI(created.SessionID, ev.RunID, uiReq.UIID, `{"confirmed":true}`)
			must(t, err)
		case "tool.start":
			sawToolStart = true
		case "tool.end":
			if strings.Contains(string(ev.Data), `"hi"`) {
				sawToolEnd = true
			}
		case "text.delta":
			if strings.Contains(string(ev.Data), "done!") {
				sawText = true
			}
		case "run.failed", "run.cancelled":
			t.Fatalf("run terminated unsuccessfully: %s", raw)
		case "run.completed":
			goto done
		}
	}
done:
	if !sawConnState || !sawThinking || !sawUIReq || !sawToolStart || !sawToolEnd || !sawText {
		t.Fatalf("missing expected events: conn=%v thinking=%v ui=%v toolStart=%v toolEnd=%v text=%v",
			sawConnState, sawThinking, sawUIReq, sawToolStart, sawToolEnd, sawText)
	}

	// Explicit Reconnect drops and restores the link while preserving subscriptions.
	must(t, c.Reconnect())
	sessionsJSON, err := c.ListSessions()
	must(t, err)
	if !strings.Contains(sessionsJSON, created.SessionID) {
		t.Fatalf("sessions after Reconnect missing created session: %s", sessionsJSON)
	}
}
