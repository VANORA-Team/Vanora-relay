package mobile

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
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
			"type":    "message_start",
			"message": map[string]any{"role": "user", "content": cmd.Message, "timestamp": 1},
		})
		_ = enc.Encode(map[string]any{
			"type":    "message_start",
			"message": map[string]any{"role": "assistant", "content": []any{}, "timestamp": 2},
		})
		_ = enc.Encode(map[string]any{
			"type":                  "message_update",
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
			"result":  map[string]any{"content": []map[string]any{{"type": "text", "text": "hi"}}},
			"isError": false, "durationMs": 5,
		})
		_ = enc.Encode(map[string]any{
			"type":                  "message_update",
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

type lanTestStore struct{ value string }

func (s *lanTestStore) Load() (string, error) { return s.value, nil }
func (s *lanTestStore) Save(value string) error {
	s.value = value
	return nil
}

func TestLANSharingWithoutAccount(t *testing.T) {
	t.Setenv("VANORA_MOBILE_FAKE_CLI", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	executable, err := os.Executable()
	must(t, err)
	service, err := desktop.New(&desktop.Config{
		Executable: executable,
		Workspaces: []desktop.WorkspaceConfig{
			{ID: "shared", WorkingDir: dir, SessionDir: filepath.Join(dir, "sessions"), Owner: "local",
				LANAccess: true, Tools: []string{"read"}, ApprovalPolicy: "remote"},
			{ID: "private", WorkingDir: dir, SessionDir: filepath.Join(dir, "private"), Owner: "local"},
		},
	}, filepath.Join(dir, "state"))
	must(t, err)
	defer service.Close()

	desktopStore := &lanTestStore{}
	server, err := lan.OpenServer(desktopStore, service)
	must(t, err)
	defer server.Stop()
	service.SetLANAuthority(server.Allows)
	if err := server.Listen(ctx, "0.0.0.0:0"); err == nil {
		t.Fatal("wildcard address accepted")
	}
	must(t, server.Listen(ctx, "127.0.0.1:0"))

	_, controlLink, err := server.Invite(lan.Control)
	must(t, err)
	target, err := lan.ParseTarget(controlLink)
	must(t, err)
	wrongPin := target
	wrongPin.Pin = target.Token
	controllerStore := &lanTestStore{}
	controller, err := NewLANClient(controllerStore)
	must(t, err)
	defer controller.Close()
	if err := controller.ConnectLAN(wrongPin.Link(), "Controller"); err == nil {
		t.Fatal("incorrect desktop key pin accepted")
	}
	must(t, controller.ConnectLAN(controlLink, "Controller"))
	if state := controller.ConnectionState(); !strings.Contains(state, `"path":"lan"`) || controller.UserID() != "" {
		t.Fatalf("unexpected LAN state: %s", state)
	}
	saved, err := lan.ParseTarget(controller.LANAddress())
	must(t, err)
	if saved.Token != "" {
		t.Fatal("connection retained the pairing token")
	}
	workspaces, err := controller.ListWorkspaces()
	must(t, err)
	if !strings.Contains(workspaces, `"workspace_id":"shared"`) || strings.Contains(workspaces, `"workspace_id":"private"`) {
		t.Fatalf("wrong LAN workspace scope: %s", workspaces)
	}

	readerStore := &lanTestStore{}
	reader, err := NewLANClient(readerStore)
	must(t, err)
	defer reader.Close()
	if err := reader.ConnectLAN(controlLink, "Reader"); !errors.Is(err, lan.ErrUnpaired) {
		t.Fatalf("pairing link reused by another key: %v", err)
	}
	invite, _, err := server.Invite(lan.Read)
	must(t, err)
	if !server.RevokeInvitation(invite.ID) || server.RevokeInvitation(invite.ID) {
		t.Fatal("unexpected pairing link revocation")
	}
	_, readLink, err := server.Invite(lan.Read)
	must(t, err)
	must(t, reader.ConnectLAN(readLink, "Reader"))
	readerAddress := reader.LANAddress()
	if _, err := reader.CreateSession("shared", NewRequestID(), "Denied"); !errors.Is(err, errUnavailable) {
		t.Fatalf("read-only device created a session: %v", err)
	}
	created, err := controller.CreateSession("shared", NewRequestID(), "Local conversation")
	must(t, err)
	var session struct {
		ID string `json:"session_id"`
	}
	must(t, json.Unmarshal([]byte(created), &session))
	_, err = reader.OpenSession(session.ID)
	must(t, err)
	if _, err := reader.StartRun(session.ID, NewRequestID(), "Denied"); err == nil || err.Error() != "tool_denied" {
		t.Fatalf("read-only device started a run: %v", err)
	}

	_, err = controller.OpenSession(session.ID)
	must(t, err)
	_, err = controller.StartRun(session.ID, NewRequestID(), "Request approval")
	must(t, err)
	for {
		if ctx.Err() != nil {
			t.Fatal("LAN run did not reach approval")
		}
		raw, err := controller.NextEvent(100)
		must(t, err)
		if strings.Contains(raw, `"kind":"ui.request"`) {
			break
		}
	}
	service.AuthorityLost()
	_, err = controller.OpenSession(session.ID)
	must(t, err)
	controllerID := ""
	for _, authorized := range server.Status().Clients {
		if authorized.Name == "Controller" {
			controllerID = authorized.ID
		}
	}
	if controllerID == "" {
		t.Fatal("controller missing from the authorized clients list")
	}
	must(t, server.RevokeClients(controllerID))
	service.RefreshLANAccess()
	if err := controller.Reconnect(); !errors.Is(err, lan.ErrUnpaired) {
		t.Fatalf("revoked device reconnected: %v", err)
	}
	for {
		if ctx.Err() != nil {
			t.Fatal("run continued after the controller was revoked")
		}
		raw, err := reader.NextEvent(100)
		must(t, err)
		if strings.Contains(raw, `"reason":"authority_lost"`) {
			t.Fatalf("official authority loss stopped a LAN run: %s", raw)
		}
		if strings.Contains(raw, `"reason":"lan_access_revoked"`) {
			break
		}
	}

	reader.Close()
	server.Stop()
	restarted, err := lan.OpenServer(desktopStore, service)
	must(t, err)
	defer restarted.Stop()
	service.SetLANAuthority(restarted.Allows)
	must(t, restarted.Listen(ctx, "127.0.0.1:0"))
	readTarget, err := lan.ParseTarget(readerAddress)
	must(t, err)
	readTarget.Address = restarted.Status().Address
	returning, err := NewLANClient(readerStore)
	must(t, err)
	defer returning.Close()
	must(t, returning.ConnectLAN(readTarget.Link(), "Reader"))
	if got := restarted.Status().Clients; len(got) != 1 || got[0].Name != "Reader" {
		t.Fatalf("authorization state did not persist: %+v", got)
	}
}

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
	desktopConn, err := transport.DialPairedDesktop(ctx, signalURL, host, service, func(_ string, peer endpoint.PeerIdentity, _ []byte) bool {
		return peer.DeviceID == phone.creds.DeviceID() && peer.PublicKey.Equal(phone.creds.PublicKey())
	})
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
			Owner:          desktop.LocalOwner,
			Tools:          []string{"read", "bash"},
			ShowThinking:   true,
			ShowTools:      true,
			ApprovalPolicy: "remote",
		}},
	}
	service, err := desktop.New(cfg, filepath.Join(dir, "state"))
	must(t, err)
	defer service.Close()
	service.SetOfficialOwner(host.creds.UserID())
	service.AuthorityUntil(time.Now().Add(time.Minute))

	desktopConn, err := transport.DialPairedDesktop(ctx, signalURL, host, service, func(_ string, peer endpoint.PeerIdentity, _ []byte) bool {
		return peer.DeviceID == phone.creds.DeviceID() && peer.PublicKey.Equal(phone.creds.PublicKey())
	})
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

func TestSelfRelaySharingWithoutAccount(t *testing.T) {
	t.Setenv("VANORA_MOBILE_FAKE_CLI", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Setenv("STUN_URLS", "local")
	t.Setenv("TURN_PUBLIC_IP", "127.0.0.1")
	t.Setenv("TURN_BIND_IP", "127.0.0.1")
	t.Setenv("TURN_PORT", "0")
	t.Setenv("TURN_TCP", "false")
	t.Setenv("TURN_RELAY_MIN_PORT", "0")
	t.Setenv("TURN_RELAY_MAX_PORT", "0")
	network, err := ice.FromEnv()
	must(t, err)
	defer network.Close()

	relayToken := strings.Repeat("mobile-self-", 4)
	hub := signalserver.NewSelfHosted(relayToken, network)
	go hub.Run(ctx)
	relaySrv := httptest.NewServer(hub)
	defer relaySrv.Close()
	signalURL := "ws" + strings.TrimPrefix(relaySrv.URL, "http")

	dir := t.TempDir()
	executable, err := os.Executable()
	must(t, err)
	service, err := desktop.New(&desktop.Config{
		Executable: executable,
		Workspaces: []desktop.WorkspaceConfig{
			{ID: "self-only", WorkingDir: dir, SessionDir: filepath.Join(dir, "self-sessions"), Owner: "local",
				SelfAccess: true, Tools: []string{"read"}, ApprovalPolicy: "remote"},
			{ID: "lan-only", WorkingDir: dir, SessionDir: filepath.Join(dir, "lan-sessions"), Owner: "local",
				LANAccess: true, Tools: []string{"read"}},
			{ID: "private", WorkingDir: dir, SessionDir: filepath.Join(dir, "private"), Owner: "local"},
		},
	}, filepath.Join(dir, "state"))
	must(t, err)
	defer service.Close()

	desktopStore := &lanTestStore{}
	server, err := selfrelay.OpenServer(desktopStore, service)
	must(t, err)
	onlineCh := make(chan bool, 4)
	server.SetObserver(func(online bool, _ string) {
		select {
		case onlineCh <- online:
		default:
		}
	})
	service.SetSelfAuthority(server.Allows)
	must(t, server.Connect(ctx, signalURL, relayToken, "SelfDesktop"))
	defer server.Stop()
	select {
	case ok := <-onlineCh:
		if !ok {
			t.Fatal("desktop self-relay did not come online")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for desktop self-relay online")
	}

	_, controlInvite, err := server.InvitePairing(ctx, selfrelay.Control, true)
	must(t, err)
	controlLink := controlInvite.Link

	// Wrong relay token rejected.
	controllerStore := &lanTestStore{}
	controller, err := NewSelfRelayClient(controllerStore)
	must(t, err)
	defer controller.Close()
	if err := controller.ConnectSelfRelayWithToken(controlLink, strings.Repeat("wrong-self-", 4), "Controller"); !errors.Is(err, selfrelay.ErrUnauthorized) {
		t.Fatalf("wrong relay token: got %v, want ErrUnauthorized", err)
	}

	// Valid pairing succeeds without any official login.
	must(t, controller.Pair(controlInvite.Code, signalURL, "", "Controller"))
	if controller.UserID() != "" {
		t.Fatalf("self-relay client unexpectedly reported official user_id %q", controller.UserID())
	}
	saved, err := selfrelay.ParseTarget(controller.SelfRelayTarget())
	must(t, err)
	if saved.Pair != "" {
		t.Fatal("SelfRelayTarget retained one-time pairing token")
	}

	// Only self_access workspace is exposed (not lan_access, not private).
	workspaces, err := controller.ListWorkspaces()
	must(t, err)
	if !strings.Contains(workspaces, `"workspace_id":"self-only"`) ||
		strings.Contains(workspaces, `"workspace_id":"lan-only"`) ||
		strings.Contains(workspaces, `"workspace_id":"private"`) {
		t.Fatalf("wrong self-relay workspace scope: %s", workspaces)
	}

	// One-time pairing link cannot be reused by another device.
	readerStore := &lanTestStore{}
	reader, err := NewSelfRelayClient(readerStore)
	must(t, err)
	defer reader.Close()
	if err := reader.ConnectSelfRelay(controlLink, "Reader"); !errors.Is(err, selfrelay.ErrUnpaired) {
		t.Fatalf("reused pairing link accepted: %v", err)
	}

	// Pair read-only device (without embedding token, supplied out-of-band).
	_, readInvite, err := server.InvitePairing(ctx, selfrelay.Read, false)
	must(t, err)
	must(t, reader.Pair(readInvite.Link, "", relayToken, "Reader"))
	readerSaved := reader.SelfRelayTarget()
	if _, err := reader.CreateSession("self-only", NewRequestID(), "Denied"); !errors.Is(err, errUnavailable) {
		t.Fatalf("read-only self-relay client created session: %v", err)
	}

	created, err := controller.CreateSession("self-only", NewRequestID(), "Self conversation")
	must(t, err)
	var sess struct {
		ID string `json:"session_id"`
	}
	must(t, json.Unmarshal([]byte(created), &sess))
	_, err = reader.OpenSession(sess.ID)
	must(t, err)
	if _, err := reader.StartRun(sess.ID, NewRequestID(), "Denied"); err == nil || err.Error() != "tool_denied" {
		t.Fatalf("read-only self-relay client started run: %v", err)
	}

	// Start run on controller, wait for approval UI, ensure official AuthorityLost does not disrupt it.
	_, err = controller.OpenSession(sess.ID)
	must(t, err)
	_, err = controller.StartRun(sess.ID, NewRequestID(), "Request approval")
	must(t, err)
	for {
		if ctx.Err() != nil {
			t.Fatal("self-relay run did not reach approval")
		}
		raw, err := controller.NextEvent(100)
		must(t, err)
		if strings.Contains(raw, `"kind":"ui.request"`) {
			break
		}
	}
	service.AuthorityLost()
	_, err = controller.OpenSession(sess.ID)
	must(t, err)

	// Revoke controller -> active run stops with self_access_revoked and reconnect fails with ErrUnpaired.
	controllerID := ""
	for _, cl := range server.Status().Clients {
		if cl.Name == "Controller" {
			controllerID = cl.ID
		}
	}
	if controllerID == "" {
		t.Fatal("controller missing from self-relay clients")
	}
	must(t, server.RevokeClients(controllerID))
	service.RefreshSelfAccess()
	if err := controller.Reconnect(); !errors.Is(err, selfrelay.ErrUnpaired) {
		t.Fatalf("revoked self-relay device reconnected: %v", err)
	}
	for {
		if ctx.Err() != nil {
			t.Fatal("run continued after self-relay controller revocation")
		}
		raw, err := reader.NextEvent(100)
		must(t, err)
		if strings.Contains(raw, `"reason":"authority_lost"`) {
			t.Fatalf("official authority loss stopped self-relay run: %s", raw)
		}
		if strings.Contains(raw, `"reason":"self_access_revoked"`) {
			break
		}
	}

	// Persistence across desktop restart: Reader reconnects without pairing token.
	reader.Close()
	server.Stop()
	restarted, err := selfrelay.OpenServer(desktopStore, service)
	must(t, err)
	defer restarted.Stop()
	restartedOnline := make(chan bool, 4)
	restarted.SetObserver(func(online bool, _ string) {
		select {
		case restartedOnline <- online:
		default:
		}
	})
	service.SetSelfAuthority(restarted.Allows)
	must(t, restarted.Connect(ctx, signalURL, relayToken, "SelfDesktop"))
	<-restartedOnline
	returning, err := NewSelfRelayClient(readerStore)
	must(t, err)
	defer returning.Close()
	must(t, returning.ConnectSelfRelay(readerSaved, "Reader"))
	if got := restarted.Status().Clients; len(got) != 1 || got[0].Name != "Reader" {
		t.Fatalf("self-relay paired clients did not persist: %+v", got)
	}
}

func TestOfficialDualSiteIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cnSigner := identitytest.NewAuthority(10 * time.Minute)
	globalSigner := identitytest.NewAuthority(10 * time.Minute)

	cnHub := signalserver.New(cnSigner.PublicKey(), nil, nil)
	cnHub.RequireIssuer("https://auth.cn.example/realms/vanora")
	go cnHub.Run(ctx)
	cnSrv := httptest.NewServer(cnHub)
	defer cnSrv.Close()
	cnSignalURL := "ws" + strings.TrimPrefix(cnSrv.URL, "http")

	globalHub := signalserver.New(globalSigner.PublicKey(), nil, nil)
	globalHub.RequireIssuer("https://auth.global.example/realms/vanora")
	go globalHub.Run(ctx)
	globalSrv := httptest.NewServer(globalHub)
	defer globalSrv.Close()
	globalSignalURL := "ws" + strings.TrimPrefix(globalSrv.URL, "http")

	issueFor := func(signer *identitytest.Authority, issuer, subject string) transport.IdentitySource {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		must(t, err)
		return &siteTestIdentity{key: k, signer: signer, issuer: issuer, subject: subject}
	}

	cnPhone := issueFor(cnSigner, "https://auth.cn.example/realms/vanora", "user-cn")
	globalPhone := issueFor(globalSigner, "https://auth.global.example/realms/vanora", "user-global")

	// Cross-site dialing MUST fail at signaling handshake.
	cnToGlobal := newClient(globalSignalURL, cnPhone)
	defer cnToGlobal.Close()
	if _, err := cnToGlobal.Devices(); err == nil {
		t.Fatal("CN account was accepted by GLOBAL relay")
	}
	globalToCN := newClient(cnSignalURL, globalPhone)
	defer globalToCN.Close()
	if _, err := globalToCN.Devices(); err == nil {
		t.Fatal("GLOBAL account was accepted by CN relay")
	}

	// Same-site dialing succeeds independently for both sites.
	cnClient := newClient(cnSignalURL, cnPhone)
	defer cnClient.Close()
	if _, err := cnClient.Devices(); err != nil {
		t.Fatalf("CN client failed on CN relay: %v", err)
	}
	globalClient := newClient(globalSignalURL, globalPhone)
	defer globalClient.Close()
	if _, err := globalClient.Devices(); err != nil {
		t.Fatalf("GLOBAL client failed on GLOBAL relay: %v", err)
	}
}

type siteTestIdentity struct {
	key     ed25519.PrivateKey
	signer  *identitytest.Authority
	issuer  string
	subject string
}

func (s *siteTestIdentity) Current(context.Context) (*endpoint.Credentials, endpoint.LeaseProof, error) {
	now := time.Now()
	cert, err := s.signer.IssueWithKey(s.issuer, s.subject, s.key.Public().(ed25519.PublicKey), now)
	if err != nil {
		return nil, endpoint.LeaseProof{}, err
	}
	p, err := identity.VerifyCertificate(cert, s.signer.PublicKey(), now)
	if err != nil {
		return nil, endpoint.LeaseProof{}, err
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, endpoint.LeaseProof{}, err
	}
	lease, _, err := s.signer.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
	if err != nil {
		return nil, endpoint.LeaseProof{}, err
	}
	c, err := endpoint.OpenCredentials(cert, s.key, s.signer.PublicKey(), now)
	return c, endpoint.LeaseProof{Certificate: cert, Lease: lease}, err
}
