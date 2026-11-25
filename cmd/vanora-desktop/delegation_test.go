package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"vanora-relay/adapter/remote"
)

func TestScopedRequestIDAndNonTransitiveDelegationGuard(t *testing.T) {
	idA := remote.ScopedRequestID("agent-alpha", "req-1")
	idB := remote.ScopedRequestID("agent-beta", "req-1")
	if idA == idB {
		t.Fatalf("ScopedRequestID collided across namespaces: %q", idA)
	}
	if !strings.HasPrefix(idA, "fwd:") || len(idA) > 128 {
		t.Fatalf("unexpected ScopedRequestID format: %q (len=%d)", idA, len(idA))
	}
	if idSame := remote.ScopedRequestID("agent-alpha", "req-1"); idSame != idA {
		t.Fatalf("ScopedRequestID is not deterministic: %q != %q", idSame, idA)
	}
	if plain := remote.ScopedRequestID("", "req-1"); plain != "req-1" {
		t.Fatalf("empty namespace altered request_id: %q", plain)
	}

	// Non-transitive delegation guard: when running inside a linked session
	// (VANORA_LINK_ORIGIN set), outbound mutating Sidecar & ctl commands are refused.
	t.Setenv("VANORA_LINK_ORIGIN", "peer-a/agent-1")

	if err := runCtl([]string{"run", "-peer", "desk-b", "-session", "s1", "-text", "hop2"}); err != errTransitiveDelegation {
		t.Fatalf("runCtl transitive mutation err = %v, want %v", err, errTransitiveDelegation)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	am := &accessManager{
		ctx:     ctx,
		dir:     t.TempDir(),
		emitter: &jsonEmitter{out: &out},
	}
	am.remoteCommand(accessCommand{
		Type:      "remote.run.start",
		RequestID: "r-hop2",
		PeerID:    "desk-b",
		SessionID: "s1",
		Text:      "hop2",
	})
	var emitted map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &emitted); err != nil {
		t.Fatalf("decode remote.error: %v (%s)", err, out.String())
	}
	if emitted["type"] != "remote.error" || !strings.Contains(emitted["error"].(string), "transitive peer delegation") {
		t.Fatalf("expected transitive delegation error, got %+v", emitted)
	}
}
