package testtunnel

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairnet"
	"vanora-relay/protocol"
)

type Request struct {
	Type    string `json:"type"`
	ID      string `json:"request_id"`
	Session string `json:"session_id"`
	After   int64  `json:"after_seq"`
	Path    string `json:"-"`
}

type Desktop struct {
	Requests chan Request
}

func NewDesktop() *Desktop { return &Desktop{Requests: make(chan Request, 32)} }

func (*Desktop) Open(transport.Peer)   {}
func (*Desktop) Closed(transport.Peer) {}

func (d *Desktop) Message(peer transport.Peer, raw []byte) {
	var req Request
	if json.Unmarshal(raw, &req) != nil || req.ID == "" {
		return
	}
	if path, ok := peer.(transport.PathReporter); ok {
		req.Path = path.Path()
	}
	d.Requests <- req
	var data any
	switch req.Type {
	case "workspace.list":
		data = []map[string]string{{"workspace_id": "tunnel-workspace"}}
	case "session.open":
		data = map[string]int64{"last_seq": 0}
	case "events.resume":
		_ = peer.Send(protocol.Encode(map[string]any{
			"type": "event", "seq": req.After + 1, "session_id": req.Session, "kind": "fixture.event",
		}), false)
		data = map[string]int64{"last_seq": req.After + 1}
	default:
		data = map[string]bool{"ok": true}
	}
	_ = peer.Send(protocol.Encode(map[string]any{"type": "result", "request_id": req.ID, "data": data}), false)
}

func (d *Desktop) AwaitRequest(t *testing.T, kind, path string) Request {
	t.Helper()
	req := Await(t, d.Requests)
	if req.Type != kind || path != "" && req.Path != path {
		t.Fatalf("got %s on %s, expected %s on %s", req.Type, req.Path, kind, path)
	}
	return req
}

func AdmitOfficial(t *testing.T, signalURL string, host, visitor *account.Account, role string) {
	t.Helper()
	credentials, _, err := visitor.Current(t.Context())
	Must(t, err)
	group, local := host.PairingIdentity(signalURL, "desktop")
	Must(t, group.Admit(local, pairnet.Member{
		ID: visitor.DeviceID(), Owner: visitor.UserID(), Role: role,
		Pin: base64.RawURLEncoding.EncodeToString(credentials.PublicKey()),
	}, true))
}
