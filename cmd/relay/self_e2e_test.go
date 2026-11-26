package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"vanora-relay/internal/cftunnel"
	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

type cfV4Server struct {
	mu          sync.Mutex
	accountID   string
	zoneID      string
	zoneName    string
	token       string
	nextID      int
	tunnels     map[string]cftunnel.Tunnel
	secrets     map[string]string
	configs     map[string]map[string]any
	dnsRecords  map[string]cftunnel.DNSRecord
	disconnected map[string]int
}

func newCFV4Server(accountID, zoneID, zoneName, token string) *cfV4Server {
	return &cfV4Server{
		accountID:    accountID,
		zoneID:       zoneID,
		zoneName:     zoneName,
		token:        token,
		tunnels:      make(map[string]cftunnel.Tunnel),
		secrets:      make(map[string]string),
		configs:      make(map[string]map[string]any),
		dnsRecords:   make(map[string]cftunnel.DNSRecord),
		disconnected: make(map[string]int),
	}
}

func (s *cfV4Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		writeCF(w, http.StatusUnauthorized, false, nil, []map[string]any{{"code": 10000, "message": "auth error"}})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tunnelsPrefix := "/accounts/" + s.accountID + "/cfd_tunnel"
	zonePath := "/zones/" + s.zoneID
	dnsPrefix := zonePath + "/dns_records"

	switch {
	case r.Method == http.MethodGet && r.URL.Path == zonePath:
		writeCF(w, http.StatusOK, true, map[string]any{
			"id":      s.zoneID,
			"name":    s.zoneName,
			"status":  "active",
			"account": map[string]string{"id": s.accountID},
		}, nil)
	case r.Method == http.MethodGet && r.URL.Path == tunnelsPrefix:
		nameFilter := r.URL.Query().Get("name")
		var list []cftunnel.Tunnel
		for _, tun := range s.tunnels {
			if nameFilter != "" && tun.Name != nameFilter {
				continue
			}
			list = append(list, tun)
		}
		if list == nil {
			list = []cftunnel.Tunnel{}
		}
		writeCFPage(w, list)
	case r.Method == http.MethodPost && r.URL.Path == tunnelsPrefix:
		var body struct {
			Name      string `json:"name"`
			ConfigSrc string `json:"config_src"`
			Secret    string `json:"tunnel_secret"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			writeCF(w, http.StatusBadRequest, false, nil, nil)
			return
		}
		s.nextID++
		id := fmt.Sprintf("tun-%04d", s.nextID)
		tun := cftunnel.Tunnel{ID: id, Name: body.Name, Status: cftunnel.TunnelInactive, CreatedAt: time.Now().UTC(), ConfigSrc: body.ConfigSrc}
		s.tunnels[id] = tun
		s.secrets[id] = body.Secret
		writeCF(w, http.StatusOK, true, tun, nil)
	case strings.HasPrefix(r.URL.Path, tunnelsPrefix+"/"):
		rest := strings.TrimPrefix(r.URL.Path, tunnelsPrefix+"/")
		id, sub, _ := strings.Cut(rest, "/")
		tun, exists := s.tunnels[id]
		if !exists {
			writeCF(w, http.StatusNotFound, false, nil, []map[string]any{{"code": 1003, "message": "not found"}})
			return
		}
		switch {
		case r.Method == http.MethodGet && sub == "":
			writeCF(w, http.StatusOK, true, tun, nil)
		case r.Method == http.MethodPatch && sub == "":
			var body struct {
				Secret string `json:"tunnel_secret"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.secrets[id] = body.Secret
			writeCF(w, http.StatusOK, true, tun, nil)
		case r.Method == http.MethodDelete && sub == "":
			delete(s.tunnels, id)
			delete(s.configs, id)
			writeCF(w, http.StatusOK, true, tun, nil)
		case r.Method == http.MethodGet && sub == "configurations":
			cfg, ok := s.configs[id]
			if !ok {
				writeCF(w, http.StatusNotFound, false, nil, []map[string]any{{"code": 1055, "message": "config missing"}})
				return
			}
			writeCF(w, http.StatusOK, true, map[string]any{"config": cfg, "version": 1}, nil)
		case r.Method == http.MethodPut && sub == "configurations":
			var body struct {
				Config map[string]any `json:"config"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.configs[id] = body.Config
			writeCF(w, http.StatusOK, true, map[string]any{"config": body.Config, "version": 1}, nil)
		case r.Method == http.MethodGet && sub == "token":
			tok := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"a":%q,"t":%q,"s":%q}`, s.accountID, id, s.secrets[id])))
			writeCF(w, http.StatusOK, true, tok, nil)
		case r.Method == http.MethodGet && sub == "connections":
			writeCFPage(w, []any{})
		case r.Method == http.MethodDelete && sub == "connections":
			s.disconnected[id]++
			writeCF(w, http.StatusOK, true, map[string]any{}, nil)
		default:
			writeCF(w, http.StatusNotFound, false, nil, nil)
		}
	case r.Method == http.MethodGet && r.URL.Path == dnsPrefix:
		exact := r.URL.Query().Get("name.exact")
		var list []cftunnel.DNSRecord
		for _, rec := range s.dnsRecords {
			if exact != "" && !strings.EqualFold(rec.Hostname, exact) {
				continue
			}
			list = append(list, rec)
		}
		if list == nil {
			list = []cftunnel.DNSRecord{}
		}
		writeCFPage(w, list)
	case r.Method == http.MethodPost && r.URL.Path == dnsPrefix:
		var rec cftunnel.DNSRecord
		_ = json.NewDecoder(r.Body).Decode(&rec)
		s.nextID++
		rec.ID = fmt.Sprintf("dns-%04d", s.nextID)
		s.dnsRecords[rec.ID] = rec
		writeCF(w, http.StatusOK, true, rec, nil)
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, dnsPrefix+"/"):
		id := strings.TrimPrefix(r.URL.Path, dnsPrefix+"/")
		if _, ok := s.dnsRecords[id]; !ok {
			writeCF(w, http.StatusNotFound, false, nil, nil)
			return
		}
		var rec cftunnel.DNSRecord
		_ = json.NewDecoder(r.Body).Decode(&rec)
		rec.ID = id
		s.dnsRecords[id] = rec
		writeCF(w, http.StatusOK, true, rec, nil)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, dnsPrefix+"/"):
		id := strings.TrimPrefix(r.URL.Path, dnsPrefix+"/")
		delete(s.dnsRecords, id)
		writeCF(w, http.StatusOK, true, map[string]string{"id": id}, nil)
	default:
		writeCF(w, http.StatusNotFound, false, nil, nil)
	}
}

func writeCF(w http.ResponseWriter, status int, ok bool, result any, errs []map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": ok, "result": result, "errors": errs})
}

func writeCFPage(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true, "result": result,
		"result_info": map[string]int{"page": 1, "per_page": 100, "total_pages": 1},
	})
}

func TestSelfHostedAccountFreeEndToEndTunnelFlow(t *testing.T) {
	const (
		selfToken = "self-e2e-relay-bearer-token-at-least-32-bytes!"
		cfToken   = "cf-e2e-scoped-api-token-at-least-32-bytes!"
		edgeKey   = "edge-e2e-hmac-secret-at-least-32-visible-bytes!"
		accountID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		zoneID    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		baseDom   = "edge.self.example"
	)

	newKey := func() (ed25519.PublicKey, ed25519.PrivateKey, string) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.SelfDeviceID(pub)
		if err != nil {
			t.Fatal(err)
		}
		return pub, priv, id
	}
	shaHex := func(b []byte) string {
		h := sha256.Sum256(b)
		return hex.EncodeToString(h[:])
	}

	deskPub, deskPriv, deskID := newKey()
	mobPub, mobPriv, mobID := newKey()
	strangerPub, strangerPriv, strangerID := newKey()

	cfAPI := newCFV4Server(accountID, zoneID, "self.example", cfToken)
	cfServer := httptest.NewServer(cfAPI)
	t.Cleanup(cfServer.Close)

	cfg := cftunnel.Config{
		Channel:        cftunnel.ChannelSelf,
		Mode:           cftunnel.ModeManaged,
		Process:        cftunnel.ProcessAll,
		Store:          cftunnel.StoreSQLite,
		SQLitePath:     filepath.Join(t.TempDir(), "self-tunnels.db"),
		ControlOrigin:  "https://self-relay.example",
		AccountID:      accountID,
		ZoneID:         zoneID,
		BaseDomain:     baseDom,
		Namespace:      "selfe2e",
		TunnelToken:    cfToken,
		DNSToken:       cfToken,
		MasterKey:      bytes.Repeat([]byte{0x42}, 32),
		EdgeGate:       cftunnel.EdgeWorkerHMAC,
		EdgeKey:        []byte(edgeKey),
		EdgeCanaryHost: "canary." + baseDom,
		SelfDevices:    map[string]struct{}{deskID: {}},
		AccountCap:     16,
		Reaper:         cftunnel.ReaperConfig{Mode: cftunnel.ReaperOff},
		CloudflareRate: cftunnel.RateConfig{PerSecond: 50, Burst: 50, Concurrency: 4},
	}

	handler, closeServer, err := buildServer(t.Context(), cfg, relayStartup{
		selfToken:  selfToken,
		newNetwork: func() (relayNetwork, error) { return new(startupNetwork), nil },
		newCloudflare: func(c cftunnel.Config) (cftunnel.Cloudflare, error) {
			return cftunnel.NewCFClient(c, cftunnel.CFClientOptions{BaseURL: cfServer.URL, HTTPClient: cfServer.Client()})
		},
		canaryClient: &http.Client{Transport: canaryTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://canary.edge.self.example/v1/tunnel/ws" {
				t.Errorf("unexpected canary URL: %s", r.URL)
			}
			return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader("Forbidden"))}, nil
		})},
	})
	if err != nil {
		t.Fatalf("buildServer(self): %v", err)
	}
	t.Cleanup(closeServer)

	relayServer := httptest.NewServer(handler)
	t.Cleanup(relayServer.Close)
	wsURL := "ws" + strings.TrimPrefix(relayServer.URL, "http") + "/v1/signal"

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)

	dialSelf := func(role string, pub ed25519.PublicKey, priv ed25519.PrivateKey, devID string) (*websocket.Conn, string) {
		t.Helper()
		ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": {"Bearer " + selfToken}},
		})
		if err != nil {
			t.Fatalf("dial %s: %v", role, err)
		}
		t.Cleanup(func() { _ = ws.CloseNow() })
		readMsg := func() protocol.Message {
			_, raw, err := ws.Read(ctx)
			if err != nil {
				t.Fatalf("read %s: %v", role, err)
			}
			var m protocol.Message
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
		chal := readMsg()
		if chal.Type != "auth.challenge" {
			t.Fatalf("expected auth.challenge, got %s", chal.Type)
		}
		login := protocol.Message{Type: "auth.login", Connection: chal.Connection, From: devID, To: "signal"}
		if err := login.Sign(priv, protocol.Encode(map[string]string{
			"role":       role,
			"public_key": base64.RawURLEncoding.EncodeToString(pub),
		})); err != nil {
			t.Fatal(err)
		}
		if err := ws.Write(ctx, websocket.MessageText, protocol.Encode(login)); err != nil {
			t.Fatal(err)
		}
		okMsg := readMsg()
		if okMsg.Type != "auth.ok" {
			t.Fatalf("expected auth.ok, got %s %s", okMsg.Type, okMsg.Data)
		}
		var okData struct {
			Device      string `json:"device_id"`
			Mode        string `json:"mode"`
			TunnelScope string `json:"tunnel_scope"`
		}
		if err := json.Unmarshal(okMsg.Data, &okData); err != nil || okData.Mode != "self" || okData.Device != devID || okData.TunnelScope == "" {
			t.Fatalf("unexpected auth.ok: %s (%v)", okMsg.Data, err)
		}
		return ws, okData.TunnelScope
	}
	readWS := func(ws *websocket.Conn, want string) protocol.Message {
		t.Helper()
		_, raw, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("ws read waiting for %s: %v", want, err)
		}
		var m protocol.Message
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if m.Type != want {
			t.Fatalf("got ws %s (%s), want %s", m.Type, m.Data, want)
		}
		return m
	}
	sendSigned := func(ws *websocket.Conn, priv ed25519.PrivateKey, m protocol.Message, body any) {
		t.Helper()
		if err := m.Sign(priv, protocol.Encode(body)); err != nil {
			t.Fatal(err)
		}
		if err := ws.Write(ctx, websocket.MessageText, protocol.Encode(m)); err != nil {
			t.Fatal(err)
		}
	}

	deskWS, scopeID := dialSelf("desktop", deskPub, deskPriv, deskID)
	mobWS, mobScope := dialSelf("mobile", mobPub, mobPriv, mobID)
	strangerWS, _ := dialSelf("mobile", strangerPub, strangerPriv, strangerID)
	if mobScope != scopeID {
		t.Fatalf("scope mismatch: %s vs %s", mobScope, scopeID)
	}

	// Desktop registers online granting ONLY paired mobID (not strangerID).
	card := protocol.Message{Type: "device.card", From: deskID, To: "self"}
	if err := card.Sign(deskPriv, []byte("My Self Desktop")); err != nil {
		t.Fatal(err)
	}
	if err := deskWS.Write(ctx, websocket.MessageText, protocol.Encode(protocol.Message{
		Type: "device.online",
		Data: protocol.Encode(map[string]any{"card": card, "guests": []string{mobID}}),
	})); err != nil {
		t.Fatal(err)
	}
	readWS(deskWS, "device.registered")

	// Desktop announces starting tunnel runtime before initial registration.
	sendSigned(deskWS, deskPriv, protocol.Message{Type: "tunnel.host", From: deskID, To: "signal", Seq: 1}, map[string]any{
		"aud": "tunnel-v1", "scope": scopeID, "socket_id": "sock-1", "runtime_id": "rt-self-1",
		"phase": "starting", "generation": 0, "incarnation": 0, "can_recover": true,
	})
	readWS(deskWS, "tunnel.host.ack")

	httpClient := relayServer.Client()
	callTunnel := func(action, body, idem string) (int, []byte) {
		t.Helper()
		chalAction, _, _ := strings.Cut(action, "/")
		chalReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, relayServer.URL+"/v1/tunnels/challenge",
			strings.NewReader(fmt.Sprintf(`{"action":%q,"device_id":%q}`, chalAction, deskID)))
		chalReq.Header.Set("Authorization", "Bearer "+selfToken)
		chalResp, err := httpClient.Do(chalReq)
		if err != nil {
			t.Fatal(err)
		}
		chalRaw, _ := io.ReadAll(chalResp.Body)
		chalResp.Body.Close()
		if chalResp.StatusCode != http.StatusOK {
			t.Fatalf("challenge failed: %d %s", chalResp.StatusCode, chalRaw)
		}
		var chal struct{ Challenge string }
		if err := json.Unmarshal(chalRaw, &chal); err != nil {
			t.Fatal(err)
		}
		path := "/v1/tunnels/" + deskID + "/" + action
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, relayServer.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+selfToken)
		req.Header.Set("Vanora-Public-Key", base64.RawURLEncoding.EncodeToString(deskPub))
		req.Header.Set("Vanora-Challenge", chal.Challenge)
		req.Header.Set("Vanora-Proof", cftunnel.SignHTTPProof(deskPriv, cfg.Channel, cfg.ControlOrigin, path, deskID,
			chal.Challenge, shaHex([]byte(body)), idem, shaHex(deskPub)))
		if idem != "" {
			req.Header.Set("Idempotency-Key", idem)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, raw
	}

	waitOp := func(opID string) cftunnel.OperationView {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			code, raw := callTunnel("operations/"+opID, `{}`, "")
			if code != http.StatusOK {
				t.Fatalf("poll op %s: %d %s", opID, code, raw)
			}
			var view cftunnel.OperationView
			if err := json.Unmarshal(raw, &view); err != nil {
				t.Fatal(err)
			}
			if view.CompletedAt != nil {
				if view.Error != "" {
					t.Fatalf("op %s completed with error: %s", opID, view.Error)
				}
				return view
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatalf("op %s did not complete in time", opID)
		return cftunnel.OperationView{}
	}

	// 1. Register -> Worker creates CF tunnel, ingress, and DNS -> StateReady
	code, raw := callTunnel("register", `{"origin":"127.0.0.1:43210","runtime_id":"rt-self-1","if_generation":0}`, "e2e-reg")
	if code != http.StatusAccepted {
		t.Fatalf("register got %d %s", code, raw)
	}
	var regOp cftunnel.OperationView
	if err := json.Unmarshal(raw, &regOp); err != nil {
		t.Fatal(err)
	}
	waitOp(regOp.ID)

	// 2. Fetch connector token (fast path)
	code, raw = callTunnel("token", `{"origin":"127.0.0.1:43210","runtime_id":"rt-self-1","if_generation":1}`, "")
	if code != http.StatusOK {
		t.Fatalf("token got %d %s", code, raw)
	}
	var tok cftunnel.ConnectorToken
	if err := json.Unmarshal(raw, &tok); err != nil || tok.ConnectorToken == "" || !strings.HasSuffix(tok.Hostname, "."+baseDom) || tok.Generation != 1 || tok.Incarnation != 1 {
		t.Fatalf("unexpected token: %+v (%v)", tok, err)
	}

	// 3. Desktop marks listening on WSS
	sendSigned(deskWS, deskPriv, protocol.Message{Type: "tunnel.host", From: deskID, To: "signal", Seq: 2}, map[string]any{
		"aud": "tunnel-v1", "scope": scopeID, "socket_id": "sock-1", "runtime_id": "rt-self-1",
		"phase": "listening", "generation": tok.Generation, "incarnation": tok.Incarnation, "can_recover": true,
	})
	readWS(deskWS, "tunnel.host.ack")

	// 4. Unpaired stranger is denied uniformly
	sendSigned(strangerWS, strangerPriv, protocol.Message{Type: "tunnel.connect", Connection: protocol.NewID(), From: strangerID, To: deskID, Seq: 1}, map[string]any{
		"aud": "tunnel-v1", "scope": scopeID, "expected_owner": deskID,
		"target_pin_hash": shaHex(deskPub), "client_nonce": "stranger-nonce",
	})
	if errMsg := readWS(strangerWS, "error"); string(errMsg.Data) != `"device_unavailable"` {
		t.Fatalf("stranger got %s, want device_unavailable", errMsg.Data)
	}

	// 5. Paired mobile connects -> desktop permits -> mobile gets real edge_ticket -> verified by Node Worker
	connID := protocol.NewID()
	sendSigned(mobWS, mobPriv, protocol.Message{Type: "tunnel.connect", Connection: connID, From: mobID, To: deskID, Seq: 1}, map[string]any{
		"aud": "tunnel-v1", "scope": scopeID, "expected_owner": deskID,
		"target_pin_hash": shaHex(deskPub), "client_nonce": "mobile-nonce-1",
	})
	offer := readWS(deskWS, "tunnel.offer")
	if offer.Connection != connID {
		t.Fatalf("offer connection mismatch: %s", offer.Connection)
	}
	const jti = "self_e2e_jti_1"
	sendSigned(deskWS, deskPriv, protocol.Message{Type: "tunnel.permit", Connection: connID, From: deskID, To: mobID, Seq: 1}, map[string]any{
		"aud": "tunnel-v1", "scope": scopeID, "generation": tok.Generation, "incarnation": tok.Incarnation,
		"runtime_id": "rt-self-1", "hostname": tok.Hostname, "jti": jti, "client_nonce": "mobile-nonce-1",
		"visitor_key_hash": shaHex(mobPub), "path": "/v1/tunnel/ws", "expires_at": time.Now().Add(15 * time.Second).UTC(),
	})
	target := readWS(mobWS, "tunnel.target")
	var targetData struct {
		Permit      protocol.Message `json:"permit"`
		EdgeTicket  string           `json:"edge_ticket"`
		AccessUntil time.Time        `json:"access_until"`
	}
	if err := json.Unmarshal(target.Data, &targetData); err != nil || targetData.EdgeTicket == "" || !targetData.AccessUntil.After(time.Now()) {
		t.Fatalf("unexpected tunnel.target: %s (%v)", target.Data, err)
	}
	if _, err := targetData.Permit.Verify(deskPub); err != nil {
		t.Fatalf("permit signature invalid: %v", err)
	}

	// Cross-verify the live-minted edge_ticket directly against deploy/cf-edge-worker/worker.js using Node!
	if nodeBin, err := exec.LookPath("node"); err == nil {
		workerPath, err := filepath.Abs(filepath.Join("..", "..", "deploy", "cf-edge-worker", "worker.js"))
		if err != nil {
			t.Fatal(err)
		}
		script := `import { pathToFileURL } from "node:url";
const { verifyTicket } = await import(pathToFileURL(process.env.WORKER_PATH).href);
const req = {
  url: "https://" + process.env.TICKET_HOST + "/v1/tunnel/ws",
  method: "GET",
  headers: new Headers({
    Upgrade: "websocket",
    "Vanora-Ticket-ID": process.env.TICKET_JTI,
    "Vanora-Edge-Ticket": process.env.TICKET_VAL,
  }),
};
const ok = await verifyTicket(req, { EDGE_KEY: process.env.EDGE_KEY });
if (!ok) { console.error("worker rejected live relay edge ticket"); process.exit(1); }`
		cmd := exec.CommandContext(ctx, nodeBin, "--input-type=module", "-e", script)
		cmd.Env = append(cmd.Environ(),
			"WORKER_PATH="+workerPath,
			"TICKET_HOST="+tok.Hostname,
			"TICKET_JTI="+jti,
			"TICKET_VAL="+targetData.EdgeTicket,
			"EDGE_KEY="+edgeKey,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("live worker verification failed: %v\n%s", err, out)
		}
	}

	// 6. Origin reconcile -> disconnect -> token blocked -> resume -> release -> recover -> deprovision
	code, raw = callTunnel("origin", `{"origin":"127.0.0.1:44444","runtime_id":"rt-self-1","if_generation":1}`, "e2e-origin")
	if code != http.StatusAccepted {
		t.Fatalf("origin got %d %s", code, raw)
	}
	var op cftunnel.OperationView
	_ = json.Unmarshal(raw, &op)
	waitOp(op.ID)

	code, raw = callTunnel("disconnect", `{"if_generation":2}`, "e2e-disc")
	if code != http.StatusAccepted {
		t.Fatalf("disconnect got %d %s", code, raw)
	}
	_ = json.Unmarshal(raw, &op)
	waitOp(op.ID)

	code, raw = callTunnel("token", `{"origin":"127.0.0.1:44444","runtime_id":"rt-self-1","if_generation":3}`, "")
	if code != http.StatusConflict || !strings.Contains(string(raw), "tunnel_suspended") {
		t.Fatalf("expected 409 tunnel_suspended after disconnect, got %d %s", code, raw)
	}

	code, raw = callTunnel("resume", `{"origin":"127.0.0.1:44444","runtime_id":"rt-self-1","if_generation":3}`, "e2e-resume")
	if code != http.StatusAccepted {
		t.Fatalf("resume got %d %s", code, raw)
	}
	_ = json.Unmarshal(raw, &op)
	waitOp(op.ID)

	code, raw = callTunnel("release", `{"if_generation":4}`, "e2e-rel")
	if code != http.StatusAccepted {
		t.Fatalf("release got %d %s", code, raw)
	}
	_ = json.Unmarshal(raw, &op)
	waitOp(op.ID)

	code, raw = callTunnel("recover", `{"origin":"127.0.0.1:45555","runtime_id":"rt-self-1","if_generation":5}`, "e2e-rec")
	if code != http.StatusAccepted {
		t.Fatalf("recover got %d %s", code, raw)
	}
	_ = json.Unmarshal(raw, &op)
	waitOp(op.ID)

	code, raw = callTunnel("status", `{}`, "")
	if code != http.StatusOK {
		t.Fatalf("status got %d %s", code, raw)
	}
	var view cftunnel.AllocationView
	if err := json.Unmarshal(raw, &view); err != nil || view.State != cftunnel.StateReady || view.Incarnation != 2 || view.Hostname != tok.Hostname {
		t.Fatalf("unexpected recovered status: %+v (%v)", view, err)
	}

	code, raw = callTunnel("deprovision", fmt.Sprintf(`{"if_generation":%d}`, view.Generation), "e2e-deprov")
	if code != http.StatusAccepted {
		t.Fatalf("deprovision got %d %s", code, raw)
	}
	_ = json.Unmarshal(raw, &op)
	waitOp(op.ID)

	cfAPI.mu.Lock()
	leftTunnels, leftDNS := len(cfAPI.tunnels), len(cfAPI.dnsRecords)
	cfAPI.mu.Unlock()
	if leftTunnels != 0 || leftDNS != 0 {
		t.Fatalf("Cloudflare resources leaked after deprovision: tunnels=%d dns=%d", leftTunnels, leftDNS)
	}
}
