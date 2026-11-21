package signal_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"
	"vanora-relay/endpoint"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/internal/membership"
	"vanora-relay/internal/signal"
	"vanora-relay/protocol"
)

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type client struct {
	ws  *websocket.Conn
	ctx context.Context
	*endpoint.Credentials
	proof endpoint.LeaseProof
}

func (c *client) send(t *testing.T, m protocol.Message) {
	t.Helper()
	check(t, c.ws.Write(c.ctx, websocket.MessageText, protocol.Encode(m)))
}
func (c *client) read(t *testing.T, expect string) protocol.Message {
	t.Helper()
	_, b, e := c.ws.Read(c.ctx)
	check(t, e)
	var m protocol.Message
	check(t, json.Unmarshal(b, &m))
	if m.Type != expect {
		t.Fatalf("want %s, got %s %s", expect, m.Type, m.Data)
	}
	return m
}
func login(t *testing.T, ctx context.Context, url, role, subject string, signer *identitytest.Authority) *client {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	now := time.Now()
	cert, err := signer.IssueWithKey("https://issuer.example", subject, pub, now)
	check(t, err)
	p, err := identity.VerifyCertificate(cert, signer.PublicKey(), now)
	check(t, err)
	nonce := make([]byte, 24)
	rand.Read(nonce)
	lease, _, err := signer.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
	check(t, err)
	creds, err := endpoint.OpenCredentials(cert, key, signer.PublicKey(), now)
	check(t, err)
	ws, _, err := websocket.Dial(ctx, url, nil)
	check(t, err)
	t.Cleanup(func() { ws.CloseNow() })
	c := &client{ws, ctx, creds, endpoint.LeaseProof{Certificate: cert, Lease: lease}}
	m, err := creds.Login(c.read(t, "auth.challenge"), role, lease)
	check(t, err)
	c.send(t, m)
	c.read(t, "auth.ok")
	return c
}

func TestAuthorizedGuestWebRTC(t *testing.T) {
	t.Run("direct_without_membership", func(t *testing.T) { exerciseGuestWebRTC(t, false) })
	t.Run("relay_only_with_membership", func(t *testing.T) { exerciseGuestWebRTC(t, true) })
}

func receive[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		var zero T
		return zero
	}
}

func exerciseGuestWebRTC(t *testing.T, entitled bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t.Setenv("TURN_PUBLIC_IP", "127.0.0.1")
	t.Setenv("TURN_BIND_IP", "127.0.0.1")
	t.Setenv("TURN_PORT", "0")
	t.Setenv("TURN_TCP", "false")
	t.Setenv("TURN_RELAY_MIN_PORT", "0")
	t.Setenv("TURN_RELAY_MAX_PORT", "0")
	network, err := ice.FromEnv()
	check(t, err)
	t.Cleanup(func() { network.Close() })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	signer, err := identitytest.NewAuthorityWithKey(key, time.Minute*10)
	check(t, err)
	token := strings.Repeat("a", 40)
	billing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var who struct{ Issuer, Subject string }
		if r.Method != "POST" || r.URL.Path != "/internal/v1/relay/entitlement" || r.Header.Get("Authorization") != "Bearer "+token || json.NewDecoder(r.Body).Decode(&who) != nil || who.Issuer != "https://issuer.example" || who.Subject != "guest" {
			http.Error(w, "unexpected identity", 403)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"relay_allowed": entitled, "valid_until": time.Now().Add(time.Hour).Unix()}})
	}))
	defer billing.Close()
	h := signal.New(signer.PublicKey(), &membership.Client{URL: billing.URL, Token: token}, network)
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	host := login(t, ctx, url, "desktop", "owner", signer)
	guest := login(t, ctx, url, "mobile", "guest", signer)
	publish := func(guests []string) {
		m, err := host.Online("workstation", guests)
		check(t, err)
		host.send(t, m)
	}
	publish(nil)
	host.read(t, "device.registered")
	_, denied, err := guest.Request(host.DeviceID(), host.UserID())
	check(t, err)
	guest.send(t, denied)
	if string(guest.read(t, "error").Data) != `"device_unavailable"` {
		t.Fatal("unauthorized resource disclosed")
	}
	publish([]string{guest.UserID()})
	host.read(t, "device.registered")
	guest.send(t, protocol.Message{Type: "devices.list"})
	var cards []protocol.Message
	check(t, json.Unmarshal(guest.read(t, "devices.list").Data, &cards))
	if len(cards) != 1 {
		t.Fatal("missing guest directory entry")
	}
	device, err := endpoint.VerifyDevice(cards[0], signer.PublicKey(), time.Now())
	check(t, err)
	if device.Name != "workstation" || device.Owner != host.UserID() {
		t.Fatal("unexpected desktop identity")
	}
	phoneSession, m, err := guest.Request(device.DeviceID, device.Owner)
	check(t, err)
	guest.send(t, m)
	desktopSession, reply, err := host.Accept(host.read(t, "connect.request"), func(id string) bool { return id == guest.UserID() }, time.Now())
	check(t, err)
	host.send(t, reply)
	check(t, phoneSession.Accepted(guest.read(t, "connect.accept"), time.Now()))
	desktopAccess, err := desktopSession.Access()
	check(t, err)
	phoneAccess, err := phoneSession.Access()
	check(t, err)
	check(t, desktopAccess.Update(true, host.proof, time.Now()))
	check(t, phoneAccess.Update(true, guest.proof, time.Now()))
	if desktopAccess.Allows(time.Now(), true, true) || phoneAccess.Allows(time.Now(), true, true) {
		t.Fatal("permitted application data before receiving a peer lease")
	}
	pc := func(c *client) *webrtc.PeerConnection {
		var servers []webrtc.ICEServer
		check(t, json.Unmarshal(c.read(t, "ice.config").Data, &servers))
		policy := webrtc.ICETransportPolicyAll
		if entitled {
			if len(servers) != 2 || servers[1].Username == "" {
				t.Fatal("visitor did not receive TURN credentials")
			}
			policy = webrtc.ICETransportPolicyRelay
		} else if len(servers) != 1 || len(servers[0].URLs) == 0 || !strings.HasPrefix(servers[0].URLs[0], "stun:") || servers[0].Username != "" {
			t.Fatalf("unexpected direct-only config: %+v", servers)
		}
		var settings webrtc.SettingEngine
		settings.SetIncludeLoopbackCandidate(true)
		settings.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
		api := webrtc.NewAPI(webrtc.WithSettingEngine(settings))
		peer, e := api.NewPeerConnection(webrtc.Configuration{ICEServers: servers, ICETransportPolicy: policy})
		check(t, e)
		t.Cleanup(func() { peer.Close() })
		return peer
	}
	mobile, desktop := pc(guest), pc(host)
	desktopInbox, phoneInbox := make(chan []byte, 2), make(chan []byte, 2)
	desktopReady := make(chan *webrtc.DataChannel, 1)
	phoneReady := make(chan struct{}, 1)
	desktop.OnDataChannel(func(dc *webrtc.DataChannel) {
		dc.OnMessage(func(msg webrtc.DataChannelMessage) { desktopInbox <- msg.Data })
		dc.OnOpen(func() { desktopReady <- dc })
	})
	dc, err := mobile.CreateDataChannel("vanora", nil)
	check(t, err)
	dc.OnMessage(func(msg webrtc.DataChannelMessage) { phoneInbox <- msg.Data })
	dc.OnOpen(func() { phoneReady <- struct{}{} })
	exchange := func(kind string, from, to *client, s, r *endpoint.Session, a, b *webrtc.PeerConnection, desc webrtc.SessionDescription) {
		t.Helper()
		gather := webrtc.GatheringCompletePromise(a)
		check(t, a.SetLocalDescription(desc))
		select {
		case <-gather:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		record, e := s.Seal(kind, protocol.Encode(a.LocalDescription()))
		check(t, e)
		from.send(t, record)
		forwarded := to.read(t, kind)
		tampered := forwarded
		tampered.Body = base64.RawURLEncoding.EncodeToString([]byte(`{"value":"replacement"}`))
		if _, e = r.Open(tampered, time.Now()); e == nil {
			t.Fatal("accepted a substituted SDP")
		}
		verified, e := r.Open(forwarded, time.Now())
		check(t, e)
		if _, e = r.Open(forwarded, time.Now()); e == nil {
			t.Fatal("accepted a replay")
		}
		var remote webrtc.SessionDescription
		check(t, json.Unmarshal(verified, &remote))
		check(t, b.SetRemoteDescription(remote))
	}
	offer, err := mobile.CreateOffer(nil)
	check(t, err)
	exchange("rtc.offer", guest, host, phoneSession, desktopSession, mobile, desktop, offer)
	answer, err := desktop.CreateAnswer(nil)
	check(t, err)
	exchange("rtc.answer", host, guest, desktopSession, phoneSession, desktop, mobile, answer)
	remoteChannel := receive(t, ctx, desktopReady)
	receive(t, ctx, phoneReady)
	check(t, dc.Send(protocol.Encode(guest.proof)))
	check(t, remoteChannel.Send(protocol.Encode(host.proof)))
	verifyFirst := func(access *endpoint.Access, inbox <-chan []byte) {
		t.Helper()
		var proof endpoint.LeaseProof
		check(t, json.Unmarshal(receive(t, ctx, inbox), &proof))
		check(t, access.Update(false, proof, time.Now()))
		if !access.Allows(time.Now(), true, true) || access.Allows(time.Now(), true, false) {
			t.Fatal("incorrect authorization for live endpoints")
		}
	}
	verifyFirst(desktopAccess, desktopInbox)
	verifyFirst(phoneAccess, phoneInbox)
	check(t, dc.SendText("测试流式会话"))
	if string(receive(t, ctx, desktopInbox)) != "测试流式会话" {
		t.Fatal("desktop received incorrect request")
	}
	check(t, remoteChannel.SendText("桌面回复"))
	if string(receive(t, ctx, phoneInbox)) != "桌面回复" {
		t.Fatal("phone received incorrect response")
	}
	now := time.Now()
	if desktopAccess.Update(false, host.proof, now) == nil {
		t.Fatal("accepted a foreign lease")
	}
	desktopAccess.AuthorityLost()
	if desktopAccess.Allows(now, true, true) || !desktopAccess.Allows(now, false, true) || desktopAccess.Allows(now.Add(time.Minute), false, true) {
		t.Fatal("incorrect outage boundary")
	}
	pair, err := mobile.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	check(t, err)
	if pair == nil || (pair.Local.Typ == webrtc.ICECandidateTypeRelay) != entitled || (pair.Remote.Typ == webrtc.ICECandidateTypeRelay) != entitled {
		t.Fatalf("unexpected selected ICE pair: %v", pair)
	}
	publish(nil)
	if string(guest.read(t, "connect.closed").Data) != `"access_revoked"` {
		t.Fatal("missing revocation")
	}
}
