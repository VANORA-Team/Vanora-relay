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
	return loginWithHeader(t, ctx, url, role, subject, signer, nil)
}

func loginWithHeader(t *testing.T, ctx context.Context, url, role, subject string, signer *identitytest.Authority, header http.Header) *client {
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
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
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
	t.Run("direct_when_membership_denies", func(t *testing.T) {
		exerciseGuestWebRTC(t, billingServer(t, false), false)
	})
	t.Run("relay_only_with_membership", func(t *testing.T) {
		exerciseGuestWebRTC(t, billingServer(t, true), true)
	})
}

// billingServer starts one site's entitlement service for the test account and
// records whether that site grants relay access.
func billingServer(t *testing.T, entitled bool) *membership.Client {
	t.Helper()
	token := strings.Repeat("a", 40)
	billing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var who struct{ Issuer, Subject string }
		if r.Method != "POST" || r.URL.Path != "/internal/v1/relay/entitlement" || r.Header.Get("Authorization") != "Bearer "+token || json.NewDecoder(r.Body).Decode(&who) != nil || who.Issuer != "https://issuer.example" || who.Subject != "guest" {
			http.Error(w, "unexpected identity", 403)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"relay_allowed": entitled, "valid_until": time.Now().Add(time.Hour).Unix()}})
	}))
	t.Cleanup(billing.Close)
	return &membership.Client{URL: billing.URL, Token: token}
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

func exerciseGuestWebRTC(t *testing.T, verifier signal.EntitlementVerifier, entitled bool) {
	t.Helper()
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
	check(t, err)
	t.Cleanup(func() { network.Close() })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	signer, err := identitytest.NewAuthorityWithKey(key, time.Minute*10)
	check(t, err)
	h := signal.New(signer.PublicKey(), verifier, network)
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

func TestOfficialHubIsolatesSites(t *testing.T) {
	cnSigner := identitytest.NewAuthority(10 * time.Minute)
	globalSigner := identitytest.NewAuthority(10 * time.Minute)
	h := signal.New(cnSigner.PublicKey(), nil, nil)
	h.RequireIssuer("https://auth.cn.example/realms/vanora")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	dialOfficial := func(signer *identitytest.Authority, issuer string) error {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		check(t, err)
		now := time.Now()
		cert, err := signer.IssueWithKey(issuer, "user-1", pub, now)
		check(t, err)
		p, err := identity.VerifyCertificate(cert, signer.PublicKey(), now)
		check(t, err)
		nonce := make([]byte, 24)
		_, _ = rand.Read(nonce)
		lease, _, err := signer.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
		check(t, err)
		creds, err := endpoint.OpenCredentials(cert, key, signer.PublicKey(), now)
		check(t, err)
		ws, _, err := websocket.Dial(ctx, url, nil)
		check(t, err)
		defer ws.CloseNow()
		_, raw, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		var challenge protocol.Message
		check(t, json.Unmarshal(raw, &challenge))
		m, err := creds.Login(challenge, "mobile", lease)
		check(t, err)
		if err := ws.Write(ctx, websocket.MessageText, protocol.Encode(m)); err != nil {
			return err
		}
		_, replyRaw, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		var reply protocol.Message
		check(t, json.Unmarshal(replyRaw, &reply))
		if reply.Type != "auth.ok" {
			t.Fatalf("unexpected reply %s", reply.Type)
		}
		return nil
	}

	if err := dialOfficial(globalSigner, "https://auth.global.example/realms/vanora"); err == nil {
		t.Fatal("CN hub accepted certificate signed by GLOBAL authority")
	}
	if err := dialOfficial(cnSigner, "https://auth.global.example/realms/vanora"); err == nil {
		t.Fatal("CN hub accepted certificate with mismatched issuer")
	}
	if err := dialOfficial(cnSigner, "https://auth.cn.example/realms/vanora"); err != nil {
		t.Fatalf("CN hub rejected valid CN certificate: %v", err)
	}
}

func TestSelfHostedAccessTokenAndPairingRouting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t.Setenv("STUN_URLS", "local")
	t.Setenv("TURN_PUBLIC_IP", "127.0.0.1")
	t.Setenv("TURN_BIND_IP", "127.0.0.1")
	t.Setenv("TURN_PORT", "0")
	t.Setenv("TURN_TCP", "false")
	t.Setenv("TURN_RELAY_MIN_PORT", "0")
	t.Setenv("TURN_RELAY_MAX_PORT", "0")
	network, err := ice.FromEnv()
	check(t, err)
	t.Cleanup(func() { network.Close() })

	token := strings.Repeat("self-token-", 4)
	h := signal.NewSelfHosted(token, network)
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	for name, header := range map[string]http.Header{
		"missing": nil,
		"wrong":   {"Authorization": {"Bearer not-the-token"}},
	} {
		ws, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header})
		if ws != nil {
			ws.CloseNow()
		}
		if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s token: err=%v status=%v", name, err, resp)
		}
	}

	authHeader := http.Header{"Authorization": {"Bearer " + token}}

	// Official certificate must be rejected on a self-hosted hub.
	officialSigner := identitytest.NewAuthority(10 * time.Minute)
	{
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		check(t, err)
		now := time.Now()
		cert, err := officialSigner.IssueWithKey("https://issuer.example", "guest", pub, now)
		check(t, err)
		p, err := identity.VerifyCertificate(cert, officialSigner.PublicKey(), now)
		check(t, err)
		nonce := make([]byte, 24)
		_, _ = rand.Read(nonce)
		lease, _, err := officialSigner.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
		check(t, err)
		creds, err := endpoint.OpenCredentials(cert, key, officialSigner.PublicKey(), now)
		check(t, err)
		ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: authHeader})
		check(t, err)
		defer ws.CloseNow()
		_, raw, err := ws.Read(ctx)
		check(t, err)
		var ch protocol.Message
		check(t, json.Unmarshal(raw, &ch))
		loginMsg, err := creds.Login(ch, "mobile", lease)
		check(t, err)
		check(t, ws.Write(ctx, websocket.MessageText, protocol.Encode(loginMsg)))
		if _, _, err := ws.Read(ctx); err == nil {
			t.Fatal("self-hosted hub accepted official certificate")
		}
	}

	type selfEndpoint struct {
		ws   *websocket.Conn
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
		id   string
	}
	dialSelf := func(role string) *selfEndpoint {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		check(t, err)
		devID, err := identity.SelfDeviceID(pub)
		check(t, err)
		ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: authHeader})
		check(t, err)
		t.Cleanup(func() { ws.CloseNow() })
		_, raw, err := ws.Read(ctx)
		check(t, err)
		var ch protocol.Message
		check(t, json.Unmarshal(raw, &ch))
		loginMsg := protocol.Message{Type: "auth.login", Connection: ch.Connection, From: devID, To: "signal"}
		check(t, loginMsg.Sign(priv, protocol.Encode(map[string]string{
			"role":       role,
			"public_key": base64.RawURLEncoding.EncodeToString(pub),
		})))
		check(t, ws.Write(ctx, websocket.MessageText, protocol.Encode(loginMsg)))
		_, okRaw, err := ws.Read(ctx)
		check(t, err)
		var okMsg protocol.Message
		check(t, json.Unmarshal(okRaw, &okMsg))
		if okMsg.Type != "auth.ok" || !strings.Contains(string(okMsg.Data), `"mode":"self"`) {
			t.Fatalf("unexpected self auth.ok: %s %s", okMsg.Type, okMsg.Data)
		}
		return &selfEndpoint{ws: ws, pub: pub, priv: priv, id: devID}
	}
	readSelf := func(ep *selfEndpoint, expect string) protocol.Message {
		_, b, err := ep.ws.Read(ctx)
		check(t, err)
		var m protocol.Message
		check(t, json.Unmarshal(b, &m))
		if m.Type != expect {
			t.Fatalf("want %s, got %s %s", expect, m.Type, m.Data)
		}
		return m
	}
	sendSelf := func(ep *selfEndpoint, m protocol.Message) {
		check(t, ep.ws.Write(ctx, websocket.MessageText, protocol.Encode(m)))
	}

	desk := dialSelf("desktop")
	phone := dialSelf("mobile")

	// Self-hosted hub disables anonymous directory and external leases.
	sendSelf(phone, protocol.Message{Type: "devices.list"})
	if got := string(readSelf(phone, "error").Data); got != `"directory_unavailable"` {
		t.Fatalf("devices.list error = %s", got)
	}
	sendSelf(phone, protocol.Message{Type: "auth.lease", Data: protocol.Encode(map[string]string{"lease": "unused"})})
	if got := string(readSelf(phone, "error").Data); got != `"lease_unsupported"` {
		t.Fatalf("auth.lease error = %s", got)
	}

	card := protocol.Message{Type: "device.card", From: desk.id, To: "self"}
	check(t, card.Sign(desk.priv, []byte("HomePC")))
	sendSelf(desk, protocol.Message{Type: "device.online", Data: protocol.Encode(map[string]any{"card": card})})
	readSelf(desk, "device.registered")

	// Rejecting an unpaired connection before accept reports access_denied.
	deniedConn := protocol.NewID()
	reqDenied := protocol.Message{Type: "connect.request", Connection: deniedConn, From: phone.id, To: desk.id, Seq: 1}
	check(t, reqDenied.Sign(phone.priv, []byte(`{"name":"Stranger"}`)))
	sendSelf(phone, reqDenied)
	gotReq := readSelf(desk, "connect.request")
	if gotReq.Certificate != "" || gotReq.Connection != deniedConn {
		t.Fatalf("unexpected self connect.request: %+v", gotReq)
	}
	reject := protocol.Message{Type: "connect.close", Connection: deniedConn, From: desk.id, To: phone.id, Seq: 1}
	check(t, reject.Sign(desk.priv, nil))
	sendSelf(desk, reject)
	if got := string(readSelf(phone, "connect.closed").Data); got != `"access_denied"` {
		t.Fatalf("denied connect.closed = %s", got)
	}
	readSelf(desk, "connect.closed")

	// Accepted self-hosted connection grants TURN without any entitlement backend.
	okConn := protocol.NewID()
	reqOK := protocol.Message{Type: "connect.request", Connection: okConn, From: phone.id, To: desk.id, Seq: 1}
	check(t, reqOK.Sign(phone.priv, []byte(`{"name":"PairedPhone"}`)))
	sendSelf(phone, reqOK)
	readSelf(desk, "connect.request")
	accept := protocol.Message{Type: "connect.accept", Connection: okConn, From: desk.id, To: phone.id, Seq: 1}
	check(t, accept.Sign(desk.priv, []byte(`{"nonce":"`+protocol.NewID()+`"}`)))
	sendSelf(desk, accept)
	gotAccept := readSelf(phone, "connect.accept")
	if gotAccept.Certificate != "" {
		t.Fatalf("self connect.accept carried certificate")
	}
	var servers []webrtc.ICEServer
	check(t, json.Unmarshal(readSelf(phone, "ice.config").Data, &servers))
	readSelf(desk, "ice.config")
	if len(servers) != 2 || servers[1].Username == "" {
		t.Fatalf("self-hosted connection did not receive TURN credentials: %+v", servers)
	}
}
