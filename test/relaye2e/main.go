// Command relaye2e exercises a real relay process across isolated Linux
// network namespaces. It is a test harness, not part of the product: the
// parent role creates identities and a local entitlement service, runs the
// relay binary, and starts desktop/mobile roles inside their own namespaces.
//
// Scenarios:
//   - TURN/UDP relay with entitlement: relay-only WebRTC, TURN byte
//     accounting, a raw TURN allocation to a public-unicast peer, and
//     revocation.
//   - TURN/TCP control channel with entitlement: relay-only WebRTC.
//   - Membership denial: direct-only ICE configuration, unreachable peers
//     because IP forwarding is disabled, no relay credentials.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/turn/v4"
	"github.com/pion/webrtc/v4"
	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/protocol"
)

const (
	relayIP      = "172.31.60.1"
	relayPort    = 8787
	entitlePort  = 19099
	turnPort     = 3478
	relayMinPort = 49152
	relayMaxPort = 49200
	echoPayload  = "turn-echo-中文"
	hostProbe    = 19999
)

type options struct {
	role       string
	dir        string
	url        string
	ca         string
	seed       string
	issuer     string
	turnMode   string
	bin        string
	relay      string
	scenario   string
	expectTurn bool
}

func main() {
	var o options
	flag.StringVar(&o.role, "role", "", "parent, desktop, mobile or echo")
	flag.StringVar(&o.dir, "dir", "/tmp/relaye2e", "scratch directory")
	flag.StringVar(&o.url, "url", "", "signaling URL (children)")
	flag.StringVar(&o.ca, "ca", "", "relay TLS certificate (children)")
	flag.StringVar(&o.seed, "seed", "", "authority seed file (children)")
	flag.StringVar(&o.issuer, "issuer", "https://issuer.example", "certificate issuer")
	flag.StringVar(&o.turnMode, "turn-mode", "udp", "expected TURN transport: udp, tcp or none")
	flag.StringVar(&o.bin, "bin", "", "harness binary used to start child roles")
	flag.StringVar(&o.relay, "relay", "", "relay binary")
	flag.StringVar(&o.scenario, "scenario", "", "scenario name")
	flag.BoolVar(&o.expectTurn, "expect-turn", true, "deprecated; turn-mode decides")
	flag.Parse()

	var err error
	switch o.role {
	case "parent":
		err = runParent(o)
	case "desktop":
		err = runDesktop(o)
	case "mobile":
		err = runMobile(o)
	case "echo":
		err = runEcho(o)
	default:
		err = fmt.Errorf("unknown role %q", o.role)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", o.role, err)
		os.Exit(1)
	}
}

func (o options) signalingURL() string {
	if o.url != "" {
		return o.url
	}
	return "wss://" + net.JoinHostPort(relayIP, strconv.Itoa(relayPort)) + "/v1/signal"
}

// ---------------------------------------------------------------- parent --

type scenario struct {
	name    string
	udp     bool
	tcp     bool
	allowed bool
	mode    string
	timeout time.Duration
}

type relayProcess struct {
	cmd *exec.Cmd
	log *processLog
}

type processLog struct {
	mu   sync.Mutex
	text strings.Builder
}

func (log *processLog) Write(data []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.text.Write(data)
}

func (log *processLog) String() string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.text.String()
}

func runParent(o options) error {
	if o.relay == "" || o.bin == "" {
		return errors.New("parent needs -relay and -bin")
	}
	if err := os.MkdirAll(o.dir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"desktop.ready", "revoke", "mobile.done", "echo.ready"} {
		_ = os.Remove(filepath.Join(o.dir, name))
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	key := ed25519.NewKeyFromSeed(seed)
	authority, err := identitytest.NewAuthorityWithKey(key, 10*time.Minute)
	if err != nil {
		return err
	}
	seedPath := filepath.Join(o.dir, "authority.seed")
	if err := writeFile(seedPath, hex.EncodeToString(seed)); err != nil {
		return err
	}
	pubPath := filepath.Join(o.dir, "authority.pub")
	if err := writeFile(pubPath, hex.EncodeToString(authority.PublicKey())); err != nil {
		return err
	}

	certPath, keyPath, err := writeTLSCert(o.dir, net.ParseIP(relayIP))
	if err != nil {
		return err
	}

	token := strings.Repeat("k", 40)
	stub := &entitlementStub{token: token}
	stub.allowed.Store(true)
	stubServer := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", strconv.Itoa(entitlePort)),
		Handler:           stub.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", stubServer.Addr)
	if err != nil {
		return fmt.Errorf("entitlement listener: %w", err)
	}
	go func() { _ = stubServer.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = stubServer.Shutdown(ctx)
	}()

	echo := startEcho(o)
	defer stopProcess(echo.cmd)
	if err := waitFile(filepath.Join(o.dir, "echo.ready"), 10*time.Second); err != nil {
		return fmt.Errorf("echo peer: %w\n%s", err, echo.log.String())
	}

	probe, err := net.ListenPacket("udp4", net.JoinHostPort(relayIP, strconv.Itoa(hostProbe)))
	if err != nil {
		return fmt.Errorf("relay host probe: %w", err)
	}
	defer probe.Close()
	go func() {
		buf := make([]byte, 256)
		for {
			n, from, err := probe.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = probe.WriteTo(append([]byte("leak:"), buf[:n]...), from)
		}
	}()

	scenarios := []scenario{
		{name: "turn_udp_entitled", udp: true, tcp: false, allowed: true, mode: "udp", timeout: 60 * time.Second},
		{name: "turn_tcp_control_entitled", udp: false, tcp: true, allowed: true, mode: "tcp", timeout: 60 * time.Second},
		{name: "membership_denied_fail_closed", udp: true, tcp: false, allowed: false, mode: "none", timeout: 45 * time.Second},
	}
	for _, sc := range scenarios {
		fmt.Printf("\n=== scenario %s ===\n", sc.name)
		if err := runScenario(o, sc, stub, certPath, keyPath, token); err != nil {
			return fmt.Errorf("%s: %w", sc.name, err)
		}
		fmt.Printf("PASS %s\n", sc.name)
	}
	fmt.Println("ALL_SCENARIOS_PASS")
	return nil
}

func runScenario(o options, sc scenario, stub *entitlementStub, certPath, keyPath, token string) error {
	stub.allowed.Store(sc.allowed)
	stub.hits.Store(0)
	for _, name := range []string{"desktop.ready", "revoke", "mobile.done"} {
		_ = os.Remove(filepath.Join(o.dir, name))
	}

	relay, err := startRelay(o, sc, certPath, keyPath, token)
	if err != nil {
		return err
	}
	defer stopProcess(relay.cmd)

	if err := waitHealth(certPath, 20*time.Second); err != nil {
		return fmt.Errorf("relay health: %w\n%s", err, relay.log.String())
	}

	desktopLog := filepath.Join(o.dir, "desktop-"+sc.name+".log")
	desktop, desktopBuf, err := startChild(o, "vanora-desktop", "desktop", sc)
	if err != nil {
		return err
	}
	desktopErr := make(chan error, 1)
	go func() { desktopErr <- desktop.Wait() }()

	if err := waitFile(filepath.Join(o.dir, "desktop.ready"), 25*time.Second); err != nil {
		_ = desktop.Process.Kill()
		<-desktopErr
		_ = os.WriteFile(desktopLog, []byte(desktopBuf.String()), 0o644)
		return fmt.Errorf("desktop did not become ready: %w\n%s", err, desktopBuf.String())
	}

	mobileLog := filepath.Join(o.dir, "mobile-"+sc.name+".log")
	mobileOut, mobileErr := runMobileChild(o, "vanora-mobile", sc)
	_ = os.WriteFile(mobileLog, []byte(mobileOut), 0o644)
	if mobileErr != nil {
		_ = desktop.Process.Kill()
		<-desktopErr
		return fmt.Errorf("mobile: %w\n%s\n--- desktop ---\n%s\n--- relay ---\n%s\n--- stub ---\nhits=%d last=%v", mobileErr, mobileOut, desktopBuf.String(), relay.log.String(), stub.hits.Load(), stub.last.Load())
	}

	select {
	case err := <-desktopErr:
		if err != nil {
			_ = os.WriteFile(desktopLog, []byte(desktopBuf.String()), 0o644)
			return fmt.Errorf("desktop: %w\n%s", err, desktopBuf.String())
		}
	case <-time.After(25 * time.Second):
		_ = desktop.Process.Kill()
		<-desktopErr
		return fmt.Errorf("desktop did not exit\n%s", desktopBuf.String())
	}
	_ = os.WriteFile(desktopLog, []byte(desktopBuf.String()), 0o644)
	if got := stub.hits.Load(); got == 0 {
		return errors.New("entitlement endpoint was never called")
	}

	log := relay.log.String()
	_ = os.WriteFile(filepath.Join(o.dir, "relay-"+sc.name+".log"), []byte(log), 0o644)
	switch sc.mode {
	case "udp":
		for _, want := range []string{"TURN_PAIR relay/relay", "DATA_OK", "TURN_ECHO_OK", "HAIRPIN_OK", "RELAY_HOST_DENIED", "REVOKED"} {
			if !strings.Contains(mobileOut, want) {
				return fmt.Errorf("mobile missing %q\n%s", want, mobileOut)
			}
		}
		if !regexp.MustCompile(`relay_bytes=[1-9][0-9]*`).MatchString(log) {
			return fmt.Errorf("relay did not account bytes\n%s", log)
		}
	case "tcp":
		for _, want := range []string{"TURN_PAIR relay/relay", "DATA_OK", "REVOKED"} {
			if !strings.Contains(mobileOut, want) {
				return fmt.Errorf("mobile missing %q\n%s", want, mobileOut)
			}
		}
		if !regexp.MustCompile(`relay_bytes=[1-9][0-9]*`).MatchString(log) {
			return fmt.Errorf("relay did not account bytes\n%s", log)
		}
	case "none":
		for _, want := range []string{"NO_TURN", "DIRECT_BLOCKED"} {
			if !strings.Contains(mobileOut, want) {
				return fmt.Errorf("mobile missing %q\n%s", want, mobileOut)
			}
		}
	}
	if !strings.Contains(desktopBuf.String(), "DESKTOP_OK") {
		return fmt.Errorf("desktop missing DESKTOP_OK\n%s", desktopBuf.String())
	}
	fmt.Printf("relay log tail: %s\n", tail(log, 3))
	return nil
}

func startRelay(o options, sc scenario, certPath, keyPath, token string) (*relayProcess, error) {
	var buf processLog
	cmd := exec.Command(o.relay)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Env = mergeEnv(os.Environ(), map[string]string{
		"RELAY_IDENTITY_PUBLIC_KEY": readTrim(filepath.Join(o.dir, "authority.pub")),
		"RELAY_MEMBERSHIP_URL":      "http://127.0.0.1:" + strconv.Itoa(entitlePort),
		"RELAY_MEMBERSHIP_TOKEN":    token,
		"RELAY_ADDR":                "0.0.0.0:" + strconv.Itoa(relayPort),
		"RELAY_TLS_CERT":            certPath,
		"RELAY_TLS_KEY":             keyPath,
		"TURN_PUBLIC_IP":            relayIP,
		"TURN_BIND_IP":              relayIP,
		"TURN_RELAY_BIND_IP":        relayIP,
		"TURN_PORT":                 strconv.Itoa(turnPort),
		"TURN_UDP":                  strconv.FormatBool(sc.udp),
		"TURN_TCP":                  strconv.FormatBool(sc.tcp),
		"TURN_RELAY_MIN_PORT":       strconv.Itoa(relayMinPort),
		"TURN_RELAY_MAX_PORT":       strconv.Itoa(relayMaxPort),
		"TURN_REALM":                "vanora",
		"STUN_URLS":                 "local",
	})
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &relayProcess{cmd: cmd, log: &buf}, nil
}

func startChild(o options, ns, role string, sc scenario) (*exec.Cmd, *processLog, error) {
	var buf processLog
	cmd := exec.Command("ip", "netns", "exec", ns, o.bin,
		"-role", role,
		"-dir", o.dir,
		"-url", o.signalingURL(),
		"-ca", filepath.Join(o.dir, "relay.crt"),
		"-seed", filepath.Join(o.dir, "authority.seed"),
		"-issuer", o.issuer,
		"-turn-mode", sc.mode,
		"-scenario", sc.name,
	)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return cmd, &buf, nil
}

func runMobileChild(o options, ns string, sc scenario) (string, error) {
	cmd, buf, err := startChild(o, ns, "mobile", sc)
	if err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(sc.timeout):
		_ = cmd.Process.Kill()
		<-done
		return buf.String(), errors.New("timed out")
	}
}

func waitHealth(certPath string, timeout time.Duration) error {
	pool, err := loadCA(certPath)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: relayIP,
			MinVersion: tls.VersionTLS12,
		}},
	}
	url := "https://" + net.JoinHostPort(relayIP, strconv.Itoa(relayPort)) + "/healthz"
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("health status %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return last
}

// -------------------------------------------------------------- children --

type signalClient struct {
	ctx   context.Context
	ws    *websocket.Conn
	creds *endpoint.Credentials
	proof endpoint.LeaseProof
}

func (c *signalClient) send(m protocol.Message) error {
	return c.ws.Write(c.ctx, websocket.MessageText, protocol.Encode(m))
}

func (c *signalClient) read(expect string) (protocol.Message, error) {
	_, b, err := c.ws.Read(c.ctx)
	if err != nil {
		return protocol.Message{}, err
	}
	var m protocol.Message
	if err := json.Unmarshal(b, &m); err != nil {
		return protocol.Message{}, err
	}
	if m.Type != expect {
		return protocol.Message{}, fmt.Errorf("want %s, got %s %s", expect, m.Type, m.Data)
	}
	return m, nil
}

func loadAuthority(seedPath string) (*identitytest.Authority, error) {
	raw, err := os.ReadFile(seedPath)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed is %d bytes", len(seed))
	}
	return identitytest.NewAuthorityWithKey(ed25519.NewKeyFromSeed(seed), 10*time.Minute)
}

func login(ctx context.Context, o options, authority *identitytest.Authority, role, subject string) (*signalClient, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	cert, err := authority.IssueWithKey(o.issuer, subject, pub, now)
	if err != nil {
		return nil, err
	}
	p, err := identity.VerifyCertificate(cert, authority.PublicKey(), now)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	lease, _, err := authority.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
	if err != nil {
		return nil, err
	}
	creds, err := endpoint.OpenCredentials(cert, key, authority.PublicKey(), now)
	if err != nil {
		return nil, err
	}
	pool, err := loadCA(o.ca)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Transport: &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: relayIP,
			MinVersion: tls.VersionTLS12,
		},
	}}
	ws, _, err := websocket.Dial(ctx, o.signalingURL(), &websocket.DialOptions{HTTPClient: httpClient})
	if err != nil {
		return nil, err
	}
	c := &signalClient{ctx: ctx, ws: ws, creds: creds, proof: endpoint.LeaseProof{Certificate: cert, Lease: lease}}
	challenge, err := c.read("auth.challenge")
	if err != nil {
		return nil, err
	}
	hello, err := creds.Login(challenge, role, lease)
	if err != nil {
		return nil, err
	}
	if err := c.send(hello); err != nil {
		return nil, err
	}
	if _, err := c.read("auth.ok"); err != nil {
		return nil, err
	}
	return c, nil
}

func readICEServers(c *signalClient) ([]webrtc.ICEServer, error) {
	m, err := c.read("ice.config")
	if err != nil {
		return nil, err
	}
	var servers []webrtc.ICEServer
	if err := json.Unmarshal(m.Data, &servers); err != nil {
		return nil, err
	}
	return servers, nil
}

func turnServer(servers []webrtc.ICEServer, transport string) (webrtc.ICEServer, bool) {
	for _, s := range servers {
		for _, u := range s.URLs {
			if !strings.HasPrefix(u, "turn:") && !strings.HasPrefix(u, "turns:") {
				continue
			}
			if transport == "tcp" && !strings.Contains(u, "transport=tcp") {
				continue
			}
			if transport == "udp" && strings.Contains(u, "transport=tcp") {
				continue
			}
			return s, true
		}
	}
	return webrtc.ICEServer{}, false
}

func anyTURN(servers []webrtc.ICEServer) bool {
	for _, s := range servers {
		for _, u := range s.URLs {
			if strings.HasPrefix(u, "turn:") || strings.HasPrefix(u, "turns:") {
				return true
			}
		}
	}
	return false
}

func stunServer(servers []webrtc.ICEServer) string {
	for _, s := range servers {
		for _, u := range s.URLs {
			if strings.HasPrefix(u, "stun:") {
				return strings.TrimPrefix(u, "stun:")
			}
		}
	}
	return ""
}

func newPeer(servers []webrtc.ICEServer, relayOnly bool) (*webrtc.PeerConnection, error) {
	policy := webrtc.ICETransportPolicyAll
	if relayOnly {
		policy = webrtc.ICETransportPolicyRelay
	}
	return webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: servers, ICETransportPolicy: policy})
}

func exchange(c *signalClient, s *endpoint.Session, pc *webrtc.PeerConnection, kind string, desc webrtc.SessionDescription) error {
	gather := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(desc); err != nil {
		return err
	}
	select {
	case <-gather:
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
	record, err := s.Seal(kind, protocol.Encode(pc.LocalDescription()))
	if err != nil {
		return err
	}
	return c.send(record)
}

func receive(c *signalClient, s *endpoint.Session, pc *webrtc.PeerConnection, kind string) error {
	m, err := c.read(kind)
	if err != nil {
		return err
	}
	tampered := m
	tampered.Body = base64.RawURLEncoding.EncodeToString([]byte(`{"value":"replacement"}`))
	if _, err := s.Open(tampered, time.Now()); err == nil {
		return errors.New("accepted a substituted SDP")
	}
	body, err := s.Open(m, time.Now())
	if err != nil {
		return err
	}
	if _, err := s.Open(m, time.Now()); err == nil {
		return errors.New("accepted a replayed SDP")
	}
	var remote webrtc.SessionDescription
	if err := json.Unmarshal(body, &remote); err != nil {
		return err
	}
	return pc.SetRemoteDescription(remote)
}

func runDesktop(o options) error {
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	authority, err := loadAuthority(o.seed)
	if err != nil {
		return err
	}
	host, err := login(ctx, o, authority, "desktop", "owner")
	if err != nil {
		return err
	}
	guestID := identity.RemoteUserID(o.issuer, "guest")
	online, err := host.creds.Online("workstation", []string{guestID})
	if err != nil {
		return err
	}
	if err := host.send(online); err != nil {
		return err
	}
	if _, err := host.read("device.registered"); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(o.dir, "desktop.ready"), "1"); err != nil {
		return err
	}
	req, err := host.read("connect.request")
	if err != nil {
		return err
	}
	sess, reply, err := host.creds.Accept(req, func(id string) bool { return id == guestID }, time.Now())
	if err != nil {
		return err
	}
	if err := host.send(reply); err != nil {
		return err
	}
	servers, err := readICEServers(host)
	if err != nil {
		return err
	}
	if o.turnMode == "none" {
		if anyTURN(servers) {
			return errors.New("relay issued TURN credentials without entitlement")
		}
		if err := waitFile(filepath.Join(o.dir, "mobile.done"), 30*time.Second); err != nil {
			return err
		}
		fmt.Println("DESKTOP_OK")
		return nil
	}
	pc, err := newPeer(servers, true)
	if err != nil {
		return err
	}
	defer pc.Close()

	inbox := make(chan []byte, 8)
	opened := make(chan *webrtc.DataChannel, 1)
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		dc.OnMessage(func(m webrtc.DataChannelMessage) { inbox <- m.Data })
		dc.OnOpen(func() { opened <- dc })
	})
	if err := receive(host, sess, pc, "rtc.offer"); err != nil {
		return err
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return err
	}
	if err := exchange(host, sess, pc, "rtc.answer", answer); err != nil {
		return err
	}
	var dc *webrtc.DataChannel
	select {
	case dc = <-opened:
	case <-ctx.Done():
		return ctx.Err()
	}
	access, err := sess.Access()
	if err != nil {
		return err
	}
	if err := access.Update(true, host.proof, time.Now()); err != nil {
		return err
	}
	if err := dc.Send(protocol.Encode(host.proof)); err != nil {
		return err
	}
	var guestProof endpoint.LeaseProof
	if err := json.Unmarshal(<-inbox, &guestProof); err != nil {
		return err
	}
	if err := access.Update(false, guestProof, time.Now()); err != nil {
		return err
	}
	if !access.Allows(time.Now(), true, true) || access.Allows(time.Now(), true, false) {
		return errors.New("desktop authorization did not converge")
	}
	select {
	case msg := <-inbox:
		if string(msg) != "ping-中文" {
			return fmt.Errorf("desktop got %q", msg)
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := dc.SendText("pong-桌面"); err != nil {
		return err
	}
	if err := waitFile(filepath.Join(o.dir, "revoke"), 20*time.Second); err != nil {
		return err
	}
	offline, err := host.creds.Online("workstation", nil)
	if err != nil {
		return err
	}
	if err := host.send(offline); err != nil {
		return err
	}
	closed, err := host.read("connect.closed")
	if err != nil {
		return err
	}
	if string(closed.Data) != `"access_revoked"` {
		return fmt.Errorf("desktop close reason: %s", closed.Data)
	}
	if _, err := host.read("device.registered"); err != nil {
		return err
	}
	fmt.Println("DESKTOP_OK")
	return nil
}

func runMobile(o options) error {
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	if err := waitFile(filepath.Join(o.dir, "desktop.ready"), 25*time.Second); err != nil {
		return err
	}
	authority, err := loadAuthority(o.seed)
	if err != nil {
		return err
	}
	guest, err := login(ctx, o, authority, "mobile", "guest")
	if err != nil {
		return err
	}
	if err := guest.send(protocol.Message{Type: "devices.list"}); err != nil {
		return err
	}
	list, err := guest.read("devices.list")
	if err != nil {
		return err
	}
	var cards []protocol.Message
	if err := json.Unmarshal(list.Data, &cards); err != nil {
		return err
	}
	if len(cards) != 1 {
		return fmt.Errorf("want one directory entry, got %d", len(cards))
	}
	device, err := endpoint.VerifyDevice(cards[0], authority.PublicKey(), time.Now())
	if err != nil {
		return err
	}
	if device.Name != "workstation" {
		return fmt.Errorf("unexpected device name %q", device.Name)
	}
	sess, request, err := guest.creds.Request(device.DeviceID, device.Owner)
	if err != nil {
		return err
	}
	if err := guest.send(request); err != nil {
		return err
	}
	accepted, err := guest.read("connect.accept")
	if err != nil {
		return err
	}
	if err := sess.Accepted(accepted, time.Now()); err != nil {
		return err
	}
	servers, err := readICEServers(guest)
	if err != nil {
		return err
	}
	_, hasTurn := turnServer(servers, o.turnMode)
	if o.turnMode == "none" {
		if anyTURN(servers) {
			return errors.New("received TURN credentials without entitlement")
		}
		hasTurn = false
		fmt.Println("NO_TURN")
		pc, err := newPeer(servers, false)
		if err != nil {
			return err
		}
		defer pc.Close()
		failed := make(chan struct{}, 1)
		pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
			if s == webrtc.ICEConnectionStateFailed {
				failed <- struct{}{}
			}
		})
		// A connection that never leaves the direct path must fail: the
		// namespaces cannot reach one another while forwarding is off.
		select {
		case <-failed:
		case <-time.After(15 * time.Second):
		}
		if state := pc.ICEConnectionState(); state == webrtc.ICEConnectionStateConnected ||
			state == webrtc.ICEConnectionStateCompleted {
			return fmt.Errorf("direct path unexpectedly connected: %s", state)
		}
		fmt.Println("DIRECT_BLOCKED")
		if err := writeFile(filepath.Join(o.dir, "mobile.done"), "1"); err != nil {
			return err
		}
		return nil
	}
	if !hasTurn {
		return fmt.Errorf("no TURN credentials for mode %s: %+v", o.turnMode, servers)
	}
	pc, err := newPeer(servers, true)
	if err != nil {
		return err
	}
	defer pc.Close()
	inbox := make(chan []byte, 8)
	opened := make(chan struct{}, 1)
	dc, err := pc.CreateDataChannel("vanora", nil)
	if err != nil {
		return err
	}
	dc.OnMessage(func(m webrtc.DataChannelMessage) { inbox <- m.Data })
	dc.OnOpen(func() { opened <- struct{}{} })
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := exchange(guest, sess, pc, "rtc.offer", offer); err != nil {
		return err
	}
	if err := receive(guest, sess, pc, "rtc.answer"); err != nil {
		return err
	}
	select {
	case <-opened:
	case <-ctx.Done():
		return ctx.Err()
	}
	access, err := sess.Access()
	if err != nil {
		return err
	}
	if err := access.Update(true, guest.proof, time.Now()); err != nil {
		return err
	}
	if err := dc.Send(protocol.Encode(guest.proof)); err != nil {
		return err
	}
	var hostProof endpoint.LeaseProof
	if err := json.Unmarshal(<-inbox, &hostProof); err != nil {
		return err
	}
	if err := access.Update(false, hostProof, time.Now()); err != nil {
		return err
	}
	if !access.Allows(time.Now(), true, true) {
		return errors.New("guest authorization did not converge")
	}
	if err := dc.SendText("ping-中文"); err != nil {
		return err
	}
	select {
	case msg := <-inbox:
		if string(msg) != "pong-桌面" {
			return fmt.Errorf("guest got %q", msg)
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil {
		return err
	}
	if pair == nil || pair.Local.Typ != webrtc.ICECandidateTypeRelay || pair.Remote.Typ != webrtc.ICECandidateTypeRelay {
		return fmt.Errorf("selected pair is not relay/relay: %+v", pair)
	}
	fmt.Println("TURN_PAIR relay/relay")
	fmt.Println("DATA_OK")
	if o.turnMode == "udp" {
		if err := rawTurnPolicy(servers); err != nil {
			return err
		}
	}
	if err := writeFile(filepath.Join(o.dir, "revoke"), "1"); err != nil {
		return err
	}
	closed, err := guest.read("connect.closed")
	if err != nil {
		return err
	}
	if string(closed.Data) != `"access_revoked"` {
		return fmt.Errorf("unexpected close reason %s", closed.Data)
	}
	fmt.Println("REVOKED")
	return nil
}

// runEcho is a UDP echo peer that lives on 8.8.8.8 in its own namespace, so
// relayed traffic must traverse the relay's public-unicast peer path.
func runEcho(o options) error {
	addr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 9000}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := writeFile(filepath.Join(o.dir, "echo.ready"), "1"); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		reply := append([]byte("echo:"), buf[:n]...)
		if _, err := conn.WriteToUDP(reply, from); err != nil {
			return err
		}
	}
}

type turnConn struct {
	client *turn.Client
	relay  net.PacketConn
}

func turnDial(servers []webrtc.ICEServer) (*turnConn, error) {
	srv, ok := turnServer(servers, "udp")
	if !ok {
		return nil, errors.New("no UDP TURN server")
	}
	turnAddr := ""
	for _, u := range srv.URLs {
		if strings.HasPrefix(u, "turn:") && !strings.Contains(u, "transport=tcp") {
			turnAddr = trimURI(u)
			break
		}
	}
	if turnAddr == "" {
		return nil, errors.New("no usable TURN URL")
	}
	stunAddr := stunServer(servers)
	if stunAddr == "" {
		stunAddr = turnAddr
	}
	password, _ := srv.Credential.(string)
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: stunAddr,
		TURNServerAddr: turnAddr,
		Username:       srv.Username,
		Password:       password,
		Realm:          "vanora",
		Conn:           conn,
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := client.Listen(); err != nil {
		client.Close()
		return nil, err
	}
	relay, err := client.Allocate()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("allocate: %w", err)
	}
	return &turnConn{client: client, relay: relay}, nil
}

func (c *turnConn) Close() {
	if c == nil {
		return
	}
	_ = c.relay.Close()
	c.client.Close()
}

func rawTurnPolicy(servers []webrtc.ICEServer) error {
	if err := rawTurnEcho(servers); err != nil {
		return err
	}
	fmt.Println("TURN_ECHO_OK")
	if err := rawTurnHairpin(servers); err != nil {
		return err
	}
	fmt.Println("HAIRPIN_OK")
	if err := rawTurnHostDenied(servers); err != nil {
		return err
	}
	fmt.Println("RELAY_HOST_DENIED")
	return nil
}

func rawTurnEcho(servers []webrtc.ICEServer) error {
	c, err := turnDial(servers)
	if err != nil {
		return err
	}
	defer c.Close()
	peer := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 9000}
	if err := c.relay.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	if _, err := c.relay.WriteTo([]byte(echoPayload), peer); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	n, _, err := c.relay.ReadFrom(buf)
	if err != nil {
		return err
	}
	if got, want := string(buf[:n]), "echo:"+echoPayload; got != want {
		return fmt.Errorf("echo %q, want %q", got, want)
	}
	return nil
}

// rawTurnHairpin sends between two allocations of the same grant. The relay
// must deliver internally instead of exposing its own address to the network.
func rawTurnHairpin(servers []webrtc.ICEServer) error {
	a, err := turnDial(servers)
	if err != nil {
		return err
	}
	defer a.Close()
	b, err := turnDial(servers)
	if err != nil {
		return err
	}
	defer b.Close()
	if err := b.relay.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if err := b.client.CreatePermission(&net.UDPAddr{IP: net.ParseIP(relayIP)}); err != nil {
		return fmt.Errorf("hairpin permission: %w", err)
	}
	if _, err := a.relay.WriteTo([]byte("hairpin"), b.relay.LocalAddr()); err != nil {
		return fmt.Errorf("hairpin write: %w", err)
	}
	buf := make([]byte, 64)
	n, _, err := b.relay.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("hairpin read: %w", err)
	}
	if string(buf[:n]) != "hairpin" {
		return fmt.Errorf("hairpin got %q", buf[:n])
	}
	return nil
}

// rawTurnHostDenied proves a relayed socket cannot reach unrelated services on
// the relay host: only allocations of the same grant may use the public IP.
// The parent listens on the probe port and echoes anything it receives, so a
// reply here means the relay forwarded a packet it should have refused.
func rawTurnHostDenied(servers []webrtc.ICEServer) error {
	c, err := turnDial(servers)
	if err != nil {
		return err
	}
	defer c.Close()
	dst := &net.UDPAddr{IP: net.ParseIP(relayIP), Port: hostProbe}
	if _, err := c.relay.WriteTo([]byte("probe"), dst); err != nil {
		return fmt.Errorf("relay host write: %w", err)
	}
	if err := c.relay.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	buf := make([]byte, 256)
	n, _, err := c.relay.ReadFrom(buf)
	if err == nil {
		return fmt.Errorf("relay host leaked %q", buf[:n])
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		return fmt.Errorf("relay host probe: %w", err)
	}
	return nil
}

func trimURI(raw string) string {
	s := strings.TrimPrefix(raw, "turn:")
	s = strings.TrimPrefix(s, "turns:")
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	return s
}

// ------------------------------------------------------------- utilities --

type entitlementStub struct {
	token   string
	allowed atomic.Bool
	hits    atomic.Int64
	last    atomic.Value
}

func (s *entitlementStub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/relay/entitlement", func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+s.token {
			s.last.Store("bad token")
			http.Error(w, "unexpected token", http.StatusForbidden)
			return
		}
		var who struct{ Issuer, Subject string }
		if err := json.NewDecoder(r.Body).Decode(&who); err != nil || who.Issuer != "https://issuer.example" || who.Subject != "guest" {
			s.last.Store(fmt.Sprintf("unexpected identity %+v err=%v", who, err))
			http.Error(w, "unexpected identity", http.StatusForbidden)
			return
		}
		s.last.Store(fmt.Sprintf("allowed=%v", s.allowed.Load()))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"relay_allowed": s.allowed.Load(),
				"valid_until":   time.Now().Add(time.Hour).Unix(),
			},
		})
	})
	return mux
}

func loadCA(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("no certificate in " + path)
	}
	return pool, nil
}

func writeTLSCert(dir string, ip net.IP) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vanora relay e2e"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	certPath := filepath.Join(dir, "relay.crt")
	keyPath := filepath.Join(dir, "relay.key")
	if err := writeFile(certPath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))); err != nil {
		return "", "", err
	}
	if err := writeFile(keyPath, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func startEcho(o options) *relayProcess {
	var buf processLog
	cmd := exec.Command("ip", "netns", "exec", "vanora-echo", o.bin, "-role", "echo", "-dir", o.dir)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "echo start: %v\n", err)
		return &relayProcess{cmd: cmd, log: &buf}
	}
	return &relayProcess{cmd: cmd, log: &buf}
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

func waitFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("timed out waiting for " + path)
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func readTrim(path string) string {
	raw, _ := os.ReadFile(path)
	return strings.TrimSpace(string(raw))
}

func mergeEnv(base []string, overrides map[string]string) []string {
	out := make([]string, 0, len(base)+len(overrides))
	for _, kv := range base {
		key, _, ok := strings.Cut(kv, "=")
		if ok {
			if _, replaced := overrides[key]; replaced {
				continue
			}
		}
		out = append(out, kv)
	}
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
