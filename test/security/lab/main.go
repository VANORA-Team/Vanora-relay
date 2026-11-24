// Command seclab runs isolated security tests against a real Vanora relay
// binary inside Linux network namespaces (no IP forwarding between clients and
// echo peers; TURN is the only bridged path).
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
	relayIP        = "172.31.60.1"
	secondaryIP    = "8.8.8.1"
	relayPort      = 8787
	entitlePort    = 19099
	turnPort       = 3478
	relayMinPort   = 49152
	relayMaxPort   = 49200
	hostProbePort  = 19999
	secProbePort   = 19998
	echoServerAddr = "8.8.8.8:9000"
)

type options struct {
	role     string
	dir      string
	url      string
	ca       string
	seed     string
	issuer   string
	bin      string
	relay    string
	scenario string
	token    string
}

func main() {
	var o options
	flag.StringVar(&o.role, "role", "", "parent, desktop, mobile, or echo")
	flag.StringVar(&o.dir, "dir", "/tmp/seclab", "scratch directory")
	flag.StringVar(&o.url, "url", "", "signaling URL")
	flag.StringVar(&o.ca, "ca", "", "relay TLS certificate")
	flag.StringVar(&o.seed, "seed", "", "authority seed file")
	flag.StringVar(&o.issuer, "issuer", "https://issuer.example", "certificate issuer")
	flag.StringVar(&o.bin, "bin", "", "seclab binary")
	flag.StringVar(&o.relay, "relay", "", "relay binary")
	flag.StringVar(&o.scenario, "scenario", "", "scenario name")
	flag.StringVar(&o.token, "token", "", "self-hosted bearer token")
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
	return "wss://" + net.JoinHostPort(relayIP, fmt.Sprintf("%d", relayPort)) + "/v1/signal"
}

type processLog struct {
	mu   sync.Mutex
	text strings.Builder
}

func (l *processLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.Write(p)
}

func (l *processLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.String()
}

type relayProcess struct {
	cmd *exec.Cmd
	log *processLog
}

func runParent(o options) error {
	if o.relay == "" || o.bin == "" {
		return errors.New("parent requires -relay and -bin")
	}
	if err := os.MkdirAll(o.dir, 0o755); err != nil {
		return err
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	authority, err := identitytest.NewAuthorityWithKey(ed25519.NewKeyFromSeed(seed), 10*time.Minute)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(o.dir, "authority.seed"), hex.EncodeToString(seed)); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(o.dir, "authority.pub"), hex.EncodeToString(authority.PublicKey())); err != nil {
		return err
	}

	certPath, keyPath, err := writeTLSCert(o.dir, net.ParseIP(relayIP))
	if err != nil {
		return err
	}

	entitleToken := strings.Repeat("k", 40)
	stub := &entitlementStub{token: entitleToken}
	stub.allowed.Store(true)
	stubSrv := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", entitlePort),
		Handler:           stub.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", stubSrv.Addr)
	if err != nil {
		return err
	}
	go func() { _ = stubSrv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = stubSrv.Shutdown(ctx)
	}()

	echo := startEcho(o)
	defer stopProcess(echo.cmd)
	if err := waitFile(filepath.Join(o.dir, "echo.ready"), 10*time.Second); err != nil {
		return fmt.Errorf("echo startup: %w\n%s", err, echo.log.String())
	}

	// Probe 1: advertised public IP probe (should be dropped by relayConn.WriteTo).
	stopProbe1, err := startUDPProbe(net.JoinHostPort(relayIP, fmt.Sprintf("%d", hostProbePort)), "leak-primary:")
	if err != nil {
		return err
	}
	defer stopProbe1()

	// Probe 2: secondary non-advertised IP on the relay host (8.8.8.1 on br-e).
	stopProbe2, err := startUDPProbe(net.JoinHostPort(secondaryIP, fmt.Sprintf("%d", secProbePort)), "leak-secondary:")
	if err != nil {
		return err
	}
	defer stopProbe2()

	selfToken := strings.Repeat("S", 36)

	fmt.Println("=== scenario official_turn_security ===")
	if err := runOfficialSecurityScenario(o, certPath, keyPath, entitleToken); err != nil {
		return fmt.Errorf("official_turn_security: %w", err)
	}
	fmt.Println("PASS official_turn_security")

	fmt.Println("=== scenario self_channel_smoke ===")
	if err := runSelfSmokeScenario(o, certPath, keyPath, selfToken); err != nil {
		return fmt.Errorf("self_channel_smoke: %w", err)
	}
	fmt.Println("PASS self_channel_smoke")

	fmt.Println("SECLAB_ALL_PASS")
	return nil
}

func startUDPProbe(addr, prefix string) (func(), error) {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("probe listen %s: %w", addr, err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte(prefix), buf[:n]...), from)
		}
	}()
	return func() { _ = pc.Close() }, nil
}

func runOfficialSecurityScenario(o options, certPath, keyPath, entitleToken string) error {
	for _, name := range []string{"desktop.ready", "revoke", "mobile.done", "self.devid"} {
		_ = os.Remove(filepath.Join(o.dir, name))
	}
	relay, err := startRelayProcess(o.relay, map[string]string{
		"RELAY_CHANNEL":             "cn",
		"RELAY_IDENTITY_PUBLIC_KEY": readTrim(filepath.Join(o.dir, "authority.pub")),
		"RELAY_CN_MEMBERSHIP_URL":   fmt.Sprintf("http://127.0.0.1:%d", entitlePort),
		"RELAY_CN_MEMBERSHIP_TOKEN": entitleToken,
		"RELAY_ADDR":                fmt.Sprintf("0.0.0.0:%d", relayPort),
		"RELAY_TLS_CERT":            certPath,
		"RELAY_TLS_KEY":             keyPath,
		"TURN_PUBLIC_IP":            relayIP,
		"TURN_BIND_IP":              relayIP,
		"TURN_RELAY_BIND_IP":        relayIP,
		"TURN_PORT":                 fmt.Sprintf("%d", turnPort),
		"TURN_UDP":                  "true",
		"TURN_TCP":                  "true",
		"TURN_RELAY_MIN_PORT":       fmt.Sprintf("%d", relayMinPort),
		"TURN_RELAY_MAX_PORT":       fmt.Sprintf("%d", relayMaxPort),
		"TURN_REALM":                "vanora",
		"STUN_URLS":                 "local",
	})
	if err != nil {
		return err
	}
	defer stopProcess(relay.cmd)
	if err := waitHealth(certPath, 20*time.Second); err != nil {
		return fmt.Errorf("relay health: %w\n%s", err, relay.log.String())
	}

	deskCmd, deskBuf, err := startChild(o, "vanora-desktop", "desktop", "official", "")
	if err != nil {
		return err
	}
	deskDone := make(chan error, 1)
	go func() { deskDone <- deskCmd.Wait() }()
	if err := waitFile(filepath.Join(o.dir, "desktop.ready"), 20*time.Second); err != nil {
		_ = deskCmd.Process.Kill()
		<-deskDone
		return fmt.Errorf("desktop ready: %w\n%s", err, deskBuf.String())
	}

	mobOut, mobErr := runChildSync(o, "vanora-mobile", "mobile", "official", "", 60*time.Second)
	fmt.Print(mobOut)
	if mobErr != nil {
		_ = deskCmd.Process.Kill()
		<-deskDone
		return fmt.Errorf("mobile: %w\n%s\n--- desktop ---\n%s\n--- relay ---\n%s", mobErr, mobOut, deskBuf.String(), relay.log.String())
	}
	select {
	case err := <-deskDone:
		if err != nil {
			return fmt.Errorf("desktop: %w\n%s", err, deskBuf.String())
		}
	case <-time.After(20 * time.Second):
		_ = deskCmd.Process.Kill()
		<-deskDone
		return errors.New("desktop timed out")
	}
	for _, marker := range []string{"PASS PEER_FILTER_BLOCKED", "PASS RELAY_PUBLIC_IP_DROPPED", "PASS REVOKED_CREDS_REJECTED"} {
		if !strings.Contains(mobOut, marker) {
			return fmt.Errorf("missing marker %q in output:\n%s", marker, mobOut)
		}
	}
	if strict := strings.TrimSpace(os.Getenv("VANORA_SECURITY_STRICT")); strict == "1" || strings.EqualFold(strict, "true") {
		if strings.Contains(mobOut, "FINDING ") {
			return fmt.Errorf("strict mode failed due to security finding:\n%s", mobOut)
		}
	}
	return nil
}

func runSelfSmokeScenario(o options, certPath, keyPath, selfToken string) error {
	for _, name := range []string{"desktop.ready", "revoke", "mobile.done", "self.devid"} {
		_ = os.Remove(filepath.Join(o.dir, name))
	}
	relay, err := startRelayProcess(o.relay, map[string]string{
		"RELAY_CHANNEL":       "self",
		"RELAY_SELF_TOKEN":    selfToken,
		"RELAY_ADDR":          fmt.Sprintf("0.0.0.0:%d", relayPort),
		"RELAY_TLS_CERT":      certPath,
		"RELAY_TLS_KEY":       keyPath,
		"TURN_PUBLIC_IP":      relayIP,
		"TURN_BIND_IP":        relayIP,
		"TURN_RELAY_BIND_IP":  relayIP,
		"TURN_PORT":           fmt.Sprintf("%d", turnPort),
		"TURN_UDP":            "true",
		"TURN_TCP":            "false",
		"TURN_RELAY_MIN_PORT": fmt.Sprintf("%d", relayMinPort),
		"TURN_RELAY_MAX_PORT": fmt.Sprintf("%d", relayMaxPort),
		"TURN_REALM":          "vanora",
		"STUN_URLS":           "local",
	})
	if err != nil {
		return err
	}
	defer stopProcess(relay.cmd)
	if err := waitHealth(certPath, 20*time.Second); err != nil {
		return fmt.Errorf("self relay health: %w\n%s", err, relay.log.String())
	}

	deskCmd, deskBuf, err := startChild(o, "vanora-desktop", "desktop", "self", selfToken)
	if err != nil {
		return err
	}
	deskDone := make(chan error, 1)
	go func() { deskDone <- deskCmd.Wait() }()
	if err := waitFile(filepath.Join(o.dir, "desktop.ready"), 20*time.Second); err != nil {
		_ = deskCmd.Process.Kill()
		<-deskDone
		return fmt.Errorf("self desktop ready: %w\n%s", err, deskBuf.String())
	}

	mobOut, mobErr := runChildSync(o, "vanora-mobile", "mobile", "self", selfToken, 45*time.Second)
	fmt.Print(mobOut)
	if mobErr != nil {
		_ = deskCmd.Process.Kill()
		<-deskDone
		return fmt.Errorf("self mobile: %w\n%s\n--- desktop ---\n%s", mobErr, mobOut, deskBuf.String())
	}
	select {
	case err := <-deskDone:
		if err != nil {
			return fmt.Errorf("self desktop: %w\n%s", err, deskBuf.String())
		}
	case <-time.After(15 * time.Second):
		_ = deskCmd.Process.Kill()
		<-deskDone
		return errors.New("self desktop timed out")
	}
	for _, marker := range []string{"PASS SELF_WRONG_TOKEN_401", "INFO SELF_TURN_SLIDING_RENEWAL_OK", "PASS SELF_TURN_ECHO_OK"} {
		if !strings.Contains(mobOut, marker) {
			return fmt.Errorf("missing marker %q in self output:\n%s", marker, mobOut)
		}
	}
	return nil
}

func startRelayProcess(bin string, envOverrides map[string]string) (*relayProcess, error) {
	var buf processLog
	cmd := exec.Command(bin)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Env = mergeEnv(os.Environ(), envOverrides)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &relayProcess{cmd: cmd, log: &buf}, nil
}

func startChild(o options, ns, role, scenario, token string) (*exec.Cmd, *processLog, error) {
	var buf processLog
	args := []string{
		"netns", "exec", ns, o.bin,
		"-role", role,
		"-dir", o.dir,
		"-url", o.signalingURL(),
		"-ca", filepath.Join(o.dir, "relay.crt"),
		"-seed", filepath.Join(o.dir, "authority.seed"),
		"-issuer", o.issuer,
		"-scenario", scenario,
	}
	if token != "" {
		args = append(args, "-token", token)
	}
	cmd := exec.Command("ip", args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return cmd, &buf, nil
}

func runChildSync(o options, ns, role, scenario, token string, timeout time.Duration) (string, error) {
	cmd, buf, err := startChild(o, ns, role, scenario, token)
	if err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return buf.String(), errors.New("timed out")
	}
}

// -------------------------------------------------------------- desktop --

func runDesktop(o options) error {
	if o.scenario == "self" {
		return runDesktopSelf(o)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	authority, err := loadAuthority(o.seed)
	if err != nil {
		return err
	}
	host, err := loginOfficial(ctx, o, authority, "desktop", "owner")
	if err != nil {
		return err
	}
	defer host.ws.CloseNow()
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
	_, reply, err := host.creds.Accept(req, func(id string) bool { return id == guestID }, time.Now())
	if err != nil {
		return err
	}
	if err := host.send(reply); err != nil {
		return err
	}
	if _, err := readICEServers(host); err != nil {
		return err
	}
	if err := waitFile(filepath.Join(o.dir, "revoke"), 40*time.Second); err != nil {
		return err
	}
	offline, err := host.creds.Online("workstation", nil)
	if err != nil {
		return err
	}
	if err := host.send(offline); err != nil {
		return err
	}
	if _, err := host.read("connect.closed"); err != nil {
		return err
	}
	if _, err := host.read("device.registered"); err != nil {
		return err
	}
	return nil
}

func runDesktopSelf(o options) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	devID, err := identity.SelfDeviceID(pub)
	if err != nil {
		return err
	}
	ws, err := dialSelfWS(ctx, o, o.token, "desktop", pub, priv, devID)
	if err != nil {
		return err
	}
	defer ws.CloseNow()

	card := protocol.Message{Type: "device.card", From: devID, To: "self"}
	if err := card.Sign(priv, []byte("SelfPC")); err != nil {
		return err
	}
	if err := writeWS(ctx, ws, protocol.Message{Type: "device.online", Data: protocol.Encode(map[string]any{"card": card})}); err != nil {
		return err
	}
	if _, err := readExpectWS(ctx, ws, "device.registered"); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(o.dir, "self.devid"), devID); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(o.dir, "desktop.ready"), "1"); err != nil {
		return err
	}
	req, err := readExpectWS(ctx, ws, "connect.request")
	if err != nil {
		return err
	}
	accept := protocol.Message{Type: "connect.accept", Connection: req.Connection, From: devID, To: req.From, Seq: 1}
	if err := accept.Sign(priv, []byte(`{"nonce":"`+protocol.NewID()+`"}`)); err != nil {
		return err
	}
	if err := writeWS(ctx, ws, accept); err != nil {
		return err
	}
	if _, err := readExpectWS(ctx, ws, "ice.config"); err != nil {
		return err
	}
	// Drain ice.config from refresh until mobile finishes.
	go func() {
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				return
			}
		}
	}()
	return waitFile(filepath.Join(o.dir, "mobile.done"), 30*time.Second)
}

// --------------------------------------------------------------- mobile --

func runMobile(o options) error {
	if o.scenario == "self" {
		return runMobileSelf(o)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	if err := waitFile(filepath.Join(o.dir, "desktop.ready"), 20*time.Second); err != nil {
		return err
	}
	authority, err := loadAuthority(o.seed)
	if err != nil {
		return err
	}
	guest, err := loginOfficial(ctx, o, authority, "mobile", "guest")
	if err != nil {
		return err
	}
	defer guest.ws.CloseNow()

	if err := guest.send(protocol.Message{Type: "devices.list"}); err != nil {
		return err
	}
	list, err := guest.read("devices.list")
	if err != nil {
		return err
	}
	var cards []protocol.Message
	if err := json.Unmarshal(list.Data, &cards); err != nil || len(cards) != 1 {
		return fmt.Errorf("devices.list err=%v len=%d", err, len(cards))
	}
	dev, err := endpoint.VerifyDevice(cards[0], authority.PublicKey(), time.Now())
	if err != nil {
		return err
	}
	sess, req, err := guest.creds.Request(dev.DeviceID, dev.Owner)
	if err != nil {
		return err
	}
	if err := guest.send(req); err != nil {
		return err
	}
	accept, err := guest.read("connect.accept")
	if err != nil {
		return err
	}
	if err := sess.Accepted(accept, time.Now()); err != nil {
		return err
	}
	servers, err := readICEServers(guest)
	if err != nil {
		return err
	}

	// Sanity check: echo peer works.
	if err := checkTurnEcho(servers, "sanity"); err != nil {
		return fmt.Errorf("sanity turn echo: %w", err)
	}

	// Check 1: CreatePermission to loopback/RFC1918/link-local/metadata/multicast/CGNAT must fail.
	if err := checkPeerFilter(servers); err != nil {
		return err
	}
	fmt.Println("PASS PEER_FILTER_BLOCKED")

	// Check 2: relay advertised public IP (172.31.60.1:19999 and :3478) must be dropped.
	if err := checkRelayPublicIPDropped(servers); err != nil {
		return err
	}
	fmt.Println("PASS RELAY_PUBLIC_IP_DROPPED")

	// Check 3: secondary non-advertised IP on relay host (8.8.8.1:19998).
	if leaked, err := checkSecondaryHostIP(servers); err != nil {
		return err
	} else if leaked {
		fmt.Println("FINDING VR-SEC-04 secondary_ip_reachable 8.8.8.1:19998 (peers.go:65-80 only exempts TURN_PUBLIC_IP)")
	} else {
		fmt.Println("PASS SECONDARY_IP_BLOCKED")
	}

	// Check 4: concurrent Allocate race vs TURN_MAX_ALLOCATIONS_PER_GRANT (default 8)
	// across parallel TCP + UDP control connections.
	okAllocs := testConcurrentAllocates(servers, 16)
	if okAllocs > 8 {
		fmt.Printf("FINDING VR-SEC-05 alloc_quota_race concurrent_succeeded=%d limit=8 (relay.go:216-255)\n", okAllocs)
	} else {
		fmt.Printf("PASS ALLOC_QUOTA_ENFORCED succeeded=%d\n", okAllocs)
	}

	// Check 5: keep a pre-revoke allocation open, trigger revoke, then verify both
	// existing socket death and fresh Allocate rejection (401).
	preConn, err := turnDial(servers)
	if err != nil {
		return fmt.Errorf("pre-revoke dial: %w", err)
	}
	defer preConn.Close()
	if err := writeFile(filepath.Join(o.dir, "revoke"), "1"); err != nil {
		return err
	}
	closed, err := guest.read("connect.closed")
	if err != nil {
		return err
	}
	if string(closed.Data) != `"access_revoked"` {
		return fmt.Errorf("unexpected close reason: %s", closed.Data)
	}
	if err := checkTurnEchoWithConn(preConn, "after-revoke"); err == nil {
		return errors.New("pre-revoke TURN allocation still relayed traffic after revoke")
	}
	if c2, err := turnDial(servers); err == nil {
		c2.Close()
		return errors.New("pre-revoke TURN credential still allowed fresh Allocate after revoke")
	}
	fmt.Println("PASS REVOKED_CREDS_REJECTED")
	fmt.Println("INFO NO_PER_VISITOR_GRANT_CAP_OR_BANDWIDTH_CAP (ice.go:158, relay.go:62-97)")
	return nil
}

func runMobileSelf(o options) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := waitFile(filepath.Join(o.dir, "desktop.ready"), 20*time.Second); err != nil {
		return err
	}
	deskDevID := readTrim(filepath.Join(o.dir, "self.devid"))

	// Verify wrong bearer token over real TLS gets HTTP 401.
	httpClient, err := tlsHTTPClient(o.ca)
	if err != nil {
		return err
	}
	wsBad, resp, err := websocket.Dial(ctx, o.signalingURL(), &websocket.DialOptions{
		HTTPClient: httpClient,
		HTTPHeader: http.Header{"Authorization": {"Bearer " + strings.Repeat("Z", 36)}},
	})
	if wsBad != nil {
		_ = wsBad.CloseNow()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("wrong self token got err=%v resp=%v, want 401", err, resp)
	}
	fmt.Println("PASS SELF_WRONG_TOKEN_401")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	devID, err := identity.SelfDeviceID(pub)
	if err != nil {
		return err
	}
	ws, err := dialSelfWS(ctx, o, o.token, "mobile", pub, priv, devID)
	if err != nil {
		return err
	}
	defer ws.CloseNow()

	connID := protocol.NewID()
	req := protocol.Message{Type: "connect.request", Connection: connID, From: devID, To: deskDevID, Seq: 1}
	if err := req.Sign(priv, []byte(`{"name":"SelfPhone"}`)); err != nil {
		return err
	}
	if err := writeWS(ctx, ws, req); err != nil {
		return err
	}
	if _, err := readExpectWS(ctx, ws, "connect.accept"); err != nil {
		return err
	}
	cfg1, err := readExpectWS(ctx, ws, "ice.config")
	if err != nil {
		return err
	}
	var servers []webrtc.ICEServer
	if err := json.Unmarshal(cfg1.Data, &servers); err != nil {
		return err
	}
	if _, ok := turnServer(servers); !ok {
		return fmt.Errorf("self mode missing TURN config: %+v", servers)
	}
	if err := checkTurnEcho(servers, "self-smoke"); err != nil {
		return fmt.Errorf("self TURN echo: %w", err)
	}
	fmt.Println("PASS SELF_TURN_ECHO_OK")

	// Wait past the 10s ice.refresh cooldown and verify sliding renewal works.
	time.Sleep(10500 * time.Millisecond)
	if err := writeWS(ctx, ws, protocol.Message{Type: "ice.refresh", Connection: connID}); err != nil {
		return err
	}
	cfg2, err := readExpectWS(ctx, ws, "ice.config")
	if err != nil {
		return err
	}
	var renewed []webrtc.ICEServer
	if err := json.Unmarshal(cfg2.Data, &renewed); err != nil {
		return err
	}
	if _, ok := turnServer(renewed); !ok {
		return fmt.Errorf("self ice.refresh lost TURN servers: %+v", renewed)
	}
	fmt.Println("INFO SELF_TURN_SLIDING_RENEWAL_OK (hub.go:408-411 unbounded 10m sliding renewal)")
	return writeFile(filepath.Join(o.dir, "mobile.done"), "1")
}

func checkPeerFilter(servers []webrtc.ICEServer) error {
	c, err := turnDial(servers)
	if err != nil {
		return err
	}
	defer c.Close()
	blocked := []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.31.61.2",
		"169.254.169.254",
		"224.0.0.1",
		"100.64.0.1",
	}
	for _, ip := range blocked {
		if err := c.client.CreatePermission(&net.UDPAddr{IP: net.ParseIP(ip), Port: 9999}); err == nil {
			return fmt.Errorf("CreatePermission unexpectedly succeeded for blocked IP %s", ip)
		}
	}
	return nil
}

func checkRelayPublicIPDropped(servers []webrtc.ICEServer) error {
	c, err := turnDial(servers)
	if err != nil {
		return err
	}
	defer c.Close()
	for _, port := range []int{hostProbePort, turnPort} {
		dst := &net.UDPAddr{IP: net.ParseIP(relayIP), Port: port}
		if _, err := c.relay.WriteTo([]byte("probe-pub"), dst); err != nil {
			return err
		}
	}
	_ = c.relay.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 256)
	n, _, err := c.relay.ReadFrom(buf)
	if err == nil {
		return fmt.Errorf("relay leaked packet on publicIP: %q", buf[:n])
	}
	return nil
}

func checkSecondaryHostIP(servers []webrtc.ICEServer) (bool, error) {
	c, err := turnDial(servers)
	if err != nil {
		return false, err
	}
	defer c.Close()
	dst := &net.UDPAddr{IP: net.ParseIP(secondaryIP), Port: secProbePort}
	if _, err := c.relay.WriteTo([]byte("sec-probe"), dst); err != nil {
		return false, nil
	}
	_ = c.relay.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _, err := c.relay.ReadFrom(buf)
	if err == nil && strings.Contains(string(buf[:n]), "leak-secondary:sec-probe") {
		return true, nil
	}
	return false, nil
}

func testConcurrentAllocates(servers []webrtc.ICEServer, attempts int) int {
	srv, ok := turnServer(servers)
	if !ok {
		return 0
	}
	turnAddr := ""
	for _, u := range srv.URLs {
		if strings.HasPrefix(u, "turn:") {
			s := strings.TrimPrefix(u, "turn:")
			if i := strings.IndexByte(s, '?'); i >= 0 {
				s = s[:i]
			}
			turnAddr = s
			break
		}
	}
	pass, _ := srv.Credential.(string)

	// Pre-connect TCP clients so all Allocate() calls race concurrently inside pion/turn.
	type prepared struct {
		client *turn.Client
	}
	prepped := make([]prepared, 0, attempts)
	for i := 0; i < attempts; i++ {
		tcpConn, err := net.DialTimeout("tcp4", turnAddr, 3*time.Second)
		if err != nil {
			continue
		}
		c, err := turn.NewClient(&turn.ClientConfig{
			TURNServerAddr: turnAddr,
			Username:       srv.Username,
			Password:       pass,
			Realm:          "vanora",
			Conn:           turn.NewSTUNConn(tcpConn),
		})
		if err != nil {
			_ = tcpConn.Close()
			continue
		}
		if err := c.Listen(); err != nil {
			c.Close()
			continue
		}
		prepped = append(prepped, prepared{client: c})
	}

	startCh := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []*turnConn
	for _, p := range prepped {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startCh
			if relay, err := p.client.Allocate(); err == nil {
				mu.Lock()
				conns = append(conns, &turnConn{client: p.client, relay: relay})
				mu.Unlock()
			} else {
				p.client.Close()
			}
		}()
	}
	close(startCh)
	wg.Wait()
	count := len(conns)
	for _, c := range conns {
		c.Close()
	}
	return count
}

func checkTurnEcho(servers []webrtc.ICEServer, payload string) error {
	c, err := turnDial(servers)
	if err != nil {
		return err
	}
	defer c.Close()
	return checkTurnEchoWithConn(c, payload)
}

func checkTurnEchoWithConn(c *turnConn, payload string) error {
	peer, err := net.ResolveUDPAddr("udp4", echoServerAddr)
	if err != nil {
		return err
	}
	_ = c.relay.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.relay.WriteTo([]byte(payload), peer); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, _, err := c.relay.ReadFrom(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != "echo:"+payload {
		return fmt.Errorf("got %q, want %q", buf[:n], "echo:"+payload)
	}
	return nil
}

func runEcho(o options) error {
	addr, err := net.ResolveUDPAddr("udp4", echoServerAddr)
	if err != nil {
		return err
	}
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
		_, _ = conn.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
	}
}

// ------------------------------------------------------------- helpers --

type signalClient struct {
	ctx   context.Context
	ws    *websocket.Conn
	creds *endpoint.Credentials
}

func (c *signalClient) send(m protocol.Message) error {
	return writeWS(c.ctx, c.ws, m)
}

func (c *signalClient) read(expect string) (protocol.Message, error) {
	return readExpectWS(c.ctx, c.ws, expect)
}

func writeWS(ctx context.Context, ws *websocket.Conn, m protocol.Message) error {
	return ws.Write(ctx, websocket.MessageText, protocol.Encode(m))
}

func readExpectWS(ctx context.Context, ws *websocket.Conn, expect string) (protocol.Message, error) {
	_, b, err := ws.Read(ctx)
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

func tlsHTTPClient(caPath string) (*http.Client, error) {
	pool, err := loadCA(caPath)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: relayIP,
			MinVersion: tls.VersionTLS12,
		},
	}}, nil
}

func loginOfficial(ctx context.Context, o options, authority *identitytest.Authority, role, subject string) (*signalClient, error) {
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
	_, _ = rand.Read(nonce)
	lease, _, err := authority.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
	if err != nil {
		return nil, err
	}
	creds, err := endpoint.OpenCredentials(cert, key, authority.PublicKey(), now)
	if err != nil {
		return nil, err
	}
	httpClient, err := tlsHTTPClient(o.ca)
	if err != nil {
		return nil, err
	}
	ws, _, err := websocket.Dial(ctx, o.signalingURL(), &websocket.DialOptions{HTTPClient: httpClient})
	if err != nil {
		return nil, err
	}
	c := &signalClient{ctx: ctx, ws: ws, creds: creds}
	ch, err := c.read("auth.challenge")
	if err != nil {
		return nil, err
	}
	hello, err := creds.Login(ch, role, lease)
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

func dialSelfWS(ctx context.Context, o options, token, role string, pub ed25519.PublicKey, priv ed25519.PrivateKey, devID string) (*websocket.Conn, error) {
	httpClient, err := tlsHTTPClient(o.ca)
	if err != nil {
		return nil, err
	}
	ws, _, err := websocket.Dial(ctx, o.signalingURL(), &websocket.DialOptions{
		HTTPClient: httpClient,
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	if err != nil {
		return nil, err
	}
	ch, err := readExpectWS(ctx, ws, "auth.challenge")
	if err != nil {
		_ = ws.CloseNow()
		return nil, err
	}
	m := protocol.Message{Type: "auth.login", Connection: ch.Connection, From: devID, To: "signal"}
	if err := m.Sign(priv, protocol.Encode(map[string]string{
		"role":       role,
		"public_key": base64.RawURLEncoding.EncodeToString(pub),
	})); err != nil {
		_ = ws.CloseNow()
		return nil, err
	}
	if err := writeWS(ctx, ws, m); err != nil {
		_ = ws.CloseNow()
		return nil, err
	}
	if _, err := readExpectWS(ctx, ws, "auth.ok"); err != nil {
		_ = ws.CloseNow()
		return nil, err
	}
	return ws, nil
}

func readICEServers(c *signalClient) ([]webrtc.ICEServer, error) {
	m, err := c.read("ice.config")
	if err != nil {
		return nil, err
	}
	var servers []webrtc.ICEServer
	return servers, json.Unmarshal(m.Data, &servers)
}

func turnServer(servers []webrtc.ICEServer) (webrtc.ICEServer, bool) {
	for _, s := range servers {
		for _, u := range s.URLs {
			if strings.HasPrefix(u, "turn:") && !strings.Contains(u, "transport=tcp") {
				return s, true
			}
		}
	}
	return webrtc.ICEServer{}, false
}

type turnConn struct {
	client *turn.Client
	relay  net.PacketConn
}

func turnDial(servers []webrtc.ICEServer) (*turnConn, error) {
	srv, ok := turnServer(servers)
	if !ok {
		return nil, errors.New("no UDP TURN server")
	}
	turnAddr := ""
	for _, u := range srv.URLs {
		if strings.HasPrefix(u, "turn:") && !strings.Contains(u, "transport=tcp") {
			s := strings.TrimPrefix(u, "turn:")
			if i := strings.IndexByte(s, '?'); i >= 0 {
				s = s[:i]
			}
			turnAddr = s
			break
		}
	}
	pass, _ := srv.Credential.(string)
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: turnAddr,
		TURNServerAddr: turnAddr,
		Username:       srv.Username,
		Password:       pass,
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
		return nil, err
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

type entitlementStub struct {
	token   string
	allowed atomic.Bool
}

func (s *entitlementStub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/relay/entitlement", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+s.token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
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

func loadAuthority(seedPath string) (*identitytest.Authority, error) {
	raw, err := os.ReadFile(seedPath)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	return identitytest.NewAuthorityWithKey(ed25519.NewKeyFromSeed(seed), 10*time.Minute)
}

func waitHealth(certPath string, timeout time.Duration) error {
	client, err := tlsHTTPClient(certPath)
	if err != nil {
		return err
	}
	client.Timeout = 2 * time.Second
	url := fmt.Sprintf("https://%s:%d/healthz", relayIP, relayPort)
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

func loadCA(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("no cert in " + path)
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
		Subject:               pkix.Name{CommonName: "vanora seclab"},
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
	_ = cmd.Start()
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
		k, _, ok := strings.Cut(kv, "=")
		if ok {
			if _, replaced := overrides[k]; replaced {
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
