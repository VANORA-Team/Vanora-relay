package lan

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coder/websocket"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/dialretry"
	"vanora-relay/internal/pairing"
)

const (
	tokenHeader   = "X-Vanora-Pairing"
	nameHeader    = "X-Vanora-Client-Name"
	roleHeader    = "X-Vanora-Client-Role"
	addressHeader = "X-Vanora-Client-Address"
)

var ErrUnpaired = errors.New("LAN: device authorization required")

type Target struct {
	Address string
	Pin     string
	Token   string
}

func ParseTarget(link string) (Target, error) {
	parsed, err := url.Parse(strings.TrimSpace(link))
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Path != path ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Opaque != "" {
		return Target{}, errors.New("LAN: invalid pairing link")
	}
	address, err := parseLocalAddress(parsed.Host)
	if err != nil || address.Port() == 0 {
		return Target{}, errors.New("LAN: link must use a private IP address and port")
	}
	params, err := url.ParseQuery(parsed.Fragment)
	pin, token := params.Get("pin"), params.Get("pair")
	if err != nil || !validToken(pin) || (token != "" && !validToken(token)) {
		return Target{}, errors.New("LAN: invalid pairing parameters")
	}
	return Target{Address: address.String(), Pin: pin, Token: token}, nil
}

func (t Target) Link() string {
	params := url.Values{"pin": {t.Pin}}
	if t.Token != "" {
		params.Set("pair", t.Token)
	}
	return (&url.URL{Scheme: "https", Host: t.Address, Path: path, Fragment: params.Encode()}).String()
}

func Dial(ctx context.Context, target Target, seed, name string, handler transport.Handler) (transport.Peer, func(), error) {
	return DialWithOptions(ctx, target, seed, name, "mobile", "", handler)
}

func DialWithOptions(ctx context.Context, target Target, seed, name, role, localAddr string, handler transport.Handler) (transport.Peer, func(), error) {
	return DialWithOptionsFor(ctx, ctx, target, seed, name, role, localAddr, handler)
}

// DialWithOptionsFor bounds only the WebSocket handshake with setupCtx while
// attaching the resulting peer's lifetime to lifetimeCtx.
func DialWithOptionsFor(setupCtx, lifetimeCtx context.Context, target Target, seed, name, role, localAddr string, handler transport.Handler) (transport.Peer, func(), error) {
	if role == "" {
		role = "mobile"
	}
	if role != "mobile" && role != "desktop" {
		return nil, nil, errors.New("LAN: invalid client role")
	}
	address, err := parseLocalAddress(target.Address)
	if err != nil || address.Port() == 0 || !validToken(target.Pin) ||
		(target.Token != "" && !validToken(target.Token)) {
		return nil, nil, errors.New("LAN: invalid desktop target")
	}
	certificate, localPin, err := makeCertificate(seed)
	if err != nil {
		return nil, nil, err
	}
	if localPin == target.Pin {
		return nil, nil, errors.New("LAN: cannot connect to self")
	}
	if !validName(name) {
		return nil, nil, errors.New("LAN: invalid device name")
	}
	var advertiseAddr string
	if strings.TrimSpace(localAddr) != "" {
		parsedLocal, err := parseLocalAddress(strings.TrimSpace(localAddr))
		if err != nil || parsedLocal.Port() == 0 {
			return nil, nil, errors.New("LAN: invalid local listener address")
		}
		advertiseAddr = parsedLocal.String()
	}
	httpTransport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{certificate},
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if peerFingerprint(state) != target.Pin {
				return errors.New("LAN: desktop public key differs from pairing link")
			}
			return nil
		},
	}}
	defer httpTransport.CloseIdleConnections()
	client := &http.Client{
		Transport: httpTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	header := http.Header{}
	header.Set(nameHeader, base64.RawURLEncoding.EncodeToString([]byte(name)))
	if role == "desktop" {
		header.Set(roleHeader, role)
	}
	if advertiseAddr != "" {
		header.Set(addressHeader, advertiseAddr)
	}
	if target.Token != "" {
		header.Set(tokenHeader, target.Token)
	}
	dialCtx, cancel := context.WithTimeout(setupCtx, 10*time.Second)
	defer cancel()
	socketURL := (&url.URL{Scheme: "wss", Host: address.String(), Path: path}).String()
	var socket *websocket.Conn
	var response *http.Response
	err = dialretry.Dial(dialCtx, func() error {
		var derr error
		socket, response, derr = websocket.Dial(dialCtx, socketURL, &websocket.DialOptions{HTTPClient: client, HTTPHeader: header})
		if derr != nil && response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return derr
	})
	if err != nil {
		if response != nil && response.StatusCode == http.StatusUnauthorized {
			return nil, nil, ErrUnpaired
		}
		return nil, nil, err
	}
	p := newPeer(lifetimeCtx, socket, target.Pin, pathForAddress(address.Addr()), func() bool { return true })
	return p, func() { go p.run(handler, transport.MaxFrameSize) }, nil
}

func validName(name string) bool {
	return name != "" && len(name) <= 128 && utf8.ValidString(name) &&
		strings.TrimSpace(name) == name && !strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf)
	})
}

func ResolveCode(ctx context.Context, input, address, seed string) (string, error) {
	code, embedded, hasAddress := strings.Cut(input, "@")
	if hasAddress {
		if address != "" && address != embedded {
			return "", pairing.ErrInvalid
		}
		address = embedded
	}
	host, err := parseLocalAddress(address)
	if err != nil || host.Port() == 0 {
		return "", errors.New("LAN pairing code requires the desktop's private IP and port")
	}
	cert, _, err := makeCertificate(seed)
	if err != nil {
		return "", err
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	link, err := pairing.ResolveAt(ctx, client, &url.URL{Scheme: "https", Host: host.String(), Path: path}, code)
	if err != nil {
		return "", err
	}
	target, err := ParseTarget(link)
	if err != nil || target.Address != host.String() || target.Token == "" {
		return "", pairing.ErrInvalid
	}
	return link, nil
}

// ProbeTarget performs a lightweight mTLS reachability and desktop-pin check
// against target without opening or replacing a WebSocket session.
func ProbeTarget(ctx context.Context, target Target, seed string, timeout time.Duration) error {
	address, err := parseLocalAddress(target.Address)
	if err != nil || address.Port() == 0 || !validToken(target.Pin) {
		return errors.New("LAN: invalid desktop target")
	}
	certificate, localPin, err := makeCertificate(seed)
	if err != nil {
		return err
	}
	if localPin == target.Pin {
		return errors.New("LAN: cannot connect to self")
	}
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{certificate},
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if peerFingerprint(state) != target.Pin {
				return errors.New("LAN: desktop public key differs from pairing link")
			}
			return nil
		},
	}}
	defer tr.CloseIdleConnections()
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	probeURL := (&url.URL{Scheme: "https", Host: address.String(), Path: path, RawQuery: "probe=1"}).String()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return err
	}
	var resp *http.Response
	err = dialretry.Dial(pctx, func() error {
		var derr error
		resp, derr = client.Do(req)
		if derr == nil {
			_ = resp.Body.Close()
		}
		return derr
	})
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnpaired
	}
	if resp.StatusCode != http.StatusNoContent {
		return errors.New("LAN: probe failed")
	}
	return nil
}
