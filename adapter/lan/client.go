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
)

const (
	tokenHeader = "X-Vanora-Pairing"
	nameHeader  = "X-Vanora-Client-Name"
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
	address, err := parseLocalAddress(target.Address)
	if err != nil || address.Port() == 0 || !validToken(target.Pin) ||
		(target.Token != "" && !validToken(target.Token)) {
		return nil, nil, errors.New("LAN: invalid desktop target")
	}
	certificate, _, err := makeCertificate(seed)
	if err != nil {
		return nil, nil, err
	}
	if !validName(name) {
		return nil, nil, errors.New("LAN: invalid device name")
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
	if target.Token != "" {
		header.Set(tokenHeader, target.Token)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	socketURL := (&url.URL{Scheme: "wss", Host: address.String(), Path: path}).String()
	socket, response, err := websocket.Dial(dialCtx, socketURL, &websocket.DialOptions{HTTPClient: client, HTTPHeader: header})
	if err != nil {
		if response != nil && response.StatusCode == http.StatusUnauthorized {
			return nil, nil, ErrUnpaired
		}
		return nil, nil, err
	}
	p := newPeer(ctx, socket, target.Pin, func() bool { return true })
	return p, func() { go p.run(handler, transport.MaxFrameSize) }, nil
}

func validName(name string) bool {
	return name != "" && len(name) <= 128 && utf8.ValidString(name) &&
		strings.TrimSpace(name) == name && !strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf)
	})
}
