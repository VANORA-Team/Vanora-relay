package selfrelay

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/dialretry"
	"vanora-relay/protocol"
)

const (
	dialTimeout        = 15 * time.Second
	signalTimeout      = 5 * time.Second
	handshakeTimeout   = 45 * time.Second
	signalReadLimit    = 192 << 10
	minICERefreshAge   = 11 * time.Second
	iceRefreshInterval = 30 * time.Second
)

type iceServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

type connectRequestBody struct {
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
	PairProof string `json:"pair_proof,omitempty"`
	Role      string `json:"role,omitempty"`
}

type connectAcceptBody struct {
	Nonce     string `json:"nonce"`
	PublicKey string `json:"public_key"`
}

type negotiationRecord struct {
	Nonce string          `json:"nonce"`
	Value json.RawMessage `json:"value"`
}

// selfSession enforces end-to-end Ed25519 signing and monotonic sequencing for
// one self-hosted WebRTC negotiation without an external CA.
type selfSession struct {
	connID    string
	nonce     string
	localID   string
	remoteID  string
	localKey  ed25519.PrivateKey
	remotePub ed25519.PublicKey
	desktop   bool
	sent      uint64
	received  uint64
	round     uint32
	answered  bool
}

func (s *selfSession) sign(kind string, body []byte) (protocol.Message, error) {
	m := protocol.Message{
		Type:       kind,
		Connection: s.connID,
		From:       s.localID,
		To:         s.remoteID,
		Round:      s.round,
		Seq:        s.sent + 1,
	}
	err := m.Sign(s.localKey, body)
	if err == nil {
		s.sent++
	}
	return m, err
}

func (s *selfSession) validStep(kind string, round uint32, fromHost bool) bool {
	switch kind {
	case "rtc.offer":
		return !fromHost && round != 0 && round == s.round+1 && (s.round == 0 || s.answered)
	case "rtc.answer":
		return fromHost && round != 0 && round == s.round && !s.answered
	case "rtc.candidate":
		return round != 0 && round == s.round
	}
	return false
}

func (s *selfSession) advance(kind string, round uint32) {
	switch kind {
	case "rtc.offer":
		s.round, s.answered = round, false
	case "rtc.answer":
		s.answered = true
	}
}

func (s *selfSession) seal(kind string, value json.RawMessage) (protocol.Message, error) {
	round := s.round
	if kind == "rtc.offer" {
		round++
	}
	if s.nonce == "" || !json.Valid(value) || !s.validStep(kind, round, s.desktop) {
		return protocol.Message{}, errors.New("selfrelay: invalid negotiation step")
	}
	s.advance(kind, round)
	return s.sign(kind, protocol.Encode(negotiationRecord{Nonce: s.nonce, Value: value}))
}

func (s *selfSession) open(m protocol.Message) (json.RawMessage, error) {
	if s.nonce == "" || m.Connection != s.connID || m.From != s.remoteID || m.To != s.localID || m.Seq <= s.received || !s.validStep(m.Type, m.Round, !s.desktop) {
		return nil, errors.New("selfrelay: unexpected negotiation record")
	}
	body, err := m.Verify(s.remotePub)
	if err != nil {
		return nil, err
	}
	var rec negotiationRecord
	if json.Unmarshal(body, &rec) != nil || rec.Nonce != s.nonce || !json.Valid(rec.Value) {
		return nil, errors.New("selfrelay: invalid negotiation binding")
	}
	s.received = m.Seq
	s.advance(m.Type, m.Round)
	return rec.Value, nil
}

func (s *selfSession) closeMsg() (protocol.Message, error) {
	return s.sign("connect.close", nil)
}

type peerLink struct {
	ctx        context.Context
	id         string
	desktop    bool
	userID     string
	allows     func() bool
	sendSignal func(protocol.Message) error
	onClose    func(*peerLink)
	handler    transport.Handler
	deferStart bool

	stateMu  sync.Mutex
	session  *selfSession
	accepted bool

	dcMu   sync.Mutex
	pc     *webrtc.PeerConnection
	dc     *webrtc.DataChannel
	dcOpen bool
	ice    []iceServer
	iceSet bool

	candMu          sync.Mutex
	negotiationSent bool
	pendingOut      []webrtc.ICECandidateInit
	pendingIn       []webrtc.ICECandidateInit
	remoteSet       bool

	sendMu sync.Mutex
	sendID uint32

	recvMu    sync.Mutex
	recvID    uint32
	recvNext  uint32
	recvTotal uint32
	recvBuf   []byte
	recvAt    time.Time

	cbMu   sync.Mutex
	cbOpen bool

	closed atomic.Bool
	opened atomic.Bool

	inbox chan protocol.Message
	wake  chan struct{}
	done  chan struct{}
	errCh chan error
	ready chan struct{}
	peer  *peer
}

type peer struct {
	link  *peerLink
	inbox chan []byte
	once  sync.Once
}

func newPeerLink(ctx context.Context, session *selfSession, userID string, desktop, accepted, deferStart bool, allows func() bool, sendSignal func(protocol.Message) error, onClose func(*peerLink), handler transport.Handler) *peerLink {
	l := &peerLink{
		ctx:        ctx,
		id:         session.connID,
		desktop:    desktop,
		userID:     userID,
		allows:     allows,
		sendSignal: sendSignal,
		onClose:    onClose,
		handler:    handler,
		deferStart: deferStart,
		session:    session,
		accepted:   accepted,
		inbox:      make(chan protocol.Message, 64),
		wake:       make(chan struct{}, 1),
		done:       make(chan struct{}),
		errCh:      make(chan error, 1),
		ready:      make(chan struct{}),
	}
	l.peer = &peer{link: l, inbox: make(chan []byte, 32)}
	return l
}

func (l *peerLink) signal() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *peerLink) route(m protocol.Message) {
	select {
	case l.inbox <- m:
	case <-l.done:
	default:
		l.close(errors.New("selfrelay: signaling backlog"), false)
	}
}

func (l *peerLink) setICE(servers []iceServer) {
	l.dcMu.Lock()
	first := l.pc == nil && !l.iceSet
	l.ice, l.iceSet = servers, true
	l.dcMu.Unlock()
	if first {
		l.signal()
	}
}

func (l *peerLink) run() {
	timer := time.NewTimer(handshakeTimeout)
	defer timer.Stop()
	stopped := false
	for {
		if l.closed.Load() {
			return
		}
		if err := l.tryStart(); err != nil {
			l.close(err, true)
			return
		}
		if l.opened.Load() && !stopped {
			timer.Stop()
			stopped = true
		}
		select {
		case <-l.ctx.Done():
			l.close(transport.ErrClosed, false)
			return
		case <-l.done:
			return
		case <-l.wake:
		case m := <-l.inbox:
			if err := l.handleSignal(m); err != nil {
				notify := !errors.Is(err, ErrUnpaired)
				var closedErr *transport.ClosedError
				var sigErr transport.SignalError
				if errors.As(err, &closedErr) || errors.As(err, &sigErr) {
					notify = false
				}
				l.close(err, notify)
				return
			}
		case <-timer.C:
			if !l.opened.Load() {
				l.close(transport.ErrHandshakeTimeout, true)
				return
			}
		}
	}
}

func (l *peerLink) tryStart() error {
	l.dcMu.Lock()
	if l.pc != nil || !l.iceSet {
		l.dcMu.Unlock()
		return nil
	}
	servers := l.ice
	l.dcMu.Unlock()

	l.stateMu.Lock()
	accepted := l.accepted
	l.stateMu.Unlock()
	if !accepted {
		return nil
	}
	return l.startWebRTC(servers)
}

func (l *peerLink) startWebRTC(servers []iceServer) error {
	settings := webrtc.SettingEngine{}
	settings.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settings))
	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: toICEServers(servers)})
	if err != nil {
		return fmt.Errorf("selfrelay: create peer connection: %w", err)
	}
	pc.OnICECandidate(l.onLocalCandidate)
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			if !l.closed.Load() {
				l.close(errors.New("selfrelay: WebRTC connection failed"), false)
			}
		}
	})
	if l.desktop {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			if !l.attachDataChannel(dc) {
				_ = dc.Close()
			}
		})
	}
	l.dcMu.Lock()
	if l.closed.Load() {
		l.dcMu.Unlock()
		_ = pc.Close()
		return transport.ErrPeerClosed
	}
	if l.pc != nil {
		l.dcMu.Unlock()
		_ = pc.Close()
		return nil
	}
	l.pc = pc
	l.dcMu.Unlock()

	if l.desktop {
		return nil
	}

	dc, err := pc.CreateDataChannel("vanora", nil)
	if err != nil {
		return fmt.Errorf("selfrelay: create data channel: %w", err)
	}
	l.attachDataChannel(dc)

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("selfrelay: create offer: %w", err)
	}
	l.beginNegotiation()
	if err := pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("selfrelay: set local offer: %w", err)
	}
	l.stateMu.Lock()
	record, err := l.session.seal("rtc.offer", protocol.Encode(pc.LocalDescription()))
	l.stateMu.Unlock()
	if err != nil {
		return err
	}
	if err := l.sendSignal(record); err != nil {
		return err
	}
	l.flushCandidates()
	return nil
}

func (l *peerLink) handleSignal(m protocol.Message) error {
	switch m.Type {
	case "connect.accept":
		return l.handleAccept(m)
	case "rtc.offer":
		return l.handleOffer(m)
	case "rtc.answer":
		return l.handleAnswer(m)
	case "rtc.candidate":
		return l.handleCandidate(m)
	case "connect.closed":
		var reason string
		_ = json.Unmarshal(m.Data, &reason)
		if reason == "access_denied" || reason == "access_revoked" {
			return ErrUnpaired
		}
		return &transport.ClosedError{Reason: reason}
	case "error":
		var code string
		_ = json.Unmarshal(m.Data, &code)
		if code == "refresh_unavailable" {
			return nil
		}
		return transport.SignalError(code)
	default:
		return fmt.Errorf("selfrelay: unexpected signaling record %s", m.Type)
	}
}

func (l *peerLink) handleAccept(m protocol.Message) error {
	if l.desktop {
		return errors.New("selfrelay: desktop received connect.accept")
	}
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	if l.accepted {
		return errors.New("selfrelay: duplicate connect.accept")
	}
	if m.Connection != l.session.connID || m.From != l.session.remoteID || m.To != l.session.localID || m.Round != 0 || m.Seq != 1 || m.Certificate != "" {
		return fmt.Errorf("selfrelay: invalid connect.accept header: %w", transport.ErrIdentityChanged)
	}
	body, err := m.Verify(l.session.remotePub)
	if err != nil {
		return fmt.Errorf("selfrelay: desktop accept signature invalid: %w: %w", transport.ErrIdentityChanged, err)
	}
	var payload connectAcceptBody
	if err := json.Unmarshal(body, &payload); err != nil || !protocol.ValidID(payload.Nonce) {
		return errors.New("selfrelay: malformed connect.accept body")
	}
	pub, err := parsePublicKeyB64(payload.PublicKey)
	if err != nil || !pub.Equal(l.session.remotePub) {
		return fmt.Errorf("selfrelay: desktop public key differs from pairing pin: %w", transport.ErrIdentityChanged)
	}
	l.session.nonce = payload.Nonce
	l.session.received = m.Seq
	l.accepted = true
	l.signal()
	return nil
}

func (l *peerLink) handleOffer(m protocol.Message) error {
	desc, err := l.openDescription(m)
	if err != nil {
		return err
	}
	if desc.Type != webrtc.SDPTypeOffer {
		return errors.New("selfrelay: expected SDP offer")
	}
	pc := l.connection()
	if pc == nil {
		return errors.New("selfrelay: offer before ICE configuration")
	}
	if err := pc.SetRemoteDescription(desc); err != nil {
		return fmt.Errorf("selfrelay: set remote offer: %w", err)
	}
	l.markRemoteSet()
	if !l.desktop {
		return errors.New("selfrelay: mobile received SDP offer")
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("selfrelay: create answer: %w", err)
	}
	l.beginNegotiation()
	if err := pc.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("selfrelay: set local answer: %w", err)
	}
	l.stateMu.Lock()
	record, err := l.session.seal("rtc.answer", protocol.Encode(pc.LocalDescription()))
	l.stateMu.Unlock()
	if err != nil {
		return err
	}
	if err := l.sendSignal(record); err != nil {
		return err
	}
	l.flushCandidates()
	return nil
}

func (l *peerLink) handleAnswer(m protocol.Message) error {
	desc, err := l.openDescription(m)
	if err != nil {
		return err
	}
	if desc.Type != webrtc.SDPTypeAnswer {
		return errors.New("selfrelay: expected SDP answer")
	}
	pc := l.connection()
	if pc == nil {
		return errors.New("selfrelay: answer before ICE configuration")
	}
	if err := pc.SetRemoteDescription(desc); err != nil {
		return fmt.Errorf("selfrelay: set remote answer: %w", err)
	}
	l.markRemoteSet()
	return nil
}

func (l *peerLink) openDescription(m protocol.Message) (webrtc.SessionDescription, error) {
	var desc webrtc.SessionDescription
	l.stateMu.Lock()
	raw, err := l.session.open(m)
	l.stateMu.Unlock()
	if err != nil {
		return desc, err
	}
	if err := json.Unmarshal(raw, &desc); err != nil || desc.SDP == "" {
		return desc, errors.New("selfrelay: invalid SDP payload")
	}
	return desc, nil
}

func (l *peerLink) handleCandidate(m protocol.Message) error {
	l.stateMu.Lock()
	raw, err := l.session.open(m)
	l.stateMu.Unlock()
	if err != nil {
		return err
	}
	var candidate webrtc.ICECandidateInit
	if err := json.Unmarshal(raw, &candidate); err != nil {
		return errors.New("selfrelay: invalid ICE candidate")
	}
	l.candMu.Lock()
	if !l.remoteSet {
		l.pendingIn = append(l.pendingIn, candidate)
		l.candMu.Unlock()
		return nil
	}
	l.candMu.Unlock()
	if pc := l.connection(); pc != nil {
		_ = pc.AddICECandidate(candidate)
	}
	return nil
}

func (l *peerLink) beginNegotiation() {
	l.candMu.Lock()
	l.negotiationSent = false
	l.pendingOut = nil
	l.candMu.Unlock()
}

func (l *peerLink) onLocalCandidate(candidate *webrtc.ICECandidate) {
	if candidate == nil || l.closed.Load() {
		return
	}
	init := candidate.ToJSON()
	l.candMu.Lock()
	if !l.negotiationSent {
		l.pendingOut = append(l.pendingOut, init)
		l.candMu.Unlock()
		return
	}
	err := l.sendCandidate(init)
	l.candMu.Unlock()
	if err != nil {
		l.close(err, false)
	}
}

func (l *peerLink) flushCandidates() {
	l.candMu.Lock()
	l.negotiationSent = true
	pending := l.pendingOut
	l.pendingOut = nil
	var err error
	for _, c := range pending {
		if l.closed.Load() {
			break
		}
		if err = l.sendCandidate(c); err != nil {
			break
		}
	}
	l.candMu.Unlock()
	if err != nil {
		l.close(err, false)
	}
}

func (l *peerLink) sendCandidate(candidate webrtc.ICECandidateInit) error {
	data, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	l.stateMu.Lock()
	record, err := l.session.seal("rtc.candidate", data)
	l.stateMu.Unlock()
	if err != nil {
		return err
	}
	return l.sendSignal(record)
}

func (l *peerLink) markRemoteSet() {
	l.candMu.Lock()
	l.remoteSet = true
	pending := l.pendingIn
	l.pendingIn = nil
	l.candMu.Unlock()
	if pc := l.connection(); pc != nil {
		for _, c := range pending {
			_ = pc.AddICECandidate(c)
		}
	}
}

func (l *peerLink) connection() *webrtc.PeerConnection {
	l.dcMu.Lock()
	defer l.dcMu.Unlock()
	return l.pc
}

func (l *peerLink) attachDataChannel(dc *webrtc.DataChannel) bool {
	if l.closed.Load() {
		return false
	}
	l.dcMu.Lock()
	if l.dc != nil || l.dcOpen {
		l.dcMu.Unlock()
		return false
	}
	l.dc = dc
	l.dcMu.Unlock()

	dc.OnOpen(func() {
		if l.closed.Load() {
			return
		}
		l.dcMu.Lock()
		l.dcOpen = true
		l.dcMu.Unlock()
		if !l.allows() {
			l.close(ErrUnpaired, true)
			return
		}
		if l.opened.CompareAndSwap(false, true) {
			close(l.ready)
			if !l.deferStart {
				l.peer.start()
			}
		}
	})
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		l.onWireData(m.Data)
	})
	dc.OnClose(func() {
		if !l.closed.Load() {
			l.close(transport.ErrPeerClosed, false)
		}
	})
	return true
}

func (l *peerLink) onData(data []byte) {
	if l.closed.Load() {
		return
	}
	if !l.allows() {
		l.close(ErrUnpaired, true)
		return
	}
	frame := append([]byte(nil), data...)
	select {
	case l.peer.inbox <- frame:
	default:
		l.close(errors.New("selfrelay: application backlog"), false)
	}
}

func (l *peerLink) close(err error, notifyRemote bool) {
	if !l.closed.CompareAndSwap(false, true) {
		return
	}
	if err == nil {
		err = transport.ErrPeerClosed
	}
	select {
	case l.errCh <- err:
	default:
	}
	if notifyRemote && l.sendSignal != nil {
		l.stateMu.Lock()
		accepted := l.accepted
		var rec protocol.Message
		if accepted {
			rec, _ = l.session.closeMsg()
		}
		l.stateMu.Unlock()
		if rec.Type != "" {
			_ = l.sendSignal(rec)
		}
	}
	if l.onClose != nil {
		l.onClose(l)
	}
	close(l.done)
	l.dcMu.Lock()
	dc, pc := l.dc, l.pc
	l.dcMu.Unlock()
	if dc != nil {
		_ = dc.Close()
	}
	if pc != nil {
		_ = pc.Close()
	}
	l.signal()
}

func (p *peer) start() {
	p.once.Do(func() {
		if !p.link.closed.Load() {
			go p.run()
		}
	})
}

func (p *peer) run() {
	l := p.link
	h := l.handler
	if l.deferStart && l.closed.Load() {
		return
	}
	if !l.closed.Load() {
		l.cbMu.Lock()
		if !l.closed.Load() {
			l.cbOpen = true
			if h != nil {
				h.Open(p)
			}
		}
		l.cbMu.Unlock()
	}
	for {
		select {
		case <-l.done:
			for {
				select {
				case data := <-p.inbox:
					if h != nil {
						h.Message(p, data)
					}
				default:
					l.cbMu.Lock()
					opened := l.cbOpen
					l.cbOpen = false
					l.cbMu.Unlock()
					if opened && h != nil {
						h.Closed(p)
					}
					return
				}
			}
		case data := <-p.inbox:
			if h != nil {
				h.Message(p, data)
			}
		}
	}
}

func (p *peer) UserID() string { return p.link.userID }

func (p *peer) Allows(bool) bool {
	return !p.link.closed.Load() && p.link.allows()
}

func (p *peer) Send(data []byte, _ bool) error {
	l := p.link
	if l.closed.Load() {
		return transport.ErrPeerClosed
	}
	if !l.allows() {
		return ErrUnpaired
	}
	return p.send(data)
}

func (p *peer) SendRemoval(removal transport.Removal) error { return p.send(protocol.Encode(removal)) }

func (p *peer) send(data []byte) error {
	l := p.link
	l.dcMu.Lock()
	dc, open := l.dc, l.dcOpen
	l.dcMu.Unlock()
	if dc == nil || !open {
		return transport.ErrPeerClosed
	}
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	if l.closed.Load() {
		return transport.ErrPeerClosed
	}
	if err := l.sendApp(dc, data); err != nil {
		if errors.Is(err, transport.ErrFrameTooLarge) {
			return err
		}
		l.close(fmt.Errorf("selfrelay: send: %w", err), false)
		return err
	}
	return nil
}

func (p *peer) Close() { p.link.close(transport.ErrPeerClosed, true) }

func (p *peer) Path() string {
	pc := p.link.connection()
	if pc == nil {
		return "unknown"
	}
	sctp := pc.SCTP()
	if sctp == nil {
		return "unknown"
	}
	dtls := sctp.Transport()
	if dtls == nil {
		return "unknown"
	}
	iceTransport := dtls.ICETransport()
	if iceTransport == nil {
		return "unknown"
	}
	pair, err := iceTransport.GetSelectedCandidatePair()
	if err != nil || pair == nil {
		return "unknown"
	}
	if (pair.Local != nil && pair.Local.Typ == webrtc.ICECandidateTypeRelay) ||
		(pair.Remote != nil && pair.Remote.Typ == webrtc.ICECandidateTypeRelay) {
		return "relay"
	}
	return "direct"
}

func toICEServers(servers []iceServer) []webrtc.ICEServer {
	if len(servers) == 0 {
		return nil
	}
	out := make([]webrtc.ICEServer, 0, len(servers))
	for _, s := range servers {
		out = append(out, webrtc.ICEServer{
			URLs:       s.URLs,
			Username:   s.Username,
			Credential: s.Credential,
		})
	}
	return out
}

func dialSignalFor(ctx context.Context, rawURL, relayToken, role string, priv ed25519.PrivateKey, pub ed25519.PublicKey, devID, desktop string, scope *string) (*websocket.Conn, error) {
	signalURL, err := NormalizeSignalURL(rawURL)
	if err != nil {
		return nil, err
	}
	if err := ValidateRelayToken(relayToken); err != nil {
		return nil, err
	}
	dctx, stop := context.WithTimeout(ctx, dialTimeout)
	defer stop()
	httpClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	header := http.Header{"Authorization": []string{"Bearer " + relayToken}}
	var ws *websocket.Conn
	var resp *http.Response
	err = dialretry.Dial(dctx, func() error {
		var derr error
		ws, resp, derr = websocket.Dial(dctx, signalURL, &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: header})
		if derr != nil && resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return derr
	})
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return nil, ErrUnauthorized
		}
		return nil, fmt.Errorf("selfrelay: dial: %w", err)
	}
	if resp == nil || resp.Request == nil || resp.Request.URL == nil || !sameSignalOrigin(signalURL, resp.Request.URL) {
		ws.CloseNow()
		return nil, errors.New("selfrelay: signaling endpoint changed origin")
	}
	ws.SetReadLimit(signalReadLimit)

	challenge, err := readSignal(dctx, ws)
	if err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("selfrelay: read auth challenge: %w", err)
	}
	if challenge.Type != "auth.challenge" || !protocol.ValidID(challenge.Connection) {
		ws.CloseNow()
		return nil, errors.New("selfrelay: invalid auth challenge")
	}
	login := protocol.Message{
		Type:       "auth.login",
		Connection: challenge.Connection,
		From:       devID,
		To:         "signal",
	}
	if err := login.Sign(priv, protocol.Encode(map[string]string{
		"role":       role,
		"desktop":    desktop,
		"public_key": base64.RawURLEncoding.EncodeToString(pub),
	})); err != nil {
		ws.CloseNow()
		return nil, err
	}
	if err := writeSignal(dctx, ws, login); err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("selfrelay: write login: %w", err)
	}
	okMsg, err := readSignal(dctx, ws)
	if err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("selfrelay: read auth result: %w", err)
	}
	if okMsg.Type != "auth.ok" {
		ws.CloseNow()
		return nil, fmt.Errorf("selfrelay: expected auth.ok, got %s", okMsg.Type)
	}
	var accepted struct {
		Device      string `json:"device_id"`
		Mode        string `json:"mode"`
		TunnelScope string `json:"tunnel_scope"`
	}
	if json.Unmarshal(okMsg.Data, &accepted) != nil || accepted.Device != devID || accepted.Mode != "self" {
		ws.CloseNow()
		return nil, errors.New("selfrelay: relay is not running in self-hosted pairing mode")
	}
	if scope != nil {
		*scope = accepted.TunnelScope
	}
	return ws, nil
}

func readSignal(ctx context.Context, ws *websocket.Conn) (protocol.Message, error) {
	var m protocol.Message
	kind, data, err := ws.Read(ctx)
	if err != nil {
		return m, err
	}
	if kind != websocket.MessageText {
		return m, errors.New("selfrelay: signaling record is not text")
	}
	err = json.Unmarshal(data, &m)
	return m, err
}

func writeSignal(ctx context.Context, ws *websocket.Conn, m protocol.Message) error {
	deadline, cancel := context.WithTimeout(ctx, signalTimeout)
	defer cancel()
	return ws.Write(deadline, websocket.MessageText, protocol.Encode(m))
}
