package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"

	"vanora-relay/endpoint"
	"vanora-relay/protocol"
)

// iceServer mirrors the relay's standard RTCIceServer JSON without importing
// the server-side TURN implementation into the endpoint transport.
type iceServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// link is one authenticated WebRTC connection. Its run goroutine owns the
// negotiation state machine; DataChannel callbacks only feed events into it.
type link struct {
	c       *Client
	id      string
	desktop bool
	session *endpoint.Session

	// stateMu serializes Session and Access. Both are documented as owned by a
	// serial event loop because Access.Update replaces Session identity fields.
	stateMu     sync.Mutex
	access      *endpoint.Access
	localProof  endpoint.LeaseProof
	accepted    bool
	acceptedAt  time.Time
	refreshedAt time.Time
	remoteUser  string

	// dcMu guards the Pion objects and the ICE configuration.
	dcMu      sync.Mutex
	pc        *webrtc.PeerConnection
	dc        *webrtc.DataChannel
	dcOpen    bool
	proofSent bool // Initial lease reached the ordered channel before application sends.
	ice       []iceServer
	iceSet    bool

	// candMu guards trickled candidates and the per-negotiation send gate.
	candMu          sync.Mutex
	negotiationSent bool
	pendingOut      []webrtc.ICECandidateInit
	pendingIn       []webrtc.ICECandidateInit
	remoteSet       bool

	msgMu          sync.Mutex
	remoteVerified bool

	// sendMu makes DataChannel writes safe for the refresh loop, the message
	// pump and Peer.Send. sendID and chunk assembly state are guarded by it or
	// by recvMu respectively.
	sendMu sync.Mutex
	sendID uint32

	recvMu    sync.Mutex
	recvID    uint32
	recvNext  uint32
	recvTotal uint32
	recvBuf   []byte
	recvAt    time.Time

	// cbMu serializes Open and Closed for one peer.
	cbMu   sync.Mutex
	cbOpen bool

	closed    atomic.Bool
	opened    atomic.Bool
	permitted atomic.Bool

	inbox chan protocol.Message
	wake  chan struct{}
	done  chan struct{}
	errCh chan error
	ready chan struct{}
	peer  *peer
}

type peer struct {
	link  *link
	inbox chan []byte
	ready chan struct{}
}

func newLink(c *Client, id string, session *endpoint.Session, desktop, accepted bool) *link {
	l := &link{
		c:        c,
		id:       id,
		desktop:  desktop,
		session:  session,
		accepted: accepted,
		inbox:    make(chan protocol.Message, 64),
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
		errCh:    make(chan error, 1),
		ready:    make(chan struct{}),
	}
	if accepted {
		l.acceptedAt = time.Now()
	}
	l.permitted.Store(true)
	l.peer = &peer{link: l, inbox: make(chan []byte, 32), ready: l.ready}
	return l
}

func (l *link) isClosed() bool { return l.closed.Load() }

func (l *link) signal() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *link) route(m protocol.Message) {
	select {
	case l.inbox <- m:
	case <-l.done:
	default:
		l.close(errors.New("transport: signaling backlog"), false)
	}
}

// setICE records the relay's ICE configuration. The first configuration
// starts negotiation. Later configurations are relay refresh replies: the
// relay reuses the grant's TURN credentials and only extends their expiry, so
// an established connection keeps its allocation and a healthy direct path is
// never interrupted. Store the latest servers for any future negotiation.
func (l *link) setICE(servers []iceServer) {
	l.dcMu.Lock()
	first := l.pc == nil && !l.iceSet
	l.ice, l.iceSet = servers, true
	l.dcMu.Unlock()
	if first {
		l.signal()
	}
}

// run advances one link from signaling to an open channel and then keeps
// handling renegotiation and trickled candidates until the link closes.
func (l *link) run() {
	timer := time.NewTimer(handshakeTimeout)
	defer timer.Stop()
	stopped := false
	for {
		if l.closed.Load() {
			return
		}
		if err := l.step(); err != nil {
			notify := true
			var closed *ClosedError
			var rejected SignalError
			if errors.As(err, &closed) || errors.As(err, &rejected) {
				notify = false
			}
			l.close(err, notify)
			return
		}
		if l.opened.Load() && !stopped {
			timer.Stop()
			stopped = true
		}
		select {
		case <-l.c.ctx.Done():
			l.close(ErrClosed, false)
			return
		case <-l.done:
			return
		case <-l.wake:
		case m := <-l.inbox:
			if err := l.handleSignal(m); err != nil {
				notify := true
				var closed *ClosedError
				var rejected SignalError
				if errors.As(err, &closed) || errors.As(err, &rejected) {
					notify = false
				}
				l.close(err, notify)
				return
			}
		case <-timer.C:
			if !l.opened.Load() {
				l.close(ErrHandshakeTimeout, true)
				return
			}
		}
	}
}

// step starts the peer connection once its inputs are ready and opens the peer
// after both leases have been verified.
func (l *link) step() error {
	if err := l.tryStart(); err != nil {
		return err
	}
	return l.maybeOpen()
}

func (l *link) tryStart() error {
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
	return l.start(servers)
}

func (l *link) start(servers []iceServer) error {
	settings := webrtc.SettingEngine{}
	// Loopback is advertised in addition to normal host, STUN and TURN
	// candidates. It makes same-machine and CI topologies work without changing
	// the direct-first priority used between real endpoints.
	settings.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settings))
	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: toICEServers(servers)})
	if err != nil {
		return fmt.Errorf("transport: create peer connection: %w", err)
	}
	pc.OnICECandidate(l.onLocalCandidate)
	pc.OnConnectionStateChange(l.onConnectionState)
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
		return ErrPeerClosed
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
		return fmt.Errorf("transport: create data channel: %w", err)
	}
	l.attachDataChannel(dc)

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("transport: create offer: %w", err)
	}
	l.beginNegotiation()
	if err := pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("transport: set local offer: %w", err)
	}
	local := pc.LocalDescription()
	l.stateMu.Lock()
	record, err := l.session.Seal("rtc.offer", protocol.Encode(local))
	l.stateMu.Unlock()
	if err != nil {
		return fmt.Errorf("transport: sign offer: %w", err)
	}
	if err := l.c.sendSignal(record); err != nil {
		return err
	}
	l.flushCandidates()
	return nil
}

func (l *link) handleSignal(m protocol.Message) error {
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
		return &ClosedError{Reason: reason}
	case "error":
		var code string
		_ = json.Unmarshal(m.Data, &code)
		// The relay rate-limits ICE refreshes. A redundant refresh never
		// invalidates an established link, so keep it open.
		if code == "refresh_unavailable" {
			return nil
		}
		return SignalError(code)
	default:
		return fmt.Errorf("%w: unexpected %s", ErrMalformedResponse, m.Type)
	}
}

func (l *link) handleAccept(m protocol.Message) error {
	if l.desktop {
		return fmt.Errorf("%w: desktop received connect.accept", ErrMalformedResponse)
	}
	l.stateMu.Lock()
	if l.accepted {
		l.stateMu.Unlock()
		return fmt.Errorf("%w: duplicate connect.accept", ErrMalformedResponse)
	}
	err := l.session.Accepted(m, time.Now())
	if err == nil {
		l.accepted, l.acceptedAt = true, time.Now()
	}
	l.stateMu.Unlock()
	if err != nil {
		return fmt.Errorf("transport: accept rejected: %w", err)
	}
	l.setRemoteUser(l.session.RemoteUserID())
	if err := l.initAccess(); err != nil {
		return err
	}
	l.signal()
	return nil
}

func (l *link) handleOffer(m protocol.Message) error {
	desc, err := l.openDescription(m)
	if err != nil {
		return err
	}
	if desc.Type != webrtc.SDPTypeOffer {
		return fmt.Errorf("%w: expected an SDP offer", ErrMalformedResponse)
	}
	pc := l.connection()
	if pc == nil {
		return fmt.Errorf("%w: offer before ICE configuration", ErrMalformedResponse)
	}
	if err := pc.SetRemoteDescription(desc); err != nil {
		return fmt.Errorf("transport: set remote offer: %w", err)
	}
	l.markRemoteSet()
	l.drainIncoming()
	if !l.desktop {
		// The endpoint session rules only let the desktop answer, so a valid
		// mobile offer cannot reach this branch.
		return fmt.Errorf("%w: mobile received an offer", ErrMalformedResponse)
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("transport: create answer: %w", err)
	}
	l.beginNegotiation()
	if err := pc.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("transport: set local answer: %w", err)
	}
	local := pc.LocalDescription()
	l.stateMu.Lock()
	record, err := l.session.Seal("rtc.answer", protocol.Encode(local))
	l.stateMu.Unlock()
	if err != nil {
		return fmt.Errorf("transport: sign answer: %w", err)
	}
	if err := l.c.sendSignal(record); err != nil {
		return err
	}
	l.flushCandidates()
	return nil
}

func (l *link) handleAnswer(m protocol.Message) error {
	desc, err := l.openDescription(m)
	if err != nil {
		return err
	}
	if desc.Type != webrtc.SDPTypeAnswer {
		return fmt.Errorf("%w: expected an SDP answer", ErrMalformedResponse)
	}
	pc := l.connection()
	if pc == nil {
		return fmt.Errorf("%w: answer before ICE configuration", ErrMalformedResponse)
	}
	if err := pc.SetRemoteDescription(desc); err != nil {
		return fmt.Errorf("transport: set remote answer: %w", err)
	}
	l.markRemoteSet()
	l.drainIncoming()
	return nil
}

func (l *link) openDescription(m protocol.Message) (webrtc.SessionDescription, error) {
	var desc webrtc.SessionDescription
	l.stateMu.Lock()
	raw, err := l.session.Open(m, time.Now())
	l.stateMu.Unlock()
	if err != nil {
		return desc, fmt.Errorf("transport: verify negotiation record: %w", err)
	}
	if err := json.Unmarshal(raw, &desc); err != nil {
		return desc, fmt.Errorf("transport: decode SDP: %w", err)
	}
	if desc.SDP == "" {
		return desc, fmt.Errorf("%w: empty SDP", ErrMalformedResponse)
	}
	return desc, nil
}

func (l *link) handleCandidate(m protocol.Message) error {
	l.stateMu.Lock()
	raw, err := l.session.Open(m, time.Now())
	l.stateMu.Unlock()
	if err != nil {
		return fmt.Errorf("transport: verify candidate: %w", err)
	}
	var candidate webrtc.ICECandidateInit
	if err := json.Unmarshal(raw, &candidate); err != nil {
		return fmt.Errorf("transport: decode candidate: %w", err)
	}
	l.candMu.Lock()
	if !l.remoteSet {
		l.pendingIn = append(l.pendingIn, candidate)
		l.candMu.Unlock()
		return nil
	}
	l.candMu.Unlock()
	if pc := l.connection(); pc != nil {
		// Candidates arrive over the signed channel; a single unusable
		// candidate must not tear down an otherwise healthy negotiation.
		_ = pc.AddICECandidate(candidate)
	}
	return nil
}

func (l *link) beginNegotiation() {
	l.candMu.Lock()
	l.negotiationSent = false
	l.pendingOut = nil
	l.candMu.Unlock()
}

func (l *link) onLocalCandidate(candidate *webrtc.ICECandidate) {
	if candidate == nil || l.closed.Load() {
		return
	}
	l.queueCandidate(candidate.ToJSON())
}

// queueCandidate buffers a candidate until the offer or answer is on the wire,
// then seals and sends it. The session sequence is assigned while sealing, so
// the buffer handoff and the signaling write stay under candMu: a candidate
// gathered after the flush must not overtake one still in the buffer, or the
// peer rejects the sequence and closes a healthy link.
func (l *link) queueCandidate(init webrtc.ICECandidateInit) {
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

func (l *link) flushCandidates() {
	l.candMu.Lock()
	l.negotiationSent = true
	pending := l.pendingOut
	l.pendingOut = nil
	var err error
	for _, candidate := range pending {
		if l.closed.Load() {
			break
		}
		if err = l.sendCandidate(candidate); err != nil {
			break
		}
	}
	l.candMu.Unlock()
	if err != nil {
		l.close(err, false)
	}
}

func (l *link) sendCandidate(candidate webrtc.ICECandidateInit) error {
	data, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	l.stateMu.Lock()
	record, err := l.session.Seal("rtc.candidate", data)
	l.stateMu.Unlock()
	if err != nil {
		return fmt.Errorf("transport: sign candidate: %w", err)
	}
	return l.c.sendSignal(record)
}

func (l *link) markRemoteSet() {
	l.candMu.Lock()
	l.remoteSet = true
	pending := l.pendingIn
	l.pendingIn = nil
	l.candMu.Unlock()
	pc := l.connection()
	if pc == nil {
		return
	}
	for _, candidate := range pending {
		_ = pc.AddICECandidate(candidate)
	}
}

func (l *link) drainIncoming() {
	l.candMu.Lock()
	pending := l.pendingIn
	l.pendingIn = nil
	l.candMu.Unlock()
	pc := l.connection()
	if pc == nil {
		return
	}
	for _, candidate := range pending {
		_ = pc.AddICECandidate(candidate)
	}
}

func (l *link) connection() *webrtc.PeerConnection {
	l.dcMu.Lock()
	defer l.dcMu.Unlock()
	return l.pc
}

func (l *link) onConnectionState(state webrtc.PeerConnectionState) {
	switch state {
	case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
		if !l.closed.Load() {
			l.close(errors.New("transport: WebRTC connection failed"), false)
		}
	}
}

// attachDataChannel wires one channel. A second channel is refused so an
// attacker cannot create a parallel unsigned path.
func (l *link) attachDataChannel(dc *webrtc.DataChannel) bool {
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
		if err := l.sendProof(); err != nil {
			l.close(err, false)
			return
		}
		l.signal()
	})
	dc.OnMessage(func(message webrtc.DataChannelMessage) {
		l.onWireData(message.Data)
	})
	dc.OnClose(func() {
		if !l.closed.Load() {
			l.close(ErrPeerClosed, false)
		}
	})
	return true
}

// onData enforces the lease proof before any application frame reaches the
// handler. Proof frames are repeated on renewal; application frames must carry
// a type field.
func (l *link) onData(data []byte) {
	if l.closed.Load() {
		return
	}
	l.msgMu.Lock()
	verified := l.remoteVerified
	l.msgMu.Unlock()

	if !verified {
		proof, ok := parseLeaseProof(data)
		if !ok {
			l.close(errors.New("transport: first data channel frame is not a lease proof"), false)
			return
		}
		l.stateMu.Lock()
		var err error
		if l.access == nil {
			err = errors.New("transport: no accepted session")
		} else {
			err = l.access.Update(false, proof, time.Now())
		}
		allowed := err == nil && l.access != nil && l.access.Allows(time.Now(), true, true)
		l.stateMu.Unlock()
		if err != nil {
			l.close(fmt.Errorf("transport: remote lease rejected: %w", err), false)
			return
		}
		if !allowed {
			l.close(ErrUnauthorized, false)
			return
		}
		l.msgMu.Lock()
		l.remoteVerified = true
		l.msgMu.Unlock()
		l.signal()
		return
	}

	if proof, ok := parseLeaseProof(data); ok {
		l.stateMu.Lock()
		var err error
		if l.access == nil {
			err = errors.New("transport: no accepted session")
		} else {
			err = l.access.Update(false, proof, time.Now())
		}
		l.stateMu.Unlock()
		if err != nil {
			l.close(fmt.Errorf("transport: renewed remote lease rejected: %w", err), false)
		}
		return
	}

	frame := append([]byte(nil), data...)
	if l.closed.Load() {
		return
	}
	select {
	case l.peer.inbox <- frame:
	default:
		// A handler that cannot keep up must not stall proof refresh or the
		// DataChannel read loop. Fail closed instead of buffering without bound.
		l.close(errors.New("transport: application backlog"), false)
	}
}

func parseLeaseProof(data []byte) (endpoint.LeaseProof, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return endpoint.LeaseProof{}, false
	}
	if _, isApplication := fields["type"]; isApplication {
		return endpoint.LeaseProof{}, false
	}
	var proof endpoint.LeaseProof
	if json.Unmarshal(data, &proof) != nil || proof.Certificate == "" || proof.Lease == "" {
		return endpoint.LeaseProof{}, false
	}
	return proof, true
}

func (l *link) maybeOpen() error {
	if l.opened.Load() || l.closed.Load() {
		return nil
	}
	l.dcMu.Lock()
	ready := l.dcOpen && l.proofSent
	l.dcMu.Unlock()
	if !ready {
		return nil
	}
	l.msgMu.Lock()
	verified := l.remoteVerified
	l.msgMu.Unlock()
	if !verified {
		return nil
	}

	now := time.Now()
	l.stateMu.Lock()
	allowed := l.access != nil && l.access.Allows(now, true, true)
	l.stateMu.Unlock()
	if !allowed {
		return ErrUnauthorized
	}
	if !l.opened.CompareAndSwap(false, true) {
		return nil
	}
	go l.peer.run()
	return nil
}

func (l *link) initAccess() error {
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	access, err := l.session.Access()
	if err != nil {
		return fmt.Errorf("transport: session access: %w", err)
	}
	if l.localProof.Certificate != "" {
		if err := access.Update(true, l.localProof, time.Now()); err != nil {
			return fmt.Errorf("transport: local lease rejected: %w", err)
		}
	}
	l.access = access
	return nil
}

func (l *link) updateLocal(proof endpoint.LeaseProof, until time.Time) {
	if l.closed.Load() {
		return
	}
	var err error
	l.stateMu.Lock()
	l.localProof = proof
	if l.access != nil {
		err = l.access.Update(true, proof, time.Now())
	}
	l.stateMu.Unlock()
	if err != nil {
		l.close(fmt.Errorf("transport: local lease rejected: %w", err), false)
		return
	}
	if l.opened.Load() {
		if err := l.sendProof(); err != nil {
			l.close(err, false)
		}
	}
}

func (l *link) authorityLost() {
	l.stateMu.Lock()
	if l.access != nil {
		l.access.AuthorityLost()
	}
	l.stateMu.Unlock()
}

func (l *link) sendProof() error {
	if l.closed.Load() {
		return ErrPeerClosed
	}
	l.stateMu.Lock()
	proof := l.localProof
	l.stateMu.Unlock()
	if proof.Certificate == "" || proof.Lease == "" {
		return nil
	}
	data, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	l.dcMu.Lock()
	dc, open := l.dc, l.dcOpen
	l.dcMu.Unlock()
	if dc == nil || !open {
		return nil
	}
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	if l.closed.Load() {
		return ErrPeerClosed
	}
	if err := l.writeChunk(dc, data, time.Now().Add(signalTimeout)); err != nil {
		return fmt.Errorf("transport: send lease proof: %w", err)
	}
	l.dcMu.Lock()
	l.proofSent = true
	l.dcMu.Unlock()
	return nil
}

func (l *link) setRemoteUser(id string) {
	l.stateMu.Lock()
	l.remoteUser = id
	l.stateMu.Unlock()
}

func (l *link) remoteUserID() string {
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	return l.remoteUser
}

func (l *link) close(err error, notifyRemote bool) {
	if !l.closed.CompareAndSwap(false, true) {
		return
	}
	if err == nil {
		err = ErrPeerClosed
	}
	select {
	case l.errCh <- err:
	default:
	}

	if notifyRemote && !l.c.closed.Load() {
		l.stateMu.Lock()
		accepted := l.accepted
		var record protocol.Message
		if accepted {
			record, _ = l.session.Close()
		}
		l.stateMu.Unlock()
		if record.Type != "" {
			_ = l.c.sendSignal(record)
		}
	}

	l.c.mu.Lock()
	if l.c.links[l.id] == l {
		delete(l.c.links, l.id)
	}
	l.c.mu.Unlock()

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

func toICEServers(servers []iceServer) []webrtc.ICEServer {
	if len(servers) == 0 {
		return nil
	}
	out := make([]webrtc.ICEServer, 0, len(servers))
	for _, server := range servers {
		out = append(out, webrtc.ICEServer{
			URLs:       server.URLs,
			Username:   server.Username,
			Credential: server.Credential,
		})
	}
	return out
}

func (p *peer) run() {
	l := p.link
	h := l.c.handler
	if !l.isClosed() {
		l.cbMu.Lock()
		if !l.isClosed() {
			l.cbOpen = true
			if h != nil {
				h.Open(p)
			}
		}
		l.cbMu.Unlock()
	}
	close(p.ready)

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

func (p *peer) UserID() string { return p.link.remoteUserID() }

func (p *peer) Allows(requiresOnline bool) bool {
	l := p.link
	if l.isClosed() || !l.permitted.Load() {
		return false
	}
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	return l.access != nil && l.access.Allows(time.Now(), requiresOnline, true)
}

func (p *peer) Send(data []byte, requiresOnline bool) error {
	l := p.link
	if l.isClosed() || !l.permitted.Load() {
		return ErrPeerClosed
	}
	l.stateMu.Lock()
	allowed := l.access != nil && l.access.Allows(time.Now(), requiresOnline, true)
	l.stateMu.Unlock()
	if !allowed {
		return ErrUnauthorized
	}
	l.dcMu.Lock()
	dc, open := l.dc, l.dcOpen
	l.dcMu.Unlock()
	if dc == nil || !open {
		return ErrPeerClosed
	}
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	if l.isClosed() {
		return ErrPeerClosed
	}
	if err := l.sendApp(dc, data); err != nil {
		if errors.Is(err, ErrFrameTooLarge) {
			return err
		}
		l.close(fmt.Errorf("transport: send: %w", err), false)
		return err
	}
	return nil
}

func (p *peer) Close() { p.link.close(ErrPeerClosed, true) }
