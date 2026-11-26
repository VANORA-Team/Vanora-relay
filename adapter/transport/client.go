package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"vanora-relay/endpoint"
	"vanora-relay/internal/dialretry"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/pairnet"
	"vanora-relay/protocol"
)

// Roles accepted by Dial. They match the signaling service's login roles.
const (
	RoleDesktop = "desktop"
	RoleMobile  = "mobile"
)

const (
	// ProofRefreshAge is how long a successfully accepted local lease proof may
	// be reused before the adapter asks IdentitySource for a fresh one. The
	// authority caps lease lifetimes at 60 seconds, so refreshing at 30
	// seconds leaves 30 seconds of margin for a slow or failing authority.
	ProofRefreshAge = 30 * time.Second

	// proofRefreshLead refreshes early when a source hands out a lease that is
	// already close to expiry.
	proofRefreshLead = 20 * time.Second
	refreshRetry     = 5 * time.Second
	refreshTimeout   = 10 * time.Second

	// minICERefreshAge keeps the first ice.refresh outside the relay's
	// ten-second post-acceptance window. The extra second absorbs clock skew
	// between the endpoint and the relay.
	minICERefreshAge = 11 * time.Second

	// iceRefreshInterval is the steady-state cadence for extending active TURN
	// allocations. The relay rejects refreshes less than ten seconds apart.
	iceRefreshInterval = 30 * time.Second

	// currentMaxAge coalesces concurrent or immediately repeated refresh calls
	// so one user action does not hammer the identity authority.
	currentMaxAge = 2 * time.Second

	dialTimeout      = 15 * time.Second
	signalTimeout    = 5 * time.Second
	handshakeTimeout = 45 * time.Second
	signalReadLimit  = 192 << 10
)

// IdentitySource supplies the endpoint's current certificate, private key and
// authority lease. It is owned by the embedding application; the adapter never
// persists or renews keys itself. Current must return material for the same
// device and remote user every time, and must return a lease that is valid at
// the time of the call.
type IdentitySource interface {
	Current(context.Context) (*endpoint.Credentials, endpoint.LeaseProof, error)
}

// AuthorityObserver is an optional interface a Handler may implement. The
// adapter calls AuthorityLost when the local identity authority stops allowing
// online work, and AuthorityRestored when a verified lease makes it live again.
// Both transitions are reported even while no peer is connected, so the host
// can stop tool execution without waiting for a peer callback.
type AuthorityObserver interface {
	AuthorityLost()
	AuthorityRestored()
}

// Errors returned by the adapter.
var (
	ErrClosed            = errors.New("transport: client closed")
	ErrPeerClosed        = errors.New("transport: peer closed")
	ErrNotDesktop        = errors.New("transport: desktop role required")
	ErrNotMobile         = errors.New("transport: mobile role required")
	ErrUnauthorized      = errors.New("transport: access is not authorized")
	ErrHandshakeTimeout  = errors.New("transport: peer handshake timeout")
	ErrIdentityChanged   = errors.New("transport: identity source changed identity")
	ErrInvalidArgument   = errors.New("transport: invalid argument")
	ErrMalformedResponse = errors.New("transport: malformed relay response")
)

// SignalError is an error code returned by the signaling service for one
// request or connection. The code is stable and safe to compare with
// errors.Is or a direct string comparison.
type SignalError string

func (e SignalError) Error() string { return "transport: relay rejected request: " + string(e) }

// ClosedError reports that the signaling service closed one connection.
type ClosedError struct{ Reason string }

func (e *ClosedError) Error() string {
	if e.Reason == "" {
		return "transport: connection closed"
	}
	return "transport: connection closed: " + e.Reason
}

// Client is one authenticated signaling session. It is safe for concurrent
// use. When the signaling socket is lost, Done is closed and every peer is
// Closed; the host reconnects by calling Dial again with the same
// IdentitySource.
type Client struct {
	role       string
	desktop    string
	source     IdentitySource
	handler    Handler
	pairedRole endpoint.PairRoleAuthorizer
	network    *NetworkHandler
	netHookMu  sync.Mutex
	netHook    func()

	ws *websocket.Conn

	ctx    context.Context
	cancel context.CancelFunc

	done     chan struct{}
	doneOnce sync.Once
	closed   atomic.Bool

	writeMu sync.Mutex
	fetchMu sync.Mutex

	mu         sync.Mutex
	creds      *endpoint.Credentials
	proof      endpoint.LeaseProof
	proofUntil time.Time
	fetchedAt  time.Time
	refreshAt  time.Time
	ca         ed25519.PublicKey
	publicKey  ed25519.PublicKey
	deviceID   string
	userID     string
	authority  bool
	guests     map[string]bool
	pairTicket string
	links      map[string]*link

	authCbMu sync.Mutex

	waitMu  sync.Mutex
	waiters map[string][]*waiter

	publishMu sync.Mutex
	devicesMu sync.Mutex

	refreshWake chan struct{}
}

type waiter struct {
	kind string
	ch   chan protocol.Message
}

type leaseUpdate struct {
	Lease       string `json:"lease"`
	Certificate string `json:"certificate,omitempty"`
}

// Dial opens an official mobile signaling connection. Desktops supply their
// device pairing policy to DialPairedDesktop before publishing.
func Dial(ctx context.Context, url, role string, source IdentitySource, h Handler) (*Client, error) {
	if role == RoleDesktop {
		return nil, fmt.Errorf("%w: use DialPairedDesktop with a pairing authorizer", ErrInvalidArgument)
	}
	return dial(ctx, url, role, source, h, nil, "")
}

func DialMobileFor(ctx context.Context, url, desktop string, source IdentitySource, h Handler) (*Client, error) {
	return dial(ctx, url, RoleMobile, source, h, nil, desktop)
}

// DialDesktopControllerFor opens a target-scoped outbound signaling connection
// using the desktop's own official identity without publishing host presence.
func DialDesktopControllerFor(ctx context.Context, url, desktop string, source IdentitySource, h Handler) (*Client, error) {
	if strings.TrimSpace(desktop) == "" {
		return nil, fmt.Errorf("%w: target desktop required", ErrInvalidArgument)
	}
	return dial(ctx, url, RoleDesktop, source, h, nil, desktop)
}

func DialPairedDesktop(ctx context.Context, url string, source IdentitySource, h Handler, paired endpoint.PairAuthorizer) (*Client, error) {
	if paired == nil {
		return nil, ErrInvalidArgument
	}
	return DialPairedDesktopWithRole(ctx, url, source, h, func(connection string, peer endpoint.PeerIdentity, _, _ string, proof []byte) bool {
		return paired(connection, peer, proof)
	})
}

func DialPairedDesktopWithRole(ctx context.Context, url string, source IdentitySource, h Handler, paired endpoint.PairRoleAuthorizer) (*Client, error) {
	if paired == nil {
		return nil, ErrInvalidArgument
	}
	return dial(ctx, url, RoleDesktop, source, h, paired, "")
}

func dial(ctx context.Context, url, role string, source IdentitySource, h Handler, paired endpoint.PairRoleAuthorizer, desktop string) (*Client, error) {
	if role != RoleDesktop && role != RoleMobile {
		return nil, fmt.Errorf("%w: role %q", ErrInvalidArgument, role)
	}
	if source == nil {
		return nil, fmt.Errorf("%w: identity source is nil", ErrInvalidArgument)
	}
	if err := checkSignalURL(url); err != nil {
		return nil, err
	}
	dctx, stop := context.WithTimeout(ctx, dialTimeout)
	defer stop()

	// Never follow a redirect: a signaling endpoint must be exactly the origin
	// the caller verified when it built the URL.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	var ws *websocket.Conn
	var resp *http.Response
	var err error
	err = dialretry.Dial(dctx, func() error {
		var derr error
		ws, resp, derr = websocket.Dial(dctx, url, &websocket.DialOptions{HTTPClient: client})
		if derr != nil && resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return derr
	})
	if err != nil {
		return nil, fmt.Errorf("transport: dial: %w", err)
	}
	if resp == nil || resp.Request == nil || resp.Request.URL == nil ||
		!sameSignalOrigin(url, resp.Request.URL) {
		ws.CloseNow()
		return nil, fmt.Errorf("%w: signaling endpoint changed origin", ErrInvalidArgument)
	}
	ws.SetReadLimit(signalReadLimit)

	c := &Client{
		role:        role,
		desktop:     desktop,
		source:      source,
		handler:     h,
		pairedRole:  paired,
		ws:          ws,
		done:        make(chan struct{}),
		guests:      make(map[string]bool),
		links:       make(map[string]*link),
		waiters:     make(map[string][]*waiter),
		refreshWake: make(chan struct{}, 1),
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	fail := func(err error) (*Client, error) {
		c.cancel()
		ws.CloseNow()
		return nil, err
	}

	challenge, err := readSignal(dctx, ws)
	if err != nil {
		return fail(fmt.Errorf("transport: read auth challenge: %w", err))
	}
	if challenge.Type != "auth.challenge" || !protocol.ValidID(challenge.Connection) {
		return fail(fmt.Errorf("%w: invalid auth challenge", ErrMalformedResponse))
	}

	creds, proof, _, err := c.loadCredentials(dctx)
	if err != nil {
		return fail(err)
	}
	login, err := creds.LoginFor(challenge, role, proof.Lease, desktop)
	if err != nil {
		return fail(fmt.Errorf("transport: sign login: %w", err))
	}
	if err := writeSignal(dctx, ws, login); err != nil {
		return fail(fmt.Errorf("transport: write login: %w", err))
	}
	ok, err := readSignal(dctx, ws)
	if err != nil {
		return fail(fmt.Errorf("transport: read auth result: %w", err))
	}
	if ok.Type != "auth.ok" {
		return fail(fmt.Errorf("%w: expected auth.ok, got %s", ErrMalformedResponse, ok.Type))
	}
	var accepted struct {
		Device string `json:"device_id"`
		User   string `json:"remote_user_id"`
	}
	if json.Unmarshal(ok.Data, &accepted) != nil || accepted.Device != c.deviceID || accepted.User != c.userID {
		return fail(fmt.Errorf("%w: relay accepted a different endpoint identity", ErrMalformedResponse))
	}

	if provider, ok := source.(interface {
		PairingIdentity(string, string) (*pairnet.Group, pairnet.Member)
	}); ok && role == RoleDesktop && desktop == "" {
		group, _ := provider.PairingIdentity(url, role)
		if group != nil {
			c.network = &NetworkHandler{Handler: h, Group: func() *pairnet.Group { return group }, Device: func(p Peer) string { return p.(*peer).link.remoteDevice }}
			c.network.Changed = func() {
				c.mu.Lock()
				var closed []*link
				for _, l := range c.links {
					if l.desktop && !group.Allows(l.remoteDevice) {
						l.permitted.Store(false)
						closed = append(closed, l)
					}
				}
				c.mu.Unlock()
				for _, l := range closed {
					l.close(ErrUnauthorized, true)
				}
				c.netHookMu.Lock()
				hook := c.netHook
				c.netHookMu.Unlock()
				if hook != nil {
					hook()
				}
			}
			c.handler = c.network
		}
	}
	go c.readLoop()
	go c.refreshLoop()
	return c, nil
}

// Done is closed when the signaling socket is lost or Close is called. The
// host reconnects by calling Dial again; the adapter never reuses a Client.
func (c *Client) Done() <-chan struct{} { return c.done }

// AuthorityOnline reports the current local authority state. It is false
// while IdentitySource fails to provide a fresh lease or after Close.
func (c *Client) AuthorityOnline() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authority && !c.closed.Load()
}

// Close stops the client, closes every peer, and closes Done. It is safe to
// call more than once.
func (c *Client) Close() {
	c.mu.Lock()
	links := make([]*link, 0, len(c.links))
	for _, l := range c.links {
		links = append(links, l)
	}
	closed := c.closed.Load()
	c.mu.Unlock()
	if closed {
		return
	}
	for _, l := range links {
		l.close(ErrClosed, true)
	}
	c.shutdown(ErrClosed)
}

// Publish announces this desktop and its complete guest allowlist. The owner
// is always allowed and need not appear in guests. The local allowlist and any
// connected peer that lost access are updated before the new directory entry
// is sent, so failures leave the adapter stricter, never more permissive.
func (c *Client) Publish(ctx context.Context, name string, guests []string) error {
	if c.role != RoleDesktop {
		return ErrNotDesktop
	}
	if len(guests) > 256 {
		return fmt.Errorf("%w: too many guests", ErrInvalidArgument)
	}
	allowed := make(map[string]bool, len(guests))
	for _, id := range guests {
		if len(id) == 0 || len(id) > 128 || containsControl(id) {
			return fmt.Errorf("%w: invalid guest identifier", ErrInvalidArgument)
		}
		allowed[id] = true
	}

	c.publishMu.Lock()
	defer c.publishMu.Unlock()

	creds, _, _, err := c.current(ctx)
	if err != nil {
		return err
	}
	online, err := creds.Online(name, guests)
	if err != nil {
		return fmt.Errorf("transport: build device card: %w", err)
	}

	c.mu.Lock()
	c.guests = allowed
	owner := c.userID
	links := make([]*link, 0, len(c.links))
	for _, l := range c.links {
		links = append(links, l)
	}
	c.mu.Unlock()

	// Fail closed for revoked guests before the directory is updated.
	for _, l := range links {
		if !l.desktop {
			continue
		}
		if !peerAllowed(owner, allowed, l.remoteUserID()) {
			l.permitted.Store(false)
			l.close(ErrUnauthorized, true)
		}
	}

	w := c.expect("device.registered")
	defer c.cancelWait(w)

	if err := c.sendSignal(online); err != nil {
		return err
	}
	m, err := w.await(ctx, c.done)
	if err != nil {
		return err
	}
	if m.Type != "device.registered" {
		return waiterFailure(m)
	}
	var registered struct {
		Ticket string `json:"pairing_ticket"`
	}
	_ = json.Unmarshal(m.Data, &registered)
	c.mu.Lock()
	c.pairTicket = registered.Ticket
	c.mu.Unlock()
	return nil
}

func (c *Client) NetworkChanged() {
	if c.network != nil {
		c.network.Broadcast()
	}
}

// SetNetworkChangedHook registers an optional callback triggered whenever the
// host's pairing network changes (from inbound sync or local revocation).
func (c *Client) SetNetworkChangedHook(fn func()) {
	c.netHookMu.Lock()
	c.netHook = fn
	c.netHookMu.Unlock()
}

func (c *Client) PairingTicket() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pairTicket
}

// Devices lists signed, verified desktops that currently allow this endpoint.
// Entries that fail certificate, signature or owner verification are omitted;
// the returned Devices are safe to display.
func (c *Client) Devices(ctx context.Context) ([]endpoint.Device, error) {
	if c.closed.Load() {
		return nil, ErrClosed
	}
	c.devicesMu.Lock()
	defer c.devicesMu.Unlock()

	w := c.expect("devices.list")
	defer c.cancelWait(w)
	if err := c.sendSignal(protocol.Message{Type: "devices.list"}); err != nil {
		return nil, err
	}
	m, err := w.await(ctx, c.done)
	if err != nil {
		return nil, err
	}
	if m.Type != "devices.list" {
		return nil, waiterFailure(m)
	}
	var cards []protocol.Message
	if err := json.Unmarshal(m.Data, &cards); err != nil {
		return nil, fmt.Errorf("transport: decode device list: %w", err)
	}
	c.mu.Lock()
	ca := c.ca
	c.mu.Unlock()
	if len(ca) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: no authority key", ErrMalformedResponse)
	}
	now := time.Now()
	devices := make([]endpoint.Device, 0, len(cards))
	for _, card := range cards {
		device, err := endpoint.VerifyDevice(card, ca, now)
		if err != nil {
			continue
		}
		devices = append(devices, device)
	}
	return devices, nil
}

// ConnectOptions configures an outbound official connection.
type ConnectOptions struct {
	Pin     ed25519.PublicKey
	Token   []byte
	Role    string
	Name    string
	Handler Handler
}

// Connect opens one peer to the selected desktop and waits until the desktop
// accepted the request and both endpoints verified each other's lease proof
// on the encrypted channel. deviceID and ownerID must come from a trusted
// binding or invitation, not only from the discovery directory.
func (c *Client) Connect(ctx context.Context, deviceID, ownerID string) (Peer, error) {
	return c.ConnectPaired(ctx, deviceID, ownerID, nil, nil)
}

func (c *Client) ConnectPaired(ctx context.Context, deviceID, ownerID string, pin ed25519.PublicKey, token []byte) (Peer, error) {
	return c.ConnectPairedWithOptions(ctx, deviceID, ownerID, ConnectOptions{Pin: pin, Token: token})
}

func (c *Client) ConnectPairedWithOptions(ctx context.Context, deviceID, ownerID string, opts ConnectOptions) (Peer, error) {
	if c.role != RoleMobile && c.role != RoleDesktop {
		return nil, ErrNotMobile
	}
	if deviceID == "" || ownerID == "" || containsControl(deviceID) || containsControl(ownerID) {
		return nil, fmt.Errorf("%w: device and owner are required", ErrInvalidArgument)
	}
	if c.closed.Load() {
		return nil, ErrClosed
	}

	creds, proof, _, err := c.current(ctx)
	if err != nil {
		return nil, err
	}
	if deviceID == creds.DeviceID() {
		return nil, fmt.Errorf("%w: cannot connect to self", ErrInvalidArgument)
	}
	reqRole := opts.Role
	if reqRole == "" && c.role == RoleDesktop {
		reqRole = RoleDesktop
	}
	session, request, err := creds.RequestPairedWithMeta(deviceID, ownerID, opts.Pin, opts.Token, endpoint.ConnectRequestMeta{
		Role: reqRole,
		Name: opts.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("transport: build connect request: %w", err)
	}
	l := newLink(c, session.ID(), session, false, false)
	l.remoteDevice = deviceID
	l.handler = opts.Handler
	l.localProof = proof
	c.addLink(l)
	go l.run()

	if err := c.sendSignal(request); err != nil {
		l.close(err, false)
		return nil, err
	}

	select {
	case <-l.ready:
		if l.isClosed() {
			return nil, ErrPeerClosed
		}
		return l.peer, nil
	case err := <-l.errCh:
		l.close(err, false)
		return nil, err
	case <-ctx.Done():
		select {
		case <-l.ready:
			if !l.isClosed() {
				return l.peer, nil
			}
		default:
		}
		l.close(ctx.Err(), true)
		return nil, ctx.Err()
	case <-c.done:
		return nil, ErrClosed
	}
}

// acceptRequest handles one inbound connect.request on a desktop.
func (c *Client) acceptRequest(m protocol.Message) {
	if c.role != RoleDesktop || c.desktop != "" || c.closed.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(c.ctx, refreshTimeout)
	defer cancel()
	creds, proof, _, err := c.current(ctx)
	if err != nil {
		return
	}
	session, reply, err := creds.AcceptPairedWithRole(m, c.allowsUser, c.pairedRole, time.Now())
	if err != nil {
		if reply.Type == "connect.close" {
			_ = c.sendSignal(reply)
		}
		return
	}
	l := newLink(c, session.ID(), session, true, true)
	l.remoteDevice = m.From
	l.localProof = proof
	l.setRemoteUser(session.RemoteUserID())
	if err := l.initAccess(); err != nil {
		l.close(err, false)
		return
	}
	c.addLink(l)
	if c.pairedRole != nil && !c.pairedRole(m.Connection, session.RemotePrincipal(), "", "", nil) {
		l.close(ErrUnauthorized, true)
		return
	}
	if !c.allowsUser(session.RemoteUserID()) {
		l.permitted.Store(false)
		l.close(ErrUnauthorized, true)
		return
	}
	go l.run()
	if err := c.sendSignal(reply); err != nil {
		l.close(err, false)
	}
}

func (c *Client) RevokeDevice(device string) {
	c.mu.Lock()
	var revoked []*link
	for _, l := range c.links {
		if l.desktop && (device == "" || device == l.remoteDevice) {
			l.permitted.Store(false)
			revoked = append(revoked, l)
		}
	}
	c.mu.Unlock()
	for _, l := range revoked {
		l.close(ErrUnauthorized, true)
	}
}

func (c *Client) addLink(l *link) {
	c.mu.Lock()
	if !l.desktop || l.remoteUserID() == "" || l.remoteUserID() == c.userID || c.guests[l.remoteUserID()] {
		l.permitted.Store(true)
	} else {
		l.permitted.Store(false)
	}
	if _, dup := c.links[l.id]; dup {
		// A duplicate connection id means a replayed or forked frame. Close
		// the newcomer and keep the live link instead of silently orphaning
		// its bookkeeping.
		c.mu.Unlock()
		l.close(ErrUnauthorized, true)
		return
	}
	c.links[l.id] = l
	c.mu.Unlock()
}

func (c *Client) allowsUser(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return peerAllowed(c.userID, c.guests, id)
}

func peerAllowed(owner string, guests map[string]bool, id string) bool {
	return id != "" && (id == owner || guests[id])
}

func containsControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// loadCredentials obtains and verifies current identity material. It pins the
// device, user and authority key for the lifetime of this Client.
func (c *Client) loadCredentials(ctx context.Context) (*endpoint.Credentials, endpoint.LeaseProof, time.Time, error) {
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()

	now := time.Now()
	c.mu.Lock()
	cached, cachedProof, cachedUntil, fetchedAt := c.creds, c.proof, c.proofUntil, c.fetchedAt
	c.mu.Unlock()
	if cached != nil && now.Sub(fetchedAt) < currentMaxAge && now.Before(cachedUntil) {
		return cached, cachedProof, cachedUntil, nil
	}

	creds, proof, err := c.source.Current(ctx)
	if err != nil {
		c.setAuthority(false)
		return nil, endpoint.LeaseProof{}, time.Time{}, fmt.Errorf("transport: identity unavailable: %w", err)
	}
	principal, until, err := verifyProof(creds, proof, now)
	if err != nil {
		c.setAuthority(false)
		return nil, endpoint.LeaseProof{}, time.Time{}, err
	}

	c.mu.Lock()
	if c.ca != nil {
		if !c.ca.Equal(creds.CA()) || c.deviceID != creds.DeviceID() ||
			c.userID != principal.RemoteUserID() || !bytes.Equal(c.publicKey, principal.PublicKey) {
			c.mu.Unlock()
			c.setAuthority(false)
			return nil, endpoint.LeaseProof{}, time.Time{}, ErrIdentityChanged
		}
	} else {
		c.ca = creds.CA()
		c.publicKey = append(ed25519.PublicKey(nil), principal.PublicKey...)
		c.deviceID = creds.DeviceID()
		c.userID = principal.RemoteUserID()
	}
	c.creds, c.proof, c.proofUntil, c.fetchedAt = creds, proof, until, now
	next := now.Add(ProofRefreshAge)
	if early := until.Add(-proofRefreshLead); early.Before(next) {
		next = early
	}
	if floor := now.Add(time.Second); next.Before(floor) {
		next = floor
	}
	c.refreshAt = next
	c.mu.Unlock()

	c.setAuthority(true)
	select {
	case c.refreshWake <- struct{}{}:
	default:
	}
	return creds, proof, until, nil
}

// current refreshes the signaling lease and every established peer before
// returning identity material for a new operation.
func (c *Client) current(ctx context.Context) (*endpoint.Credentials, endpoint.LeaseProof, time.Time, error) {
	creds, proof, until, err := c.loadCredentials(ctx)
	if err != nil {
		return nil, endpoint.LeaseProof{}, time.Time{}, err
	}
	if err := c.leaseUpdateMessage(proof); err != nil {
		return nil, endpoint.LeaseProof{}, time.Time{}, err
	}
	c.applyProof(proof, until)
	return creds, proof, until, nil
}

func (c *Client) leaseUpdateMessage(proof endpoint.LeaseProof) error {
	return c.sendSignal(protocol.Message{Type: "auth.lease", Data: protocol.Encode(leaseUpdate{Lease: proof.Lease, Certificate: proof.Certificate})})
}

func (c *Client) applyProof(proof endpoint.LeaseProof, until time.Time) {
	c.mu.Lock()
	links := make([]*link, 0, len(c.links))
	for _, l := range c.links {
		links = append(links, l)
	}
	c.mu.Unlock()
	for _, l := range links {
		l.updateLocal(proof, until)
	}
}

func (c *Client) setAuthority(online bool) {
	c.mu.Lock()
	changed := c.authority != online
	c.authority = online
	closed := c.closed.Load()
	links := make([]*link, 0, len(c.links))
	if !online {
		for _, l := range c.links {
			links = append(links, l)
		}
	}
	c.mu.Unlock()

	for _, l := range links {
		l.authorityLost()
	}
	if changed && !closed {
		c.notifyAuthority(online)
	}
}

// notifyAuthority reports one authority transition to the optional observer.
// The callback is serialized and never runs under c.mu or a connection lock.
// Re-checking the current state under authCbMu prevents an older transition
// from arriving after a newer one.
func (c *Client) notifyAuthority(online bool) {
	observer, ok := c.handler.(AuthorityObserver)
	if !ok {
		return
	}
	c.authCbMu.Lock()
	defer c.authCbMu.Unlock()
	c.mu.Lock()
	current := c.authority
	c.mu.Unlock()
	if current != online {
		return
	}
	if online {
		observer.AuthorityRestored()
		return
	}
	observer.AuthorityLost()
}

func (c *Client) refreshLoop() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		c.mu.Lock()
		at := c.refreshAt
		c.mu.Unlock()
		if at.IsZero() {
			at = time.Now().Add(ProofRefreshAge)
		}
		delay := time.Until(at)
		if delay < time.Second {
			delay = time.Second
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(delay)
		select {
		case <-c.ctx.Done():
			return
		case <-c.refreshWake:
			continue
		case <-timer.C:
		}
		ctx, cancel := context.WithTimeout(c.ctx, refreshTimeout)
		err := c.renew(ctx, time.Now())
		cancel()
		if err != nil {
			c.setAuthority(false)
			c.mu.Lock()
			c.refreshAt = time.Now().Add(refreshRetry)
			c.mu.Unlock()
		}
	}
}

// renew refreshes the signaling lease and then extends the relay's ICE grants
// for accepted mobile links. The lease update is written first, so the relay
// processes it before the refresh that depends on a live, current lease.
func (c *Client) renew(ctx context.Context, now time.Time) error {
	if _, _, _, err := c.current(ctx); err != nil {
		return err
	}
	c.refreshICE(now)
	return nil
}

// refreshICE extends active TURN allocations. Only the phone may refresh in
// the relay protocol; a desktop receives the regenerated configuration as a
// reply. Links younger than the relay's acceptance window are skipped so the
// request is never rejected as refresh_unavailable.
func (c *Client) refreshICE(now time.Time) {
	c.mu.Lock()
	links := make([]*link, 0, len(c.links))
	for _, l := range c.links {
		links = append(links, l)
	}
	c.mu.Unlock()
	for _, l := range links {
		if l.desktop || l.isClosed() {
			continue
		}
		l.stateMu.Lock()
		accepted, acceptedAt, refreshedAt := l.accepted, l.acceptedAt, l.refreshedAt
		l.stateMu.Unlock()
		if !accepted || acceptedAt.IsZero() || now.Sub(acceptedAt) < minICERefreshAge {
			continue
		}
		if !refreshedAt.IsZero() && now.Sub(refreshedAt) < iceRefreshInterval {
			continue
		}
		if err := c.sendSignal(protocol.Message{Type: "ice.refresh", Connection: l.id}); err != nil {
			l.close(err, false)
			return
		}
		l.stateMu.Lock()
		l.refreshedAt = now
		l.stateMu.Unlock()
	}
}

func (c *Client) readLoop() {
	for {
		m, err := readSignal(c.ctx, c.ws)
		if err != nil {
			c.shutdown(fmt.Errorf("transport: signaling lost: %w", err))
			return
		}
		c.dispatch(m)
	}
}

func (c *Client) dispatch(m protocol.Message) {
	switch m.Type {
	case "auth.ok", "auth.renewed":
		return
	case "device.registered", "devices.list":
		c.notifyWaiters(m)
	case "error":
		if l := c.link(m.Connection); l != nil {
			l.route(m)
			return
		}
		c.notifyWaiters(m)
	case "connect.request":
		if c.role == RoleDesktop && c.desktop == "" {
			go c.acceptRequest(m)
		}
	case "connect.accept", "connect.closed", "rtc.offer", "rtc.answer", "rtc.candidate":
		if l := c.link(m.Connection); l != nil {
			l.route(m)
		}
	case "ice.config":
		l := c.link(m.Connection)
		if l == nil {
			return
		}
		var servers []iceServer
		if json.Unmarshal(m.Data, &servers) != nil {
			l.close(fmt.Errorf("%w: invalid ice.config", ErrMalformedResponse), false)
			return
		}
		l.setICE(servers)
	}
}

func (c *Client) link(id string) *link {
	if !protocol.ValidID(id) {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.links[id]
}

func (c *Client) expect(kind string) *waiter {
	w := &waiter{kind: kind, ch: make(chan protocol.Message, 1)}
	c.waitMu.Lock()
	c.waiters[kind] = append(c.waiters[kind], w)
	c.waitMu.Unlock()
	return w
}

func (c *Client) cancelWait(w *waiter) {
	c.waitMu.Lock()
	defer c.waitMu.Unlock()
	list := c.waiters[w.kind]
	for i, candidate := range list {
		if candidate == w {
			c.waiters[w.kind] = append(list[:i], list[i+1:]...)
			if len(c.waiters[w.kind]) == 0 {
				delete(c.waiters, w.kind)
			}
			return
		}
	}
}

func (c *Client) notifyWaiters(m protocol.Message) {
	c.waitMu.Lock()
	var targets []*waiter
	if m.Type == "error" {
		for kind, list := range c.waiters {
			targets = append(targets, list...)
			delete(c.waiters, kind)
		}
	} else {
		targets = c.waiters[m.Type]
		delete(c.waiters, m.Type)
	}
	c.waitMu.Unlock()
	for _, w := range targets {
		select {
		case w.ch <- m:
		default:
		}
	}
}

func (w *waiter) await(ctx context.Context, done <-chan struct{}) (protocol.Message, error) {
	select {
	case m := <-w.ch:
		return m, nil
	case <-ctx.Done():
		return protocol.Message{}, ctx.Err()
	case <-done:
		return protocol.Message{}, ErrClosed
	}
}

// waiterFailure converts a relay error delivered to an unrelated request
// waiter into a typed error. A missing or malformed reply also fails closed.
func waiterFailure(m protocol.Message) error {
	if m.Type != "error" {
		return fmt.Errorf("%w: unexpected %s reply", ErrMalformedResponse, m.Type)
	}
	var code string
	if json.Unmarshal(m.Data, &code) != nil || code == "" {
		return ErrMalformedResponse
	}
	return SignalError(code)
}

func (c *Client) sendSignal(m protocol.Message) error {
	if c.closed.Load() {
		return ErrClosed
	}
	c.writeMu.Lock()
	err := writeSignal(c.ctx, c.ws, m)
	c.writeMu.Unlock()
	if err != nil {
		c.shutdown(fmt.Errorf("transport: signaling write: %w", err))
	}
	return err
}

func (c *Client) shutdown(err error) {
	c.doneOnce.Do(func() {
		c.closed.Store(true)
		c.mu.Lock()
		wasAuthority := c.authority
		c.authority = false
		links := make([]*link, 0, len(c.links))
		for _, l := range c.links {
			links = append(links, l)
		}
		c.mu.Unlock()
		if wasAuthority {
			c.notifyAuthority(false)
		}
		for _, l := range links {
			l.close(err, false)
		}
		c.cancel()
		_ = c.ws.CloseNow()
		close(c.done)
	})
}

func readSignal(ctx context.Context, ws *websocket.Conn) (protocol.Message, error) {
	var m protocol.Message
	kind, data, err := ws.Read(ctx)
	if err != nil {
		return m, err
	}
	if kind != websocket.MessageText {
		return m, fmt.Errorf("%w: signaling record is not text", ErrMalformedResponse)
	}
	err = json.Unmarshal(data, &m)
	return m, err
}

func writeSignal(ctx context.Context, ws *websocket.Conn, m protocol.Message) error {
	deadline, cancel := context.WithTimeout(ctx, signalTimeout)
	defer cancel()
	return ws.Write(deadline, websocket.MessageText, protocol.Encode(m))
}

func verifyProof(creds *endpoint.Credentials, proof endpoint.LeaseProof, now time.Time) (identity.Principal, time.Time, error) {
	if creds == nil {
		return identity.Principal{}, time.Time{}, fmt.Errorf("%w: identity source returned no credentials", ErrInvalidArgument)
	}
	if proof.Certificate == "" || proof.Lease == "" {
		return identity.Principal{}, time.Time{}, fmt.Errorf("%w: identity source returned no lease proof", ErrInvalidArgument)
	}
	if proof.Certificate != creds.Certificate() {
		return identity.Principal{}, time.Time{}, fmt.Errorf("%w: lease certificate differs from credentials", ErrInvalidArgument)
	}
	ca := creds.CA()
	if len(ca) != ed25519.PublicKeySize {
		return identity.Principal{}, time.Time{}, fmt.Errorf("%w: invalid authority key", ErrInvalidArgument)
	}
	principal, err := identity.VerifyCertificate(proof.Certificate, ca, now)
	if err != nil {
		return identity.Principal{}, time.Time{}, fmt.Errorf("transport: endpoint certificate rejected: %w", err)
	}
	if principal.DeviceID != creds.DeviceID() || principal.RemoteUserID() != creds.UserID() {
		return identity.Principal{}, time.Time{}, fmt.Errorf("%w: certificate does not match credentials", ErrInvalidArgument)
	}
	until, err := identity.VerifyEndpointLease(proof.Lease, ca, now, proof.Certificate, principal)
	if err != nil {
		return identity.Principal{}, time.Time{}, fmt.Errorf("transport: endpoint lease rejected: %w", err)
	}
	return principal, until, nil
}

// checkSignalURL enforces the signaling endpoint policy: TLS outside the local
// machine, and plain ws only for an explicit loopback host. A caller cannot
// accidentally send an identity challenge over a LAN in clear text.
func checkSignalURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: invalid signaling URL", ErrInvalidArgument)
	}
	switch u.Scheme {
	case "wss":
		return nil
	case "ws":
	default:
		return fmt.Errorf("%w: signaling URL must use wss or loopback ws", ErrInvalidArgument)
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: plain ws is allowed only to a loopback host", ErrInvalidArgument)
	}
	return nil
}

// sameSignalOrigin checks the handshake response against the requested URL.
// Redirects are disabled, so this is a defense-in-depth check that the
// authenticated challenge came from the origin the caller chose.
func sameSignalOrigin(raw string, got *url.URL) bool {
	want, err := url.Parse(raw)
	if err != nil || got == nil {
		return false
	}
	scheme := "http"
	if want.Scheme == "wss" {
		scheme = "https"
	}
	return strings.EqualFold(got.Scheme, scheme) &&
		strings.EqualFold(got.Host, want.Host) &&
		got.RequestURI() == want.RequestURI()
}
