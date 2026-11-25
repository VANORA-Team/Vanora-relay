// Package mobile exposes the phone adapter to Android and Apple hosts via gomobile bind.
// Network operations and NextEvent block and should run off the native UI thread.
package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/pairnet"
	"vanora-relay/internal/routes"
)

// Store is supplied by the native app's secure storage. Missing state returns "", nil.
// Save must atomically replace the previous value. Use a separate store per account.
type Store interface {
	Load() (string, error)
	Save(value string) error
}

// Client owns one phone identity, one signaling socket and at most one selected desktop.
type Client struct {
	mesh           *phoneNetwork
	book           *pairnet.Database
	group          *pairnet.Group
	child          bool
	scopeTarget    string
	deviceName     string
	synced         chan struct{}
	identity       *account.Account
	source         transport.IdentitySource
	url            string
	lanKey         string
	lanTarget      *lan.Target
	lanName        string
	selfKey        string
	selfTarget     *selfrelay.Target
	selfName       string
	officialInvite *pairing.Official
	ctx            context.Context
	stop           context.CancelFunc
	op             sync.Mutex // dial, selection, subscription setup and link recovery
	mu             sync.Mutex
	socket         *transport.Client
	peer           transport.Peer
	device, owner  string
	connState      string
	connPath       string
	connErr        string
	pending        map[string]chan reply
	subscriptions  map[string]*cursor
	events         []event
	ready          chan struct{}
	retry          chan struct{}
	retryNow       chan struct{}
	generation     atomic.Uint64
	inboundFrames  atomic.Uint64
	betterWake     chan struct{}
	altLANRoutes   []string
	routeTracker   *routes.Tracker
}

type reply struct {
	data json.RawMessage
	err  error
}
type cursor struct {
	applied, delivered int64
	queued             int64
	watchPresence      bool
}
type event struct {
	session string
	seq     int64
	payload string
}

// NewClient opens the configured secure identity store for one official site
// channel (CN or GLOBAL). Use a separate Store slot per site. No network is
// opened until login or discovery.
func NewClient(identityURL, signalURL, publicKeyHex string, store Store) (*Client, error) {
	if store == nil {
		return nil, errors.New("secure storage required")
	}
	a, err := account.New(identityURL, publicKeyHex, store)
	if err != nil {
		return nil, err
	}
	c := newClient(signalURL, a)
	c.identity = a
	c.startNetwork()
	return c, nil
}

// NewLANClient creates an account-free client. Use a secure store dedicated to LAN pairing.
func NewLANClient(store Store) (*Client, error) {
	db, err := pairnet.Open(store)
	if err != nil {
		return nil, err
	}
	key, err := lan.LoadClientKey(db)
	if err != nil {
		return nil, err
	}
	c := newClient("", nil)
	c.lanKey = key
	c.book = db
	c.startNetwork()
	return c, nil
}

// NewSelfRelayClient creates an account-free client for a user-hosted relay
// (RELAY_CHANNEL=self). Use a secure store dedicated to self-hosted pairing.
func NewSelfRelayClient(store Store) (*Client, error) {
	db, err := pairnet.Open(store)
	if err != nil {
		return nil, err
	}
	key, err := selfrelay.LoadClientKey(db)
	if err != nil {
		return nil, err
	}
	c := newClient("", nil)
	c.selfKey = key
	c.book = db
	c.startNetwork()
	return c, nil
}

func newClient(signalURL string, source transport.IdentitySource) *Client {
	ctx, stop := context.WithCancel(context.Background())
	c := &Client{
		url:           signalURL,
		source:        source,
		ctx:           ctx,
		stop:          stop,
		connState:     "disconnected",
		pending:       make(map[string]chan reply),
		subscriptions: make(map[string]*cursor),
		ready:         make(chan struct{}, 1),
		retry:         make(chan struct{}, 1),
		retryNow:      make(chan struct{}, 1),
		betterWake:    make(chan struct{}, 1),
		routeTracker:  routes.NewTracker(),
	}
	go c.recoverConnection()
	go c.maintainRoutes()
	return c
}

// Enroll binds this mobile endpoint's key to the user represented by the host
// app's existing authentication token.
func (c *Client) Enroll(token string) error {
	if c.identity == nil {
		return errors.New("no account configured")
	}
	return c.identity.Enroll(c.ctx, token)
}

// UpdateToken supplies a refreshed host app authentication token for automatic
// certificate renewal without re-running enrollment. If a desktop was selected
// and disconnected due to credential expiry, background recovery is triggered.
func (c *Client) UpdateToken(token string) error {
	if c.identity == nil {
		return errors.New("no account configured")
	}
	if err := c.identity.UpdateToken(token); err != nil {
		return err
	}
	c.mu.Lock()
	shouldRetry := c.device != "" && c.peer == nil
	c.mu.Unlock()
	if shouldRetry {
		signal(c.retry)
	}
	return nil
}
func (c *Client) UserID() string {
	if c.identity == nil {
		return ""
	}
	return c.identity.UserID()
}
func (c *Client) DeviceID() string {
	if c.identity == nil {
		return ""
	}
	return c.identity.DeviceID()
}

// Reset disconnects from any desktop and clears the locally enrolled account,
// replacing the endpoint key so the user can sign into a different account.
func (c *Client) Reset() error {
	if c.child {
		return errors.New("reset the account on the main client")
	}
	c.op.Lock()
	defer c.op.Unlock()
	c.disconnect()
	if c.identity == nil {
		return errors.New("no account configured")
	}
	err := c.identity.Reset()
	if err == nil {
		c.mu.Lock()
		c.group = nil
		c.mu.Unlock()
	}
	return err
}

// ConnectionState returns a JSON snapshot of the client's current connection
// state, active WebRTC transport path ("direct", "relay", or "unknown"), and
// enrolled identity identifiers.
func (c *Client) ConnectionState() string {
	c.mu.Lock()
	state := c.connState
	path := c.connPath
	errMsg := c.connErr
	device := c.device
	owner := c.owner
	p := c.peer
	c.mu.Unlock()
	if state == "connected" && p != nil {
		if live := peerPath(p); live != "" {
			path = live
		}
	}
	gen := c.generation.Load()
	hint := c.routeTracker.TransportHint(time.Now())
	b, _ := json.Marshal(map[string]string{
		"state":          state,
		"device_id":      device,
		"owner":          owner,
		"path":           path,
		"error":          errMsg,
		"user_id":        c.UserID(),
		"self_device_id": c.DeviceID(),
		"generation":     strconv.FormatUint(gen, 10),
		"transport_hint": hint,
	})
	return string(b)
}

// Reconnect drops the current transport link while preserving the selected
// desktop and active session cursors, then immediately dials again. Call this
// when the device switches networks (e.g. Wi-Fi <-> cellular) or returns to the
// foreground.
func (c *Client) Reconnect() error {
	c.op.Lock()
	defer c.op.Unlock()
	c.mu.Lock()
	if c.device == "" {
		c.mu.Unlock()
		return errors.New("no desktop selected")
	}
	oldPeer := c.peer
	c.detachLocked()
	c.setStateLocked("reconnecting", "", "")
	c.mu.Unlock()
	if oldPeer != nil {
		oldPeer.Close()
	}
	if c.socket != nil {
		c.socket.Close()
		c.socket = nil
	}
	err := c.connectLocked()
	if err != nil {
		if !c.handleAuthError(err) {
			signal(c.retry)
		}
	}
	return err
}

func (c *Client) dial() (*transport.Client, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	if c.source == nil {
		return nil, errors.New("official relay requires an account client")
	}
	if c.socket != nil {
		select {
		case <-c.socket.Done():
			c.socket.Close()
			c.socket = nil
		default:
			return c.socket, nil
		}
	}
	s, err := transport.DialMobileFor(c.ctx, c.url, c.scopeTarget, c.source, (*handler)(c))
	if err != nil {
		return nil, err
	}
	c.socket = s
	return s, nil
}

// Devices returns a verified JSON directory with device_id, owner, name, issuer and subject.
func (c *Client) Devices() (string, error) {
	c.op.Lock()
	defer c.op.Unlock()
	socket, err := c.dial()
	if err != nil {
		return "", err
	}
	ctx, stop := context.WithTimeout(c.ctx, 15*time.Second)
	defer stop()
	items, err := socket.Devices(ctx)
	if err != nil {
		return "", err
	}
	type item struct {
		DeviceID string `json:"device_id"`
		Owner    string `json:"owner"`
		Name     string `json:"name"`
		Issuer   string `json:"issuer"`
		Subject  string `json:"subject"`
	}
	out := make([]item, 0, len(items))
	for _, d := range items {
		out = append(out, item{d.DeviceID, d.Owner, d.Name, d.Issuer, d.Subject})
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// Connect pins both values. The adapter reconnects to this desktop on link loss.
// A different selection clears queued events and subscriptions from the previous desktop.
func (c *Client) Connect(deviceID, ownerID string) error {
	if c.source == nil {
		return errors.New("official relay requires an account client")
	}
	if deviceID == "" || ownerID == "" {
		return errors.New("desktop and owner required")
	}
	c.op.Lock()
	defer c.op.Unlock()
	if c.identity != nil {
		bound, ok := c.desktopBinding(deviceID)
		if !ok || bound.Owner != ownerID {
			c.handleAuthError(pairing.ErrInvalid)
			return pairing.ErrInvalid
		}
	}
	c.officialInvite = nil
	return c.selectDesktop(deviceID, ownerID, false)
}

// Pair accepts a scanned QR link or a typed pairing code. Official clients use
// their configured site. For a self-hosted code, supply the node's signal URL.
func (c *Client) Pair(input, signalURL, relayToken, clientName string) error {
	if c.child {
		return errors.New("pair devices on the main client")
	}
	if c.lanKey != "" {
		link := strings.TrimSpace(input)
		if !strings.Contains(link, "://") {
			var err error
			link, err = lan.ResolveCode(c.ctx, link, signalURL, c.lanKey)
			if err != nil {
				return err
			}
		}
		target, err := lan.ParseTarget(link)
		if err != nil || target.Token == "" {
			return pairing.ErrInvalid
		}
		return c.ConnectLAN(link, clientName)
	}
	if c.selfKey == "" && c.identity == nil {
		return errors.New("pairing requires an official or self-hosted relay client")
	}
	link := strings.TrimSpace(input)
	service := c.url
	if c.selfKey != "" && signalURL != "" {
		var err error
		service, err = selfrelay.NormalizeSignalURL(signalURL)
		if err != nil {
			return err
		}
	}
	if !strings.Contains(link, "://") {
		if service == "" {
			return errors.New("self-hosted pairing code requires the relay URL")
		}
		var err error
		link, err = pairing.Resolve(c.ctx, service, link)
		if err != nil {
			return err
		}
	}
	if c.selfKey != "" {
		target, err := selfrelay.ParseTarget(link)
		if err != nil || target.Pair == "" || (service != "" && service != target.SignalURL) {
			return pairing.ErrInvalid
		}
		return c.ConnectSelfRelayWithToken(link, relayToken, clientName)
	}
	target, err := pairing.ParseOfficial(link, c.url)
	if err != nil {
		return err
	}
	c.op.Lock()
	defer c.op.Unlock()
	c.deviceName = clientName
	c.officialInvite = &target
	return c.selectDesktop(target.Device, target.Owner, true)
}

// ConnectLAN pairs with a private desktop link or reconnects using LANAddress.
func (c *Client) ConnectLAN(link, clientName string) error {
	if c.lanKey == "" {
		return errors.New("LAN requires a LAN client")
	}
	target, err := lan.ParseTarget(link)
	if err != nil {
		return err
	}
	if c.child && c.scopeTarget != target.Pin {
		return errors.New("desktop handle is bound to a different device")
	}
	c.op.Lock()
	defer c.op.Unlock()
	if c.lanTarget != nil && c.lanTarget.Address != target.Address && c.lanTarget.Pin == target.Pin {
		c.mu.Lock()
		old := c.peer
		c.detachLocked()
		c.mu.Unlock()
		if old != nil {
			old.Close()
		}
	}
	c.lanTarget = &target
	c.lanName = clientName
	if err := c.selectDesktop(target.Pin, "lan", target.Token != ""); err != nil {
		return err
	}
	c.lanTarget.Token = ""
	return nil
}

// LANAddress returns the current paired desktop address with the invitation removed.
func (c *Client) LANAddress() string {
	c.op.Lock()
	defer c.op.Unlock()
	if c.lanTarget == nil || c.lanTarget.Token != "" {
		return ""
	}
	return c.lanTarget.Link()
}

// ConnectSelfRelay pairs with a desktop through a self-hosted relay using a
// pairing link (which embeds the relay token) or reconnects using SelfRelayTarget.
func (c *Client) ConnectSelfRelay(link, clientName string) error {
	return c.ConnectSelfRelayWithToken(link, "", clientName)
}

// ConnectSelfRelayWithToken pairs or reconnects through a self-hosted relay,
// allowing the caller to supply the relay bearer token out-of-band when the
// pairing link omitted it.
func (c *Client) ConnectSelfRelayWithToken(link, relayToken, clientName string) error {
	if c.selfKey == "" {
		return errors.New("self-hosted relay requires a self-relay client")
	}
	target, err := selfrelay.ParseTarget(link)
	if err != nil {
		return err
	}
	if c.child && c.scopeTarget != target.Pin {
		return errors.New("desktop handle is bound to a different device")
	}
	if strings.TrimSpace(relayToken) != "" {
		if err := selfrelay.ValidateRelayToken(strings.TrimSpace(relayToken)); err != nil {
			return err
		}
		target.Token = strings.TrimSpace(relayToken)
	}
	if target.Token == "" {
		return errors.New("selfrelay: relay token required")
	}
	c.op.Lock()
	defer c.op.Unlock()
	if c.child && c.book.Profile().Service != target.SignalURL {
		return errors.New("desktop handle is bound to a different relay")
	}
	if !c.child && c.book.Profile().Service != target.SignalURL {
		c.disconnect()
		c.mu.Lock()
		c.group = nil
		c.mu.Unlock()
	}
	if c.selfTarget != nil && (c.selfTarget.SignalURL != target.SignalURL || c.selfTarget.Token != target.Token) && c.selfTarget.Pin == target.Pin {
		c.mu.Lock()
		old := c.peer
		c.detachLocked()
		c.mu.Unlock()
		if old != nil {
			old.Close()
		}
	}
	c.selfTarget = &target
	c.selfName = clientName
	if err := c.selectDesktop(target.Pin, "self", target.Pair != ""); err != nil {
		return err
	}
	c.selfTarget.Pair = ""
	return nil
}

// SelfRelayTarget returns the paired self-hosted relay target with the
// one-time pairing token stripped so the host app can store it for reconnects.
func (c *Client) SelfRelayTarget() string {
	c.op.Lock()
	defer c.op.Unlock()
	if c.selfTarget == nil || c.selfTarget.Pair != "" {
		return ""
	}
	return c.selfTarget.Link()
}

func (c *Client) selectDesktop(deviceID, ownerID string, freshInvite bool) error {
	if c.child && deviceID != c.scopeTarget {
		return errors.New("desktop handle is bound to a different device")
	}
	if c.mesh != nil && !c.child {
		c.closeChild(deviceID)
	}
	c.mu.Lock()
	same := deviceID == c.device && ownerID == c.owner
	old := c.peer
	if same && freshInvite && old != nil {
		c.detachLocked()
	}
	if !same {
		c.detachLocked()
		c.device = deviceID
		c.owner = ownerID
		c.subscriptions = make(map[string]*cursor)
		c.events = nil
	}
	c.mu.Unlock()
	if same && !freshInvite && old != nil && old.Allows(false) {
		return nil
	}
	if old != nil {
		old.Close()
	}
	c.mu.Lock()
	c.setStateLocked("connecting", "", "")
	c.mu.Unlock()
	err := c.connectLocked()
	if err != nil {
		if !c.handleAuthError(err) {
			signal(c.retry)
		}
	}
	return err
}

func (c *Client) connectLocked() error {
	c.mu.Lock()
	d, o := c.device, c.owner
	c.mu.Unlock()
	if d == "" {
		return errors.New("no desktop selected")
	}
	group, local, remote, invited := c.networkBinding(d)
	if group != nil && !invited {
		member, known := group.Get(d)
		self, hasSelf := group.Get(local.ID)
		if (known && !member.Active()) || (hasSelf && !self.Active()) {
			return pairing.ErrInvalid
		}
	}
	p, start, err := c.dialPeer(d, o)
	if err != nil {
		c.mu.Lock()
		c.setStateLocked("reconnecting", "", err.Error())
		c.mu.Unlock()
		return err
	}
	if group != nil {
		if err := group.Admit(local, remote, invited); err != nil {
			p.Close()
			return err
		}
		if c.book != nil && !c.child {
			profile := pairnet.Profile{Name: local.Name}
			if c.selfTarget != nil {
				profile.Service, profile.Token = c.selfTarget.SignalURL, c.selfTarget.Token
			}
			if err := c.book.SetProfile(profile); err != nil {
				p.Close()
				return err
			}
		}
	}
	c.mu.Lock()
	if !p.Allows(true) {
		c.setStateLocked("reconnecting", "", "desktop authorization expired")
		c.mu.Unlock()
		p.Close()
		return errors.New("desktop authorization expired")
	}
	c.peer = p
	c.generation.Add(1)
	c.group = group
	c.synced = make(chan struct{})
	synced := c.synced
	activePath := peerPath(p)
	c.routeTracker.RecordActivePath(activePath, time.Now())
	c.setStateLocked("connected", activePath, "")
	resume := make(map[string]int64, len(c.subscriptions))
	for id, cur := range c.subscriptions {
		resume[id] = cur.applied
	}
	c.mu.Unlock()
	if start != nil {
		start()
	}
	if group != nil {
		if err := c.syncPeer(p, group); err != nil {
			p.Close()
			return err
		}
		if invited {
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-synced:
			case <-c.ctx.Done():
				return c.ctx.Err()
			case <-timer.C:
				return errors.New("pairing network synchronization timed out")
			}
		}
	}
	for id, seq := range resume {
		if _, err := c.subscribe(p, id, seq); err != nil {
			if errors.Is(err, errSnapshot) || errors.Is(err, errUnavailable) || p.Allows(false) {
				// Decouple session subscription health from transport health: if the
				// underlying peer remains live, surface a session-scoped error instead
				// of tearing down healthy subscriptions on the same connection.
				c.mu.Lock()
				delete(c.subscriptions, id)
				c.enqueueLocked(event{payload: controlEvent(id, err.Error())})
				c.mu.Unlock()
				continue
			}
			p.Close()
			return err
		}
	}
	return nil
}

func (c *Client) dialPeer(device, owner string) (transport.Peer, func(), error) {
	if c.lanTarget != nil {
		return c.dialLANPeer()
	}
	if c.selfTarget != nil {
		p, start, err := selfrelay.Dial(c.ctx, *c.selfTarget, c.selfKey, c.selfName, (*handler)(c))
		if err == nil {
			c.selfTarget.Pair = ""
		}
		return p, start, err
	}
	s, err := c.dial()
	if err != nil {
		return nil, nil, err
	}
	ctx, stop := context.WithTimeout(c.ctx, 30*time.Second)
	defer stop()
	var pin, token []byte
	if target := c.officialInvite; target != nil {
		pin, token = target.Pin, target.Token
	} else if c.identity != nil {
		bound, ok := c.desktopBinding(device)
		if !ok || bound.Owner != owner {
			return nil, nil, pairing.ErrInvalid
		}
		pin, err = base64.RawURLEncoding.Strict().DecodeString(bound.Pin)
		if err != nil || len(pin) != 32 {
			return nil, nil, pairing.ErrInvalid
		}
	}
	p, err := s.ConnectPaired(ctx, device, owner, pin, token)
	if err == nil && c.officialInvite != nil {
		bound := account.PeerBinding{Owner: owner, Pin: base64.RawURLEncoding.EncodeToString(pin)}
		group, _ := c.identity.PairingIdentity(c.url, "mobile")
		if err := c.identity.BindNetworkPeer(group, device, bound); err != nil {
			p.Close()
			return nil, nil, err
		}
		c.officialInvite = nil
	}
	return p, nil, err
}

func (c *Client) recoverConnection() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.retry:
		case <-c.retryNow:
		}
		for delay := time.Second; ; delay = min(delay*2, 15*time.Second) {
			timer := time.NewTimer(delay)
			select {
			case <-c.ctx.Done():
				timer.Stop()
				return
			case <-c.retryNow:
				timer.Stop()
				delay = time.Second
			case <-timer.C:
			}
			c.op.Lock()
			c.mu.Lock()
			want := c.device != "" && c.peer == nil
			c.mu.Unlock()
			var err error
			if want {
				err = c.connectLocked()
			}
			c.op.Unlock()
			if !want || err == nil || c.handleAuthError(err) {
				break
			}
		}
	}
}

// Disconnect forgets the selected desktop and disables automatic reconnect. The identity is retained.
func (c *Client) Disconnect() { c.op.Lock(); defer c.op.Unlock(); c.disconnect() }
func (c *Client) disconnect() {
	if c.mesh != nil && !c.child {
		c.closeChildren()
	}
	c.lanTarget = nil
	c.lanName = ""
	c.selfTarget = nil
	c.selfName = ""
	c.officialInvite = nil
	c.mu.Lock()
	p := c.peer
	c.device = ""
	c.owner = ""
	c.detachLocked()
	clear(c.subscriptions)
	c.events = nil
	c.setStateLocked("disconnected", "", "")
	c.mu.Unlock()
	if p != nil {
		p.Close()
	}
	if c.socket != nil {
		c.socket.Close()
		c.socket = nil
	}
}
func (c *Client) Close() { c.stop(); c.Disconnect() }

func (c *Client) detachLocked() {
	c.peer = nil
	for id, ch := range c.pending {
		ch <- reply{err: errors.New("connection lost")}
		delete(c.pending, id)
	}
	c.events = slices.DeleteFunc(c.events, func(e event) bool { return e.session != "" })
	for _, cur := range c.subscriptions {
		cur.queued = cur.applied
		cur.delivered = cur.applied
	}
}

func (c *Client) setStateLocked(state, path, errMsg string) {
	if c.connState == state && c.connPath == path && c.connErr == errMsg {
		return
	}
	c.connState = state
	c.connPath = path
	c.connErr = errMsg
	if len(c.events) >= 256 {
		return
	}
	payload, _ := json.Marshal(map[string]string{
		"type":      "connection.state",
		"state":     state,
		"device_id": c.device,
		"owner":     c.owner,
		"path":      path,
		"error":     errMsg,
	})
	c.enqueueLocked(event{payload: string(payload)})
}

func (c *Client) handleAuthError(err error) bool {
	var closed *transport.ClosedError
	pairingRequired := errors.Is(err, lan.ErrUnpaired) || errors.Is(err, selfrelay.ErrUnpaired) || errors.Is(err, pairing.ErrInvalid) ||
		(errors.As(err, &closed) && closed.Reason == "access_denied")
	relayTokenInvalid := errors.Is(err, selfrelay.ErrUnauthorized)
	if !pairingRequired && !relayTokenInvalid && !isLoginRequiredError(err) {
		return false
	}
	c.mu.Lock()
	c.setStateLocked("disconnected", "", err.Error())
	if len(c.events) < 256 {
		eventType, state := "auth.state", "login_required"
		if pairingRequired {
			eventType, state = "access.state", "pairing_required"
		} else if relayTokenInvalid {
			eventType, state = "access.state", "relay_token_invalid"
		}
		payload, _ := json.Marshal(map[string]string{
			"type":  eventType,
			"state": state,
			"error": err.Error(),
		})
		c.enqueueLocked(event{payload: string(payload)})
	}
	c.mu.Unlock()
	return true
}

func isLoginRequiredError(err error) bool {
	return errors.Is(err, account.ErrNotEnrolled) ||
		errors.Is(err, account.ErrExpired) ||
		errors.Is(err, account.ErrCredential) ||
		errors.Is(err, account.ErrStateInvalid) ||
		errors.Is(err, account.ErrAuthorityChanged)
}

func peerPath(p transport.Peer) string {
	if pr, ok := p.(transport.PathReporter); ok {
		return pr.Path()
	}
	return "unknown"
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
func controlEvent(session, code string) string {
	b, _ := json.Marshal(map[string]string{"type": "subscription.error", "session_id": session, "code": code})
	return string(b)
}
func (c *Client) enqueueLocked(e event) { c.events = append(c.events, e); signal(c.ready) }

// handler is private so transport types never leak into mobile bindings.
type handler Client

func (h *handler) Open(p transport.Peer) {}
func (h *handler) Closed(p transport.Peer) {
	c := (*Client)(h)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peer == p {
		c.detachLocked()
		if c.device != "" {
			c.setStateLocked("reconnecting", "", "connection lost")
			signal(c.retry)
		} else {
			c.setStateLocked("disconnected", "", "")
		}
	}
}
func (h *handler) Message(p transport.Peer, b []byte) {
	c := (*Client)(h)
	var m struct {
		Type    string          `json:"type"`
		ID      string          `json:"request_id"`
		Data    json.RawMessage `json:"data"`
		Code    string          `json:"code"`
		Session string          `json:"session_id"`
		Seq     int64           `json:"seq"`
	}
	if json.Unmarshal(b, &m) != nil {
		p.Close()
		return
	}
	c.mu.Lock()
	if c.peer != p {
		c.mu.Unlock()
		return
	}
	c.inboundFrames.Add(1)
	if m.Type == "pairnet.removed" && c.group != nil {
		group, id := c.group, c.device
		c.mu.Unlock()
		var removal transport.Removal
		if json.Unmarshal(b, &removal) == nil {
			if changed, _ := group.ReceiveRemoval(id, removal.Receiver, removal.Epoch); changed {
				signal(c.mesh.wake)
			}
		}
		p.Close()
		return
	}
	if m.Type == "pairnet.state" && c.group != nil {
		group, id := c.group, c.device
		c.mu.Unlock()
		var frame transport.NetworkFrame
		if len(b) > 2<<20 || json.Unmarshal(b, &frame) != nil {
			p.Close()
			return
		}
		changed, err := group.Merge(id, frame.Members)
		if err != nil {
			p.Close()
			return
		}
		c.mu.Lock()
		if c.peer == p && c.synced != nil {
			close(c.synced)
			c.synced = nil
			changed = true
		}
		c.mu.Unlock()
		if changed {
			signal(c.mesh.wake)
			signal(c.betterWake)
		}
		return
	}
	bad := false
	switch m.Type {
	case "result", "error":
		if ch := c.pending[m.ID]; ch != nil {
			var err error
			if m.Type == "error" {
				err = errors.New(m.Code)
				switch m.Code {
				case "snapshot_required":
					err = errSnapshot
				case "unavailable":
					err = errUnavailable
				}
			}
			ch <- reply{m.Data, err}
			delete(c.pending, m.ID)
		}
	case "event":
		if m.Seq == 0 && m.Session != "" {
			if len(c.events) < 256 {
				c.enqueueLocked(event{session: m.Session, seq: 0, payload: string(b)})
			}
			break
		}
		cur := c.subscriptions[m.Session]
		if cur != nil && m.Seq > cur.queued {
			if m.Seq != cur.queued+1 || len(c.events) >= 256 {
				// The host needs a fresh snapshot when events no longer fit or form a gap.
				// Keep the connection and the other sessions' cursors usable.
				delete(c.subscriptions, m.Session)
				c.events = slices.DeleteFunc(c.events, func(e event) bool { return e.session == m.Session })
				c.enqueueLocked(event{session: m.Session, payload: controlEvent(m.Session, errSnapshot.Error())})
			} else {
				cur.queued = m.Seq
				c.enqueueLocked(event{m.Session, m.Seq, string(b)})
			}
		}
	default:
		bad = true
	}
	c.mu.Unlock()
	if bad {
		p.Close()
	}
}

var errSnapshot = errors.New("snapshot_required")
var errUnavailable = errors.New("unavailable")

// NextEvent returns the next event JSON, or an empty string on timeout. Use one consumer per client.
func (c *Client) NextEvent(timeoutMillis int64) (string, error) {
	if timeoutMillis < 0 || timeoutMillis > 60000 {
		return "", errors.New("timeout must be 0..60000 ms")
	}
	timer := time.NewTimer(time.Duration(timeoutMillis) * time.Millisecond)
	defer timer.Stop()
	for {
		c.mu.Lock()
		if len(c.events) > 0 {
			e := c.events[0]
			c.events[0] = event{}
			c.events = c.events[1:]
			if e.session != "" {
				if cur := c.subscriptions[e.session]; cur != nil && e.seq > 0 {
					cur.delivered = e.seq
				}
			}
			c.mu.Unlock()
			return e.payload, nil
		}
		c.mu.Unlock()
		select {
		case <-c.ctx.Done():
			return "", c.ctx.Err()
		case <-timer.C:
			return "", nil
		case <-c.ready:
		}
	}
}

// Acknowledge advances the reconnect cursor after the app applies (or durably stores) an event.
func (c *Client) Acknowledge(sessionID string, seq int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cur := c.subscriptions[sessionID]
	if cur == nil || seq < 0 || seq > cur.delivered {
		return errors.New("cursor was not delivered")
	}
	cur.applied = max(cur.applied, seq)
	return nil
}

func (c *Client) currentPeer() (transport.Peer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peer == nil || (c.group != nil && !c.group.Allows(c.device)) {
		return nil, errors.New("desktop disconnected")
	}
	return c.peer, nil
}
func (c *Client) request(p transport.Peer, req map[string]any, online bool) (string, error) {
	return c.requestWithTimeout(p, req, online, 20*time.Second)
}

func (c *Client) requestWithTimeout(p transport.Peer, req map[string]any, online bool, timeout time.Duration) (string, error) {
	id := req["request_id"].(string)
	if id == "" || len(id) > 128 {
		return "", errors.New("request_id must be 1..128 bytes")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	ch := make(chan reply, 1)
	c.mu.Lock()
	if c.peer != p || len(c.pending) >= 32 || c.pending[id] != nil {
		c.mu.Unlock()
		return "", errors.New("desktop disconnected, busy, or request already pending")
	}
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.pending[id] == ch {
			delete(c.pending, id)
		}
		c.mu.Unlock()
	}()
	if err := p.Send(body, online); err != nil {
		return "", err
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-c.ctx.Done():
		return "", c.ctx.Err()
	case <-timer.C:
		return "", fmt.Errorf("desktop response timeout")
	case r := <-ch:
		return string(r.data), r.err
	}
}

func (c *Client) subscribe(p transport.Peer, id string, seq int64) (string, error) {
	if seq < 0 || id == "" {
		return "", errors.New("session and nonnegative cursor required")
	}
	c.mu.Lock()
	if len(c.subscriptions) >= 64 && c.subscriptions[id] == nil {
		c.mu.Unlock()
		return "", errors.New("too many open sessions")
	}
	watch := false
	if existing := c.subscriptions[id]; existing != nil {
		watch = existing.watchPresence
	}
	c.subscriptions[id] = &cursor{applied: seq, delivered: seq, queued: seq, watchPresence: watch}
	c.events = slices.DeleteFunc(c.events, func(e event) bool { return e.session == id })
	c.mu.Unlock()
	req := map[string]any{"type": "events.resume", "request_id": NewRequestID(), "session_id": id, "after_seq": seq}
	if watch {
		req["watch_presence"] = true
	}
	data, err := c.request(p, req, false)
	if errors.Is(err, errSnapshot) || errors.Is(err, errUnavailable) {
		c.mu.Lock()
		delete(c.subscriptions, id)
		c.mu.Unlock()
	}
	return data, err
}
