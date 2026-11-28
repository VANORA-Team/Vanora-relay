package cftunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/strictjson"
	"vanora-relay/protocol"
)

type ConnectorProcess interface {
	Stop()
}

type StartConnectorFunc func(context.Context, ConnectorOptions) (ConnectorProcess, error)

type HostOptions struct {
	Channel           string
	Scope             string
	ControlOrigin     string
	DeviceID          string
	OwnerID           string
	PrivateKey        ed25519.PrivateKey
	SelfToken         string
	CA                ed25519.PublicKey
	LeaseSource       func(context.Context) (endpoint.LeaseProof, error)
	Handler           transport.Handler
	SendSignal        func(protocol.Message) error
	AuthorizeOffer    func(OfferRequest) (OfferDecision, error)
	CloudflaredBinary string
	PinnedConnector   bool
	StartConnector    StartConnectorFunc
	Observe           func(HostStatus)
	HTTPClient        *http.Client
}

type HostStatus struct {
	Enabled              bool   `json:"enabled"`
	State                string `json:"state"`
	Hostname             string `json:"hostname,omitempty"`
	Generation           int64  `json:"generation"`
	Incarnation          int64  `json:"incarnation"`
	ManualResumeRequired bool   `json:"manual_resume_required"`
	ConnectorReady       bool   `json:"connector_ready"`
	ActivePeers          int    `json:"active_peers"`
	Error                string `json:"error,omitempty"`
}

type OfferRequest struct {
	ConnectionID string
	Principal    identity.Principal
	Role         string
}

type OfferDecision struct {
	UserID string
	Allows func() bool
}

type HostManager struct {
	opts    HostOptions
	control *ControlClient
	pub     ed25519.PublicKey

	lifecycle sync.Mutex
	manageMu  sync.Mutex
	opMu      sync.Mutex
	signalMu  sync.Mutex
	observeMu sync.Mutex
	mu        sync.Mutex

	ctx             context.Context
	cancel          context.CancelFunc
	listener        *Listener
	sendSignal      func(protocol.Message) error
	runtimeID       string
	socketID        string
	seq             uint64
	phase           string
	listeningSeq    uint64
	ackedUntil      time.Time
	ackedSeq        uint64
	ack             chan struct{}
	wake            chan struct{}
	leaseWake       chan struct{}
	offerSlots      chan struct{}
	workers         sync.WaitGroup
	status          HostStatus
	observed        HostStatus
	paused          bool
	stopping        bool
	reconcileCancel context.CancelFunc
	connector       ConnectorProcess
	connectorRun    uint64
	revision        uint64
	lease           endpoint.LeaseProof
	leaseUntil      time.Time
	leaseVersion    atomic.Uint64
}

func NewHostManager(opts HostOptions) (*HostManager, error) {
	if !tunnelIdentifier.MatchString(opts.Scope) || opts.OwnerID == "" || opts.SendSignal == nil ||
		opts.AuthorizeOffer == nil || opts.Handler == nil || (opts.Channel == "self" && opts.OwnerID != opts.DeviceID) {
		return nil, errors.New("cftunnel: invalid host configuration")
	}
	control, err := NewControlClient(ControlOptions{Channel: opts.Channel, ControlOrigin: opts.ControlOrigin,
		DeviceID: opts.DeviceID, PrivateKey: opts.PrivateKey, SelfToken: opts.SelfToken,
		CA: opts.CA, LeaseSource: opts.LeaseSource, HTTPClient: opts.HTTPClient})
	if err != nil {
		return nil, err
	}
	opts.PrivateKey = slices.Clone(opts.PrivateKey)
	opts.CA = slices.Clone(opts.CA)
	if opts.StartConnector == nil {
		opts.StartConnector = func(ctx context.Context, connector ConnectorOptions) (ConnectorProcess, error) {
			return StartConnector(ctx, connector)
		}
	}
	return &HostManager{
		opts: opts, control: control, pub: control.pub, sendSignal: opts.SendSignal,
		ack: make(chan struct{}, 1), wake: make(chan struct{}, 1), leaseWake: make(chan struct{}, 1),
		offerSlots: make(chan struct{}, 8), status: HostStatus{State: "disabled"},
	}, nil
}

type hostHandler struct {
	transport.Handler
	host *HostManager
}

func (h hostHandler) Open(peer transport.Peer) {
	h.host.observe()
	h.Handler.Open(peer)
}

func (h hostHandler) Closed(peer transport.Peer) {
	h.Handler.Closed(peer)
	h.host.observe()
}

func (h *HostManager) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.ctx != nil {
		return errors.New("cftunnel: host has already started")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	listener, err := NewListener(ListenerOptions{PrivateKey: h.opts.PrivateKey, Handler: hostHandler{h.opts.Handler, h}})
	if err != nil {
		return errors.New("cftunnel: loopback listener unavailable")
	}
	h.mu.Lock()
	h.ctx, h.cancel = context.WithCancel(ctx)
	h.listener, h.runtimeID, h.socketID = listener, protocol.NewID(), protocol.NewID()
	h.phase = "starting"
	h.status = HostStatus{Enabled: true, State: "starting"}
	h.mu.Unlock()
	if _, err := h.announce(); err != nil {
		h.cancel()
		_ = listener.Close()
		h.mu.Lock()
		h.status = HostStatus{State: "disabled", Error: "signaling_unavailable"}
		h.mu.Unlock()
		h.observe()
		return errors.New("cftunnel: host signaling unavailable")
	}
	h.observe()
	h.workers.Go(h.run)
	h.workers.Go(h.heartbeat)
	h.workers.Go(h.renewPeers)
	go func() {
		<-h.ctx.Done()
		h.Stop()
	}()
	return nil
}

// ReattachSignal rebinds the running HostManager to a replacement signaling
// socket on the same scope so the loopback listener and cloudflared connector
// stay alive across brief signaling reconnects.
func (h *HostManager) ReattachSignal(scope string, send func(protocol.Message) error) error {
	if scope != h.opts.Scope || send == nil {
		return errors.New("cftunnel: signal reattach scope mismatch")
	}
	h.mu.Lock()
	if h.ctx == nil || h.stopping || h.ctx.Err() != nil {
		h.mu.Unlock()
		return ErrTunnelUnavailable
	}
	h.sendSignal = send
	h.socketID = protocol.NewID()
	h.ackedUntil = time.Time{}
	h.ackedSeq = h.seq
	if h.phase == "listening" {
		h.listeningSeq = 0
	}
	h.mu.Unlock()
	if _, err := h.announce(); err != nil {
		return err
	}
	h.observe()
	return nil
}

func (h *HostManager) Stop() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	h.mu.Lock()
	if h.ctx == nil || h.stopping {
		h.mu.Unlock()
		return
	}
	h.stopping = true
	h.paused = true
	h.setPhaseLocked("stopping")
	h.mu.Unlock()
	h.listener.RevokeAll()
	h.cancel()
	_, _ = h.announce()
	h.workers.Wait()
	h.opMu.Lock()
	h.stopConnector()
	_ = h.listener.Close()
	h.opMu.Unlock()
	h.mu.Lock()
	h.lease = endpoint.LeaseProof{}
	h.leaseUntil = time.Time{}
	h.status = HostStatus{State: "disabled"}
	h.mu.Unlock()
	h.observe()
}

func (h *HostManager) Status() HostStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	status := h.status
	status.ConnectorReady = status.ConnectorReady && h.ackedUntil.After(time.Now())
	if h.listener != nil {
		status.ActivePeers = h.listener.ActivePeers()
	}
	return status
}

func (h *HostManager) observe() {
	if h.opts.Observe == nil {
		return
	}
	h.observeMu.Lock()
	defer h.observeMu.Unlock()
	status := h.Status()
	if status != h.observed {
		h.observed = status
		h.opts.Observe(status)
	}
}

func (h *HostManager) setPhaseLocked(phase string) {
	h.phase = phase
	if phase != "listening" {
		h.status.ConnectorReady = false
		h.listeningSeq = 0
	}
}

func (h *HostManager) sendMessage(msg protocol.Message) error {
	h.mu.Lock()
	send := h.sendSignal
	h.mu.Unlock()
	if send == nil {
		return errors.New("cftunnel: host signaling unavailable")
	}
	return send(msg)
}

func (h *HostManager) announce() (uint64, error) {
	h.signalMu.Lock()
	defer h.signalMu.Unlock()
	h.mu.Lock()
	body := struct {
		signalDomain
		signalBinding
		SocketID   string `json:"socket_id"`
		Phase      string `json:"phase"`
		CanRecover bool   `json:"can_recover"`
	}{signalDomain{tunnelAudience, h.opts.Scope}, h.bindingLocked(), h.socketID, h.phase, h.phase != "stopping"}
	h.seq++
	if h.phase == "listening" && h.listeningSeq == 0 {
		h.listeningSeq = h.seq
	}
	msg := protocol.Message{Type: "tunnel.host", From: h.opts.DeviceID, To: "signal", Seq: h.seq}
	send := h.sendSignal
	h.mu.Unlock()
	if send == nil {
		return 0, errors.New("cftunnel: host signaling unavailable")
	}
	if err := msg.Sign(h.opts.PrivateKey, protocol.Encode(body)); err != nil {
		return 0, err
	}
	return msg.Seq, send(msg)
}

func (h *HostManager) syncPresence(ctx context.Context) error {
	seq, err := h.announce()
	if err != nil {
		return err
	}
	ackCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	return h.waitAck(ackCtx, seq)
}

func isBindingMismatch(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden && apiErr.Code == "device_binding_mismatch"
}

func (h *HostManager) heartbeat() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	consecutiveErrors := 0
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			if _, err := h.announce(); err != nil {
				consecutiveErrors++
				h.mu.Lock()
				h.ackedUntil = time.Time{}
				h.mu.Unlock()
				h.observe()
				if consecutiveErrors >= 3 {
					h.cancel()
					return
				}
				continue
			}
			consecutiveErrors = 0
			h.observe()
		}
	}
}

func (h *HostManager) run() {
	for attempt := 0; ; {
		select {
		case <-h.ctx.Done():
			return
		case <-h.wake:
		}
		for {
			h.opMu.Lock()
			h.mu.Lock()
			canStart := !h.paused && h.connector == nil && time.Now().Before(h.ackedUntil)
			var ctx context.Context
			var cancel context.CancelFunc
			if canStart {
				ctx, cancel = context.WithTimeout(h.ctx, 45*time.Second)
				h.reconcileCancel = cancel
			}
			h.mu.Unlock()
			var err error
			if canStart {
				err = h.reconcile(ctx)
				cancel()
				h.mu.Lock()
				h.reconcileCancel = nil
				if h.paused {
					err = nil
				}
				h.mu.Unlock()
			}
			h.opMu.Unlock()
			h.observe()
			if err == nil {
				attempt = 0
				break
			}
			h.fail(err)
			floor, _ := retryControl(err)
			if backoff(h.ctx, attempt, max(time.Second, floor)) != nil {
				return
			}
			attempt++
		}
	}
}

func (h *HostManager) bindingLocked() signalBinding {
	return signalBinding{h.status.Generation, h.status.Incarnation, h.runtimeID}
}

func (h *HostManager) allocation(ctx context.Context) (AllocationView, error) {
	a, err := h.control.Status(ctx, h.opts.DeviceID)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound && apiErr.Code == "not_found" {
		return AllocationView{DeviceID: h.opts.DeviceID, State: "disabled"}, nil
	}
	if err == nil && !h.validAllocation(a) {
		return AllocationView{}, errors.New("cftunnel: invalid allocation")
	}
	return a, err
}

func (h *HostManager) validAllocation(a AllocationView) bool {
	switch a.State {
	case "ready", "disabled", "pending", "reconciling", "releasing", "released", "disconnecting", "suspended", "deprovisioning", "quarantined":
	default:
		return false
	}
	return a.DeviceID == h.opts.DeviceID && a.Generation >= a.Incarnation && a.Incarnation >= 0 &&
		(a.Hostname == "" || validHostname(a.Hostname)) &&
		(a.State != "ready" || a.Incarnation > 0 && a.Hostname != "")
}

func (h *HostManager) setAllocation(a AllocationView) {
	h.mu.Lock()
	h.status.State, h.status.Generation, h.status.Incarnation = a.State, a.Generation, a.Incarnation
	h.status.Hostname, h.status.ManualResumeRequired = a.Hostname, a.ManualResumeRequired
	h.status.Error = ""
	h.mu.Unlock()
}

func (h *HostManager) awaitMutation(ctx context.Context, result MutationResult, err error) error {
	id := result.Operation.ID
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict && apiErr.Code == "operation_in_progress" && apiErr.OperationID != "" {
		id, err = apiErr.OperationID, nil
	}
	if err != nil || id == "" {
		return err
	}
	_, err = h.control.WaitOperation(ctx, h.opts.DeviceID, id)
	return err
}

func (h *HostManager) reconcile(ctx context.Context) error {
	for attempt := 0; ; attempt++ {
		a, err := h.allocation(ctx)
		if err != nil {
			return err
		}
		h.setAllocation(a)
		if a.ManualResumeRequired || a.State == "suspended" {
			h.mu.Lock()
			h.paused = true
			h.status.State, h.status.ManualResumeRequired = "suspended", true
			h.setPhaseLocked("stopping")
			h.mu.Unlock()
			_, _ = h.announce()
			return nil
		}
		h.observe()
		control, device, origin := h.control, h.opts.DeviceID, h.listener.Origin()
		var result MutationResult
		switch a.State {
		case "disabled":
			result, err = control.Register(ctx, device, origin, h.runtimeID, a.Generation)
		case "released":
			result, err = control.Recover(ctx, device, origin, h.runtimeID, a.Generation)
		case "ready":
			result, err = control.ReconcileOrigin(ctx, device, origin, h.runtimeID, a.Generation)
			if isBindingMismatch(err) {
				if syncErr := h.syncPresence(ctx); syncErr != nil {
					return syncErr
				}
				result, err = control.ReconcileOrigin(ctx, device, origin, h.runtimeID, a.Generation)
			}
		case "pending", "reconciling", "releasing", "disconnecting", "deprovisioning":
			if err := backoff(ctx, attempt, 200*time.Millisecond); err != nil {
				return err
			}
			continue
		default:
			return errors.New("cftunnel: allocation unavailable")
		}
		asyncOp := result.Operation.ID != ""
		if err = h.awaitMutation(ctx, result, err); err != nil {
			return err
		}
		if a.State == "disabled" || a.State == "released" {
			updated, statusErr := h.allocation(ctx)
			if statusErr != nil {
				return statusErr
			}
			h.setAllocation(updated)
			if updated.Generation != a.Generation || updated.Incarnation != a.Incarnation {
				if syncErr := h.syncPresence(ctx); syncErr != nil {
					return syncErr
				}
			}
			continue
		}
		if a.State == "ready" && result.Allocation.State == "ready" {
			if !h.validAllocation(result.Allocation) {
				return errors.New("cftunnel: invalid reconciled allocation")
			}
			return h.startConnector(ctx, result.Allocation)
		}
		if a.State == "ready" && asyncOp {
			updated, statusErr := h.allocation(ctx)
			if statusErr != nil {
				return statusErr
			}
			if updated.State == "ready" {
				h.setAllocation(updated)
				if updated.Generation != a.Generation || updated.Incarnation != a.Incarnation {
					if syncErr := h.syncPresence(ctx); syncErr != nil {
						return syncErr
					}
				}
				return h.startConnector(ctx, updated)
			}
		}
	}
}

func (h *HostManager) startConnector(ctx context.Context, allocation AllocationView) error {
	h.setAllocation(allocation)
	token, err := h.control.Token(ctx, h.opts.DeviceID, h.listener.Origin(), h.runtimeID, allocation.Generation)
	if isBindingMismatch(err) {
		if syncErr := h.syncPresence(ctx); syncErr != nil {
			return syncErr
		}
		token, err = h.control.Token(ctx, h.opts.DeviceID, h.listener.Origin(), h.runtimeID, allocation.Generation)
	}
	if err != nil {
		return err
	}
	if token.Hostname != allocation.Hostname || !validHostname(token.Hostname) ||
		token.Generation != allocation.Generation || token.Incarnation != allocation.Incarnation ||
		token.Incarnation <= 0 || token.ConnectorToken == "" || token.TunnelID == "" {
		return errors.New("cftunnel: invalid connector response")
	}
	if h.opts.Channel != "self" {
		if _, err := h.localLease(ctx); err != nil {
			return err
		}
	}
	h.mu.Lock()
	if h.paused || h.stopping || ctx.Err() != nil {
		h.mu.Unlock()
		return context.Canceled
	}
	h.connectorRun++
	run := h.connectorRun
	h.mu.Unlock()
	origin := h.listener.Origin()
	options := ConnectorOptions{Binary: h.opts.CloudflaredBinary, Token: token.ConnectorToken,
		Observe: func(event ConnectorEvent) { h.connectorEvent(run, event.State) }}
	if h.opts.PinnedConnector {
		options.PinnedHostname, options.PinnedOrigin = token.Hostname, origin
	}
	connector, err := h.opts.StartConnector(h.ctx, options)
	if err != nil || connector == nil {
		h.stopConnector()
		return errors.New("cftunnel: connector startup failed")
	}
	h.mu.Lock()
	h.connector = connector
	h.mu.Unlock()
	return nil
}

func (h *HostManager) connectorEvent(run uint64, state string) {
	switch state {
	case "ready", "starting", "backoff", "stopped", "exited", "start_failed", "startup_timeout", "fallback", "failed":
	default:
		return
	}
	var failedConnector ConnectorProcess
	h.mu.Lock()
	if h.stopping || h.paused || run != h.connectorRun {
		h.mu.Unlock()
		return
	}
	phase := "starting"
	if state == "ready" {
		phase = "listening"
	}
	if state == "failed" {
		failedConnector = h.connector
		h.connector = nil
		h.connectorRun++
	}
	changed := h.phase != phase
	h.setPhaseLocked(phase)
	h.mu.Unlock()
	if failedConnector != nil {
		// Stop asynchronously so we never deadlock when called from the connector's own observer goroutine.
		go failedConnector.Stop()
		h.listener.RevokeAll()
		if _, err := h.announce(); err != nil {
			h.cancel()
		}
		h.observe()
		select {
		case h.wake <- struct{}{}:
		default:
		}
		return
	}
	if changed {
		if phase != "listening" {
			h.listener.RevokeAll()
		}
		if _, err := h.announce(); err != nil {
			h.cancel()
		}
		h.observe()
	}
}

func (h *HostManager) stopConnector() {
	h.mu.Lock()
	connector := h.connector
	h.connector = nil
	h.connectorRun++
	h.status.ConnectorReady = false
	h.mu.Unlock()
	if connector != nil {
		connector.Stop()
	}
}

func (h *HostManager) fail(err error) {
	code := "tunnel_operation_failed"
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case "entitlement_denied", "membership_unavailable", "rate_limited", "owner_quota_exhausted",
			"account_capacity", "dns_conflict", "tunnel_suspended":
			code = apiErr.Code
		}
	}
	h.mu.Lock()
	if !h.stopping {
		h.status.Error = code
	}
	h.mu.Unlock()
	h.observe()
}

func (h *HostManager) verifiedLeaseExpiry(proof endpoint.LeaseProof, now time.Time) (time.Time, bool) {
	if proof.Certificate == "" || proof.Lease == "" || len(h.opts.CA) != ed25519.PublicKeySize {
		return time.Time{}, false
	}
	principal, err := identity.VerifyCertificate(proof.Certificate, h.opts.CA, now)
	if err != nil || principal.DeviceID != h.opts.DeviceID || principal.RemoteUserID() != h.opts.OwnerID ||
		!principal.PublicKey.Equal(h.pub) || !principal.Expires.After(now) {
		return time.Time{}, false
	}
	until, err := identity.VerifyEndpointLease(proof.Lease, h.opts.CA, now, proof.Certificate, principal)
	if err != nil || !until.After(now) {
		return time.Time{}, false
	}
	if principal.Expires.Before(until) {
		until = principal.Expires
	}
	return until, true
}

func (h *HostManager) localLease(ctx context.Context) (endpoint.LeaseProof, error) {
	now := time.Now()
	h.mu.Lock()
	if h.lease.Lease != "" && now.Add(10*time.Second).Before(h.leaseUntil) {
		proof := h.lease
		h.mu.Unlock()
		return proof, nil
	}
	h.mu.Unlock()
	proof, err := h.control.proof(ctx)
	if err != nil {
		return endpoint.LeaseProof{}, err
	}
	until, ok := h.verifiedLeaseExpiry(proof, time.Now())
	if !ok {
		return endpoint.LeaseProof{}, errors.New("cftunnel: local tunnel owner changed")
	}
	h.setLocalLease(proof, until)
	return proof, nil
}

func (h *HostManager) setLocalLease(proof endpoint.LeaseProof, until time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopping || h.opts.Channel == "self" {
		return
	}
	if proof == h.lease {
		if until.After(h.leaseUntil) {
			h.leaseUntil = until
		}
		return
	}
	h.lease = proof
	h.leaseUntil = until
	h.leaseVersion.Add(1)
	select {
	case h.leaseWake <- struct{}{}:
	default:
	}
}

func (h *HostManager) renewPeers() {
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-h.leaseWake:
			h.mu.Lock()
			proof, revision := h.lease, h.leaseVersion.Load()
			h.mu.Unlock()
			if proof.Lease != "" {
				_ = h.listener.updateLocalLease(proof, func() bool { return h.leaseVersion.Load() == revision })
			}
		}
	}
}

func (h *HostManager) UpdateLocalLease(proof endpoint.LeaseProof) {
	if h.opts.Channel == "self" {
		return
	}
	until, _ := h.verifiedLeaseExpiry(proof, time.Now())
	h.setLocalLease(proof, until)
}

func (h *HostManager) AuthorityLost() {
	h.mu.Lock()
	h.lease = endpoint.LeaseProof{}
	h.leaseUntil = time.Time{}
	h.leaseVersion.Add(1)
	h.revision++
	listener := h.listener
	h.mu.Unlock()
	if listener != nil {
		listener.AuthorityLost()
	}
}

func (h *HostManager) revoke(action func(*Listener)) {
	h.mu.Lock()
	h.revision++
	listener := h.listener
	h.mu.Unlock()
	if listener != nil {
		action(listener)
		h.observe()
	}
}

func (h *HostManager) RevokeVisitor(deviceID string) {
	h.revoke(func(listener *Listener) {
		if deviceID == "" {
			listener.RevokeAll()
		} else {
			listener.RevokeVisitor(deviceID)
		}
	})
}

func (h *HostManager) RevokeUser(userID string) {
	h.revoke(func(listener *Listener) { listener.RevokeUser(userID) })
}

func (h *HostManager) RecheckPeers() {
	h.revoke(func(listener *Listener) { listener.RecheckPeers() })
}

func (h *HostManager) HandleSignal(m protocol.Message) {
	if !unsignedRelayMessage(m) {
		return
	}
	if m.Type == "tunnel.host.ack" {
		var body struct {
			RuntimeID string    `json:"runtime_id"`
			ExpiresAt time.Time `json:"expires_at"`
			Seq       uint64    `json:"seq,omitempty"`
		}
		now := time.Now()
		if m.Connection != "" || m.From != "" || m.To != "" || strictjson.Decode(m.Data, &body) != nil ||
			!body.ExpiresAt.After(now) || body.ExpiresAt.After(now.Add(time.Minute)) {
			return
		}
		h.mu.Lock()
		becameReady := false
		if body.RuntimeID == h.runtimeID && h.runtimeID != "" && !body.ExpiresAt.Before(h.ackedUntil) {
			validSeq := false
			if body.Seq > 0 {
				if body.Seq <= h.seq && (body.Seq > h.ackedSeq || body.ExpiresAt.After(h.ackedUntil)) {
					if body.Seq > h.ackedSeq {
						h.ackedSeq = body.Seq
					}
					validSeq = true
				}
			} else if h.ackedSeq < h.seq {
				h.ackedSeq++
				validSeq = true
			}
			if validSeq {
				if h.listeningSeq != 0 && h.ackedSeq >= h.listeningSeq {
					becameReady = !h.status.ConnectorReady || !now.Before(h.ackedUntil)
					h.status.ConnectorReady = true
				}
				h.ackedUntil = body.ExpiresAt
				close(h.ack)
				h.ack = make(chan struct{})
				select {
				case h.wake <- struct{}{}:
				default:
				}
			}
		}
		h.mu.Unlock()
		if becameReady {
			h.observe()
		}
		return
	}
	if !protocol.ValidID(m.Connection) {
		return
	}
	h.mu.Lock()
	listener, binding := h.listener, h.bindingLocked()
	if listener == nil {
		h.mu.Unlock()
		return
	}
	if m.Type == "tunnel.offer" {
		if h.stopping || h.ctx == nil || h.ctx.Err() != nil {
			h.mu.Unlock()
			return
		}
		select {
		case h.offerSlots <- struct{}{}:
			h.workers.Add(1)
			h.mu.Unlock()
			go func() {
				defer h.workers.Done()
				defer func() { <-h.offerSlots }()
				h.offer(m)
			}()
		default:
			h.mu.Unlock()
		}
		return
	}
	h.mu.Unlock()
	switch m.Type {
	case "tunnel.access":
		var body accessBody
		if m.From == "" && m.To == "" && strictjson.Decode(m.Data, &body) == nil && body.signalBinding == binding {
			if until := boundedAccessUntil(body.AccessUntil, time.Now()); !until.IsZero() {
				listener.updateAccessUntil(m.Connection, body.JTI, until)
			}
		}
	case "tunnel.close":
		var body closeBody
		if m.From == "" && m.To == "" && strictjson.Decode(m.Data, &body) == nil && body.valid(h.opts.Scope) {
			listener.CloseConnection(m.Connection)
		}
	}
}

func boundedAccessUntil(until, now time.Time) time.Time {
	maximum := now.Add(time.Minute)
	if !until.After(now) || until.After(maximum.Add(5*time.Second)) {
		return time.Time{}
	}
	if until.After(maximum) {
		return maximum
	}
	return until
}

func (h *HostManager) offer(m protocol.Message) {
	var offered struct {
		Connect          protocol.Message `json:"connect"`
		VisitorPublicKey string           `json:"visitor_public_key,omitempty"`
		signalBinding
		AccessUntil time.Time `json:"access_until"`
	}
	now := time.Now()
	if m.To != h.opts.DeviceID || m.From == m.To || !tunnelIdentifier.MatchString(m.From) ||
		strictjson.Decode(m.Data, &offered) != nil || !offered.signalBinding.valid() ||
		!endpointMessage(offered.Connect, "tunnel.connect", m.Connection, m.From, m.To) || offered.Connect.Seq != 1 {
		return
	}
	offered.AccessUntil = boundedAccessUntil(offered.AccessUntil, now)
	if offered.AccessUntil.IsZero() {
		return
	}
	h.mu.Lock()
	if h.phase != "listening" || h.ctx.Err() != nil || !now.Before(h.ackedUntil) || h.bindingLocked() != offered.signalBinding {
		h.mu.Unlock()
		return
	}
	hostname, proof, leaseUntil, revision, lifetime := h.status.Hostname, h.lease, h.leaseUntil, h.revision, h.ctx
	h.mu.Unlock()
	if h.opts.Channel != "self" && (proof.Lease == "" || !now.Add(2*time.Second).Before(leaseUntil)) {
		refreshCtx, cancel := context.WithTimeout(lifetime, 2*time.Second)
		refreshed, err := h.localLease(refreshCtx)
		cancel()
		if err == nil {
			proof = refreshed
		}
	}
	now = time.Now()
	remote, local, ok := h.offerIdentities(offered.Connect, offered.VisitorPublicKey, proof, now)
	var connect connectBody
	if !ok {
		// If our own local lease was missing/expired on an official channel, check
		// whether this was a genuine signed visitor offer so we fail fast instead of
		// making the visitor wait 5s for a permit timeout.
		if h.opts.Channel != "self" && offered.VisitorPublicKey == "" {
			if r, err := identity.VerifyCertificate(offered.Connect.Certificate, h.opts.CA, now); err == nil &&
				r.DeviceID == offered.Connect.From && r.Expires.After(now) &&
				readSigned(offered.Connect, r.PublicKey, &connect) && connect.valid(h.opts.Scope) &&
				connect.ExpectedOwner == h.opts.OwnerID && connect.TargetPinHash == KeyHash(h.pub) &&
				tunnelIdentifier.MatchString(connect.ClientNonce) {
				h.denyOffer(m)
			}
		}
		return
	}
	if !readSigned(offered.Connect, remote.PublicKey, &connect) || !connect.valid(h.opts.Scope) ||
		connect.ExpectedOwner != h.opts.OwnerID || connect.TargetPinHash != KeyHash(h.pub) ||
		!tunnelIdentifier.MatchString(connect.ClientNonce) {
		return
	}
	role := connect.Role
	if role == "" {
		role = "mobile"
	}
	if !validRole(role) || connect.PairProof != "" || !validPresentedLease(h.opts.CA, offered.Connect.Certificate, connect.Lease, remote, now) {
		h.denyOffer(m)
		return
	}
	decision, err := h.opts.AuthorizeOffer(OfferRequest{ConnectionID: m.Connection, Principal: remote, Role: role})
	if err != nil || decision.UserID == "" || decision.Allows == nil || !decision.Allows() {
		h.denyOffer(m)
		return
	}
	expires := offered.AccessUntil
	if short := now.Add(15 * time.Second); short.Before(expires) {
		expires = short
	}
	permit := Permit{ConnectionContext: ConnectionContext{
		Channel: h.opts.Channel, Scope: h.opts.Scope, ConnectionID: m.Connection, Hostname: hostname,
		Generation: offered.Generation, Incarnation: offered.Incarnation, RuntimeID: offered.RuntimeID, JTI: protocol.NewID(),
		HostDeviceID: h.opts.DeviceID, HostKeyHash: KeyHash(h.pub), VisitorDeviceID: remote.DeviceID,
		VisitorKeyHash: KeyHash(remote.PublicKey), VisitorRole: role,
	}, VisitorPublicKey: remote.PublicKey, UserID: decision.UserID, ExpiresAt: expires, AccessUntil: offered.AccessUntil,
		Allows: decision.Allows, CA: h.opts.CA, LocalPrincipal: local, RemotePrincipal: remote, LocalLeaseProvider: h.localLease}
	h.mu.Lock()
	if h.phase != "listening" || h.ctx.Err() != nil || h.revision != revision || h.bindingLocked() != offered.signalBinding {
		h.mu.Unlock()
		h.denyOffer(m)
		return
	}
	err = h.listener.RegisterPermit(permit)
	h.mu.Unlock()
	if err != nil {
		h.denyOffer(m)
		return
	}
	msg := protocol.Message{Type: "tunnel.permit", Connection: m.Connection, From: m.To, To: m.From, Seq: 1}
	body := permitBody{signalDomain{tunnelAudience, h.opts.Scope}, offered.signalBinding, hostname, permit.JTI,
		connect.ClientNonce, permit.VisitorKeyHash, tunnelPath, expires.UTC(), ""}
	if msg.Sign(h.opts.PrivateKey, protocol.Encode(body)) != nil || h.sendMessage(msg) != nil {
		h.listener.CloseConnection(m.Connection)
	}
}

func (h *HostManager) offerIdentities(connect protocol.Message, visitorKey string, proof endpoint.LeaseProof, now time.Time) (identity.Principal, identity.Principal, bool) {
	if h.opts.Channel == "self" {
		pub, err := base64.RawURLEncoding.Strict().DecodeString(visitorKey)
		device, keyErr := identity.SelfDeviceID(ed25519.PublicKey(pub))
		return identity.Principal{DeviceID: device, Subject: device, PublicKey: pub}, identity.Principal{},
			err == nil && keyErr == nil && device == connect.From && connect.Certificate == ""
	}
	local, err := identity.VerifyCertificate(proof.Certificate, h.opts.CA, now)
	if err != nil || local.DeviceID != h.opts.DeviceID || local.RemoteUserID() != h.opts.OwnerID ||
		!local.PublicKey.Equal(h.pub) || !validPresentedLease(h.opts.CA, proof.Certificate, proof.Lease, local, now) || proof.Lease == "" {
		return identity.Principal{}, identity.Principal{}, false
	}
	remote, err := identity.VerifyCertificate(connect.Certificate, h.opts.CA, now)
	return remote, local, err == nil && remote.DeviceID == connect.From && remote.Issuer == local.Issuer &&
		remote.Expires.After(now) && visitorKey == ""
}

func validPresentedLease(ca ed25519.PublicKey, cert, lease string, principal identity.Principal, now time.Time) bool {
	if lease == "" {
		return true
	}
	if cert == "" || len(ca) != ed25519.PublicKeySize {
		return false
	}
	expires, err := identity.VerifyEndpointLease(lease, ca, now, cert, principal)
	return err == nil && expires.After(now)
}

func (h *HostManager) denyOffer(m protocol.Message) {
	msg := protocol.Message{Type: "tunnel.close", From: h.opts.DeviceID, To: m.From, Connection: m.Connection, Seq: 1}
	if msg.Sign(h.opts.PrivateKey, protocol.Encode(closeBody{signalDomain: signalDomain{tunnelAudience, h.opts.Scope}, Reason: "access_denied"})) == nil {
		_ = h.sendMessage(msg)
	}
}

func (h *HostManager) Disconnect(ctx context.Context) error { return h.manage(ctx, "disconnect") }
func (h *HostManager) Release(ctx context.Context) error    { return h.manage(ctx, "release") }
func (h *HostManager) Deprovision(ctx context.Context) error {
	return h.manage(ctx, "deprovision")
}
func (h *HostManager) Resume(ctx context.Context) error { return h.manage(ctx, "resume") }

func (h *HostManager) manage(ctx context.Context, action string) error {
	h.manageMu.Lock()
	defer h.manageMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	lifetime := h.ctx
	if lifetime == nil || h.stopping || lifetime.Err() != nil {
		h.mu.Unlock()
		return ErrTunnelUnavailable
	}
	if action != "resume" {
		h.paused = true
		h.setPhaseLocked("stopping")
		if h.reconcileCancel != nil {
			h.reconcileCancel()
		}
	}
	h.mu.Unlock()
	if action != "resume" {
		h.listener.RevokeAll()
		h.observe()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(lifetime, cancel)()
	h.opMu.Lock()
	defer h.opMu.Unlock()
	if action != "resume" {
		h.stopConnector()
		_, _ = h.announce()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := h.manageLocked(ctx, action)
	if err != nil {
		h.fail(err)
	}
	h.observe()
	return err
}

func (h *HostManager) manageLocked(ctx context.Context, action string) error {
	a, err := h.allocation(ctx)
	if err != nil {
		return err
	}
	if action == "resume" {
		h.mu.Lock()
		if h.stopping || ctx.Err() != nil {
			h.mu.Unlock()
			return context.Canceled
		}
		if h.status.ConnectorReady && a.State == "ready" {
			h.mu.Unlock()
			return nil
		}
		h.paused = true
		h.setPhaseLocked("starting")
		h.revision++
		h.mu.Unlock()
		h.listener.RevokeAll()
		h.stopConnector()
		if err := h.syncPresence(ctx); err != nil {
			return err
		}
	}
	device := h.opts.DeviceID
	for {
		var result MutationResult
		switch action {
		case "resume":
			result, err = h.control.Resume(ctx, device, h.listener.Origin(), h.runtimeID, a.Generation)
		case "disconnect":
			result, err = h.control.Disconnect(ctx, device, a.Generation)
		case "release":
			result, err = h.control.Release(ctx, device, a.Generation)
		case "deprovision":
			result, err = h.control.Deprovision(ctx, device, a.Generation)
		}
		var apiErr *APIError
		conflict := errors.As(err, &apiErr) && apiErr.Code == "operation_in_progress" && apiErr.OperationID != ""
		if err := h.awaitMutation(ctx, result, err); err != nil {
			return err
		}
		a, err = h.allocation(ctx)
		if err != nil {
			return err
		}
		h.setAllocation(a)
		if !conflict {
			break
		}
	}
	if action == "resume" {
		if err := h.syncPresence(ctx); err != nil {
			return err
		}
		h.mu.Lock()
		if h.stopping {
			h.mu.Unlock()
			return context.Canceled
		}
		h.paused = false
		h.mu.Unlock()
		if err := h.startConnector(ctx, a); err != nil {
			select {
			case h.wake <- struct{}{}:
			default:
			}
			return err
		}
	}
	return nil
}

func (h *HostManager) waitAck(ctx context.Context, seq uint64) error {
	for {
		h.mu.Lock()
		if h.ackedSeq >= seq && h.ackedUntil.After(time.Now()) {
			h.mu.Unlock()
			return nil
		}
		ack := h.ack
		h.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ack:
		}
	}
}
