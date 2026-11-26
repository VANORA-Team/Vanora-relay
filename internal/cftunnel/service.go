package cftunnel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ServiceOptions struct {
	Clock            func() time.Time
	Metrics          *Metrics
	Logger           *slog.Logger
	WorkerLease      time.Duration
	PollInterval     time.Duration
	RuntimeChecker   func(ctx context.Context, deviceID, deviceKeyHash, runtimeID string, now time.Time) bool
	Membership       MembershipLookup
	edgeCanaryOrigin string
}

type Service struct {
	cfg              Config
	scope            Scope
	store            Store
	cf               Cloudflare
	crypto           *Crypto
	now              func() time.Time
	metrics          *Metrics
	logger           *slog.Logger
	lease            time.Duration
	poll             time.Duration
	runtimeChecker   func(context.Context, string, string, string, time.Time) bool
	membership       MembershipLookup
	edgeCanaryOrigin string
	workWake         chan struct{}
}

func NewService(cfg Config, scope Scope, store Store, cf Cloudflare, crypto *Crypto, opts ServiceOptions) (*Service, error) {
	if scope.ID == "" || scope.AccountID == "" || scope.ZoneID == "" || normalizeDomain(scope.BaseDomain) != scope.BaseDomain ||
		scope.BaseDomain == "" || !namespacePattern.MatchString(scope.Namespace) || store == nil || cf == nil || crypto == nil {
		return nil, ErrInvalidClaim
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Metrics == nil {
		if gate, ok := cf.(*GatedCloudflare); ok {
			opts.Metrics = gate.metrics
		} else {
			opts.Metrics = new(Metrics)
		}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.WorkerLease <= 0 {
		opts.WorkerLease = 30 * time.Second
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = time.Second
	}
	cfg.Reaper = reaperDefaults(cfg.Reaper)
	return &Service{cfg: cfg, scope: scope, store: store, cf: cf, crypto: crypto, now: opts.Clock,
		metrics: opts.Metrics, logger: opts.Logger, lease: opts.WorkerLease, poll: opts.PollInterval,
		runtimeChecker: opts.RuntimeChecker, membership: opts.Membership, edgeCanaryOrigin: opts.edgeCanaryOrigin,
		workWake: make(chan struct{}, 1)}, nil
}

type DeviceBinding struct {
	DeviceID      string
	OwnerID       string
	DeviceKeyHash string
	OwnerManaged  bool
}

type ManagementRequest struct {
	DeviceBinding
	IfGeneration    int64
	Origin          Origin
	IdempotencyKey  string
	BodyHash        string
	Proof           *ProofUse
	Policy          ClaimPolicy
	RuntimeID       string
	CanRecover      bool
	ProtectPresence bool
	AllowNoop       bool
}

type ConnectorToken struct {
	Generation     int64  `json:"generation"`
	Incarnation    int64  `json:"incarnation"`
	Hostname       string `json:"hostname"`
	TunnelID       string `json:"tunnel_id"`
	ConnectorToken string `json:"connector_token"`
}

func (s *Service) Metrics() *Metrics { return s.metrics }
func (s *Service) ScopeID() string   { return s.scope.ID }

func (s *Service) Status(ctx context.Context, binding DeviceBinding) (Allocation, error) {
	if binding.OwnerManaged && !s.cfg.Channel.ChecksEntitlement() {
		return Allocation{}, ErrDeviceBinding
	}
	if binding.DeviceID == "" || binding.OwnerID == "" || !binding.OwnerManaged && binding.DeviceKeyHash == "" {
		return Allocation{}, ErrInvalidClaim
	}
	a, err := s.store.Get(ctx, AllocationKey{ScopeID: s.scope.ID, DeviceID: binding.DeviceID})
	if err != nil {
		return Allocation{}, err
	}
	if binding.OwnerManaged {
		if a.OwnerID != binding.OwnerID {
			return Allocation{}, ErrNotFound
		}
	} else if a.OwnerID != binding.OwnerID || a.DeviceKeyHash != binding.DeviceKeyHash {
		return Allocation{}, ErrDeviceBinding
	}
	return a, nil
}

func (s *Service) GetOperation(ctx context.Context, binding DeviceBinding, operationID string) (Operation, error) {
	a, err := s.Status(ctx, binding)
	if err != nil {
		return Operation{}, err
	}
	op, err := s.store.GetOperation(ctx, s.scope.ID, operationID)
	if err == nil && op.AllocationID != a.ID {
		return Operation{}, ErrNotFound
	}
	return op, err
}

func (s *Service) Register(ctx context.Context, req ManagementRequest) (Operation, error) {
	return s.claim(ctx, req, OpProvision)
}

func (s *Service) ReconcileOrigin(ctx context.Context, req ManagementRequest) (Operation, error) {
	return s.claim(ctx, req, OpReconcile)
}

func (s *Service) Recover(ctx context.Context, req ManagementRequest) (Operation, error) {
	return s.claim(ctx, req, OpRecover)
}

func (s *Service) Release(ctx context.Context, req ManagementRequest) (Operation, error) {
	return s.claim(ctx, req, OpRelease)
}

func (s *Service) Disconnect(ctx context.Context, req ManagementRequest) (Operation, error) {
	return s.claim(ctx, req, OpDisconnect)
}

func (s *Service) Resume(ctx context.Context, req ManagementRequest) (Operation, error) {
	return s.claim(ctx, req, OpResume)
}

func (s *Service) Deprovision(ctx context.Context, req ManagementRequest) (Operation, error) {
	return s.claim(ctx, req, OpDeprovision)
}

func (s *Service) Repair(ctx context.Context, req ManagementRequest) (Operation, error) {
	return s.claim(ctx, req, OpRepair)
}

func (s *Service) claim(ctx context.Context, req ManagementRequest, kind OperationType) (Operation, error) {
	if req.OwnerManaged && (kind != OpDisconnect && kind != OpDeprovision || !s.cfg.Channel.ChecksEntitlement()) {
		return Operation{}, ErrDeviceBinding
	}
	cmd := ClaimCommand{
		AllocationKey: AllocationKey{ScopeID: s.scope.ID, DeviceID: req.DeviceID},
		OwnerID:       req.OwnerID, DeviceKeyHash: req.DeviceKeyHash, Type: kind, IfGeneration: req.IfGeneration,
		Origin: req.Origin, IdempotencyKey: req.IdempotencyKey, BodyHash: req.BodyHash, Proof: req.Proof,
		Now: s.now(), CanRecover: req.CanRecover, ProtectPresence: req.ProtectPresence, AllowNoop: req.AllowNoop,
	}
	switch kind {
	case OpProvision, OpRecover, OpResume, OpReconcile:
		if s.cfg.Mode == ModeOff || s.cfg.Mode == ModeDrain || req.Policy.OwnerSlots <= 0 {
			return Operation{}, ErrEntitlementDenied
		}
		if req.Origin == "" {
			return Operation{}, ErrInvalidOrigin
		}
	case OpRepair, OpRelease, OpDisconnect, OpDeprovision:
		cmd.Origin = ""
	}
	a, err := s.Status(ctx, req.DeviceBinding)
	if err != nil && !(kind == OpProvision && errors.Is(err, ErrNotFound)) {
		return Operation{}, err
	}
	if req.OwnerManaged {
		cmd.DeviceKeyHash = a.DeviceKeyHash
	}
	switch kind {
	case OpProvision, OpRecover, OpResume, OpReconcile:
		if s.runtimeChecker != nil || req.Proof != nil || s.cfg.Process == ProcessControl {
			if req.RuntimeID == "" {
				return Operation{}, ErrDeviceBinding
			}
			if err := s.checkRuntime(ctx, req.DeviceBinding, a, req.RuntimeID, cmd.Now); err != nil {
				return Operation{}, err
			}
		}
	}
	if !a.BudgetHeld && (kind == OpProvision || kind == OpRecover || kind == OpResume) {
		label, hostname := s.crypto.DeriveHostname(s.scope.ID, req.OwnerID, req.DeviceID, s.scope.BaseDomain)
		cmd.Hostname = hostname
		cmd.TunnelName = s.crypto.DeriveTunnelName(s.scope.Namespace, label, a.Incarnation+1)
	}
	policy := req.Policy
	policy.AccountCap = s.cfg.AccountCap
	op, err := s.store.Claim(ctx, cmd, policy)
	if err == nil && op.ID != "" && op.CompletedAt.IsZero() && s.workWake != nil {
		select {
		case s.workWake <- struct{}{}:
		default:
		}
	}
	return op, err
}

func (s *Service) checkRuntime(ctx context.Context, binding DeviceBinding, a Allocation, runtimeID string, now time.Time) error {
	if s.runtimeChecker != nil {
		if runtimeID == "" || !s.runtimeChecker(ctx, binding.DeviceID, binding.DeviceKeyHash, runtimeID, now) {
			return ErrDeviceBinding
		}
		return nil
	}
	if runtimeID == "" && s.cfg.Process == ProcessControl {
		return ErrDeviceBinding
	}
	if runtimeID == "" || a.ID == "" {
		return nil
	}
	presence, err := s.store.GetPresence(ctx, a.ScopeID, a.ID)
	if errors.Is(err, ErrNotFound) || err == nil &&
		(presence.Generation != a.Generation || presence.RuntimeID != runtimeID || !presence.Active(now)) {
		return ErrDeviceBinding
	}
	return err
}

func (s *Service) IssueConnectorToken(ctx context.Context, req ManagementRequest) (ConnectorToken, error) {
	token, _, err := s.issueConnectorToken(ctx, req)
	return token, err
}

func (s *Service) issueConnectorToken(ctx context.Context, req ManagementRequest) (ConnectorToken, bool, error) {
	var empty ConnectorToken
	if req.OwnerManaged {
		return empty, false, ErrDeviceBinding
	}
	now := s.now()
	if s.cfg.Mode == ModeOff || s.cfg.Mode == ModeDrain || req.Policy.OwnerSlots <= 0 {
		return empty, false, ErrEntitlementDenied
	}
	origin, err := ParseOrigin(string(req.Origin))
	if err != nil {
		return empty, false, err
	}
	if err := s.checkOwnerSlots(ctx, req, now); err != nil {
		return empty, false, err
	}
	a, err := s.Status(ctx, req.DeviceBinding)
	if err != nil {
		return empty, false, err
	}
	if (req.Proof != nil || req.IfGeneration != 0) && req.IfGeneration != a.Generation {
		return empty, false, ErrGenerationConflict
	}
	if a.ManualResumeRequired {
		return empty, false, ErrTunnelSuspended
	}
	if a.State == StateReleased {
		return empty, false, ErrRecoveryRequired
	}
	if a.State != StateReady || a.Origin != origin {
		return empty, false, ErrInvalidTransition
	}
	if err := s.checkRuntime(ctx, req.DeviceBinding, a, req.RuntimeID, now); err != nil {
		return empty, false, err
	}
	if req.Proof != nil {
		if req.Proof.ScopeID != s.scope.ID {
			return empty, false, ErrScopeMismatch
		}
		if err := s.store.ConsumeProof(ctx, *req.Proof, now); err != nil {
			return empty, true, err
		}
	}
	tunnel, err := s.cf.GetTunnel(ctx, a.Resources.TunnelID)
	if cfMissing(tunnel, err) {
		return empty, true, ErrRecoveryRequired
	}
	if err != nil {
		return empty, true, err
	}
	if !matchesAllocationTunnel(a, tunnel) {
		return empty, true, ErrCFConflict
	}
	token, err := s.cf.GetToken(ctx, tunnel.ID)
	if errors.Is(err, ErrCFNotFound) {
		return empty, true, ErrRecoveryRequired
	}
	if err != nil {
		return empty, true, err
	}
	current, err := s.Status(ctx, req.DeviceBinding)
	if err != nil {
		return empty, true, err
	}
	if current.Generation != a.Generation || current.State != StateReady || current.Resources != a.Resources {
		return empty, true, ErrGenerationConflict
	}
	if err := s.checkRuntime(ctx, req.DeviceBinding, current, req.RuntimeID, s.now()); err != nil {
		return empty, true, err
	}
	if err := s.checkOwnerSlots(ctx, req, s.now()); err != nil {
		return empty, true, err
	}
	return ConnectorToken{current.Generation, current.Incarnation, current.Hostname, tunnel.ID, token}, true, nil
}

func (s *Service) checkOwnerSlots(ctx context.Context, req ManagementRequest, now time.Time) error {
	override, err := s.store.GetOwnerOverride(ctx, s.scope.ID, req.OwnerID)
	if err != nil {
		return err
	}
	if ApplyOwnerOverride(req.Policy.OwnerSlots, now, override) <= 0 {
		return ErrEntitlementDenied
	}
	return nil
}

func (s *Service) RecordPresence(ctx context.Context, binding DeviceBinding, p Presence) error {
	return s.recordPresence(ctx, binding, p, 0)
}

const edgeWebSocketPath = "/v1/tunnel/ws"

func (s *Service) PreflightEdgeCanary(ctx context.Context, httpClient *http.Client) error {
	if s.cfg.Mode != ModeManaged || s.cfg.EdgeCanaryHost == "" {
		return nil
	}
	origin := (&url.URL{Scheme: "https", Host: s.cfg.EdgeCanaryHost}).String()
	if s.edgeCanaryOrigin != "" {
		origin = s.edgeCanaryOrigin
	}
	client := http.Client{Timeout: 5 * time.Second}
	if httpClient != nil {
		client.Transport = httpClient.Transport
		if transport, ok := client.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil &&
			transport.TLSClientConfig.InsecureSkipVerify {
			return errors.New("tunnel edge canary requires TLS verification")
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+edgeWebSocketPath, nil)
	if err != nil {
		return fmt.Errorf("tunnel edge canary: %w", err)
	}
	var key [16]byte
	rand.Read(key[:])
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(key[:]))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("tunnel edge canary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return fmt.Errorf("tunnel edge canary returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) PreflightZone(ctx context.Context) error {
	zone, err := s.cf.GetZone(ctx)
	if err != nil {
		return err
	}
	name := normalizeDomain(zone.Name)
	if zone.ID != s.scope.ZoneID || zone.AccountID != s.scope.AccountID || zone.Status != "active" || name == "" ||
		(s.scope.BaseDomain != name && !strings.HasSuffix(s.scope.BaseDomain, "."+name)) {
		return ErrScopeMismatch
	}
	return nil
}

func desiredIngress(hostname string, origin Origin) IngressConfig {
	return IngressConfig{Ingress: []IngressRule{{Hostname: hostname, Service: "http://" + string(origin)}, {Service: "http_status:404"}}}
}

func IngressMatches(cfg IngressConfig, hostname string, origin Origin) bool {
	desired := desiredIngress(hostname, origin).Ingress
	if cfg.WarpRoutingEnabled || len(cfg.Ingress) != len(desired) {
		return false
	}
	return strings.EqualFold(cfg.Ingress[0].Hostname, desired[0].Hostname) &&
		cfg.Ingress[0].Path == "" && cfg.Ingress[0].Service == desired[0].Service && cfg.Ingress[1] == desired[1]
}

func cfMissing(tunnel Tunnel, err error) bool {
	return errors.Is(err, ErrCFNotFound) || err == nil && !tunnel.DeletedAt.IsZero()
}

func matchesAllocationTunnel(a Allocation, tunnel Tunnel) bool {
	return validCFSegment(tunnel.ID) && tunnel.Name == a.TunnelName &&
		(a.Resources.TunnelID == "" || a.Resources.TunnelID == tunnel.ID) && tunnel.ConfigSrc == "cloudflare"
}
