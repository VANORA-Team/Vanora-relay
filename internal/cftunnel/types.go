// Package cftunnel defines the managed named tunnel control-plane contracts.
package cftunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type AllocationState string

const (
	StatePending        AllocationState = "pending"
	StateReady          AllocationState = "ready"
	StateReconciling    AllocationState = "reconciling"
	StateReleasing      AllocationState = "releasing"
	StateReleased       AllocationState = "released"
	StateDisconnecting  AllocationState = "disconnecting"
	StateSuspended      AllocationState = "suspended"
	StateDeprovisioning AllocationState = "deprovisioning"
	StateDisabled       AllocationState = "disabled"
	StateQuarantined    AllocationState = "quarantined"
)

type OperationType string

const (
	OpProvision   OperationType = "provision"
	OpReconcile   OperationType = "reconcile"
	OpRepair      OperationType = "repair"
	OpRelease     OperationType = "release"
	OpRecover     OperationType = "recover"
	OpDisconnect  OperationType = "disconnect"
	OpDeprovision OperationType = "deprovision"
	OpResume      OperationType = "resume"
)

// Origin is a canonical loopback endpoint, serialized as host:port.
type Origin string

// ParseOrigin accepts exactly 127.0.0.1, ::1 in brackets, or localhost.
func ParseOrigin(raw string) (Origin, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil || len(port) == 0 || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
		return "", ErrInvalidOrigin
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", ErrInvalidOrigin
	}
	switch {
	case (host == "localhost" || host == "127.0.0.1") && raw[0] != '[':
		host = "127.0.0.1"
	case host == "::1" && raw[0] == '[':
	default:
		return "", ErrInvalidOrigin
	}
	return Origin(net.JoinHostPort(host, strconv.Itoa(number))), nil
}

func (o Origin) String() string { return string(o) }

// AllocationKey is the stable device key within a scope. Owner and device
// public key bindings are additionally checked on every claim.
type AllocationKey struct {
	ScopeID  string
	DeviceID string
}

// Scope binds a store partition to one site, Cloudflare account and namespace.
// UnmanagedCount reserves Cloudflare capacity for external tunnels.
type Scope struct {
	ID                string
	Channel           string
	CAPublicKeySHA256 string
	AllowedIssuer     string
	MembershipOrigin  string
	ControlOrigin     string
	AccountID         string
	ZoneID            string
	BaseDomain        string
	Namespace         string
	MasterKeySHA256   string
	UnmanagedCount    int
}

type Owner struct {
	ScopeID  string
	ID       string
	Override *OwnerOverride
}

// Resources are Cloudflare identifiers that can be checkpointed by a worker.
type Resources struct {
	TunnelID    string
	DNSRecordID string
}

// Allocation persists both the generation fencing client changes and the
// incarnation identifying a particular Cloudflare tunnel lifetime.
type Allocation struct {
	AllocationKey
	ID                   string
	OwnerID              string
	DeviceKeyHash        string
	Generation           int64
	Incarnation          int64
	State                AllocationState
	Origin               Origin
	Hostname             string
	TunnelName           string
	Resources            Resources
	BudgetHeld           bool
	ManualResumeRequired bool
	Observation          CloudflareObservation
	ReadyAt              time.Time
	RecoveryEnabledAt    time.Time
	ReleasedAt           time.Time
	CFStatus             TunnelStatus
	CFStatusSince        time.Time
	UpdatedAt            time.Time
}

// Presence is the last device observation for one allocation generation.
type Presence struct {
	ScopeID      string
	AllocationID string
	Generation   int64
	SeenAt       time.Time
	ExpiresAt    time.Time
	SocketID     string
	RuntimeID    string
	Phase        PresencePhase
	CanRecover   bool
	Seq          int64
}

type PresencePhase string

const (
	PresenceStarting  PresencePhase = "starting"
	PresenceListening PresencePhase = "listening"
	PresenceStopping  PresencePhase = "stopping"
)

func (p Presence) Active(now time.Time) bool {
	return p.ExpiresAt.After(now) && (p.Phase == PresenceStarting || p.Phase == PresenceListening)
}

// Operation is a durable unit of work. An open operation can be leased again
// after LeaseUntil. WorkerEpoch increases whenever a new lease is acquired.
type Operation struct {
	ID                   string
	ScopeID              string
	AllocationID         string
	Type                 OperationType
	Generation           int64
	WorkerID             string
	WorkerEpoch          int64
	LeaseUntil           time.Time
	CreatedAt            time.Time
	CompletedAt          time.Time
	NextAttemptAt        time.Time
	Attempts             int
	ErrorCode            ErrorCode
	PreviousState        AllocationState
	PreviousManualResume bool
	ProtectPresence      bool
	CanRecover           bool
}

func (o Operation) Fence() Fence {
	return Fence{o.ScopeID, o.AllocationID, o.ID, o.Generation, o.WorkerEpoch}
}

// Fence authorizes a worker write only during its current lease.
type Fence struct {
	ScopeID      string
	AllocationID string
	OperationID  string
	Generation   int64
	WorkerEpoch  int64
}

// Step records a named side effect. A completed step can be read back after
// retries. An unfinished step may be retried by the next lease holder.
type Step struct {
	OperationID string
	Name        string
	WorkerEpoch int64
	StartedAt   time.Time
	FinishedAt  time.Time
	Result      string
	Retry       bool
}

// FinishStepCommand can checkpoint Cloudflare resources and close the
// operation in the same transaction as the completed step.
type FinishStepCommand struct {
	Fence
	Name       string
	Result     string
	Resources  *Resources
	FinalState AllocationState
	ErrorCode  ErrorCode
	Now        time.Time
}

// IdempotencyRecord binds an owner-scoped request key to its original body
// digest and operation, including after the allocation advances.
type IdempotencyRecord struct {
	ScopeID     string
	OwnerID     string
	Key         string
	BodyHash    string
	OperationID string
	ExpiresAt   time.Time
}

// ProofUse tracks a successfully consumed challenge nonce per scope.
type ProofUse struct {
	ScopeID   string
	Nonce     string
	ExpiresAt time.Time
}

type ScanCursor struct {
	ScopeID   string
	Kind      string
	Cursor    string
	UpdatedAt time.Time
	Cycle     int64
}

// Orphan is a discovered, marked Cloudflare resource. The grace window is
// measured from its first observation, even across repeated scans.
type Orphan struct {
	ScopeID       string
	Kind          string
	ResourceID    string
	Marker        string
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	NextAttemptAt time.Time
	ResolvedAt    time.Time
	SeenCycles    int
	LastCycle     int64
}

// ClaimCommand contains authenticated owner, device and request bindings.
// IfGeneration is zero only when the caller expects no allocation to exist.
// Hostname and TunnelName are server-derived on every new incarnation.
// Now is the server's time at the start of the request.
type ClaimCommand struct {
	AllocationKey
	OwnerID         string
	DeviceKeyHash   string
	Type            OperationType
	IfGeneration    int64
	Origin          Origin
	Hostname        string
	TunnelName      string
	IdempotencyKey  string
	BodyHash        string
	IdempotencyTTL  time.Duration
	Proof           *ProofUse
	ProtectPresence bool
	CanRecover      bool
	AllowNoop       bool
	Now             time.Time
}

// ClaimPolicy carries the caller's freshly authorized limits for new slot
// occupancy. The caller authorizes all mutations before invoking Claim.
// Zero owner slots still allows cleanup of existing resources.
type ClaimPolicy struct {
	OwnerSlots int
	AccountCap int
}

type SlotCounts struct {
	OwnerHeld      int
	ScopeHeld      int
	UnmanagedCount int
}

type ReapCandidate struct {
	Allocation Allocation
	Presence   *Presence
}

// CloudflareObservation is tied to the allocation generation at scan time.
type CloudflareObservation struct {
	Generation   int64
	ObservedAt   time.Time
	TunnelExists bool
	DNSExists    bool
	Status       TunnelStatus
	StatusSince  time.Time
}

// Store coordinates atomic claims, leases, and reconciliation observations.
type Store interface {
	Close() error
	EnsureScope(context.Context, Scope) error
	Claim(context.Context, ClaimCommand, ClaimPolicy) (Operation, error)
	Get(context.Context, AllocationKey) (Allocation, error)
	GetByAllocationID(ctx context.Context, scopeID, allocationID string) (Allocation, error)
	GetByTunnelName(ctx context.Context, scopeID, tunnelName string) (Allocation, error)
	GetByTunnelID(ctx context.Context, scopeID, tunnelID string) (Allocation, error)
	UpdateUnmanagedCount(ctx context.Context, scopeID string, count int) error
	GetOperation(ctx context.Context, scopeID, operationID string) (Operation, error)
	AcquireWork(ctx context.Context, scopeID, workerID string, now time.Time, lease time.Duration) (Operation, error)
	RenewWork(context.Context, Fence, time.Time, time.Duration) error
	ReleaseWork(ctx context.Context, fence Fence, now, nextAttemptAt time.Time, code ErrorCode) error
	BeginStep(context.Context, Fence, string, time.Time) (Step, error)
	GetStep(ctx context.Context, operationID, name string) (Step, error)
	DiscardStep(context.Context, Fence, string, time.Time) error
	FinishStep(context.Context, FinishStepCommand) error
	SetPresence(context.Context, Presence) error
	GetPresence(ctx context.Context, scopeID, allocationID string) (Presence, error)
	MarkRecoveryEnabled(ctx context.Context, key AllocationKey, generation int64, now time.Time) error
	ConsumeProof(context.Context, ProofUse, time.Time) error
	LoadPause(ctx context.Context, scopeID, bucket string) (time.Time, error)
	ExtendPause(ctx context.Context, scopeID, bucket string, until time.Time) error
	ListReapCandidates(ctx context.Context, scopeID, afterID string, limit int) ([]ReapCandidate, error)
	ExpirePending(ctx context.Context, key AllocationKey, generation int64, now, staleBefore time.Time, dryRun bool) (bool, error)
	UpdateCloudflareObservation(ctx context.Context, scopeID, allocationID string, observation CloudflareObservation) error
	UpsertOrphan(context.Context, Orphan) error
	GetOrphan(ctx context.Context, scopeID, kind, resourceID string) (Orphan, error)
	ListDueOrphans(ctx context.Context, scopeID string, now time.Time, limit int) ([]Orphan, error)
	ListDueOrphansAfter(ctx context.Context, scopeID string, now time.Time, cycle int64, afterKind, afterID string, limit int) ([]Orphan, error)
	ResolveOrphan(ctx context.Context, scopeID, kind, resourceID string, seenAt, now time.Time) error
	LoadScan(ctx context.Context, scopeID, kind string) (ScanCursor, error)
	SaveScan(ctx context.Context, cursor ScanCursor, previousUpdate time.Time) error
	SetOwnerOverride(ctx context.Context, scopeID, ownerID string, override *OwnerOverride) error
	GetOwnerOverride(ctx context.Context, scopeID, ownerID string) (*OwnerOverride, error)
	PruneExpired(ctx context.Context, scopeID string, now time.Time) error
	CountSlots(ctx context.Context, scopeID, ownerID string) (SlotCounts, error)
}

// Tunnel and DNSRecord carry the identifiers needed for ownership verification
// before Cloudflare objects are adopted, updated or deleted.
type Tunnel struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	Status          TunnelStatus `json:"status"`
	CreatedAt       time.Time    `json:"created_at"`
	ConnsInactiveAt time.Time    `json:"conns_inactive_at"`
	DeletedAt       time.Time    `json:"deleted_at"`
	ConfigSrc       string       `json:"config_src"`
}

type TunnelStatus string

const (
	TunnelInactive TunnelStatus = "inactive"
	TunnelDown     TunnelStatus = "down"
	TunnelHealthy  TunnelStatus = "healthy"
	TunnelDegraded TunnelStatus = "degraded"
)

type TunnelListQuery struct {
	Name          string
	IncludePrefix string
	Status        TunnelStatus
	Page          int
	PerPage       int
}

type TunnelListPage struct {
	Tunnels    []Tunnel
	TotalCount int
	TotalPages int
}

type DNSListPage struct {
	Records    []DNSRecord
	TotalPages int
}

type IngressRule struct {
	Hostname string `json:"hostname,omitempty"`
	Path     string `json:"path,omitempty"`
	Service  string `json:"service"`
}

type IngressConfig struct {
	Ingress            []IngressRule
	WarpRoutingEnabled bool
	Version            int
}

type Connection struct {
	ID                 string `json:"id"`
	IsPendingReconnect bool   `json:"is_pending_reconnect"`
}

type Zone struct {
	ID        string
	Name      string
	Status    string
	AccountID string
}

type DNSRecord struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type"`
	Hostname string `json:"name"`
	Target   string `json:"content"`
	Comment  string `json:"comment"`
	TTL      int    `json:"ttl"`
	Proxied  bool   `json:"proxied"`
}

// Cloudflare is a client bound to the configured account and zone. Its
// mutation methods are called by leased workers or verified orphan cleanup.
type Cloudflare interface {
	CreateTunnel(context.Context, string, []byte) (Tunnel, error)
	GetTunnel(context.Context, string) (Tunnel, error)
	ListTunnels(context.Context, TunnelListQuery) (TunnelListPage, error)
	GetConfiguration(context.Context, string) (IngressConfig, error)
	PutConfiguration(context.Context, string, IngressConfig) error
	RotateSecret(context.Context, string, []byte) error
	GetToken(context.Context, string) (string, error)
	ListConnections(context.Context, string) ([]Connection, error)
	DisconnectAll(context.Context, string) error
	DeleteTunnel(context.Context, string) error
	GetZone(context.Context) (Zone, error)
	ListDNSRecords(ctx context.Context, exactHostname string) ([]DNSRecord, error)
	ListMarkedDNSRecords(ctx context.Context, page, perPage int) (DNSListPage, error)
	CreateDNSRecord(context.Context, DNSRecord) (DNSRecord, error)
	PatchDNSRecord(context.Context, DNSRecord) (DNSRecord, error)
	DeleteDNSRecord(context.Context, string) error
}

type ErrorCode string

func (c ErrorCode) Error() string { return string(c) }

type OperationInProgressError struct{ OperationID string }

func (e OperationInProgressError) Error() string { return CodeOperationInProgress.Error() }
func (e OperationInProgressError) Unwrap() error { return ErrOperationInProgress }

const (
	CodeInvalidOrigin       ErrorCode = "invalid_origin"
	CodeInvalidClaim        ErrorCode = "invalid_claim"
	CodeGenerationConflict  ErrorCode = "generation_conflict"
	CodeOperationInProgress ErrorCode = "operation_in_progress"
	CodeIdempotencyConflict ErrorCode = "idempotency_conflict"
	CodeReplayDetected      ErrorCode = "replay_detected"
	CodeOwnerQuotaExhausted ErrorCode = "owner_quota_exhausted"
	CodeAccountCapacity     ErrorCode = "account_capacity"
	CodeTunnelSuspended     ErrorCode = "tunnel_suspended"
	CodeRecoveryRequired    ErrorCode = "recovery_required"
	CodeNotFound            ErrorCode = "not_found"
	CodeScopeMismatch       ErrorCode = "scope_mismatch"
	CodeFenceLost           ErrorCode = "fence_lost"
	CodeDeviceBinding       ErrorCode = "device_binding_mismatch"
	CodeEntitlementDenied   ErrorCode = "entitlement_denied"
	CodeInvalidTransition   ErrorCode = "invalid_transition"
	CodeInvalidProof        ErrorCode = "invalid_proof"
	CodeDNSConflict         ErrorCode = "dns_conflict"
	CodePresenceActive      ErrorCode = "presence_active"
	CodePendingExpired      ErrorCode = "pending_expired"
	CodeInternal            ErrorCode = "internal"
)

var (
	ErrInvalidOrigin       error = CodeInvalidOrigin
	ErrInvalidClaim        error = CodeInvalidClaim
	ErrGenerationConflict  error = CodeGenerationConflict
	ErrOperationInProgress error = CodeOperationInProgress
	ErrIdempotencyConflict error = CodeIdempotencyConflict
	ErrReplayDetected      error = CodeReplayDetected
	ErrOwnerQuotaExhausted error = CodeOwnerQuotaExhausted
	ErrAccountCapacity     error = CodeAccountCapacity
	ErrTunnelSuspended     error = CodeTunnelSuspended
	ErrRecoveryRequired    error = CodeRecoveryRequired
	ErrNotFound            error = CodeNotFound
	ErrScopeMismatch       error = CodeScopeMismatch
	ErrFenceLost           error = CodeFenceLost
	ErrDeviceBinding       error = CodeDeviceBinding
	ErrEntitlementDenied   error = CodeEntitlementDenied
	ErrInvalidTransition   error = CodeInvalidTransition
	ErrInvalidProof        error = CodeInvalidProof
	ErrDNSConflict         error = CodeDNSConflict
	ErrPresenceActive      error = CodePresenceActive
)

// CodeOf maps wrapped domain errors to stable protocol values.
func CodeOf(err error) ErrorCode {
	if err == nil {
		return ""
	}
	var code ErrorCode
	if errors.As(err, &code) {
		return code
	}
	return CodeInternal
}

func validateLimit(label string, value, lower, upper int) error {
	if value < lower || value > upper {
		return fmt.Errorf("%s must be between %d and %d", label, lower, upper)
	}
	return nil
}
