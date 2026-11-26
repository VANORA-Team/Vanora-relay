CREATE TABLE cf_scope (
    id TEXT NOT NULL PRIMARY KEY CHECK (id <> ''),
    channel TEXT NOT NULL CHECK (channel IN ('cn', 'global', 'self')),
    ca_public_key_sha256 TEXT NOT NULL,
    allowed_issuer TEXT NOT NULL,
    membership_origin TEXT NOT NULL,
    control_origin TEXT NOT NULL CHECK (control_origin <> ''),
    account_id TEXT NOT NULL CHECK (account_id <> ''),
    zone_id TEXT NOT NULL CHECK (zone_id <> ''),
    base_domain TEXT NOT NULL CHECK (base_domain <> ''),
    namespace TEXT NOT NULL CHECK (namespace <> ''),
    master_key_sha256 TEXT NOT NULL CHECK (master_key_sha256 <> ''),
    unmanaged_count INTEGER NOT NULL CHECK (unmanaged_count >= 0),
    CHECK (
        (channel = 'self' AND ca_public_key_sha256 = '' AND allowed_issuer = '' AND membership_origin = '')
        OR (channel <> 'self' AND ca_public_key_sha256 <> '' AND allowed_issuer <> '' AND membership_origin <> '')
    ),
    UNIQUE (account_id, namespace)
);

CREATE TABLE cf_owner (
    scope_id TEXT NOT NULL REFERENCES cf_scope (id),
    id TEXT NOT NULL CHECK (id <> ''),
    override_slots INTEGER CHECK (override_slots BETWEEN 0 AND 10000),
    override_expires_at BIGINT CHECK (override_expires_at >= 0),
    CHECK ((override_slots IS NULL) = (override_expires_at IS NULL)),
    PRIMARY KEY (scope_id, id)
);

CREATE TABLE cf_allocation (
    scope_id TEXT NOT NULL,
    id TEXT NOT NULL CHECK (id <> ''),
    device_id TEXT NOT NULL CHECK (device_id <> ''),
    owner_id TEXT NOT NULL,
    device_key_hash TEXT NOT NULL CHECK (device_key_hash <> ''),
    generation BIGINT NOT NULL CHECK (generation >= 1),
    incarnation BIGINT NOT NULL CHECK (incarnation BETWEEN 1 AND generation),
    state TEXT NOT NULL CHECK (state IN (
        'pending', 'ready', 'reconciling', 'releasing', 'released',
        'disconnecting', 'suspended', 'deprovisioning', 'disabled', 'quarantined'
    )),
    origin TEXT NOT NULL,
    hostname TEXT NOT NULL,
    tunnel_name TEXT NOT NULL,
    tunnel_id TEXT NOT NULL,
    dns_record_id TEXT NOT NULL,
    budget_held INTEGER NOT NULL CHECK (budget_held IN (0, 1)),
    manual_resume_required INTEGER NOT NULL CHECK (manual_resume_required IN (0, 1)),
    observed_at BIGINT NOT NULL DEFAULT 0 CHECK (observed_at >= 0),
    tunnel_exists INTEGER NOT NULL DEFAULT 0 CHECK (tunnel_exists IN (0, 1)),
    dns_exists INTEGER NOT NULL DEFAULT 0 CHECK (dns_exists IN (0, 1)),
    ready_at BIGINT NOT NULL DEFAULT 0 CHECK (ready_at >= 0),
    recovery_enabled_at BIGINT NOT NULL DEFAULT 0 CHECK (recovery_enabled_at >= 0),
    released_at BIGINT NOT NULL DEFAULT 0 CHECK (released_at >= 0),
    cf_status TEXT NOT NULL DEFAULT '' CHECK (cf_status IN ('', 'inactive', 'down', 'healthy', 'degraded')),
    cf_status_since BIGINT NOT NULL DEFAULT 0 CHECK (cf_status_since >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at > 0),
    PRIMARY KEY (scope_id, id),
    UNIQUE (scope_id, device_id),
    FOREIGN KEY (scope_id, owner_id) REFERENCES cf_owner (scope_id, id),
    CHECK ((state IN ('released', 'disabled')) = (budget_held = 0)),
    CHECK (state NOT IN ('disconnecting', 'suspended') OR manual_resume_required = 1),
    CONSTRAINT cf_allocation_manual_gate CHECK (state NOT IN ('pending', 'ready', 'reconciling') OR manual_resume_required = 0),
    CHECK (budget_held = 0 OR (origin <> '' AND hostname <> '' AND tunnel_name <> '')),
    CHECK (budget_held = 1 OR (
        origin = '' AND hostname = '' AND tunnel_name = '' AND tunnel_id = '' AND dns_record_id = ''
        AND observed_at = 0
    )),
    CHECK (state <> 'ready' OR (tunnel_id <> '' AND dns_record_id <> '')),
    CHECK (dns_record_id = '' OR tunnel_id <> ''),
    CHECK (observed_at <> 0 OR (tunnel_exists = 0 AND dns_exists = 0))
);

CREATE UNIQUE INDEX cf_allocation_hostname ON cf_allocation (scope_id, hostname) WHERE hostname <> '';
CREATE UNIQUE INDEX cf_allocation_tunnel ON cf_allocation (scope_id, tunnel_id) WHERE tunnel_id <> '';
CREATE UNIQUE INDEX cf_allocation_tunnel_name ON cf_allocation (scope_id, tunnel_name) WHERE tunnel_name <> '';
CREATE UNIQUE INDEX cf_allocation_dns ON cf_allocation (scope_id, dns_record_id) WHERE dns_record_id <> '';
CREATE INDEX cf_allocation_slots ON cf_allocation (scope_id, owner_id) WHERE budget_held = 1;
CREATE INDEX cf_allocation_reap ON cf_allocation (scope_id, id) WHERE budget_held = 1;

CREATE TABLE cf_presence (
    scope_id TEXT NOT NULL,
    allocation_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    seen_at BIGINT NOT NULL CHECK (seen_at > 0),
    expires_at BIGINT NOT NULL CHECK (expires_at > seen_at),
    socket_id TEXT NOT NULL DEFAULT '',
    runtime_id TEXT NOT NULL DEFAULT '',
    phase TEXT NOT NULL DEFAULT 'starting' CHECK (phase IN ('starting', 'listening', 'stopping')),
    can_recover INTEGER NOT NULL DEFAULT 0 CHECK (can_recover IN (0, 1)),
    seq BIGINT NOT NULL DEFAULT 0 CHECK (seq >= 0),
    PRIMARY KEY (scope_id, allocation_id),
    FOREIGN KEY (scope_id, allocation_id) REFERENCES cf_allocation (scope_id, id)
);

CREATE INDEX cf_presence_expiry ON cf_presence (scope_id, expires_at);

CREATE TABLE cf_operation (
    id TEXT NOT NULL PRIMARY KEY CHECK (id <> ''),
    scope_id TEXT NOT NULL,
    allocation_id TEXT NOT NULL,
    operation_type TEXT NOT NULL CHECK (operation_type IN (
        'provision', 'reconcile', 'repair', 'release', 'recover', 'disconnect', 'deprovision', 'resume'
    )),
    generation BIGINT NOT NULL CHECK (generation > 0),
    worker_id TEXT NOT NULL DEFAULT '',
    worker_epoch BIGINT NOT NULL DEFAULT 0 CHECK (worker_epoch >= 0),
    lease_until BIGINT NOT NULL DEFAULT 0 CHECK (lease_until >= 0),
    created_at BIGINT NOT NULL CHECK (created_at > 0),
    completed_at BIGINT NOT NULL DEFAULT 0 CHECK (completed_at = 0 OR completed_at >= created_at),
    next_attempt_at BIGINT NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    error_code TEXT NOT NULL DEFAULT '',
    previous_state TEXT NOT NULL DEFAULT '',
    previous_manual_resume INTEGER NOT NULL DEFAULT 0 CHECK (previous_manual_resume IN (0, 1)),
    protect_presence INTEGER NOT NULL DEFAULT 0 CHECK (protect_presence IN (0, 1)),
    can_recover INTEGER NOT NULL DEFAULT 0 CHECK (can_recover IN (0, 1)),
    FOREIGN KEY (scope_id, allocation_id) REFERENCES cf_allocation (scope_id, id),
    UNIQUE (scope_id, id),
    UNIQUE (scope_id, allocation_id, generation),
    CHECK ((worker_epoch = 0) = (worker_id = '')),
    CONSTRAINT cf_operation_lease_gate CHECK (lease_until = 0 OR (worker_epoch > 0 AND completed_at = 0))
);

CREATE UNIQUE INDEX cf_one_open_operation ON cf_operation (scope_id, allocation_id) WHERE completed_at = 0;
CREATE INDEX cf_operation_work ON cf_operation (scope_id, lease_until, next_attempt_at, created_at, id) WHERE completed_at = 0;
CREATE INDEX cf_operation_expiry ON cf_operation (scope_id, completed_at) WHERE completed_at <> 0;

CREATE TABLE cf_step (
    operation_id TEXT NOT NULL REFERENCES cf_operation (id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (name <> ''),
    worker_epoch BIGINT NOT NULL CHECK (worker_epoch > 0),
    started_at BIGINT NOT NULL CHECK (started_at > 0),
    finished_at BIGINT NOT NULL DEFAULT 0 CHECK (finished_at = 0 OR finished_at >= started_at),
    result TEXT NOT NULL DEFAULT '',
    CHECK (finished_at <> 0 OR result = ''),
    PRIMARY KEY (operation_id, name)
);

CREATE TABLE cf_idempotency (
    scope_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    request_key TEXT NOT NULL CHECK (request_key <> ''),
    body_hash TEXT NOT NULL CHECK (body_hash <> ''),
    operation_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL CHECK (expires_at > 0),
    PRIMARY KEY (scope_id, owner_id, request_key),
    FOREIGN KEY (scope_id, owner_id) REFERENCES cf_owner (scope_id, id),
    FOREIGN KEY (scope_id, operation_id) REFERENCES cf_operation (scope_id, id)
);

CREATE INDEX cf_idempotency_expiry ON cf_idempotency (scope_id, expires_at);
CREATE INDEX cf_idempotency_operation ON cf_idempotency (scope_id, operation_id);

CREATE TABLE cf_proof_use (
    scope_id TEXT NOT NULL REFERENCES cf_scope (id),
    nonce TEXT NOT NULL CHECK (nonce <> ''),
    expires_at BIGINT NOT NULL CHECK (expires_at > 0),
    PRIMARY KEY (scope_id, nonce)
);

CREATE INDEX cf_proof_expiry ON cf_proof_use (scope_id, expires_at);

CREATE TABLE cf_api_pause (
    scope_id TEXT NOT NULL REFERENCES cf_scope (id),
    bucket TEXT NOT NULL CHECK (bucket <> ''),
    until_at BIGINT NOT NULL CHECK (until_at > 0),
    PRIMARY KEY (scope_id, bucket)
);

CREATE TABLE cf_scan (
    scope_id TEXT NOT NULL REFERENCES cf_scope (id),
    kind TEXT NOT NULL CHECK (kind <> ''),
    cursor_value TEXT NOT NULL,
    updated_at BIGINT NOT NULL CHECK (updated_at > 0),
    cycle BIGINT NOT NULL DEFAULT 0 CHECK (cycle >= 0),
    PRIMARY KEY (scope_id, kind)
);

CREATE TABLE cf_orphan (
    scope_id TEXT NOT NULL REFERENCES cf_scope (id),
    kind TEXT NOT NULL CHECK (kind <> ''),
    resource_id TEXT NOT NULL CHECK (resource_id <> ''),
    marker TEXT NOT NULL CHECK (marker <> ''),
    first_seen_at BIGINT NOT NULL CHECK (first_seen_at > 0),
    last_seen_at BIGINT NOT NULL CHECK (last_seen_at >= first_seen_at),
    next_attempt_at BIGINT NOT NULL CHECK (next_attempt_at >= first_seen_at),
    resolved_at BIGINT NOT NULL DEFAULT 0 CHECK (resolved_at = 0 OR resolved_at >= last_seen_at),
    seen_cycles INTEGER NOT NULL DEFAULT 1 CHECK (seen_cycles >= 1),
    last_cycle BIGINT NOT NULL DEFAULT 0 CHECK (last_cycle >= 0),
    PRIMARY KEY (scope_id, kind, resource_id)
);

CREATE INDEX cf_orphan_due ON cf_orphan (scope_id, next_attempt_at, kind, resource_id) WHERE resolved_at = 0;
