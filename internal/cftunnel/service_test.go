package cftunnel_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"vanora-relay/internal/cftunnel"
	"vanora-relay/internal/cftunnel/sqlstore"
)

type mockCloudflare struct {
	mu          sync.Mutex
	now         func() time.Time
	tunnels     map[string]cftunnel.Tunnel
	records     map[string]cftunnel.DNSRecord
	configs     map[string]cftunnel.IngressConfig
	connections map[string][]cftunnel.Connection
	errors      map[string][]error
	calls       []string
	newID       int
	loseCreate  bool
	loseDNS     bool
	tokenHook   func()
}

var _ cftunnel.Cloudflare = (*mockCloudflare)(nil)

func mockCall[T any](m *mockCloudflare, op string, action func() (T, error)) (result T, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, op)
	if pending := m.errors[op]; len(pending) != 0 {
		m.errors[op] = pending[1:]
		if pending[0] != nil {
			return result, pending[0]
		}
	}
	return action()
}

func mockWrite(m *mockCloudflare, op string, action func() error) error {
	_, err := mockCall(m, op, func() (struct{}, error) { return struct{}{}, action() })
	return err
}

func (m *mockCloudflare) CreateTunnel(_ context.Context, name string, _ []byte) (cftunnel.Tunnel, error) {
	return mockCall(m, "create_tunnel", func() (cftunnel.Tunnel, error) {
		m.newID++
		tunnel := cftunnel.Tunnel{ID: fmt.Sprintf("tunnel-%d", m.newID), Name: name, ConfigSrc: "cloudflare",
			CreatedAt: m.now(), Status: cftunnel.TunnelInactive}
		m.tunnels[tunnel.ID] = tunnel
		if m.loseCreate {
			m.loseCreate = false
			return cftunnel.Tunnel{}, cftunnel.CFTransientError{}
		}
		return tunnel, nil
	})
}

func (m *mockCloudflare) GetTunnel(_ context.Context, id string) (cftunnel.Tunnel, error) {
	return mockCall(m, "get_tunnel", func() (cftunnel.Tunnel, error) {
		if tunnel, ok := m.tunnels[id]; ok {
			return tunnel, nil
		}
		return cftunnel.Tunnel{}, cftunnel.ErrCFNotFound
	})
}

func (m *mockCloudflare) ListTunnels(_ context.Context, q cftunnel.TunnelListQuery) (cftunnel.TunnelListPage, error) {
	return mockCall(m, "list_tunnels", func() (cftunnel.TunnelListPage, error) {
		var all []cftunnel.Tunnel
		for _, tunnel := range m.tunnels {
			if (q.Name == "" || q.Name == tunnel.Name) && strings.HasPrefix(tunnel.Name, q.IncludePrefix) {
				all = append(all, tunnel)
			}
		}
		sort.Slice(all, func(left, right int) bool { return all[left].ID < all[right].ID })
		total := len(all)
		from := min(total, (q.Page-1)*q.PerPage)
		return cftunnel.TunnelListPage{Tunnels: all[from:min(total, from+q.PerPage)], TotalCount: total}, nil
	})
}

func (m *mockCloudflare) GetConfiguration(_ context.Context, id string) (cftunnel.IngressConfig, error) {
	return mockCall(m, "get_configuration", func() (cftunnel.IngressConfig, error) {
		if cfg, ok := m.configs[id]; ok {
			return cfg, nil
		}
		return cftunnel.IngressConfig{}, cftunnel.ErrCFConfigNotFound
	})
}

func (m *mockCloudflare) PutConfiguration(_ context.Context, id string, cfg cftunnel.IngressConfig) error {
	return mockWrite(m, "put_configuration", func() error { m.configs[id] = cfg; return nil })
}

func (m *mockCloudflare) GetToken(_ context.Context, _ string) (string, error) {
	token, err := mockCall(m, "get_token", func() (string, error) { return "test-connector", nil })
	if m.tokenHook != nil {
		m.tokenHook()
	}
	return token, err
}

func (m *mockCloudflare) RotateSecret(_ context.Context, id string, secret []byte) error {
	return mockWrite(m, "rotate_secret", func() error {
		if len(secret) != 32 {
			return cftunnel.ErrInvalidClaim
		}
		return nil
	})
}

func (m *mockCloudflare) ListConnections(_ context.Context, id string) ([]cftunnel.Connection, error) {
	return mockCall(m, "list_connections", func() ([]cftunnel.Connection, error) { return m.connections[id], nil })
}

func (m *mockCloudflare) DisconnectAll(_ context.Context, id string) error {
	return mockWrite(m, "disconnect_all", func() error { delete(m.connections, id); return nil })
}

func (m *mockCloudflare) DeleteTunnel(_ context.Context, id string) error {
	return mockWrite(m, "delete_tunnel", func() error { delete(m.tunnels, id); return nil })
}

func (m *mockCloudflare) GetZone(context.Context) (cftunnel.Zone, error) {
	return mockCall(m, "get_zone", func() (cftunnel.Zone, error) {
		return cftunnel.Zone{ID: "zone", Name: "example.com", Status: "active", AccountID: "account"}, nil
	})
}

func (m *mockCloudflare) ListDNSRecords(_ context.Context, name string) ([]cftunnel.DNSRecord, error) {
	return mockCall(m, "list_dns_records", func() ([]cftunnel.DNSRecord, error) {
		var found []cftunnel.DNSRecord
		for _, record := range m.records {
			if record.Hostname == name {
				found = append(found, record)
			}
		}
		return found, nil
	})
}

func (m *mockCloudflare) ListMarkedDNSRecords(_ context.Context, page, perPage int) (cftunnel.DNSListPage, error) {
	return mockCall(m, "list_marked_dns", func() (cftunnel.DNSListPage, error) {
		var all []cftunnel.DNSRecord
		for _, record := range m.records {
			if strings.HasPrefix(record.Comment, "vr1:") {
				all = append(all, record)
			}
		}
		sort.Slice(all, func(left, right int) bool { return all[left].ID < all[right].ID })
		from, to := min(len(all), (page-1)*perPage), min(len(all), page*perPage)
		return cftunnel.DNSListPage{Records: all[from:to], TotalPages: (len(all) + perPage - 1) / perPage}, nil
	})
}

func (m *mockCloudflare) CreateDNSRecord(_ context.Context, record cftunnel.DNSRecord) (cftunnel.DNSRecord, error) {
	return mockCall(m, "create_dns_record", func() (cftunnel.DNSRecord, error) {
		m.newID++
		record.ID = fmt.Sprintf("record-%d", m.newID)
		m.records[record.ID] = record
		if m.loseDNS {
			m.loseDNS = false
			return cftunnel.DNSRecord{}, cftunnel.CFTransientError{}
		}
		return record, nil
	})
}

func (m *mockCloudflare) PatchDNSRecord(_ context.Context, record cftunnel.DNSRecord) (cftunnel.DNSRecord, error) {
	return mockCall(m, "patch_dns_record", func() (cftunnel.DNSRecord, error) {
		m.records[record.ID] = record
		return record, nil
	})
}

func (m *mockCloudflare) DeleteDNSRecord(_ context.Context, id string) error {
	return mockWrite(m, "delete_dns_record", func() error { delete(m.records, id); return nil })
}

func (m *mockCloudflare) writes() []string {
	var writes []string
	for _, op := range m.calls {
		if !strings.HasPrefix(op, "get_") && !strings.HasPrefix(op, "list_") {
			writes = append(writes, op)
		}
	}
	return writes
}

type harness struct {
	t       *testing.T
	clock   time.Time
	service *cftunnel.Service
	store   *sqlstore.Store
	cf      *mockCloudflare
	crypto  *cftunnel.Crypto
	scope   cftunnel.Scope
	cfg     cftunnel.Config
}

func newHarness(t *testing.T, mode cftunnel.ReaperMode) *harness {
	t.Helper()
	h := &harness{t: t, clock: time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)}
	now := func() time.Time { return h.clock }
	h.cf = &mockCloudflare{now: now, tunnels: make(map[string]cftunnel.Tunnel), records: make(map[string]cftunnel.DNSRecord),
		configs: make(map[string]cftunnel.IngressConfig), connections: make(map[string][]cftunnel.Connection), errors: make(map[string][]error)}
	var err error
	h.store, err = sqlstore.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "tunnels.db"), sqlstore.Options{Clock: now})
	check(t, err)
	t.Cleanup(func() { check(t, h.store.Close()) })
	h.scope = cftunnel.Scope{ID: "scope", Channel: "self", AccountID: "account", ZoneID: "zone", Namespace: "site",
		BaseDomain: "tunnels.example.com", ControlOrigin: "https://control.example.com", MasterKeySHA256: "digest"}
	check(t, h.store.EnsureScope(t.Context(), h.scope))
	h.crypto, err = cftunnel.NewCrypto(bytes.Repeat([]byte{0x36}, 32), nil, nil)
	check(t, err)
	h.cfg = cftunnel.Config{Mode: cftunnel.ModeManaged, AccountCap: 1000, Reaper: cftunnel.ReaperConfig{Mode: mode}}
	h.service = h.withCloudflare(h.cf)
	return h
}

func (h *harness) withCloudflare(cf cftunnel.Cloudflare) *cftunnel.Service {
	h.t.Helper()
	service, err := cftunnel.NewService(h.cfg, h.scope, h.store, cf, h.crypto, cftunnel.ServiceOptions{Clock: func() time.Time { return h.clock }})
	check(h.t, err)
	return service
}

func request(device string) cftunnel.ManagementRequest {
	return cftunnel.ManagementRequest{
		DeviceBinding: cftunnel.DeviceBinding{DeviceID: device, OwnerID: "owner-" + device, DeviceKeyHash: "key-" + device},
		Origin:        "127.0.0.1:4482", Policy: cftunnel.ClaimPolicy{OwnerSlots: 1},
	}
}

func (h *harness) state(req cftunnel.ManagementRequest) cftunnel.Allocation {
	h.t.Helper()
	a, err := h.service.Status(h.t.Context(), req.DeviceBinding)
	check(h.t, err)
	return a
}

func (h *harness) run(expectWork bool) {
	h.t.Helper()
	processed, err := h.service.ProcessOne(h.t.Context(), "worker")
	if err != nil || processed != expectWork {
		h.t.Fatalf("ProcessOne = %v, %v", processed, err)
	}
}

func (h *harness) ready(req *cftunnel.ManagementRequest) cftunnel.Allocation {
	h.t.Helper()
	_, err := h.service.Register(h.t.Context(), *req)
	check(h.t, err)
	h.run(true)
	a := h.state(*req)
	if a.State != cftunnel.StateReady {
		h.t.Fatalf("allocation state = %s", a.State)
	}
	req.IfGeneration = a.Generation
	return a
}

func (h *harness) operation(req cftunnel.ManagementRequest, id string) cftunnel.Operation {
	h.t.Helper()
	op, err := h.service.GetOperation(h.t.Context(), req.DeviceBinding, id)
	check(h.t, err)
	return op
}

func TestLifecycleFastPathAndExternalDeletion(t *testing.T) {
	h := newHarness(t, cftunnel.ReaperOff)
	check(t, h.service.PreflightZone(t.Context()))
	req := request("device")
	req.CanRecover = true
	a := h.ready(&req)
	if a.ReadyAt != h.clock || a.RecoveryEnabledAt != h.clock || !a.BudgetHeld {
		t.Fatalf("ready dates/state: %+v", a)
	}
	check(t, h.service.RecordPresence(t.Context(), req.DeviceBinding, cftunnel.Presence{
		SocketID: "socket", RuntimeID: "runtime", Generation: a.Generation, Phase: cftunnel.PresenceListening, Seq: 1,
	}))
	req.RuntimeID = "runtime"
	h.cf.calls = nil
	token, err := h.service.IssueConnectorToken(t.Context(), req)
	if err != nil || token.Generation != a.Generation || token.TunnelID != a.Resources.TunnelID || token.ConnectorToken == "" ||
		!slices.Equal(h.cf.calls, []string{"get_tunnel", "get_token"}) {
		t.Fatalf("fast path: generation %d, calls %v, err %v", token.Generation, h.cf.calls, err)
	}
	h.cf.tokenHook = func() {
		_, err := h.service.ReconcileOrigin(t.Context(), req)
		check(t, err)
	}
	if _, err := h.service.IssueConnectorToken(t.Context(), req); !errors.Is(err, cftunnel.ErrGenerationConflict) {
		t.Fatalf("token issued across generation change: %v", err)
	}
	h.cf.tokenHook = nil
	h.run(true)
	a = h.state(req)
	req.IfGeneration = a.Generation
	delete(h.cf.tunnels, a.Resources.TunnelID)
	op, err := h.service.ReconcileOrigin(t.Context(), req)
	check(t, err)
	h.run(true)
	done := h.operation(req, op.ID)
	released := h.state(req)
	if released.State != cftunnel.StateReleased || released.BudgetHeld || len(h.cf.records) != 0 || done.ErrorCode != cftunnel.CodeRecoveryRequired {
		t.Fatalf("external deletion did not converge: %s/%s, DNS %d", released.State, done.ErrorCode, len(h.cf.records))
	}
	req.IfGeneration = released.Generation
	_, err = h.service.Recover(t.Context(), req)
	check(t, err)
	h.run(true)
	recovered := h.state(req)
	if recovered.State != cftunnel.StateReady || recovered.Incarnation != a.Incarnation+1 || recovered.Hostname != a.Hostname ||
		recovered.Resources == a.Resources {
		t.Fatalf("recovery did not allocate a new physical tunnel: %+v", recovered)
	}
}

func TestOriginDriftAndDNSOwnership(t *testing.T) {
	h := newHarness(t, cftunnel.ReaperOff)
	req := request("device")
	a := h.ready(&req)
	id := a.Resources.TunnelID
	for _, tc := range []struct {
		name  string
		drift func(cftunnel.IngressConfig) cftunnel.IngressConfig
		put   bool
	}{
		{"same", func(cfg cftunnel.IngressConfig) cftunnel.IngressConfig { return cfg }, false},
		{"path", func(cfg cftunnel.IngressConfig) cftunnel.IngressConfig { cfg.Ingress[0].Path = "^/"; return cfg }, true},
		{"wildcard", func(cfg cftunnel.IngressConfig) cftunnel.IngressConfig {
			cfg.Ingress = append([]cftunnel.IngressRule{{Hostname: "*.tunnels.example.com", Service: "http://127.0.0.1:1"}}, cfg.Ingress...)
			return cfg
		}, true},
		{"warp", func(cfg cftunnel.IngressConfig) cftunnel.IngressConfig { cfg.WarpRoutingEnabled = true; return cfg }, true},
		{"other port", func(cfg cftunnel.IngressConfig) cftunnel.IngressConfig {
			cfg.Ingress[0].Service = "http://127.0.0.1:2"
			return cfg
		}, true},
		{"1055", func(cftunnel.IngressConfig) cftunnel.IngressConfig {
			h.cf.errors["get_configuration"] = []error{cftunnel.ErrCFConfigNotFound}
			return cftunnel.IngressConfig{}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.cf.configs[id] = tc.drift(h.cf.configs[id])
			h.cf.calls = nil
			_, err := h.service.ReconcileOrigin(t.Context(), req)
			check(t, err)
			h.run(true)
			current := h.state(req)
			req.IfGeneration = current.Generation
			if current.State != cftunnel.StateReady || slices.Contains(h.cf.calls, "put_configuration") != tc.put {
				t.Fatalf("drift reconciliation = %s, %v", current.State, h.cf.calls)
			}
		})
	}
	owned := h.cf.records[a.Resources.DNSRecordID]
	owned.TTL = 3600
	owned.Target = "drifted.example.com"
	h.cf.records[owned.ID] = owned
	duplicate := owned
	duplicate.ID = "duplicate"
	h.cf.records[duplicate.ID] = duplicate
	h.cf.calls = nil
	_, err := h.service.ReconcileOrigin(t.Context(), req)
	check(t, err)
	h.run(true)
	if len(h.cf.records) != 1 || !slices.Equal(h.cf.writes(), []string{"delete_dns_record", "patch_dns_record"}) {
		t.Fatalf("duplicate reconciliation = %v, %v", h.cf.records, h.cf.calls)
	}
	for _, kind := range []string{"A", "CNAME"} {
		req.IfGeneration = h.state(req).Generation
		h.cf.records["foreign"] = cftunnel.DNSRecord{ID: "foreign", Hostname: a.Hostname, Type: kind, Target: "foreign"}
		h.cf.calls = nil
		op, err := h.service.ReconcileOrigin(t.Context(), req)
		check(t, err)
		h.run(true)
		current := h.state(req)
		if current.State != cftunnel.StateQuarantined || !current.BudgetHeld || h.operation(req, op.ID).ErrorCode != cftunnel.CodeDNSConflict ||
			len(h.cf.writes()) != 0 || h.cf.records["foreign"].ID == "" {
			t.Fatalf("foreign DNS was touched: %+v, %v", current, h.cf.calls)
		}
		delete(h.cf.records, "foreign")
		req.IfGeneration = current.Generation
		_, err = h.service.Repair(t.Context(), req)
		check(t, err)
		h.run(true)
		if h.state(req).State != cftunnel.StateReady {
			t.Fatal("repair did not restore ready allocation")
		}
	}
}

func TestReleaseDisconnectResumeAndDeprovision(t *testing.T) {
	h := newHarness(t, cftunnel.ReaperOff)
	req := request("device")
	a := h.ready(&req)
	id := a.Resources.TunnelID
	for _, active := range []bool{true, false} {
		if active {
			h.cf.connections[id] = []cftunnel.Connection{{ID: "connector"}}
		} else {
			delete(h.cf.connections, id)
			h.cf.errors["delete_tunnel"] = []error{cftunnel.ErrCFTunnelInUse}
		}
		h.cf.calls = nil
		req.IfGeneration = h.state(req).Generation
		op, err := h.service.Release(t.Context(), req)
		check(t, err)
		h.run(true)
		if h.state(req).State != cftunnel.StateReady || h.operation(req, op.ID).ErrorCode != cftunnel.ErrCFTunnelInUse ||
			slices.Contains(h.cf.writes(), "delete_dns_record") {
			t.Fatalf("release did not abandon active tunnel: %v", h.cf.calls)
		}
	}
	h.cf.calls = nil
	req.IfGeneration = h.state(req).Generation
	_, err := h.service.Disconnect(t.Context(), req)
	check(t, err)
	h.run(true)
	a = h.state(req)
	if a.State != cftunnel.StateSuspended || !a.ManualResumeRequired || !slices.Equal(h.cf.writes(), []string{"rotate_secret", "disconnect_all"}) {
		t.Fatalf("disconnect = %s, %v", a.State, h.cf.calls)
	}
	req.IfGeneration = a.Generation
	_, err = h.service.Resume(t.Context(), req)
	check(t, err)
	if current := h.state(req); current.State != cftunnel.StateReconciling || current.ManualResumeRequired {
		t.Fatalf("in-place resume claim = %+v", current)
	}
	h.run(true)
	if current := h.state(req); current.State != cftunnel.StateReady || current.Incarnation != a.Incarnation || current.Resources != a.Resources {
		t.Fatalf("in-place resume completion = %+v", current)
	}
	h.cf.calls = nil
	req.IfGeneration = h.state(req).Generation
	_, err = h.service.Deprovision(t.Context(), req)
	check(t, err)
	h.run(true)
	if current := h.state(req); current.State != cftunnel.StateDisabled || current.BudgetHeld ||
		!slices.Equal(h.cf.writes(), []string{"rotate_secret", "disconnect_all", "delete_tunnel", "delete_dns_record"}) {
		t.Fatalf("deprovision = %s, %v", current.State, h.cf.calls)
	}
}

func TestOutboxWriteFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(*mockCloudflare)
		outcome cftunnel.AllocationState
		retry   bool
	}{
		{"created before timeout", func(cf *mockCloudflare) { cf.loseCreate = true }, cftunnel.StateReady, true},
		{"DNS created before timeout", func(cf *mockCloudflare) { cf.loseDNS = true }, cftunnel.StateReady, true},
		{"ambiguous creation never visible", func(cf *mockCloudflare) { cf.errors["create_tunnel"] = []error{cftunnel.CFTransientError{}} }, cftunnel.StateQuarantined, true},
		{"conflict", func(cf *mockCloudflare) { cf.errors["create_tunnel"] = []error{cftunnel.ErrCFConflict} }, cftunnel.StateQuarantined, false},
		{"pre-write authorization failure", func(cf *mockCloudflare) { cf.errors["list_tunnels"] = []error{cftunnel.ErrCFAuthorization} }, cftunnel.StateDisabled, false},
		{"rate limit before creation", func(cf *mockCloudflare) {
			cf.errors["create_tunnel"] = []error{cftunnel.CFRateLimitError{RetryAfter: 19 * time.Second}}
		}, cftunnel.StateReady, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, cftunnel.ReaperOff)
			req := request("device")
			tc.setup(h.cf)
			op, err := h.service.Register(t.Context(), req)
			check(t, err)
			h.run(true)
			if tc.retry {
				queued := h.operation(req, op.ID)
				if !queued.CompletedAt.IsZero() || !queued.NextAttemptAt.After(h.clock) || queued.Attempts != 1 {
					t.Fatalf("backoff not persisted: %+v", queued)
				}
				if queued.ErrorCode == cftunnel.ErrCFRateLimited && queued.NextAttemptAt.Sub(h.clock) != 19*time.Second {
					t.Fatalf("Retry-After not respected: %v", queued.NextAttemptAt.Sub(h.clock))
				}
				h.clock = queued.NextAttemptAt.Add(-time.Nanosecond)
				h.run(false)
				h.clock = queued.NextAttemptAt
				h.run(true)
			}
			a := h.state(req)
			if a.State != tc.outcome || a.BudgetHeld != (tc.outcome != cftunnel.StateDisabled) || len(h.cf.tunnels) > 1 ||
				len(h.cf.records) > 1 || h.operation(req, op.ID).CompletedAt.IsZero() {
				t.Fatalf("unexpected terminal state: %s, slots %v, CF %v", a.State, a.BudgetHeld, h.cf.calls)
			}
			if tc.name != "rate limit before creation" && strings.Count(strings.Join(h.cf.writes(), " "), "create_tunnel") > 1 {
				t.Fatalf("tunnel creation was repeated: %v", h.cf.writes())
			}
		})
	}
}
