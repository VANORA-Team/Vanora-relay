package cftunnel_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"vanora-relay/internal/cftunnel"
)

func TestReaperGraceBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name       string
		kind       string
		grace      time.Duration
		status     cftunnel.TunnelStatus
		canRecover bool
	}{
		{"recoverable down", "down", 5 * time.Minute, cftunnel.TunnelDown, true},
		{"legacy down", "down", 168 * time.Hour, cftunnel.TunnelDown, false},
		{"never connected", "inactive", time.Hour, cftunnel.TunnelInactive, false},
		{"suspended", "suspended", 168 * time.Hour, "", false},
		{"unstarted pending", "pending", 15 * time.Minute, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, cftunnel.ReaperActive)
			start := h.clock
			req := request("device")
			req.CanRecover = tc.canRecover
			var a cftunnel.Allocation
			if tc.kind == "pending" {
				_, err := h.service.Register(t.Context(), req)
				check(t, err)
				a = h.state(req)
			} else {
				a = h.ready(&req)
			}
			if tc.status != "" {
				tunnel := h.cf.tunnels[a.Resources.TunnelID]
				tunnel.Status, tunnel.ConnsInactiveAt = tc.status, start
				h.cf.tunnels[tunnel.ID] = tunnel
			}
			if tc.kind == "suspended" {
				_, err := h.service.Disconnect(t.Context(), req)
				check(t, err)
				h.run(true)
				a = h.state(req)
			}
			reaper := cftunnel.NewReaper(h.service)
			h.clock = start.Add(tc.grace - time.Nanosecond)
			if sweep, err := reaper.SweepOnce(t.Context()); err != nil || sweep.Candidates[tc.kind] != 0 {
				t.Fatalf("before boundary: %+v, %v", sweep, err)
			}
			h.clock = start.Add(tc.grace)
			sweep, err := reaper.SweepOnce(t.Context())
			check(t, err)
			if sweep.Candidates[tc.kind] != 1 || sweep.ReleaseClaims+sweep.PendingExpired != 1 {
				t.Fatalf("at boundary: %+v", sweep)
			}
			h.run(tc.kind != "pending")
			released := h.state(req)
			if released.State != cftunnel.StateReleased || released.BudgetHeld || !released.ReleasedAt.Equal(h.clock) ||
				h.service.Metrics().Snapshot().ReaperReleasedTotal != 1 {
				t.Fatalf("release did not converge: %+v, metrics %+v", released, h.service.Metrics().Snapshot())
			}
			if tc.kind == "suspended" {
				req.IfGeneration = released.Generation
				if _, err := h.service.Recover(t.Context(), req); !errors.Is(err, cftunnel.ErrTunnelSuspended) || !released.ManualResumeRequired {
					t.Fatalf("manual gate after reaping: %v, %v", released.ManualResumeRequired, err)
				}
				_, err := h.service.Resume(t.Context(), req)
				check(t, err)
				pending := h.state(req)
				if pending.State != cftunnel.StatePending || pending.Incarnation != a.Incarnation+1 || pending.ManualResumeRequired {
					t.Fatalf("resume claim = %+v", pending)
				}
				h.run(true)
			}
		})
	}
}

func TestReaperObservationsPresenceAndDryRun(t *testing.T) {
	h := newHarness(t, cftunnel.ReaperDryRun)
	req := request("device")
	req.CanRecover = true
	a := h.ready(&req)
	pending := request("pending")
	_, err := h.service.Register(t.Context(), pending)
	check(t, err)
	tunnel := h.cf.tunnels[a.Resources.TunnelID]
	tunnel.Status = cftunnel.TunnelDown
	h.cf.tunnels[tunnel.ID] = tunnel
	h.clock = h.clock.Add(15 * time.Minute)
	firstSeen := h.clock
	reaper := cftunnel.NewReaper(h.service)
	h.cf.calls = nil
	sweep, err := reaper.SweepOnce(t.Context())
	check(t, err)
	if sweep.Candidates["down"] != 0 || sweep.Candidates["pending"] != 1 ||
		!h.state(req).CFStatusSince.Equal(firstSeen) {
		t.Fatalf("continuous observation: %+v", sweep)
	}
	for index, phase := range []cftunnel.PresencePhase{cftunnel.PresenceStarting, cftunnel.PresenceListening, cftunnel.PresenceStopping} {
		h.clock = firstSeen.Add(5*time.Minute + time.Duration(index)*time.Second)
		check(t, h.service.RecordPresence(t.Context(), req.DeviceBinding, cftunnel.Presence{
			SocketID: "socket", RuntimeID: "runtime", Phase: phase, Generation: a.Generation, Seq: int64(index + 1),
		}))
		sweep, err := reaper.SweepOnce(t.Context())
		check(t, err)
		want := 0
		if phase == cftunnel.PresenceStopping {
			want = 1
		}
		if sweep.Candidates["down"] != want || sweep.ReleaseClaims != 0 || sweep.PendingExpired != 0 {
			t.Fatalf("dry run with %s: %+v", phase, sweep)
		}
	}
	if len(h.cf.writes()) != 0 || h.state(req).Generation != a.Generation || h.state(pending).State != cftunnel.StatePending {
		t.Fatalf("dry run modified allocation or Cloudflare: %v", h.cf.writes())
	}
	metrics := h.service.Metrics().Snapshot()
	if metrics.ReaperSweepsTotal["dry-run"] != 4 || metrics.ReaperCandidatesTotal["down"]["dry-run"] != 1 || metrics.ReaperReleasedTotal != 0 {
		t.Fatalf("dry run metrics: %+v", metrics)
	}
}

func TestReaperPendingWithWriteIntentAndReconnectDuringRelease(t *testing.T) {
	t.Run("pending write intent", func(t *testing.T) {
		h := newHarness(t, cftunnel.ReaperActive)
		req := request("device")
		h.cf.loseCreate = true
		_, err := h.service.Register(t.Context(), req)
		check(t, err)
		h.run(true)
		h.clock = h.clock.Add(15 * time.Minute)
		sweep, err := cftunnel.NewReaper(h.service).SweepOnce(t.Context())
		check(t, err)
		if sweep.PendingExpired != 0 || h.state(req).State != cftunnel.StatePending {
			t.Fatalf("destroyed pending with write intent: %+v", sweep)
		}
		h.run(true)
		if h.state(req).State != cftunnel.StateReady {
			t.Fatal("worker did not reconcile the pending write")
		}
	})
	t.Run("brief reconnect after claim", func(t *testing.T) {
		h := newHarness(t, cftunnel.ReaperActive)
		req := request("device")
		req.CanRecover = true
		a := h.ready(&req)
		tunnel := h.cf.tunnels[a.Resources.TunnelID]
		tunnel.Status, tunnel.ConnsInactiveAt = cftunnel.TunnelDown, h.clock
		h.cf.tunnels[tunnel.ID] = tunnel
		h.clock = h.clock.Add(5 * time.Minute)
		sweep, err := cftunnel.NewReaper(h.service).SweepOnce(t.Context())
		check(t, err)
		if sweep.ReleaseClaims != 1 {
			t.Fatalf("release was not claimed: %+v", sweep)
		}
		tunnel.ConnsInactiveAt = h.clock
		h.cf.tunnels[tunnel.ID] = tunnel
		h.cf.calls = nil
		h.run(true)
		if h.state(req).State != cftunnel.StateReady || len(h.cf.writes()) != 0 {
			t.Fatalf("recent reconnect was not protected: %v", h.cf.calls)
		}
	})
}

func addOrphan(h *harness, id string) (cftunnel.Tunnel, cftunnel.DNSRecord) {
	label, name := h.crypto.DeriveHostname(h.scope.ID, "orphan", id, h.scope.BaseDomain)
	tunnel := cftunnel.Tunnel{ID: id, Name: h.crypto.DeriveTunnelName(h.scope.Namespace, label, 1),
		Status: cftunnel.TunnelDown, CreatedAt: h.clock, ConfigSrc: "cloudflare"}
	record := cftunnel.DNSRecord{ID: "dns-" + id, Type: "CNAME", Hostname: name, Target: id + ".cfargotunnel.com",
		TTL: 1, Proxied: true, Comment: h.crypto.FormatDNSMarker(h.scope.ZoneID, name, id, 1)}
	h.cf.tunnels[tunnel.ID], h.cf.records[record.ID] = tunnel, record
	return tunnel, record
}

func TestReaperOrphanGraceAndOwnership(t *testing.T) {
	for _, mode := range []cftunnel.ReaperMode{cftunnel.ReaperActive, cftunnel.ReaperDryRun} {
		t.Run(string(mode), func(t *testing.T) {
			h := newHarness(t, mode)
			tunnel, record := addOrphan(h, "orphan")
			busy, _ := addOrphan(h, "busy")
			h.cf.connections[busy.ID] = []cftunnel.Connection{{ID: "active"}}
			h.cf.tunnels["foreign"] = cftunnel.Tunnel{ID: "foreign", Name: "vr-site-unverified"}
			h.cf.records["foreign-dns"] = cftunnel.DNSRecord{ID: "foreign-dns", Type: "CNAME", Hostname: record.Hostname,
				Target: record.Target, Comment: "vr1:1:invalid"}
			start := h.clock
			reaper := cftunnel.NewReaper(h.service)
			for _, age := range []time.Duration{0, 24*time.Hour - time.Nanosecond} {
				h.clock = start.Add(age)
				sweep, err := reaper.SweepOnce(t.Context())
				check(t, err)
				if sweep.OrphansCleaned != 0 || len(h.cf.writes()) != 0 {
					t.Fatalf("orphan removed before grace: %+v", sweep)
				}
			}
			h.clock = start.Add(24 * time.Hour)
			sweep, err := reaper.SweepOnce(t.Context())
			check(t, err)
			if sweep.Candidates["orphan_tunnel"] != 1 || sweep.Candidates["orphan_dns"] != 1 {
				t.Fatalf("unexpected candidates: %+v", sweep)
			}
			if mode == cftunnel.ReaperActive {
				if sweep.OrphansCleaned != 2 || !slices.Equal(h.cf.writes(), []string{"delete_tunnel", "delete_dns_record"}) ||
					h.cf.tunnels[tunnel.ID].ID != "" || h.cf.records[record.ID].ID != "" {
					t.Fatalf("unexpected orphan cleanup: %+v, %v", sweep, h.cf.writes())
				}
			} else if sweep.OrphansCleaned != 0 || len(h.cf.writes()) != 0 {
				t.Fatalf("dry-run orphan writes: %+v, %v", sweep, h.cf.writes())
			}
			if h.cf.tunnels["foreign"].ID == "" || h.cf.records["foreign-dns"].ID == "" || h.cf.tunnels[busy.ID].ID == "" {
				t.Fatal("foreign or connected resource was deleted")
			}
		})
	}
}

func TestReaperCursorAnd429Interrupt(t *testing.T) {
	h := newHarness(t, cftunnel.ReaperActive)
	tunnel, _ := addOrphan(h, "first")
	for index := range 50 {
		id := fmt.Sprintf("padding-%02d", index)
		h.cf.tunnels[id] = cftunnel.Tunnel{ID: id, Name: "vr-site-unverified-" + id}
	}
	reaper := cftunnel.NewReaper(h.service)
	_, err := reaper.SweepOnce(t.Context())
	check(t, err)
	cursor, err := h.store.LoadScan(t.Context(), h.scope.ID, "orphan")
	check(t, err)
	if cursor.Cycle != 1 || cursor.Cursor != "tunnel:2:0" {
		t.Fatalf("first page cursor: %+v", cursor)
	}
	h.clock = h.clock.Add(24 * time.Hour)
	h.cf.errors["list_tunnels"] = []error{cftunnel.CFRateLimitError{RetryAfter: time.Minute}}
	sweep, err := reaper.SweepOnce(t.Context())
	if !errors.Is(err, cftunnel.ErrCFRateLimited) || !sweep.Paused || len(h.cf.writes()) != 0 {
		t.Fatalf("429 did not interrupt sweep: %+v, %v", sweep, err)
	}
	current, err := h.store.LoadScan(t.Context(), h.scope.ID, "orphan")
	check(t, err)
	if current != cursor {
		t.Fatalf("429 advanced cursor: %+v -> %+v", cursor, current)
	}
	reaper = cftunnel.NewReaper(h.service)
	_, err = reaper.SweepOnce(t.Context())
	check(t, err)
	first, err := h.store.GetOrphan(t.Context(), h.scope.ID, "tunnel", tunnel.ID)
	check(t, err)
	if first.SeenCycles != 1 || len(h.cf.writes()) != 0 {
		t.Fatalf("first completed cycle: %+v", first)
	}
	_, err = reaper.SweepOnce(t.Context())
	check(t, err)
	second, err := h.store.GetOrphan(t.Context(), h.scope.ID, "tunnel", tunnel.ID)
	check(t, err)
	if second.SeenCycles != 2 || len(h.cf.writes()) != 0 {
		t.Fatalf("deleted before second cycle completed: %+v", second)
	}
	_, err = reaper.SweepOnce(t.Context())
	check(t, err)
	if !slices.Equal(h.cf.writes(), []string{"delete_tunnel"}) {
		t.Fatalf("second completed scan did not delete eligible tunnel: %v", h.cf.writes())
	}
}
