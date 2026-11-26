package cftunnel

import (
	"maps"
	"sync"
	"time"
)

type MetricsSnapshot struct {
	CFAPIRequestsTotal        map[string]map[string]uint64 `json:"cf_api_requests_total"`
	CFAPIPausedEventsTotal    uint64                       `json:"cf_api_paused_events_total"`
	CFAPIPausedUntil          time.Time                    `json:"cf_api_paused_until"`
	ReaperSweepsTotal         map[string]uint64            `json:"reaper_sweeps_total"`
	ReaperCandidatesTotal     map[string]map[string]uint64 `json:"reaper_candidates_total"`
	ReaperReleasedTotal       uint64                       `json:"reaper_released_total"`
	ReaperOrphansCleanedTotal uint64                       `json:"reaper_orphans_cleaned_total"`
	OperationsTotal           map[string]map[string]uint64 `json:"operations_total"`
}

type Metrics struct {
	mu   sync.Mutex
	data MetricsSnapshot
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	data := m.data
	data.CFAPIRequestsTotal = cloneBuckets(data.CFAPIRequestsTotal)
	data.ReaperCandidatesTotal = cloneBuckets(data.ReaperCandidatesTotal)
	data.ReaperSweepsTotal = maps.Clone(data.ReaperSweepsTotal)
	data.OperationsTotal = cloneBuckets(data.OperationsTotal)
	return data
}

func cloneBuckets(source map[string]map[string]uint64) map[string]map[string]uint64 {
	result := make(map[string]map[string]uint64, len(source))
	for key, value := range source {
		result[key] = maps.Clone(value)
	}
	return result
}

func incrementBucket(buckets *map[string]map[string]uint64, first, second string, count uint64) {
	if *buckets == nil {
		*buckets = make(map[string]map[string]uint64)
	}
	if (*buckets)[first] == nil {
		(*buckets)[first] = make(map[string]uint64)
	}
	(*buckets)[first][second] += count
}

func (m *Metrics) api(op string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	outcome := string(CodeOf(err))
	if err == nil {
		outcome = "success"
	}
	incrementBucket(&m.data.CFAPIRequestsTotal, op, outcome, 1)
}

func (m *Metrics) pause(until time.Time, event bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if event {
		m.data.CFAPIPausedEventsTotal++
	}
	if until.After(m.data.CFAPIPausedUntil) {
		m.data.CFAPIPausedUntil = until
	}
}

func (m *Metrics) operation(kind OperationType, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	incrementBucket(&m.data.OperationsTotal, string(kind), outcome, 1)
}

func (m *Metrics) released() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data.ReaperReleasedTotal++
}

func (m *Metrics) sweep(mode ReaperMode, result SweepResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data.ReaperSweepsTotal == nil {
		m.data.ReaperSweepsTotal = make(map[string]uint64)
	}
	m.data.ReaperSweepsTotal[string(mode)]++
	for reason, count := range result.Candidates {
		incrementBucket(&m.data.ReaperCandidatesTotal, reason, string(mode), uint64(count))
	}
	m.data.ReaperReleasedTotal += uint64(result.PendingExpired)
	m.data.ReaperOrphansCleanedTotal += uint64(result.OrphansCleaned)
}
