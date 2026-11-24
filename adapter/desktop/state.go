package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	stateVersion = 1

	kindTextDelta     = "text.delta"
	kindThinkingDelta = "thinking.delta"
	kindToolCall      = "tool.call"
	kindToolStart     = "tool.start"
	kindToolUpdate    = "tool.update"
	kindToolEnd       = "tool.end"
	kindUIRequest     = "ui.request"
	kindUIResolved    = "ui.resolved"
	kindSync          = "sync"
	kindRunCompleted  = "run.completed"
	kindRunCancelled  = "run.cancelled"
	kindRunFailed     = "run.failed"

	visAll      = ""
	visThinking = "thinking"
	visTools    = "tools"
	visApproval = "approval"

	statusRunning    = "running"
	statusCancelling = "cancelling"
	statusCompleted  = "completed"
	statusCancelled  = "cancelled"
	statusFailed     = "failed"
)

type persistedState struct {
	Version         int                             `json:"version"`
	Sessions        map[string]*persistedSession    `json:"sessions"`
	CreatedSessions map[string]createdSessionRecord `json:"created_sessions,omitempty"`
	CreateRequests  map[string]createRequestRecord  `json:"create_requests,omitempty"`
}

type createdSessionRecord struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Title       string `json:"title"`
	WorkingDir  string `json:"working_dir"`
	SessionFile string `json:"session_file"`
	Owner       string `json:"owner"`
	Created     int64  `json:"created"`
}

type createRequestRecord struct {
	SessionID string `json:"session_id"`
	TitleSHA  string `json:"title_sha"`
	Created   int64  `json:"created"`
}

type persistedSession struct {
	// LastSeq is the newest event sequence ever assigned for this session. It
	// is persisted even when older events fall out of retention.
	LastSeq  int64                    `json:"last_seq"`
	FirstSeq int64                    `json:"first_seq,omitempty"`
	Events   []storedEvent            `json:"events,omitempty"`
	Requests map[string]requestRecord `json:"requests,omitempty"`
	Runs     map[string]runRecord     `json:"runs,omitempty"`
}

type storedEvent struct {
	Seq            int64           `json:"seq"`
	RunID          string          `json:"run_id,omitempty"`
	Kind           string          `json:"kind"`
	Data           json.RawMessage `json:"data,omitempty"`
	RequiresOnline bool            `json:"requires_online,omitempty"`
	Visibility     string          `json:"visibility,omitempty"`
	ApprovalUser   string          `json:"approval_user,omitempty"`
}

type requestRecord struct {
	RunID   string `json:"run_id"`
	TextSHA string `json:"text_sha"`
	Created int64  `json:"created"`
}

type runRecord struct {
	Status  string `json:"status"`
	UserID  string `json:"user_id,omitempty"`
	Tools   bool   `json:"tools,omitempty"`
	Created int64  `json:"created"`
}

type textDeltaData struct {
	Text string `json:"text"`
}

type thinkingDeltaData struct {
	Text string `json:"text"`
}

type toolCallData struct {
	ToolCallID string `json:"tool_call_id,omitempty"`
	ToolName   string `json:"tool_name"`
	Arguments  string `json:"arguments,omitempty"`
}

type toolStartData struct {
	ToolCallID string `json:"tool_call_id,omitempty"`
	ToolName   string `json:"tool_name"`
	Args       string `json:"args,omitempty"`
}

type toolUpdateData struct {
	ToolCallID string `json:"tool_call_id,omitempty"`
	ToolName   string `json:"tool_name"`
	Text       string `json:"text"`
	Delta      bool   `json:"delta,omitempty"`
}

type toolEndData struct {
	ToolCallID string `json:"tool_call_id,omitempty"`
	ToolName   string `json:"tool_name"`
	Text       string `json:"text,omitempty"`
	IsError    bool   `json:"is_error,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

type uiRequestData struct {
	UIID        string          `json:"ui_id"`
	RunID       string          `json:"run_id,omitempty"`
	Method      string          `json:"method"`
	Title       string          `json:"title,omitempty"`
	Message     string          `json:"message,omitempty"`
	Options     []string        `json:"options,omitempty"`
	Questions   json.RawMessage `json:"questions,omitempty"`
	Placeholder string          `json:"placeholder,omitempty"`
	Prefill     string          `json:"prefill,omitempty"`
	ExpiresAt   int64           `json:"expires_at,omitempty"`
}

type uiResolvedData struct {
	UIID   string `json:"ui_id"`
	Status string `json:"status"`
}

type runCancelledData struct {
	Reason string `json:"reason"`
}

type runFailedData struct {
	Reason string `json:"reason"`
}

func newPersistedState() *persistedState {
	return &persistedState{
		Version:         stateVersion,
		Sessions:        make(map[string]*persistedSession),
		CreatedSessions: make(map[string]createdSessionRecord),
		CreateRequests:  make(map[string]createRequestRecord),
	}
}

func newPersistedSession() *persistedSession {
	return &persistedSession{
		Requests: make(map[string]requestRecord),
		Runs:     make(map[string]runRecord),
	}
}

func loadState(dir string) (*persistedState, error) {
	name := filepath.Join(dir, "state.json")
	info, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return newPersistedState(), nil
		}
		return nil, fmt.Errorf("desktop: stat state: %w", err)
	}
	if info.IsDir() {
		return nil, errors.New("desktop: state.json is a directory")
	}
	if info.Size() > 64<<20 {
		return nil, errors.New("desktop: state.json is too large")
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("desktop: read state: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("desktop: state.json is empty")
	}
	var st persistedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("desktop: parse state: %w", err)
	}
	if st.Version != stateVersion {
		return nil, fmt.Errorf("desktop: unsupported state version %d", st.Version)
	}
	if st.Sessions == nil {
		st.Sessions = make(map[string]*persistedSession)
	}
	if st.CreatedSessions == nil {
		st.CreatedSessions = make(map[string]createdSessionRecord)
	}
	if st.CreateRequests == nil {
		st.CreateRequests = make(map[string]createRequestRecord)
	}
	for id, ps := range st.Sessions {
		if ps == nil {
			return nil, fmt.Errorf("desktop: state session %q is null", id)
		}
		if err := ps.validateAndNormalize(); err != nil {
			return nil, fmt.Errorf("desktop: state session %q: %w", id, err)
		}
	}
	return &st, nil
}

func (ps *persistedSession) validateAndNormalize() error {
	if ps.Requests == nil {
		ps.Requests = make(map[string]requestRecord)
	}
	if ps.Runs == nil {
		ps.Runs = make(map[string]runRecord)
	}
	for id, rec := range ps.Runs {
		switch rec.Status {
		case statusRunning, statusCancelling, statusCompleted, statusCancelled, statusFailed:
		default:
			return fmt.Errorf("run %q has invalid status %q", id, rec.Status)
		}
	}
	sort.Slice(ps.Events, func(i, j int) bool { return ps.Events[i].Seq < ps.Events[j].Seq })
	for i := range ps.Events {
		e := &ps.Events[i]
		if e.Seq <= 0 {
			return errors.New("event sequence must be positive")
		}
		if i > 0 && ps.Events[i-1].Seq == e.Seq {
			return fmt.Errorf("duplicate event sequence %d", e.Seq)
		}
		if e.Kind == "" {
			return fmt.Errorf("event %d has no kind", e.Seq)
		}
		if len(e.Data) > 0 && !json.Valid(e.Data) {
			return fmt.Errorf("event %d has invalid data", e.Seq)
		}
		if e.Seq > ps.LastSeq {
			ps.LastSeq = e.Seq
		}
	}
	if ps.LastSeq < 0 {
		return errors.New("negative last_seq")
	}
	ps.recalculateFirstSeq()
	return nil
}

func (ps *persistedSession) recalculateFirstSeq() {
	if len(ps.Events) == 0 {
		ps.FirstSeq = 0
		return
	}
	ps.FirstSeq = ps.Events[0].Seq
}

func (ps *persistedSession) eventBytes() int64 {
	var n int64
	for _, e := range ps.Events {
		n += estimateEventBytes(e)
	}
	return n
}

func estimateEventBytes(e storedEvent) int64 {
	return int64(48 + len(e.RunID) + len(e.Kind) + len(e.Data) + len(e.ApprovalUser))
}

func (ps *persistedSession) appendEvent(e storedEvent) {
	ps.Events = append(ps.Events, e)
	ps.LastSeq = e.Seq
	if ps.FirstSeq == 0 {
		ps.FirstSeq = e.Seq
	}
}

func (ps *persistedSession) trim(ret RetentionConfig) {
	if len(ps.Events) == 0 {
		ps.FirstSeq = 0
		return
	}
	total := ps.eventBytes()
	for len(ps.Events) > 1 && (len(ps.Events) > ret.MaxEvents || total > ret.MaxBytes) {
		total -= estimateEventBytes(ps.Events[0])
		ps.Events = ps.Events[1:]
	}
	ps.recalculateFirstSeq()
	trimMap(ps.Requests, ret.MaxRequests, func(r requestRecord) int64 { return r.Created })
	trimMap(ps.Runs, ret.MaxRequests, func(r runRecord) int64 { return r.Created })
}

func trimMap[V any](m map[string]V, max int, created func(V) int64) {
	if max <= 0 || len(m) <= max {
		return
	}
	type item struct {
		key     string
		created int64
	}
	items := make([]item, 0, len(m))
	for k, v := range m {
		items = append(items, item{key: k, created: created(v)})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].created == items[j].created {
			return items[i].key < items[j].key
		}
		return items[i].created < items[j].created
	})
	for i := range len(items) - max {
		delete(m, items[i].key)
	}
}

func saveState(dir string, st *persistedState) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("desktop: create state directory: %w", err)
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("desktop: encode state: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("desktop: create state temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("desktop: chmod state: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("desktop: write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("desktop: sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("desktop: close state: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, "state.json")); err != nil {
		return fmt.Errorf("desktop: replace state: %w", err)
	}
	return nil
}
