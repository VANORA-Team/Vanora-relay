package desktop

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	codeUnavailable     = "unavailable"
	codeToolDenied      = "tool_denied"
	codeRequestConflict = "request_conflict"
	codeSnapshotNeeded  = "snapshot_required"
	codeSnapshotLarge   = "snapshot_too_large"
	codeInvalidRequest  = "invalid_request"
	// maxReplayEvents bounds a single resume response well below the peer
	// output queue. A larger backlog is served by a fresh snapshot instead of
	// filling the queue and disconnecting the peer.
	maxReplayEvents = 128
)

type wireRequest struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	SessionID string `json:"session_id"`
	Text      string `json:"text"`
	RunID     string `json:"run_id"`
	AfterSeq  *int64 `json:"after_seq"`
}

type resultEnvelope struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id,omitempty"`
	Data      any    `json:"data,omitempty"`
}

type errorEnvelope struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id,omitempty"`
	Code      string `json:"code"`
}

type wireEvent struct {
	Type      string          `json:"type"`
	SessionID string          `json:"session_id"`
	RunID     string          `json:"run_id,omitempty"`
	Seq       int64           `json:"seq"`
	Kind      string          `json:"kind"`
	Data      json.RawMessage `json:"data,omitempty"`
}

type sessionSummary struct {
	SessionID string `json:"session_id"`
	Title     string `json:"title"`
	// CanRunTools is the wire-compatible name for "this user may start a
	// run". A tools grant with an empty local Tools list still allows a
	// text-only run, so ToolsEnabled separately reports whether local tools
	// are actually available.
	CanRunTools  bool `json:"can_run_tools"`
	ToolsEnabled bool `json:"tools_enabled"`
}

type sessionListResult struct {
	Sessions []sessionSummary `json:"sessions"`
}

type snapshotResult struct {
	Messages []Message `json:"messages"`
	LastSeq  int64     `json:"last_seq"`
}

type runStartedResult struct {
	RunID string `json:"run_id"`
}

type runStatusResult struct {
	RunID  string `json:"run_id"`
	Status string `json:"status"`
}

type resumeResult struct {
	SessionID string `json:"session_id"`
	AfterSeq  int64  `json:"after_seq"`
}

func (a *Adapter) handleData(ps *peerState, data []byte) {
	if len(data) == 0 {
		a.sendError(ps, "", codeInvalidRequest)
		return
	}
	a.mu.Lock()
	maxRequestBytes := a.maxRequestBytes
	a.mu.Unlock()
	if len(data) > maxRequestBytes {
		a.sendError(ps, "", codeInvalidRequest)
		return
	}
	var req wireRequest
	if err := json.Unmarshal(data, &req); err != nil {
		a.sendError(ps, "", codeInvalidRequest)
		return
	}
	if !validRequestID(req.RequestID) {
		a.sendError(ps, "", codeInvalidRequest)
		return
	}
	switch req.Type {
	case "session.list":
		a.handleSessionList(ps, req)
	case "session.open":
		a.handleSessionOpen(ps, req)
	case "events.resume":
		a.handleEventsResume(ps, req)
	case "run.start":
		a.handleRunStart(ps, req)
	case "run.cancel":
		a.handleRunCancel(ps, req)
	default:
		a.sendError(ps, req.RequestID, codeInvalidRequest)
	}
}

func validRequestID(id string) bool {
	if id == "" || len(id) > 256 || !utf8.ValidString(id) {
		return false
	}
	return !hasControl(id)
}

func (a *Adapter) handleSessionList(ps *peerState, req wireRequest) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Rebuild at delivery time rather than snapshotting here: an ACL reload
	// could otherwise leave a stale list in the peer's output queue.
	ps.pendingLists.Add(1)
	a.enqueueLocked(ps, delivery{listRequestID: req.RequestID})
}

func (a *Adapter) sessionListLocked(user string) sessionListResult {
	out := sessionListResult{Sessions: make([]sessionSummary, 0, len(a.cfg.sessions))}
	for _, s := range a.cfg.sessions {
		if !s.canRead(user) {
			continue
		}
		out.Sessions = append(out.Sessions, sessionSummary{
			SessionID:    s.id,
			Title:        s.title,
			CanRunTools:  s.canRun(user),
			ToolsEnabled: s.canRun(user) && len(s.tools) > 0,
		})
	}
	return out
}

func (a *Adapter) handleSessionOpen(ps *peerState, req wireRequest) {
	user := ps.peer.UserID()
	a.mu.Lock()
	defer a.mu.Unlock()
	sr, ok := a.sessions[req.SessionID]
	if !ok || !sr.cfg.canRead(user) {
		// Do not attach the requested session id to this delivery. The
		// delivery ACL check would otherwise suppress the error itself.
		delete(ps.subscriptions, req.SessionID)
		a.sendErrorLocked(ps, req.RequestID, codeUnavailable, "", false)
		return
	}
	sr.syncLocked(a)
	snapshot := snapshotResult{
		Messages: append([]Message(nil), sr.messages...),
		LastSeq:  sr.ps.LastSeq,
	}
	if sr.active != nil && sr.active.pending.Len() > 0 {
		// session.open and last_seq are read under the same lock, so an event
		// accepted after this point has a sequence greater than LastSeq.
		snapshot.Messages = append(snapshot.Messages, Message{
			Role:      "assistant",
			Text:      sr.active.pending.String(),
			Timestamp: sr.active.pendingTimestamp,
		})
	}
	if snapshot.Messages == nil {
		snapshot.Messages = []Message{}
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		delete(ps.subscriptions, req.SessionID)
		a.sendErrorLocked(ps, req.RequestID, codeUnavailable, "", false)
		return
	}
	if len(encoded) > a.cfg.maxSnapshot {
		// A bounded error is preferable to a frame the transport must reject
		// or a phone that waits forever for a snapshot it cannot receive.
		delete(ps.subscriptions, req.SessionID)
		a.sendErrorLocked(ps, req.RequestID, codeSnapshotLarge, "", false)
		return
	}
	ps.subscriptions[req.SessionID] = struct{}{}
	a.sendResultLocked(ps, req.RequestID, snapshot, req.SessionID, false)
}

func (a *Adapter) handleEventsResume(ps *peerState, req wireRequest) {
	user := ps.peer.UserID()
	if req.AfterSeq == nil || *req.AfterSeq < 0 {
		a.sendError(ps, req.RequestID, codeInvalidRequest)
		return
	}
	after := *req.AfterSeq
	a.mu.Lock()
	defer a.mu.Unlock()
	sr, ok := a.sessions[req.SessionID]
	if !ok || !sr.cfg.canRead(user) {
		delete(ps.subscriptions, req.SessionID)
		a.sendErrorLocked(ps, req.RequestID, codeUnavailable, "", false)
		return
	}
	last := sr.ps.LastSeq
	first := sr.ps.FirstSeq
	if after > last || (last > 0 && (first == 0 || after < first-1)) {
		delete(ps.subscriptions, req.SessionID)
		a.sendErrorLocked(ps, req.RequestID, codeSnapshotNeeded, "", false)
		return
	}
	pending := 0
	for _, e := range sr.ps.Events {
		if e.Seq > after {
			pending++
		}
	}
	// Replaying a large backlog while holding Adapter.mu would starve the
	// peer writer and deterministically fill the bounded output queue. Ask
	// for a fresh snapshot instead, and do not subscribe: live events would
	// create a gap the client could not fill after the rejected resume.
	free := cap(ps.out) - len(ps.out)
	if pending > maxReplayEvents || pending+1 > free {
		delete(ps.subscriptions, req.SessionID)
		if free > 0 {
			a.sendErrorLocked(ps, req.RequestID, codeSnapshotNeeded, "", false)
		}
		return
	}
	ps.subscriptions[req.SessionID] = struct{}{}
	a.sendResultLocked(ps, req.RequestID, resumeResult{SessionID: req.SessionID, AfterSeq: after}, req.SessionID, false)
	for _, e := range sr.ps.Events {
		if e.Seq <= after {
			continue
		}
		wire, err := json.Marshal(wireEvent{
			Type:      "event",
			SessionID: req.SessionID,
			RunID:     e.RunID,
			Seq:       e.Seq,
			Kind:      e.Kind,
			Data:      e.Data,
		})
		if err != nil {
			continue
		}
		a.enqueueLocked(ps, delivery{data: wire, requiresOnline: e.RequiresOnline, sessionID: req.SessionID})
	}
}

func (a *Adapter) handleRunCancel(ps *peerState, req wireRequest) {
	user := ps.peer.UserID()
	if req.SessionID == "" || req.RunID == "" {
		a.sendError(ps, req.RequestID, codeInvalidRequest)
		return
	}
	a.mu.Lock()
	sr, ok := a.sessions[req.SessionID]
	if !ok || !sr.cfg.canRead(user) {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	var r *run
	if sr.active != nil && sr.active.id == req.RunID {
		r = sr.active
	} else if sr.runs[req.RunID] != nil {
		r = sr.runs[req.RunID]
	}
	if r == nil {
		if rec, exists := sr.ps.Runs[req.RunID]; exists {
			a.mu.Unlock()
			a.sendResult(ps, req.RequestID, runStatusResult{RunID: req.RunID, Status: rec.Status}, req.SessionID, false)
			return
		}
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	if r.userID != user && sr.cfg.owner != user {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	status := r.status
	transitioned := status == statusRunning
	if transitioned {
		r.status = statusCancelling
		r.stopReason = "requested"
		r.stopFlag.Store(true)
		status = statusCancelling
	}
	a.sendResultLocked(ps, req.RequestID, runStatusResult{RunID: r.id, Status: status}, req.SessionID, r.tools)
	a.mu.Unlock()
	if transitioned {
		// Give upstream a moment to finish the current model step cleanly;
		// authority loss and shutdown use an immediate kill instead.
		r.stop(5 * time.Second)
	}
}

func (a *Adapter) handleRunStart(ps *peerState, req wireRequest) {
	runID, r, code := a.startRun(ps, req)
	if code != "" {
		a.sendError(ps, req.RequestID, code)
		return
	}
	// Enqueue the run id before the process reader can enqueue any event, so
	// a client never observes text for a run it has not learned about.
	a.sendResult(ps, req.RequestID, runStartedResult{RunID: runID}, req.SessionID, true)
	if r != nil {
		go a.executeRun(r)
	}
}

func (a *Adapter) startRun(ps *peerState, req wireRequest) (string, *run, string) {
	user := ps.peer.UserID()
	if req.SessionID == "" || req.Text == "" || !utf8.ValidString(req.Text) {
		return "", nil, codeInvalidRequest
	}
	if strings.TrimSpace(req.Text) == "" {
		return "", nil, codeInvalidRequest
	}
	textHash := payloadHash(req.Text)
	key := requestHash(user, req.SessionID, req.RequestID)

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return "", nil, codeUnavailable
	}
	if len(req.Text) > a.cfg.maxText {
		a.mu.Unlock()
		return "", nil, codeInvalidRequest
	}
	if !a.cfg.allowSlash && strings.HasPrefix(strings.TrimLeft(req.Text, " \t\r\n"), "/") {
		a.mu.Unlock()
		return "", nil, codeToolDenied
	}
	sr, ok := a.sessions[req.SessionID]
	if !ok || !sr.cfg.canRead(user) {
		a.mu.Unlock()
		return "", nil, codeUnavailable
	}
	if !sr.cfg.canRun(user) {
		a.mu.Unlock()
		return "", nil, codeToolDenied
	}
	if !a.effectiveOnlineLocked() || !ps.peer.Allows(true) || ps.closed.Load() {
		a.mu.Unlock()
		return "", nil, codeUnavailable
	}
	if rec, exists := sr.ps.Requests[key]; exists {
		a.mu.Unlock()
		if rec.TextSHA != textHash {
			return "", nil, codeRequestConflict
		}
		return rec.RunID, nil, ""
	}
	if sr.active != nil {
		a.mu.Unlock()
		return "", nil, codeUnavailable
	}
	runID, err := newRunID()
	if err != nil {
		a.mu.Unlock()
		a.logger.Error("generate run id", "session", sr.cfg.id, "error", err)
		return "", nil, codeUnavailable
	}
	cmd, err := a.buildCommand(sr.cfg)
	if err != nil {
		a.mu.Unlock()
		a.logger.Error("build vanora command", "session", sr.cfg.id, "error", err)
		return "", nil, codeUnavailable
	}
	r := &run{
		id:               runID,
		sessionID:        sr.cfg.id,
		session:          sr,
		userID:           user,
		requestID:        req.RequestID,
		text:             req.Text,
		tools:            len(sr.cfg.tools) > 0,
		started:          a.now().UnixMilli(),
		status:           statusRunning,
		authorityUntil:   a.authorityUntil,
		pendingTimestamp: a.now().UnixMilli(),
		done:             make(chan struct{}),
	}
	discardRun := func() {
		delete(sr.ps.Requests, key)
		delete(sr.ps.Runs, runID)
		delete(sr.runs, runID)
		delete(a.runs, runID)
		sr.active = nil
	}
	sr.active = r
	sr.runs[runID] = r
	a.runs[runID] = r
	sr.ps.Requests[key] = requestRecord{RunID: runID, TextSHA: textHash, Created: r.started}
	sr.ps.Runs[runID] = runRecord{Status: statusRunning, UserID: user, Tools: r.tools, Created: r.started}
	sr.ps.trim(a.cfg.retention)
	// Persist the idempotency record before spawning. A crash between this
	// write and the process start must not let a retry create a second run;
	// recovery marks the incomplete record failed instead.
	if err := a.saveLocked(); err != nil {
		discardRun()
		a.mu.Unlock()
		a.logger.Error("persist run request", "session", sr.cfg.id, "run", runID, "error", err)
		return "", nil, codeUnavailable
	}
	handle, err := startProcess(cmd)
	if err != nil {
		discardRun()
		if saveErr := a.saveLocked(); saveErr != nil {
			a.logger.Error("persist failed run start", "session", sr.cfg.id, "run", runID, "error", saveErr)
		}
		a.mu.Unlock()
		a.logger.Error("start vanora", "session", sr.cfg.id, "error", err)
		return "", nil, codeUnavailable
	}
	r.handle = handle
	a.wg.Add(1)
	a.mu.Unlock()

	return runID, r, ""
}

func (a *Adapter) sendResult(ps *peerState, requestID string, data any, sessionID string, requiresOnline bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sendResultLocked(ps, requestID, data, sessionID, requiresOnline)
}

func (a *Adapter) sendResultLocked(ps *peerState, requestID string, data any, sessionID string, requiresOnline bool) {
	wire, err := json.Marshal(resultEnvelope{Type: "result", RequestID: requestID, Data: data})
	if err != nil {
		a.logger.Error("encode result", "request", requestID, "error", err)
		return
	}
	a.enqueueLocked(ps, delivery{data: wire, requiresOnline: requiresOnline, sessionID: sessionID})
}

func (a *Adapter) sendError(ps *peerState, requestID, code string) {
	a.sendErrorLocked(ps, requestID, code, "", false)
}

func (a *Adapter) sendErrorLocked(ps *peerState, requestID, code, sessionID string, requiresOnline bool) {
	wire, err := json.Marshal(errorEnvelope{Type: "error", RequestID: requestID, Code: code})
	if err != nil {
		return
	}
	a.enqueueLocked(ps, delivery{data: wire, requiresOnline: requiresOnline, sessionID: sessionID})
}

func (a *Adapter) enqueueLocked(ps *peerState, d delivery) {
	if ps == nil || ps.closed.Load() {
		return
	}
	select {
	case ps.out <- d:
	default:
		// A peer that cannot drain ordered output is disconnected so that its
		// client reconnects and resumes from its cursor. The retained event log
		// is the recovery path.
		a.logger.Warn("peer output queue full", "user", ps.peer.UserID())
		go a.closePeer(ps)
	}
}
