package desktop

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sort"
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
	maxReplayEvents         = 128
	maxPendingGuestRequests = 16
)

type wireModeLimit struct {
	ReadOnly bool     `json:"read_only,omitempty"`
	NoTools  bool     `json:"no_tools,omitempty"`
	Tools    []string `json:"tools,omitempty"`
}

type wireRequest struct {
	Type           string         `json:"type"`
	RequestID      string         `json:"request_id"`
	SessionID      string         `json:"session_id"`
	WorkspaceID    string         `json:"workspace_id"`
	Title          string         `json:"title"`
	Text           string         `json:"text"`
	RunID          string         `json:"run_id"`
	UIID           string         `json:"ui_id"`
	Confirmed      *bool          `json:"confirmed"`
	Value          *string        `json:"value"`
	Answers        [][]string     `json:"answers"`
	Cancelled      bool           `json:"cancelled"`
	AfterSeq       *int64         `json:"after_seq"`
	LinkOrigin     string         `json:"link_origin,omitempty"`
	ModeLimit      *wireModeLimit `json:"mode_limit,omitempty"`
	GuestRequestID string         `json:"guest_request_id,omitempty"`
	Action         string         `json:"action,omitempty"`
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
	SessionID   string `json:"session_id"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	Title       string `json:"title"`
	// CanRunTools is the wire-compatible name for "this user may start a
	// run". A tools grant with an empty local Tools list still allows a
	// text-only run, so ToolsEnabled separately reports whether local tools
	// are actually available.
	CanRunTools        bool   `json:"can_run_tools"`
	ToolsEnabled       bool   `json:"tools_enabled"`
	ShowThinking       bool   `json:"show_thinking,omitempty"`
	ShowTools          bool   `json:"show_tools,omitempty"`
	ApprovalPolicy     string `json:"approval_policy,omitempty"`
	HasActiveRun       bool   `json:"has_active_run,omitempty"`
	LinkOrigin         string `json:"link_origin,omitempty"`
	AllowGuestRequests bool   `json:"allow_guest_requests,omitempty"`
}

type sessionListResult struct {
	Sessions []sessionSummary `json:"sessions"`
}

type workspaceSummary struct {
	WorkspaceID        string `json:"workspace_id"`
	Title              string `json:"title"`
	ToolsEnabled       bool   `json:"tools_enabled"`
	ShowThinking       bool   `json:"show_thinking,omitempty"`
	ShowTools          bool   `json:"show_tools,omitempty"`
	ApprovalPolicy     string `json:"approval_policy,omitempty"`
	FencePeerSessions  bool   `json:"fence_peer_sessions,omitempty"`
	AllowGuestRequests bool   `json:"allow_guest_requests,omitempty"`
}

type workspaceListResult struct {
	Workspaces []workspaceSummary `json:"workspaces"`
}

type uiRespondResult struct {
	UIID   string `json:"ui_id"`
	Status string `json:"status"`
}

type GuestRequestResult struct {
	GuestRequestID string `json:"guest_request_id"`
	Status         string `json:"status"`
	RunID          string `json:"run_id,omitempty"`
}

type GuestRespondResult struct {
	GuestRequestID string `json:"guest_request_id"`
	Status         string `json:"status"`
	RunID          string `json:"run_id,omitempty"`
}

type snapshotResult struct {
	Messages     []Message          `json:"messages"`
	LastSeq      int64              `json:"last_seq"`
	PendingUI    []uiRequestData    `json:"pending_ui,omitempty"`
	PendingGuest []guestRequestData `json:"pending_guest,omitempty"`
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

type pingResult struct {
	Pong       bool  `json:"pong"`
	ServerTime int64 `json:"server_time"`
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
	case "workspace.list":
		a.handleWorkspaceList(ps, req)
	case "session.create":
		a.handleSessionCreate(ps, req)
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
	case "ui.respond":
		a.handleUIRespond(ps, req)
	case "guest.request":
		a.handleGuestRequest(ps, req)
	case "guest.respond":
		a.handleGuestRespond(ps, req)
	case "ping":
		a.handlePing(ps, req)
	default:
		a.sendError(ps, req.RequestID, codeInvalidRequest)
	}
}

func sanitizeLinkOrigin(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", true
	}
	if len(s) > 128 || !utf8.ValidString(s) || hasControl(s) || strings.Contains(s, "/") {
		return "", false
	}
	return s, true
}

func computeSessionOrigin(user string, isOwner, fence bool, rawOrigin string) (string, bool) {
	origin, ok := sanitizeLinkOrigin(rawOrigin)
	if !ok {
		return "", false
	}
	if !isOwner {
		if fence || origin != "" {
			if origin != "" {
				return user + "/" + origin, true
			}
			return user, true
		}
		return "", true
	}
	if origin != "" {
		return user + "/" + origin, true
	}
	return "", true
}

func allowsSessionFence(s *normalizedSession, user, rawOrigin string) (allowed bool, valid bool) {
	origin, ok := sanitizeLinkOrigin(rawOrigin)
	if !ok {
		return false, false
	}
	if s.owns(user) {
		if origin == "" {
			return true, true
		}
		return s.linkOrigin == user+"/"+origin, true
	}
	if !s.fencePeerSessions && origin == "" && s.linkOrigin == "" {
		return true, true
	}
	want := user
	if origin != "" {
		want = user + "/" + origin
	}
	return s.linkOrigin != "" && s.linkOrigin == want, true
}

func (a *Adapter) handlePing(ps *peerState, req wireRequest) {
	a.mu.Lock()
	closed := a.closed || ps.closed.Load()
	now := a.now().UnixMilli()
	a.mu.Unlock()
	if closed || !ps.peer.Allows(false) {
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	a.sendResult(ps, req.RequestID, pingResult{Pong: true, ServerTime: now}, "", false)
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

func (a *Adapter) handleWorkspaceList(ps *peerState, req wireRequest) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ps.pendingLists.Add(1)
	a.enqueueLocked(ps, delivery{listRequestID: req.RequestID, workspaceList: true})
}

func (a *Adapter) workspaceListLocked(user string) workspaceListResult {
	out := workspaceListResult{Workspaces: make([]workspaceSummary, 0, len(a.cfg.workspaces))}
	for _, w := range a.cfg.workspaces {
		if !w.canCreate(user) {
			continue
		}
		policy := ""
		if w.approvalPolicy == approvalRemote {
			policy = approvalRemote
		}
		out.Workspaces = append(out.Workspaces, workspaceSummary{
			WorkspaceID:        w.id,
			Title:              w.title,
			ToolsEnabled:       len(w.tools) > 0,
			ShowThinking:       w.showThinking,
			ShowTools:          w.showTools,
			ApprovalPolicy:     policy,
			FencePeerSessions:  w.fencePeerSessions,
			AllowGuestRequests: w.allowGuestRequests,
		})
	}
	return out
}

func (a *Adapter) handleSessionCreate(ps *peerState, req wireRequest) {
	user := ps.peer.UserID()
	wsID := strings.TrimSpace(req.WorkspaceID)
	if wsID == "" {
		a.sendError(ps, req.RequestID, codeInvalidRequest)
		return
	}
	title := strings.TrimSpace(req.Title)
	if len(title) > 200 || hasControl(title) {
		a.sendError(ps, req.RequestID, codeInvalidRequest)
		return
	}
	var limitTools []string
	hasToolsLimit := false
	readOnly := false
	if req.ModeLimit != nil {
		readOnly = req.ModeLimit.ReadOnly
		if req.ModeLimit.NoTools {
			hasToolsLimit = true
		} else if len(req.ModeLimit.Tools) > 0 {
			validated, err := validateTools(req.ModeLimit.Tools)
			if err != nil {
				a.sendError(ps, req.RequestID, codeInvalidRequest)
				return
			}
			hasToolsLimit = true
			limitTools = validated
		}
	}
	key := requestHash(user, wsID, req.RequestID)

	a.mu.Lock()
	if a.closed || !a.userOnlineLocked(user) || !ps.peer.Allows(true) || ps.closed.Load() {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	w := a.cfg.workspacesByID[wsID]
	if w == nil || !w.canCreate(user) {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	linkOrigin, ok := computeSessionOrigin(user, w.owns(user), w.fencePeerSessions, req.LinkOrigin)
	if !ok {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeInvalidRequest)
		return
	}
	titleFingerprint := title + "\x00" + linkOrigin
	if readOnly {
		titleFingerprint += "\x00ro"
	}
	if hasToolsLimit {
		titleFingerprint += "\x00tools:" + strings.Join(limitTools, ",")
	}
	titleSHA := payloadHash(titleFingerprint)
	if prev, exists := a.state.CreateRequests[key]; exists {
		if prev.TitleSHA != titleSHA {
			a.mu.Unlock()
			a.sendError(ps, req.RequestID, codeRequestConflict)
			return
		}
		if sr := a.sessions[prev.SessionID]; sr != nil {
			summary := a.sessionSummaryLocked(sr, user)
			a.mu.Unlock()
			a.sendResult(ps, req.RequestID, summary, prev.SessionID, true)
			return
		}
	}
	sessionID, err := newSessionID()
	if err != nil {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	if title == "" {
		title = w.title
	}
	now := a.now()
	sessionFile, err := createVanoraSessionFile(w.sessionDir, w.workDir, sessionID, now)
	if err != nil {
		a.logger.Error("create session file", "workspace", w.id, "error", err)
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	messages, stamp, err := loadSessionMessages(sessionFile)
	if err != nil {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	var effectiveToolsLimit []string
	if hasToolsLimit {
		effectiveToolsLimit = intersectTools(w.tools, limitTools)
	}
	rec := createdSessionRecord{
		ID:            sessionID,
		WorkspaceID:   w.id,
		Title:         title,
		WorkingDir:    w.workDir,
		SessionFile:   sessionFile,
		Owner:         w.owner,
		LinkOrigin:    linkOrigin,
		ReadOnly:      readOnly,
		HasToolsLimit: hasToolsLimit,
		ToolsLimit:    effectiveToolsLimit,
		Created:       now.UnixMilli(),
	}
	sCfg := sessionFromWorkspace(w, rec, sessionFile)
	psState := newPersistedSession()
	sr := &sessionRuntime{
		cfg:      sCfg,
		ps:       psState,
		messages: messages,
		stamp:    stamp,
		loaded:   true,
		runs:     make(map[string]*run),
	}
	a.sessions[sessionID] = sr
	a.state.Sessions[sessionID] = psState
	a.state.CreatedSessions[sessionID] = rec
	a.state.CreateRequests[key] = createRequestRecord{
		SessionID: sessionID,
		TitleSHA:  titleSHA,
		Created:   now.UnixMilli(),
	}
	trimMap(a.state.CreateRequests, a.cfg.retention.MaxRequests, func(r createRequestRecord) int64 { return r.Created })
	if err := a.saveLocked(); err != nil {
		delete(a.sessions, sessionID)
		delete(a.state.Sessions, sessionID)
		delete(a.state.CreatedSessions, sessionID)
		delete(a.state.CreateRequests, key)
		a.mu.Unlock()
		a.logger.Error("persist created session", "session", sessionID, "error", err)
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	summary := a.sessionSummaryLocked(sr, user)
	a.mu.Unlock()
	a.emitObserve(map[string]any{
		"type":         "session.created",
		"session_id":   sessionID,
		"workspace_id": w.id,
		"title":        title,
		"session_file": sessionFile,
	})
	a.sendResult(ps, req.RequestID, summary, sessionID, true)
}

func (a *Adapter) sessionSummaryLocked(sr *sessionRuntime, user string) sessionSummary {
	s := sr.cfg
	policy := ""
	if s.canApprove(user) {
		policy = approvalRemote
	}
	fenceOK, _ := allowsSessionFence(s, user, "")
	canRun := s.canRun(user) && fenceOK
	return sessionSummary{
		SessionID:          s.id,
		WorkspaceID:        s.workspaceID,
		Title:              s.title,
		CanRunTools:        canRun,
		ToolsEnabled:       canRun && len(s.tools) > 0,
		ShowThinking:       s.canSeeThinking(user),
		ShowTools:          s.canSeeTools(user),
		ApprovalPolicy:     policy,
		HasActiveRun:       sr.active != nil,
		LinkOrigin:         s.linkOrigin,
		AllowGuestRequests: s.allowGuestRequests,
	}
}

func (a *Adapter) sessionListLocked(user string) sessionListResult {
	ordered := a.orderedSessionsLocked()
	out := sessionListResult{Sessions: make([]sessionSummary, 0, len(ordered))}
	for _, sr := range ordered {
		if !sr.cfg.canRead(user) {
			continue
		}
		out.Sessions = append(out.Sessions, a.sessionSummaryLocked(sr, user))
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
	rawMsgs := append([]Message(nil), sr.messages...)
	if sr.active != nil && (sr.active.pending.Len() > 0 || sr.active.pendingThinking.Len() > 0 || len(sr.active.pendingToolCalls) > 0) {
		// session.open and last_seq are read under the same lock, so an event
		// accepted after this point has a sequence greater than LastSeq.
		rawMsgs = append(rawMsgs, Message{
			Role:      "assistant",
			Text:      sr.active.pending.String(),
			Thinking:  sr.active.pendingThinking.String(),
			ToolCalls: append([]ToolCallSummary(nil), sr.active.pendingToolCalls...),
			Timestamp: sr.active.pendingTimestamp,
		})
	}
	visibleMsgs := filterMessagesForViewer(rawMsgs, sr.cfg.canSeeThinking(user), sr.cfg.canSeeTools(user))
	snapshot := snapshotResult{
		Messages: visibleMsgs,
		LastSeq:  sr.ps.LastSeq,
	}
	if sr.active != nil && sr.cfg.canApprove(user) && (sr.cfg.owns(user) || user == sr.active.userID) && len(sr.active.pendingUI) > 0 {
		pending := make([]uiRequestData, 0, len(sr.active.pendingUI))
		for _, pui := range sr.active.pendingUI {
			if !pui.resolved {
				pending = append(pending, pui.info)
			}
		}
		sort.Slice(pending, func(i, j int) bool { return pending[i].UIID < pending[j].UIID })
		snapshot.PendingUI = pending
	}
	if len(sr.ps.PendingGuest) > 0 {
		var guests []guestRequestData
		for _, item := range sr.ps.PendingGuest {
			if sr.cfg.owns(user) || item.UserID == user {
				guests = append(guests, item)
			}
		}
		snapshot.PendingGuest = guests
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
		approvalUser := e.ApprovalUser
		if e.Visibility == visApproval && approvalUser == "" && e.RunID != "" {
			if rec, ok := sr.ps.Runs[e.RunID]; ok {
				approvalUser = rec.UserID
			}
		}
		visible := sr.cfg.canSeeEvent(user, e.Visibility)
		if visible && (e.Visibility == visApproval || e.Visibility == visGuest) && !sr.cfg.owns(user) && (approvalUser == "" || user != approvalUser) {
			visible = false
		}
		var wire []byte
		var err error
		if visible {
			wire, err = json.Marshal(wireEvent{
				Type:      "event",
				SessionID: req.SessionID,
				RunID:     e.RunID,
				Seq:       e.Seq,
				Kind:      e.Kind,
				Data:      e.Data,
			})
		} else {
			wire, err = json.Marshal(wireEvent{
				Type:      "event",
				SessionID: req.SessionID,
				Seq:       e.Seq,
				Kind:      kindSync,
			})
		}
		if err != nil {
			continue
		}
		a.enqueueLocked(ps, delivery{
			data:           wire,
			requiresOnline: e.RequiresOnline,
			sessionID:      req.SessionID,
			visibility:     e.Visibility,
			approvalUser:   approvalUser,
			seq:            e.Seq,
		})
	}
}

func (a *Adapter) handleUIRespond(ps *peerState, req wireRequest) {
	user := ps.peer.UserID()
	if req.SessionID == "" || req.RunID == "" || req.UIID == "" {
		a.sendError(ps, req.RequestID, codeInvalidRequest)
		return
	}
	a.mu.Lock()
	if a.closed || !a.userOnlineLocked(user) || !ps.peer.Allows(true) || ps.closed.Load() {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	sr, ok := a.sessions[req.SessionID]
	if !ok || !sr.cfg.canApprove(user) {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	if fenceOK, valid := allowsSessionFence(sr.cfg, user, req.LinkOrigin); !valid {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeInvalidRequest)
		return
	} else if !fenceOK {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeToolDenied)
		return
	}
	r := sr.runs[req.RunID]
	if r == nil || r.terminal || r.stopFlag.Load() || !a.userOnlineLocked(r.userID) {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	if !sr.cfg.owns(user) && user != r.userID {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	pui := r.pendingUI[req.UIID]
	if pui == nil || pui.resolved {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	reply := map[string]any{
		"type": "extension_ui_response",
		"id":   req.UIID,
	}
	status := "responded"
	if req.Cancelled {
		reply["cancelled"] = true
		status = "cancelled"
	} else {
		switch pui.info.Method {
		case "confirm":
			if req.Confirmed == nil {
				a.mu.Unlock()
				a.sendError(ps, req.RequestID, codeInvalidRequest)
				return
			}
			reply["confirmed"] = *req.Confirmed
		case "select", "input", "editor":
			if req.Value == nil {
				a.mu.Unlock()
				a.sendError(ps, req.RequestID, codeInvalidRequest)
				return
			}
			reply["value"] = *req.Value
		case "ask":
			if req.Answers == nil {
				a.mu.Unlock()
				a.sendError(ps, req.RequestID, codeInvalidRequest)
				return
			}
			reply["answers"] = req.Answers
		default:
			a.mu.Unlock()
			a.sendError(ps, req.RequestID, codeUnavailable)
			return
		}
	}
	pui.resolved = true
	if pui.timer != nil {
		pui.timer.Stop()
	}
	delete(r.pendingUI, req.UIID)
	hasMoreUI := len(r.pendingUI) > 0
	a.appendEventVisibleLocked(sr, r.id, kindUIResolved, uiResolvedData{UIID: req.UIID, Status: status}, true, visApproval, r.userID)
	a.mu.Unlock()

	if err := r.writeJSON(reply); err != nil {
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	if !hasMoreUI {
		a.emitActivity(ActivityEvent{
			SessionID: req.SessionID,
			RunID:     req.RunID,
			Phase:     statusRunning,
		})
	}
	a.emitObserve(map[string]any{
		"type":       "ui.resolved",
		"session_id": req.SessionID,
		"run_id":     req.RunID,
		"ui_id":      req.UIID,
		"status":     status,
	})
	a.sendResult(ps, req.RequestID, uiRespondResult{UIID: req.UIID, Status: status}, req.SessionID, true)
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
	if fenceOK, valid := allowsSessionFence(sr.cfg, user, req.LinkOrigin); !valid {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeInvalidRequest)
		return
	} else if !fenceOK {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeToolDenied)
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
			if rec.UserID != user && !sr.cfg.owns(user) {
				a.mu.Unlock()
				a.sendError(ps, req.RequestID, codeUnavailable)
				return
			}
			a.mu.Unlock()
			a.sendResult(ps, req.RequestID, runStatusResult{RunID: req.RunID, Status: rec.Status}, req.SessionID, false)
			return
		}
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	if r.userID != user && !sr.cfg.owns(user) {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	status := r.status
	transitioned := status == statusRunning
	var uiCancels []uiCancelAction
	if transitioned {
		r.status = statusCancelling
		r.stopReason = "requested"
		r.stopFlag.Store(true)
		uiCancels = a.cancelRunPendingUILocked(r, "cancelled")
		status = statusCancelling
	}
	a.sendResultLocked(ps, req.RequestID, runStatusResult{RunID: r.id, Status: status}, req.SessionID, r.tools)
	a.mu.Unlock()
	flushUICancels(uiCancels)
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
	var limitTools []string
	hasToolsLimit := false
	if req.ModeLimit != nil {
		if req.ModeLimit.ReadOnly {
			return "", nil, codeToolDenied
		}
		if req.ModeLimit.NoTools {
			hasToolsLimit = true
		} else if len(req.ModeLimit.Tools) > 0 {
			validated, err := validateTools(req.ModeLimit.Tools)
			if err != nil {
				return "", nil, codeInvalidRequest
			}
			hasToolsLimit = true
			limitTools = validated
		}
	}
	textFingerprint := req.Text
	if req.LinkOrigin != "" {
		textFingerprint += "\x00origin:" + strings.TrimSpace(req.LinkOrigin)
	}
	if hasToolsLimit {
		textFingerprint += "\x00tools:" + strings.Join(limitTools, ",")
	}
	textHash := payloadHash(textFingerprint)
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
	if fenceOK, valid := allowsSessionFence(sr.cfg, user, req.LinkOrigin); !valid {
		a.mu.Unlock()
		return "", nil, codeInvalidRequest
	} else if !fenceOK {
		a.mu.Unlock()
		return "", nil, codeToolDenied
	}
	if !a.userOnlineLocked(user) || !ps.peer.Allows(true) || ps.closed.Load() {
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
	runCfg := sr.cfg
	if hasToolsLimit {
		narrowed := *sr.cfg
		narrowed.tools = intersectTools(sr.cfg.tools, limitTools)
		runCfg = &narrowed
	}
	runID, err := newRunID()
	if err != nil {
		a.mu.Unlock()
		a.logger.Error("generate run id", "session", sr.cfg.id, "error", err)
		return "", nil, codeUnavailable
	}
	cmd, err := a.buildCommand(runCfg)
	if err != nil {
		a.mu.Unlock()
		a.logger.Error("build vanora command", "session", sr.cfg.id, "error", err)
		return "", nil, codeUnavailable
	}
	if runCfg.linkOrigin != "" {
		if cmd.Env == nil {
			cmd.Env = os.Environ()
		}
		cmd.Env = append(cmd.Env, "VANORA_LINK_ORIGIN="+runCfg.linkOrigin)
	}
	r := &run{
		id:               runID,
		sessionID:        sr.cfg.id,
		session:          sr,
		userID:           user,
		requestID:        req.RequestID,
		text:             req.Text,
		tools:            len(runCfg.tools) > 0,
		started:          a.now().UnixMilli(),
		status:           statusRunning,
		pendingTimestamp: a.now().UnixMilli(),
		pendingUI:        make(map[string]*pendingUIRequest),
		done:             make(chan struct{}),
	}
	if officialRun(r) {
		r.authorityUntil = a.authorityUntil
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
	sessionID := sr.cfg.id
	a.mu.Unlock()

	a.emitActivity(ActivityEvent{
		SessionID: sessionID,
		RunID:     runID,
		Phase:     statusRunning,
	})
	return runID, r, ""
}

func (a *Adapter) handleGuestRequest(ps *peerState, req wireRequest) {
	user := ps.peer.UserID()
	if req.SessionID == "" || req.Text == "" || !utf8.ValidString(req.Text) || strings.TrimSpace(req.Text) == "" {
		a.sendError(ps, req.RequestID, codeInvalidRequest)
		return
	}
	textHash := payloadHash(req.Text)
	key := requestHash(user, req.SessionID, req.RequestID)

	a.mu.Lock()
	if a.closed || ps.closed.Load() || !ps.peer.Allows(false) {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	if len(req.Text) > a.cfg.maxText {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeInvalidRequest)
		return
	}
	if !a.cfg.allowSlash && strings.HasPrefix(strings.TrimLeft(req.Text, " \t\r\n"), "/") {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeToolDenied)
		return
	}
	sr, ok := a.sessions[req.SessionID]
	if !ok || !sr.cfg.canRead(user) {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	if !sr.cfg.allowGuestRequests {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeToolDenied)
		return
	}
	if prev, exists := sr.ps.GuestRequests[key]; exists {
		if prev.TextSHA != textHash {
			a.mu.Unlock()
			a.sendError(ps, req.RequestID, codeRequestConflict)
			return
		}
		res := GuestRequestResult{
			GuestRequestID: prev.GuestRequestID,
			Status:         prev.Status,
			RunID:          prev.RunID,
		}
		a.mu.Unlock()
		a.sendResult(ps, req.RequestID, res, req.SessionID, false)
		return
	}
	if len(sr.ps.PendingGuest) >= maxPendingGuestRequests {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	guestID, err := newRunID()
	if err != nil {
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	now := a.now().UnixMilli()
	item := guestRequestData{
		GuestRequestID: guestID,
		SessionID:      sr.cfg.id,
		UserID:         user,
		Text:           req.Text,
		CreatedAt:      now,
	}
	sr.ps.PendingGuest = append(sr.ps.PendingGuest, item)
	sr.ps.GuestRequests[key] = guestRequestRecord{
		GuestRequestID: guestID,
		TextSHA:        textHash,
		Status:         "pending",
		Created:        now,
	}
	a.appendEventVisibleLocked(sr, "", kindGuestRequest, item, false, visGuest, user)
	sr.ps.trim(a.cfg.retention)
	if err := a.saveLocked(); err != nil {
		sr.ps.PendingGuest = sr.ps.PendingGuest[:len(sr.ps.PendingGuest)-1]
		delete(sr.ps.GuestRequests, key)
		a.mu.Unlock()
		a.sendError(ps, req.RequestID, codeUnavailable)
		return
	}
	sessionID := sr.cfg.id
	a.mu.Unlock()

	a.emitObserve(map[string]any{
		"type":             "guest.request",
		"session_id":       sessionID,
		"guest_request_id": guestID,
		"user_id":          user,
		"text":             req.Text,
	})
	a.emitActivity(ActivityEvent{
		SessionID: sessionID,
		Phase:     "awaiting_guest_approval",
		UIID:      guestID,
	})
	a.sendResult(ps, req.RequestID, GuestRequestResult{
		GuestRequestID: guestID,
		Status:         "pending",
	}, sessionID, false)
}

func (a *Adapter) handleGuestRespond(ps *peerState, req wireRequest) {
	user := ps.peer.UserID()
	res, r, code := a.respondGuest(user, false, ps, req.SessionID, req.GuestRequestID, req.Action)
	if code != "" {
		a.sendError(ps, req.RequestID, code)
		return
	}
	a.sendResult(ps, req.RequestID, res, req.SessionID, res.Status == "approved")
	if r != nil {
		go a.executeRun(r)
	}
}

// RespondGuestLocal approves or dismisses a pending guest prompt request on
// behalf of the local desktop host user (e.g. via Sidecar session.guest.respond).
func (a *Adapter) RespondGuestLocal(sessionID, guestRequestID, action string) (GuestRespondResult, error) {
	res, r, code := a.respondGuest("", true, nil, sessionID, guestRequestID, action)
	if code != "" {
		return GuestRespondResult{}, errors.New(code)
	}
	if r != nil {
		go a.executeRun(r)
	}
	return res, nil
}

func (a *Adapter) respondGuest(user string, localHost bool, ps *peerState, sessionID, guestRequestID, rawAction string) (GuestRespondResult, *run, string) {
	sessionID = strings.TrimSpace(sessionID)
	guestRequestID = strings.TrimSpace(guestRequestID)
	action := strings.ToLower(strings.TrimSpace(rawAction))
	if sessionID == "" || guestRequestID == "" || (action != "approve" && action != "dismiss") {
		return GuestRespondResult{}, nil, codeInvalidRequest
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return GuestRespondResult{}, nil, codeUnavailable
	}
	if !localHost && (ps == nil || ps.closed.Load() || !ps.peer.Allows(action == "approve") || (action == "approve" && !a.userOnlineLocked(user))) {
		a.mu.Unlock()
		return GuestRespondResult{}, nil, codeUnavailable
	}
	sr, ok := a.sessions[sessionID]
	if !ok {
		a.mu.Unlock()
		return GuestRespondResult{}, nil, codeUnavailable
	}
	if !localHost {
		if !sr.cfg.canRead(user) {
			a.mu.Unlock()
			return GuestRespondResult{}, nil, codeUnavailable
		}
		if !sr.cfg.owns(user) {
			a.mu.Unlock()
			return GuestRespondResult{}, nil, codeToolDenied
		}
	}
	idx := slices.IndexFunc(sr.ps.PendingGuest, func(g guestRequestData) bool {
		return g.GuestRequestID == guestRequestID
	})
	if idx < 0 {
		a.mu.Unlock()
		return GuestRespondResult{}, nil, codeUnavailable
	}
	item := sr.ps.PendingGuest[idx]

	updateIdempotency := func(status, runID string) {
		for k, rec := range sr.ps.GuestRequests {
			if rec.GuestRequestID == guestRequestID {
				rec.Status = status
				rec.RunID = runID
				sr.ps.GuestRequests[k] = rec
			}
		}
	}

	if action == "dismiss" {
		sr.ps.PendingGuest = slices.Delete(sr.ps.PendingGuest, idx, idx+1)
		updateIdempotency("dismissed", "")
		a.appendEventVisibleLocked(sr, "", kindGuestResolved, guestResolvedData{
			GuestRequestID: guestRequestID,
			Status:         "dismissed",
		}, false, visGuest, item.UserID)
		_ = a.saveLocked()
		nextPhase := "cleared"
		var activeRunID string
		if sr.active != nil {
			nextPhase = statusRunning
			activeRunID = sr.active.id
		} else if len(sr.ps.PendingGuest) > 0 {
			nextPhase = "awaiting_guest_approval"
		}
		a.mu.Unlock()
		a.emitObserve(map[string]any{
			"type":             "guest.resolved",
			"session_id":       sessionID,
			"guest_request_id": guestRequestID,
			"status":           "dismissed",
		})
		a.emitActivity(ActivityEvent{
			SessionID: sessionID,
			RunID:     activeRunID,
			Phase:     nextPhase,
		})
		return GuestRespondResult{GuestRequestID: guestRequestID, Status: "dismissed"}, nil, ""
	}

	// action == "approve"
	if sr.active != nil || sr.cfg.readOnly {
		a.mu.Unlock()
		return GuestRespondResult{}, nil, codeUnavailable
	}
	runID, err := newRunID()
	if err != nil {
		a.mu.Unlock()
		return GuestRespondResult{}, nil, codeUnavailable
	}
	cmd, err := a.buildCommand(sr.cfg)
	if err != nil {
		a.mu.Unlock()
		return GuestRespondResult{}, nil, codeUnavailable
	}
	if sr.cfg.linkOrigin != "" {
		if cmd.Env == nil {
			cmd.Env = os.Environ()
		}
		cmd.Env = append(cmd.Env, "VANORA_LINK_ORIGIN="+sr.cfg.linkOrigin)
	}
	runUser := user
	if localHost {
		runUser = sr.cfg.owner
	}
	now := a.now().UnixMilli()
	r := &run{
		id:               runID,
		sessionID:        sr.cfg.id,
		session:          sr,
		userID:           runUser,
		localApproved:    localHost,
		requestID:        guestRequestID,
		text:             item.Text,
		tools:            len(sr.cfg.tools) > 0,
		started:          now,
		status:           statusRunning,
		pendingTimestamp: now,
		pendingUI:        make(map[string]*pendingUIRequest),
		done:             make(chan struct{}),
	}
	if officialRun(r) {
		r.authorityUntil = a.authorityUntil
	}
	sr.ps.PendingGuest = slices.Delete(sr.ps.PendingGuest, idx, idx+1)
	updateIdempotency("approved", runID)
	sr.active = r
	sr.runs[runID] = r
	a.runs[runID] = r
	sr.ps.Runs[runID] = runRecord{Status: statusRunning, UserID: runUser, Tools: r.tools, Created: now}
	a.appendEventVisibleLocked(sr, runID, kindGuestResolved, guestResolvedData{
		GuestRequestID: guestRequestID,
		Status:         "approved",
		RunID:          runID,
	}, false, visGuest, item.UserID)
	sr.ps.trim(a.cfg.retention)
	if err := a.saveLocked(); err != nil {
		delete(sr.ps.Runs, runID)
		delete(sr.runs, runID)
		delete(a.runs, runID)
		sr.active = nil
		a.mu.Unlock()
		return GuestRespondResult{}, nil, codeUnavailable
	}
	handle, err := startProcess(cmd)
	if err != nil {
		delete(sr.ps.Runs, runID)
		delete(sr.runs, runID)
		delete(a.runs, runID)
		sr.active = nil
		_ = a.saveLocked()
		a.mu.Unlock()
		return GuestRespondResult{}, nil, codeUnavailable
	}
	r.handle = handle
	a.wg.Add(1)
	a.mu.Unlock()

	a.emitObserve(map[string]any{
		"type":             "guest.resolved",
		"session_id":       sessionID,
		"guest_request_id": guestRequestID,
		"status":           "approved",
		"run_id":           runID,
	})
	a.emitActivity(ActivityEvent{
		SessionID: sessionID,
		RunID:     runID,
		Phase:     statusRunning,
	})
	return GuestRespondResult{
		GuestRequestID: guestRequestID,
		Status:         "approved",
		RunID:          runID,
	}, r, ""
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
