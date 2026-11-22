package desktop

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

type processHandle struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser

	stdinOnce sync.Once
	waitOnce  sync.Once
}

const (
	defaultUIApprovalTimeout = 5 * time.Minute
	maxPendingUI             = 8
	maxToolUpdateBytes       = 4 << 10
)

type pendingUIRequest struct {
	info     uiRequestData
	timer    *time.Timer
	resolved bool
}

type uiCancelAction struct {
	r  *run
	id string
}

func flushUICancels(actions []uiCancelAction) {
	for _, act := range actions {
		if act.r == nil || act.id == "" {
			continue
		}
		_ = act.r.writeJSON(map[string]any{
			"type":      "extension_ui_response",
			"id":        act.id,
			"cancelled": true,
		})
	}
}

type run struct {
	id             string
	sessionID      string
	session        *sessionRuntime
	userID         string
	requestID      string
	text           string
	tools          bool
	started        int64
	status         string
	authorityUntil time.Time

	// stopFlag is set under Adapter.mu whenever status becomes cancelling. It
	// lets the process reader notice a kill without reading locked fields.
	stopFlag   atomic.Bool
	stopOnce   sync.Once
	timerMu    sync.Mutex
	stopTimer  *time.Timer
	stopReason string

	handle  *processHandle
	writeMu sync.Mutex

	pending          strings.Builder
	pendingThinking  strings.Builder
	pendingToolCalls []ToolCallSummary
	pendingTimestamp int64
	sawUser          bool
	sawDelta         bool
	sawThinkingDelta bool
	promptHandled    bool
	settled          bool
	aborted          bool
	upstreamError    bool
	failReason       string

	pendingUI map[string]*pendingUIRequest

	terminal   bool
	finishOnce sync.Once
	done       chan struct{}
}

func startProcess(cmd *exec.Cmd) (*processHandle, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		stdout.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return nil, err
	}
	return &processHandle{cmd: cmd, stdin: stdin, stdout: stdout, stderr: stderr}, nil
}

func (h *processHandle) closeStdin() {
	if h == nil {
		return
	}
	h.stdinOnce.Do(func() {
		if h.stdin != nil {
			_ = h.stdin.Close()
		}
	})
}

// shutdown asks the child to exit by closing stdin, then enforces a bounded
// wait. It must run only after the reader has stopped using stdout.
func (h *processHandle) shutdown(timeout time.Duration) {
	if h == nil {
		return
	}
	h.closeStdin()
	h.waitOnce.Do(func() {
		if h.cmd == nil || h.cmd.Process == nil {
			return
		}
		done := make(chan struct{})
		go func() {
			_ = h.cmd.Wait()
			close(done)
		}()
		if timeout <= 0 {
			h.kill()
			<-done
			return
		}
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			h.kill()
			<-done
		}
	})
}

func (h *processHandle) kill() {
	if h == nil || h.cmd == nil || h.cmd.Process == nil {
		return
	}
	_ = h.cmd.Process.Kill()
}

func (r *run) kill() {
	if r == nil {
		return
	}
	r.handle.kill()
}

func (r *run) writeJSON(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	if r.handle == nil || r.handle.stdin == nil {
		return errors.New("desktop: process stdin is unavailable")
	}
	_, err = r.handle.stdin.Write(raw)
	return err
}

func (r *run) stop(grace time.Duration) {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		_ = r.writeJSON(map[string]any{"type": "abort"})
		if grace <= 0 {
			r.kill()
			return
		}
		timer := time.AfterFunc(grace, r.kill)
		r.timerMu.Lock()
		r.stopTimer = timer
		r.timerMu.Unlock()
	})
}

func (a *Adapter) executeRun(r *run) {
	defer a.wg.Done()
	defer func() {
		r.handle.shutdown(processExitTimeout)
		a.finishRun(r)
	}()
	go io.Copy(io.Discard, r.handle.stderr)
	if err := r.writeJSON(map[string]any{
		"id":      r.id,
		"type":    "prompt",
		"message": r.text,
	}); err != nil {
		r.failReason = "start_failed"
		return
	}
	dec := json.NewDecoder(bufio.NewReaderSize(r.handle.stdout, 128<<10))
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			switch {
			case r.stopFlag.Load():
				return
			case errors.Is(err, io.EOF):
				r.setFail("process_exit")
			default:
				r.setFail("protocol_error")
			}
			return
		}
		if a.handleRecord(r, raw) {
			return
		}
	}
}

func (r *run) setFail(reason string) {
	if r.failReason == "" {
		r.failReason = reason
	}
}

type rpcRecord struct {
	Type                  string          `json:"type"`
	ID                    string          `json:"id"`
	Command               string          `json:"command"`
	Success               *bool           `json:"success"`
	Error                 string          `json:"error"`
	Data                  json.RawMessage `json:"data"`
	Message               json.RawMessage `json:"message"`
	AssistantMessageEvent json.RawMessage `json:"assistantMessageEvent"`
	Aborted               *bool           `json:"aborted"`
	Method                string          `json:"method"`
	Title                 string          `json:"title"`
	Options               []string        `json:"options"`
	Questions             json.RawMessage `json:"questions"`
	Placeholder           string          `json:"placeholder"`
	Prefill               string          `json:"prefill"`
	Timeout               int64           `json:"timeout"`
	ToolCallID            string          `json:"toolCallId"`
	ToolName              string          `json:"toolName"`
	Args                  json.RawMessage `json:"args"`
	PartialResult         json.RawMessage `json:"partialResult"`
	Result                json.RawMessage `json:"result"`
	IsError               bool            `json:"isError"`
	DurationMs            int64           `json:"durationMs"`
}

type promptDisposition struct {
	Disposition string `json:"disposition"`
}

type updateToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type updateEnvelope struct {
	Type     string          `json:"type"`
	Delta    string          `json:"delta"`
	Content  string          `json:"content"`
	ToolCall *updateToolCall `json:"toolCall"`
}

type updateRecord struct {
	AssistantMessageEvent updateEnvelope `json:"assistantMessageEvent"`
}

type toolResultPayload struct {
	UpdateMode string          `json:"updateMode"`
	Content    json.RawMessage `json:"content"`
}

func (a *Adapter) handleRecord(r *run, raw json.RawMessage) bool {
	var rec rpcRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		r.setFail("protocol_error")
		return true
	}
	switch rec.Type {
	case "response":
		if rec.Command != "prompt" || rec.ID != r.id {
			return false
		}
		if rec.Success != nil && !*rec.Success {
			r.setFail("start_failed")
			return true
		}
		var data promptDisposition
		if len(rec.Data) > 0 {
			_ = json.Unmarshal(rec.Data, &data)
		}
		if data.Disposition == "handled" {
			a.mu.Lock()
			r.promptHandled = true
			a.mu.Unlock()
			return true
		}
		return false
	case "message_start":
		var env messageEnvelope
		if err := json.Unmarshal(rec.Message, &env); err != nil {
			return false
		}
		switch env.Role {
		case "user":
			a.addUserMessage(r, env)
		case "assistant":
			a.mu.Lock()
			if !r.terminal {
				r.pending.Reset()
				r.pendingThinking.Reset()
				r.pendingToolCalls = nil
				r.sawDelta = false
				r.sawThinkingDelta = false
				r.pendingTimestamp = env.Timestamp
				if r.pendingTimestamp == 0 {
					r.pendingTimestamp = a.now().UnixMilli()
				}
			}
			a.mu.Unlock()
		}
		return false
	case "message_update":
		var update updateRecord
		if err := json.Unmarshal(raw, &update); err != nil {
			return false
		}
		switch update.AssistantMessageEvent.Type {
		case "text_delta":
			a.emitText(r, update.AssistantMessageEvent.Delta)
		case "text_end":
			a.emitTextIfMissing(r, update.AssistantMessageEvent.Content)
		case "thinking_delta":
			a.emitThinking(r, update.AssistantMessageEvent.Delta)
		case "thinking_end":
			a.emitThinkingIfMissing(r, update.AssistantMessageEvent.Content)
		case "toolcall_end":
			a.emitToolCall(r, update.AssistantMessageEvent.ToolCall)
		}
		return false
	case "message_end":
		var env messageEnvelope
		if err := json.Unmarshal(rec.Message, &env); err != nil {
			return false
		}
		if env.Role != "assistant" {
			return false
		}
		a.completeAssistantMessage(r, env)
		if env.StopReason == "error" {
			r.upstreamError = true
		}
		return false
	case "tool_execution_start":
		a.emitToolStart(r, rec)
		return false
	case "tool_execution_update":
		a.emitToolUpdate(r, rec)
		return false
	case "tool_execution_end":
		a.emitToolEnd(r, rec)
		return false
	case "agent_settled":
		r.settled = true
		if rec.Aborted != nil {
			r.aborted = *rec.Aborted
		}
		return true
	case "extension_ui_request":
		a.handleExtensionUI(r, rec)
		return false
	default:
		return false
	}
}

func (a *Adapter) addUserMessage(r *run, env messageEnvelope) {
	text := extractText(env.Content)
	if text == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.sawUser || r.terminal {
		return
	}
	r.sawUser = true
	ts := env.Timestamp
	if ts == 0 {
		ts = a.now().UnixMilli()
	}
	r.session.messages = append(r.session.messages, Message{Role: "user", Text: text, Timestamp: ts})
}

func (a *Adapter) emitText(r *run, delta string) {
	if delta == "" {
		return
	}
	a.mu.Lock()
	if r.terminal || r.stopFlag.Load() {
		a.mu.Unlock()
		return
	}
	if r.pending.Len()+len(delta) > maxRunTextBytes {
		r.setFail("output_limit")
		a.mu.Unlock()
		r.kill()
		return
	}
	r.pending.WriteString(delta)
	r.sawDelta = true
	if r.pendingTimestamp == 0 {
		r.pendingTimestamp = a.now().UnixMilli()
	}
	for _, chunk := range splitText(delta, 4<<10) {
		a.appendEventLocked(r.session, r.id, kindTextDelta, textDeltaData{Text: chunk}, r.tools)
	}
	a.mu.Unlock()
}

func (a *Adapter) emitTextIfMissing(r *run, text string) {
	if text == "" {
		return
	}
	a.mu.Lock()
	if r.terminal || r.stopFlag.Load() || r.sawDelta {
		a.mu.Unlock()
		return
	}
	if r.pending.Len()+len(text) > maxRunTextBytes {
		r.setFail("output_limit")
		a.mu.Unlock()
		r.kill()
		return
	}
	r.pending.WriteString(text)
	r.sawDelta = true
	for _, chunk := range splitText(text, 4<<10) {
		a.appendEventLocked(r.session, r.id, kindTextDelta, textDeltaData{Text: chunk}, r.tools)
	}
	a.mu.Unlock()
}

func (a *Adapter) emitThinking(r *run, delta string) {
	if delta == "" {
		return
	}
	a.mu.Lock()
	if r.terminal || r.stopFlag.Load() || !r.session.cfg.anyThinking() {
		a.mu.Unlock()
		return
	}
	if r.pendingThinking.Len()+len(delta) > maxRunTextBytes {
		a.mu.Unlock()
		return
	}
	r.pendingThinking.WriteString(delta)
	r.sawThinkingDelta = true
	if r.pendingTimestamp == 0 {
		r.pendingTimestamp = a.now().UnixMilli()
	}
	for _, chunk := range splitText(delta, 4<<10) {
		a.appendEventVisibleLocked(r.session, r.id, kindThinkingDelta, thinkingDeltaData{Text: chunk}, r.tools, visThinking, "")
	}
	a.mu.Unlock()
}

func (a *Adapter) emitThinkingIfMissing(r *run, text string) {
	if text == "" {
		return
	}
	a.mu.Lock()
	if r.terminal || r.stopFlag.Load() || r.sawThinkingDelta || !r.session.cfg.anyThinking() {
		a.mu.Unlock()
		return
	}
	if r.pendingThinking.Len()+len(text) > maxRunTextBytes {
		a.mu.Unlock()
		return
	}
	r.pendingThinking.WriteString(text)
	r.sawThinkingDelta = true
	for _, chunk := range splitText(text, 4<<10) {
		a.appendEventVisibleLocked(r.session, r.id, kindThinkingDelta, thinkingDeltaData{Text: chunk}, r.tools, visThinking, "")
	}
	a.mu.Unlock()
}

func (a *Adapter) emitToolCall(r *run, tc *updateToolCall) {
	if tc == nil || tc.Name == "" {
		return
	}
	a.mu.Lock()
	if r.terminal || r.stopFlag.Load() || !r.session.cfg.anyTools() {
		a.mu.Unlock()
		return
	}
	summary := ToolCallSummary{
		ID:        tc.ID,
		Name:      tc.Name,
		Arguments: truncateJSON(tc.Arguments, maxToolArgsBytes),
	}
	r.pendingToolCalls = append(r.pendingToolCalls, summary)
	a.appendEventVisibleLocked(r.session, r.id, kindToolCall, toolCallData{
		ToolCallID: summary.ID,
		ToolName:   summary.Name,
		Arguments:  summary.Arguments,
	}, r.tools, visTools, "")
	a.mu.Unlock()
}

func (a *Adapter) emitToolStart(r *run, rec rpcRecord) {
	if rec.ToolName == "" {
		return
	}
	a.mu.Lock()
	if r.terminal || r.stopFlag.Load() || !r.session.cfg.anyTools() {
		a.mu.Unlock()
		return
	}
	a.appendEventVisibleLocked(r.session, r.id, kindToolStart, toolStartData{
		ToolCallID: rec.ToolCallID,
		ToolName:   rec.ToolName,
		Args:       truncateJSON(rec.Args, maxToolArgsBytes),
	}, r.tools, visTools, "")
	a.mu.Unlock()
}

func (a *Adapter) emitToolUpdate(r *run, rec rpcRecord) {
	if rec.ToolName == "" || len(rec.PartialResult) == 0 {
		return
	}
	var payload toolResultPayload
	if json.Unmarshal(rec.PartialResult, &payload) != nil {
		return
	}
	text := truncateUTF8(extractText(payload.Content), maxToolUpdateBytes)
	if text == "" {
		return
	}
	a.mu.Lock()
	if r.terminal || r.stopFlag.Load() || !r.session.cfg.anyTools() {
		a.mu.Unlock()
		return
	}
	a.appendEventVisibleLocked(r.session, r.id, kindToolUpdate, toolUpdateData{
		ToolCallID: rec.ToolCallID,
		ToolName:   rec.ToolName,
		Text:       text,
		Delta:      payload.UpdateMode == "delta",
	}, r.tools, visTools, "")
	a.mu.Unlock()
}

func (a *Adapter) emitToolEnd(r *run, rec rpcRecord) {
	if rec.ToolName == "" {
		return
	}
	var payload toolResultPayload
	var text string
	if len(rec.Result) > 0 && json.Unmarshal(rec.Result, &payload) == nil {
		text = truncateUTF8(extractText(payload.Content), maxToolResultBytes)
	}
	a.mu.Lock()
	if r.terminal || r.stopFlag.Load() || !r.session.cfg.anyTools() {
		a.mu.Unlock()
		return
	}
	r.session.messages = append(r.session.messages, Message{
		Role:       "toolResult",
		Text:       text,
		ToolCallID: rec.ToolCallID,
		ToolName:   rec.ToolName,
		IsError:    rec.IsError,
		Timestamp:  a.now().UnixMilli(),
	})
	a.appendEventVisibleLocked(r.session, r.id, kindToolEnd, toolEndData{
		ToolCallID: rec.ToolCallID,
		ToolName:   rec.ToolName,
		Text:       text,
		IsError:    rec.IsError,
		DurationMs: rec.DurationMs,
	}, r.tools, visTools, "")
	a.mu.Unlock()
}

func (a *Adapter) completeAssistantMessage(r *run, env messageEnvelope) {
	text, thinking, toolCalls := extractAssistantParts(env.Content)
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.terminal {
		return
	}
	if text == "" {
		text = r.pending.String()
	}
	if thinking == "" {
		thinking = r.pendingThinking.String()
	}
	if len(toolCalls) == 0 && len(r.pendingToolCalls) > 0 {
		toolCalls = append([]ToolCallSummary(nil), r.pendingToolCalls...)
	}
	if text != "" || thinking != "" || len(toolCalls) > 0 {
		ts := env.Timestamp
		if ts == 0 {
			ts = r.pendingTimestamp
		}
		if ts == 0 {
			ts = a.now().UnixMilli()
		}
		r.session.messages = append(r.session.messages, Message{
			Role:      "assistant",
			Text:      text,
			Thinking:  thinking,
			ToolCalls: toolCalls,
			Timestamp: ts,
		})
	}
	r.pending.Reset()
	r.pendingThinking.Reset()
	r.pendingToolCalls = nil
	r.sawDelta = false
	r.sawThinkingDelta = false
}

func (a *Adapter) handleExtensionUI(r *run, rec rpcRecord) {
	switch rec.Method {
	case "notify", "setStatus", "setWidget", "setTitle", "set_editor_text":
		return
	}
	if rec.ID == "" {
		return
	}
	switch rec.Method {
	case "confirm", "select", "input", "ask", "editor":
	default:
		a.autoCancelExtension(r, rec)
		return
	}
	var msgStr string
	if len(rec.Message) > 0 {
		_ = json.Unmarshal(rec.Message, &msgStr)
	}
	a.mu.Lock()
	if r.terminal || r.stopFlag.Load() || !r.session.cfg.remoteApproval() || !a.userOnlineLocked(r.userID) || len(r.pendingUI) >= maxPendingUI {
		a.mu.Unlock()
		a.autoCancelExtension(r, rec)
		return
	}
	if _, dup := r.pendingUI[rec.ID]; dup {
		a.mu.Unlock()
		return
	}
	dur := defaultUIApprovalTimeout
	if rec.Timeout > 0 {
		if d := time.Duration(rec.Timeout) * time.Millisecond; d > 0 && d < dur {
			dur = d
		}
	}
	info := uiRequestData{
		UIID:        rec.ID,
		RunID:       r.id,
		Method:      rec.Method,
		Title:       truncateUTF8(rec.Title, 512),
		Message:     truncateUTF8(msgStr, 4<<10),
		Options:     rec.Options,
		Questions:   rec.Questions,
		Placeholder: truncateUTF8(rec.Placeholder, 512),
		Prefill:     truncateUTF8(rec.Prefill, 4<<10),
		ExpiresAt:   a.now().Add(dur).UnixMilli(),
	}
	pui := &pendingUIRequest{info: info}
	uiID := rec.ID
	pui.timer = time.AfterFunc(dur, func() {
		a.timeoutPendingUI(r, uiID)
	})
	if r.pendingUI == nil {
		r.pendingUI = make(map[string]*pendingUIRequest)
	}
	r.pendingUI[uiID] = pui
	a.appendEventVisibleLocked(r.session, r.id, kindUIRequest, info, true, visApproval, r.userID)
	sessionID := r.session.cfg.id
	runID := r.id
	a.mu.Unlock()
	a.emitObserve(map[string]any{
		"type":       "ui.request",
		"session_id": sessionID,
		"run_id":     runID,
		"ui_id":      info.UIID,
		"method":     info.Method,
		"title":      info.Title,
	})
}

func (a *Adapter) timeoutPendingUI(r *run, uiID string) {
	a.mu.Lock()
	pui := r.pendingUI[uiID]
	if pui == nil || pui.resolved || r.terminal {
		a.mu.Unlock()
		return
	}
	pui.resolved = true
	delete(r.pendingUI, uiID)
	a.appendEventVisibleLocked(r.session, r.id, kindUIResolved, uiResolvedData{UIID: uiID, Status: "timed_out"}, true, visApproval, r.userID)
	sessionID := r.session.cfg.id
	runID := r.id
	a.mu.Unlock()
	_ = r.writeJSON(map[string]any{
		"type":      "extension_ui_response",
		"id":        uiID,
		"cancelled": true,
	})
	a.emitObserve(map[string]any{
		"type":       "ui.resolved",
		"session_id": sessionID,
		"run_id":     runID,
		"ui_id":      uiID,
		"status":     "timed_out",
	})
}

func (a *Adapter) cancelRunPendingUILocked(r *run, status string) []uiCancelAction {
	if r == nil || len(r.pendingUI) == 0 {
		return nil
	}
	actions := make([]uiCancelAction, 0, len(r.pendingUI))
	for id, pui := range r.pendingUI {
		if pui.resolved {
			continue
		}
		pui.resolved = true
		if pui.timer != nil {
			pui.timer.Stop()
		}
		delete(r.pendingUI, id)
		actions = append(actions, uiCancelAction{r: r, id: id})
		if r.session != nil && !a.closed {
			a.appendEventVisibleLocked(r.session, r.id, kindUIResolved, uiResolvedData{UIID: id, Status: status}, true, visApproval, r.userID)
		}
	}
	return actions
}

func (a *Adapter) autoCancelExtension(r *run, rec rpcRecord) {
	switch rec.Method {
	case "notify", "setStatus", "setWidget", "setTitle", "set_editor_text":
		return
	}
	if rec.ID == "" {
		return
	}
	// Every blocking extension dialog is denied locally. A prompt, permission
	// request, or question is never forwarded to the phone, and the model or
	// extension receives a cancellation rather than a fabricated answer.
	_ = r.writeJSON(map[string]any{
		"type":      "extension_ui_response",
		"id":        rec.ID,
		"cancelled": true,
	})
}

func (a *Adapter) finishRun(r *run) {
	r.finishOnce.Do(func() {
		a.mu.Lock()
		if r.terminal {
			a.mu.Unlock()
			return
		}
		r.terminal = true
		r.timerMu.Lock()
		if r.stopTimer != nil {
			r.stopTimer.Stop()
			r.stopTimer = nil
		}
		r.timerMu.Unlock()
		status := statusCompleted
		reason := ""
		switch {
		case r.failReason != "":
			status = statusFailed
			reason = r.failReason
		case r.upstreamError:
			status = statusFailed
			reason = "upstream_error"
		case r.stopFlag.Load():
			status = statusCancelled
			reason = r.stopReason
			if reason == "" {
				reason = "requested"
			}
		case r.settled && r.aborted:
			status = statusCancelled
			reason = "requested"
		case r.settled || r.promptHandled:
			status = statusCompleted
		default:
			status = statusFailed
			reason = "process_exit"
		}
		uiCancels := a.cancelRunPendingUILocked(r, "cancelled")
		if r.pending.Len() > 0 || r.pendingThinking.Len() > 0 || len(r.pendingToolCalls) > 0 {
			ts := r.pendingTimestamp
			if ts == 0 {
				ts = a.now().UnixMilli()
			}
			r.session.messages = append(r.session.messages, Message{
				Role:      "assistant",
				Text:      r.pending.String(),
				Thinking:  r.pendingThinking.String(),
				ToolCalls: append([]ToolCallSummary(nil), r.pendingToolCalls...),
				Timestamp: ts,
			})
			r.pending.Reset()
			r.pendingThinking.Reset()
			r.pendingToolCalls = nil
		}
		switch status {
		case statusCancelled:
			a.appendEventLocked(r.session, r.id, kindRunCancelled, runCancelledData{Reason: reason}, r.tools)
		case statusFailed:
			a.appendEventLocked(r.session, r.id, kindRunFailed, runFailedData{Reason: reason}, r.tools)
		default:
			a.appendEventLocked(r.session, r.id, kindRunCompleted, nil, r.tools)
		}
		if rec, ok := r.session.ps.Runs[r.id]; ok {
			rec.Status = status
			r.session.ps.Runs[r.id] = rec
		}
		delete(r.session.runs, r.id)
		if r.session.active == r {
			r.session.active = nil
		}
		delete(a.runs, r.id)
		r.session.ps.trim(a.cfg.retention)
		if err := a.saveLocked(); err != nil {
			a.logger.Error("persist run terminal", "session", r.session.cfg.id, "run", r.id, "error", err)
		}
		close(r.done)
		a.mu.Unlock()
		flushUICancels(uiCancels)
	})
}

func splitText(s string, max int) []string {
	if len(s) <= max {
		return []string{s}
	}
	out := make([]string, 0, len(s)/max+1)
	for len(s) > 0 {
		end := 0
		for end < len(s) && end < max {
			_, size := utf8.DecodeRuneInString(s[end:])
			if end+size > max {
				break
			}
			end += size
		}
		if end == 0 {
			end = max
		}
		out = append(out, s[:end])
		s = s[end:]
	}
	return out
}
