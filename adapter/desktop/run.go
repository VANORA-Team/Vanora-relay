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
	pendingTimestamp int64
	sawUser          bool
	sawDelta         bool
	promptHandled    bool
	settled          bool
	aborted          bool
	upstreamError    bool
	failReason       string

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
}

type promptDisposition struct {
	Disposition string `json:"disposition"`
}

type updateEnvelope struct {
	Type    string `json:"type"`
	Delta   string `json:"delta"`
	Content string `json:"content"`
}

type updateRecord struct {
	AssistantMessageEvent updateEnvelope `json:"assistantMessageEvent"`
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
				r.sawDelta = false
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
	case "agent_settled":
		r.settled = true
		if rec.Aborted != nil {
			r.aborted = *rec.Aborted
		}
		return true
	case "extension_ui_request":
		a.autoCancelExtension(r, rec)
		return false
	default:
		// Thinking, tool-call, tool-result, bash, queue, entry, and session
		// metadata records are intentionally ignored.
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

func (a *Adapter) completeAssistantMessage(r *run, env messageEnvelope) {
	text := extractText(env.Content)
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.terminal {
		return
	}
	if text == "" {
		text = r.pending.String()
	}
	if text != "" {
		ts := env.Timestamp
		if ts == 0 {
			ts = r.pendingTimestamp
		}
		if ts == 0 {
			ts = a.now().UnixMilli()
		}
		r.session.messages = append(r.session.messages, Message{Role: "assistant", Text: text, Timestamp: ts})
	}
	r.pending.Reset()
	r.sawDelta = false
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
		if r.pending.Len() > 0 {
			ts := r.pendingTimestamp
			if ts == 0 {
				ts = a.now().UnixMilli()
			}
			r.session.messages = append(r.session.messages, Message{
				Role:      "assistant",
				Text:      r.pending.String(),
				Timestamp: ts,
			})
			r.pending.Reset()
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
