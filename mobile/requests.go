package mobile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"vanora-relay/protocol"
)

// NewRequestID generates a unique request key. Persist it with a pending prompt before submitting.
func NewRequestID() string { return protocol.NewID() }

// ListWorkspaces returns JSON containing workspaces where this user may create new sessions.
func (c *Client) ListWorkspaces() (string, error) {
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	return c.request(p, map[string]any{"type": "workspace.list", "request_id": NewRequestID()}, false)
}

// CreateSession creates a new Vanora session inside an allowlisted desktop workspace.
// Reuse the same requestID and title when retrying after a disconnect.
func (c *Client) CreateSession(workspaceID, requestID, title string) (string, error) {
	return c.CreateSessionWithOptions(workspaceID, requestID, title, "", "")
}

// CreateSessionWithOptions creates a session with optional link_origin fence
// tag and mode_limit JSON narrowing.
func (c *Client) CreateSessionWithOptions(workspaceID, requestID, title, linkOrigin, modeLimitJSON string) (string, error) {
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	req := map[string]any{
		"type":         "session.create",
		"request_id":   requestID,
		"workspace_id": workspaceID,
		"title":        title,
	}
	if linkOrigin != "" {
		req["link_origin"] = linkOrigin
	}
	if modeLimitJSON != "" {
		limit, err := decodeModeLimit(modeLimitJSON)
		if err != nil {
			return "", err
		}
		req["mode_limit"] = limit
	}
	return c.request(p, req, true)
}

func (c *Client) ListSessions() (string, error) {
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	return c.request(p, map[string]any{"type": "session.list", "request_id": NewRequestID()}, false)
}

// OpenSession returns the desktop snapshot and subscribes starting at its last_seq.
func (c *Client) OpenSession(sessionID string) (string, error) {
	return c.OpenSessionWithOptions(sessionID, false)
}

// OpenSessionWithOptions returns the desktop snapshot and subscribes starting
// at its last_seq, optionally enabling live presence.updated events.
func (c *Client) OpenSessionWithOptions(sessionID string, watchPresence bool) (string, error) {
	c.op.Lock()
	defer c.op.Unlock()
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	req := map[string]any{"type": "session.open", "request_id": NewRequestID(), "session_id": sessionID}
	if watchPresence {
		req["watch_presence"] = true
	}
	data, err := c.request(p, req, false)
	if err != nil {
		return "", err
	}
	var snapshot struct {
		Last *int64 `json:"last_seq"`
	}
	if json.Unmarshal([]byte(data), &snapshot) != nil || snapshot.Last == nil || *snapshot.Last < 0 {
		return "", errors.New("invalid desktop snapshot")
	}
	if watchPresence {
		c.mu.Lock()
		if cur := c.subscriptions[sessionID]; cur != nil {
			cur.watchPresence = true
		} else {
			c.subscriptions[sessionID] = &cursor{applied: *snapshot.Last, delivered: *snapshot.Last, queued: *snapshot.Last, watchPresence: true}
		}
		c.mu.Unlock()
	}
	if _, err = c.subscribe(p, sessionID, *snapshot.Last); err != nil {
		return "", err
	}
	return data, nil
}

// CloseSession unsubscribes from sessionID on the desktop so it stops
// streaming events and updates online collaborator presence.
func (c *Client) CloseSession(sessionID string) error {
	c.op.Lock()
	defer c.op.Unlock()
	p, err := c.currentPeer()
	if err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.subscriptions, sessionID)
	c.mu.Unlock()
	_, err = c.request(p, map[string]any{
		"type":       "session.close",
		"request_id": NewRequestID(),
		"session_id": sessionID,
	}, false)
	return err
}

// SessionPresence returns current online collaborators for sessionID and
// optionally subscribes (watch=true) or unsubscribes (watch=false) to live
// presence.updated events.
func (c *Client) SessionPresence(sessionID string, watch bool) (string, error) {
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	data, err := c.request(p, map[string]any{
		"type":       "session.presence",
		"request_id": NewRequestID(),
		"session_id": sessionID,
		"watch":      watch,
	}, false)
	if err == nil {
		c.mu.Lock()
		if cur := c.subscriptions[sessionID]; cur != nil {
			cur.watchPresence = watch
		}
		c.mu.Unlock()
	}
	return data, err
}

// Resume restores an existing app snapshot at the last sequence the app applied.
// On snapshot_required replace the app's state with the result of OpenSession.
func (c *Client) Resume(sessionID string, afterSeq int64) error {
	c.op.Lock()
	defer c.op.Unlock()
	p, err := c.currentPeer()
	if err != nil {
		return err
	}
	_, err = c.subscribe(p, sessionID, afterSeq)
	return err
}

// StartRun returns JSON containing run_id (and status/queue_position when queued).
// Reuse the same requestID and text after reconnect.
func (c *Client) StartRun(sessionID, requestID, text string) (string, error) {
	return c.StartRunWithPolicy(sessionID, requestID, text, "")
}

// StartRunWithPolicy starts or enqueues a run on sessionID. queuePolicy may be
// "" / "enqueue" (default FIFO turn queue) or "reject" (fail with session_busy).
func (c *Client) StartRunWithPolicy(sessionID, requestID, text, queuePolicy string) (string, error) {
	return c.StartRunWithOptions(sessionID, requestID, text, queuePolicy, "", "")
}

// StartRunWithOptions starts or enqueues a run with optional queue policy,
// link_origin fence tag, and mode_limit JSON narrowing.
func (c *Client) StartRunWithOptions(sessionID, requestID, text, queuePolicy, linkOrigin, modeLimitJSON string) (string, error) {
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	req := map[string]any{
		"type":       "run.start",
		"request_id": requestID,
		"session_id": sessionID,
		"text":       text,
	}
	if queuePolicy != "" {
		req["queue_policy"] = queuePolicy
	}
	if linkOrigin != "" {
		req["link_origin"] = linkOrigin
	}
	if modeLimitJSON != "" {
		limit, err := decodeModeLimit(modeLimitJSON)
		if err != nil {
			return "", err
		}
		req["mode_limit"] = limit
	}
	return c.request(p, req, true)
}

// CancelRun returns JSON containing run_id and status.
func (c *Client) CancelRun(sessionID, runID string) (string, error) {
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	return c.request(p, map[string]any{"type": "run.cancel", "request_id": NewRequestID(), "session_id": sessionID, "run_id": runID}, true)
}

// RespondUI answers a pending remote approval or extension UI dialog.
// payloadJSON must be a JSON object with any of: confirmed (bool), value
// (string), answers ([][]string), or cancelled (bool).
func (c *Client) RespondUI(sessionID, runID, uiID, payloadJSON string) (string, error) {
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	var payload struct {
		Confirmed *bool      `json:"confirmed"`
		Value     *string    `json:"value"`
		Answers   [][]string `json:"answers"`
		Cancelled bool       `json:"cancelled"`
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(payloadJSON)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return "", errors.New("invalid UI response payload")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return "", errors.New("invalid UI response payload")
	}
	req := map[string]any{
		"type":       "ui.respond",
		"request_id": NewRequestID(),
		"session_id": sessionID,
		"run_id":     runID,
		"ui_id":      uiID,
	}
	if payload.Cancelled {
		req["cancelled"] = true
	}
	if payload.Confirmed != nil {
		req["confirmed"] = *payload.Confirmed
	}
	if payload.Value != nil {
		req["value"] = *payload.Value
	}
	if payload.Answers != nil {
		req["answers"] = payload.Answers
	}
	return c.request(p, req, true)
}

// SubmitGuestRequest submits an owner-gated prompt request on a session that
// sets allow_guest_requests: true, returning JSON with guest_request_id and
// status ("pending").
func (c *Client) SubmitGuestRequest(sessionID, requestID, text string) (string, error) {
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	if requestID == "" {
		requestID = NewRequestID()
	}
	return c.request(p, map[string]any{
		"type":       "guest.request",
		"request_id": requestID,
		"session_id": sessionID,
		"text":       text,
	}, false)
}

// RespondGuestRequest approves ("approve"), dismisses ("dismiss"), or cancels
// ("cancel") a pending guest prompt request.
func (c *Client) RespondGuestRequest(sessionID, guestRequestID, action string) (string, error) {
	return c.RespondGuestRequestWithOptions(sessionID, guestRequestID, action, "", "")
}

// RespondGuestRequestWithOptions responds to a pending guest prompt request,
// optionally refining the prompt text or narrowing tool access via
// modeLimitJSON (e.g. {"no_tools":true} or {"tools":["read","grep"]}).
func (c *Client) RespondGuestRequestWithOptions(sessionID, guestRequestID, action, text, modeLimitJSON string) (string, error) {
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	req := map[string]any{
		"type":             "guest.respond",
		"request_id":       NewRequestID(),
		"session_id":       sessionID,
		"guest_request_id": guestRequestID,
		"action":           action,
	}
	if text != "" {
		req["text"] = text
	}
	if modeLimitJSON != "" {
		limit, err := decodeModeLimit(modeLimitJSON)
		if err != nil {
			return "", err
		}
		req["mode_limit"] = limit
	}
	return c.request(p, req, action == "approve")
}

type modeLimitPayload struct {
	ReadOnly bool     `json:"read_only,omitempty"`
	NoTools  bool     `json:"no_tools,omitempty"`
	Tools    []string `json:"tools,omitempty"`
}

func decodeModeLimit(raw string) (modeLimitPayload, error) {
	var limit modeLimitPayload
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&limit); err != nil {
		return modeLimitPayload{}, errors.New("invalid mode_limit payload")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return modeLimitPayload{}, errors.New("invalid mode_limit payload")
	}
	return limit, nil
}
