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
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	return c.request(p, map[string]any{
		"type":         "session.create",
		"request_id":   requestID,
		"workspace_id": workspaceID,
		"title":        title,
	}, true)
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
	c.op.Lock()
	defer c.op.Unlock()
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	data, err := c.request(p, map[string]any{"type": "session.open", "request_id": NewRequestID(), "session_id": sessionID}, false)
	if err != nil {
		return "", err
	}
	var snapshot struct {
		Last *int64 `json:"last_seq"`
	}
	if json.Unmarshal([]byte(data), &snapshot) != nil || snapshot.Last == nil || *snapshot.Last < 0 {
		return "", errors.New("invalid desktop snapshot")
	}
	if _, err = c.subscribe(p, sessionID, *snapshot.Last); err != nil {
		return "", err
	}
	return data, nil
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

// StartRun returns JSON containing run_id. Reuse the same requestID and text after reconnect.
func (c *Client) StartRun(sessionID, requestID, text string) (string, error) {
	p, err := c.currentPeer()
	if err != nil {
		return "", err
	}
	return c.request(p, map[string]any{"type": "run.start", "request_id": requestID, "session_id": sessionID, "text": text}, true)
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
