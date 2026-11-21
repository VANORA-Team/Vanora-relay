package mobile

import (
	"encoding/json"
	"errors"

	"vanora-relay/protocol"
)

// NewRequestID generates a unique request key. Persist it with a pending prompt before submitting.
func NewRequestID() string { return protocol.NewID() }

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
