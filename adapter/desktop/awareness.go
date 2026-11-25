package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ActivityEvent represents a redacted, high-signal session transition suitable
// for background mobile notifications or widgets without exposing prompt or
// output content.
type ActivityEvent struct {
	SessionID string `json:"session_id"`
	RunID     string `json:"run_id,omitempty"`
	Phase     string `json:"phase"`
	UIID      string `json:"ui_id,omitempty"`
	Method    string `json:"method,omitempty"`
	UpdatedAt int64  `json:"updated_at"`
}

// SetActivitySink installs an optional listener invoked on meaningful session
// state transitions (run start, approval wait, guest request wait, terminal
// completion/failure/cancellation). High-volume text/thinking/tool deltas are
// never sent to this sink.
func (a *Adapter) SetActivitySink(fn func(ActivityEvent)) {
	a.mu.Lock()
	a.activitySink = fn
	a.mu.Unlock()
}

func (a *Adapter) emitActivity(ev ActivityEvent) {
	a.mu.Lock()
	enabled := a.cfg != nil && a.cfg.publishActivity
	override := a.activityForceEnabled
	fn := a.activitySink
	if ev.UpdatedAt == 0 {
		ev.UpdatedAt = a.now().UnixMilli()
	}
	a.mu.Unlock()
	if fn != nil && (enabled || override) {
		fn(ev)
	}
}

// SetActivityEnabled overrides config-level PublishActivity at runtime (e.g.
// via Sidecar access.activity.set).
func (a *Adapter) SetActivityEnabled(enabled bool) {
	a.mu.Lock()
	a.activityForceEnabled = enabled
	a.mu.Unlock()
}

// RelayTargetProvider returns the currently active relay HTTP(S)/WS(S) URL,
// desktop device_id, and pairing_ticket used to authenticate activity updates.
type RelayTargetProvider func() (signalURL, deviceID, pairingTicket string)

// ActivityPublisher coalesces per-session activity updates on a single
// drainable worker and publishes deduplicated, redacted transitions to the
// relay's /v1/signal?activity=1 endpoint.
type ActivityPublisher struct {
	ctx      context.Context
	cancel   context.CancelFunc
	provider RelayTargetProvider
	client   *http.Client

	mu        sync.Mutex
	queued    map[string]ActivityEvent
	order     []string
	published map[string]string
	wake      chan struct{}
	done      chan struct{}
}

func NewActivityPublisher(parent context.Context, provider RelayTargetProvider) *ActivityPublisher {
	ctx, cancel := context.WithCancel(parent)
	ap := &ActivityPublisher{
		ctx:      ctx,
		cancel:   cancel,
		provider: provider,
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		queued:    make(map[string]ActivityEvent),
		published: make(map[string]string),
		wake:      make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	go ap.loop()
	return ap
}

func (ap *ActivityPublisher) Close() {
	ap.cancel()
	<-ap.done
}

func (ap *ActivityPublisher) Enqueue(ev ActivityEvent) {
	if ev.SessionID == "" || ev.Phase == "" {
		return
	}
	ap.mu.Lock()
	if _, exists := ap.queued[ev.SessionID]; !exists {
		ap.order = append(ap.order, ev.SessionID)
	}
	// Replace any unsent older transition for the same session so rapid state
	// changes coalesce cleanly without out-of-order delivery.
	ap.queued[ev.SessionID] = ev
	ap.mu.Unlock()
	select {
	case ap.wake <- struct{}{}:
	default:
	}
}

func activityIdentity(target string, ev ActivityEvent) string {
	return target + "\x00" + ev.Phase + "\x00" + ev.RunID + "\x00" + ev.UIID + "\x00" + ev.Method
}

func (ap *ActivityPublisher) loop() {
	defer close(ap.done)
	for {
		ap.mu.Lock()
		if len(ap.order) == 0 {
			ap.mu.Unlock()
			select {
			case <-ap.ctx.Done():
				return
			case <-ap.wake:
				continue
			}
		}
		sid := ap.order[0]
		ap.order = ap.order[1:]
		ev := ap.queued[sid]
		delete(ap.queued, sid)
		ap.mu.Unlock()

		ap.publishOne(ev)
	}
}

func (ap *ActivityPublisher) publishOne(ev ActivityEvent) {
	if ap.provider == nil {
		return
	}
	sigURL, devID, ticket := ap.provider()
	if sigURL == "" || devID == "" || ticket == "" {
		return
	}
	ident := activityIdentity(sigURL+"\x00"+devID, ev)
	ap.mu.Lock()
	if ap.published[ev.SessionID] == ident {
		ap.mu.Unlock()
		return
	}
	ap.mu.Unlock()

	endpointURL, err := activityEndpointURL(sigURL)
	if err != nil {
		return
	}
	payload := map[string]any{
		"device_id":  devID,
		"session_id": ev.SessionID,
		"run_id":     ev.RunID,
		"phase":      ev.Phase,
		"ui_id":      ev.UIID,
		"method":     ev.Method,
		"updated_at": ev.UpdatedAt,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	delays := []time.Duration{0, time.Second, 2 * time.Second}
	for _, d := range delays {
		if d > 0 {
			timer := time.NewTimer(d)
			select {
			case <-ap.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		rctx, cancel := context.WithTimeout(ap.ctx, 4*time.Second)
		req, err := http.NewRequestWithContext(rctx, http.MethodPost, endpointURL, bytes.NewReader(body))
		if err != nil {
			cancel()
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Vanora-Desktop", devID)
		req.Header.Set("Authorization", "Bearer "+ticket)
		resp, err := ap.client.Do(req)
		cancel()
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent || (resp.StatusCode >= 200 && resp.StatusCode < 300) {
				ap.mu.Lock()
				ap.published[ev.SessionID] = ident
				ap.mu.Unlock()
				return
			}
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return
			}
		}
	}
}

func activityEndpointURL(rawSignalURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawSignalURL))
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	q := u.Query()
	q.Set("activity", "1")
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}
