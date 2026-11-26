package signal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

const (
	activityRetentionTTL         = 15 * time.Minute
	maxSessionsPerDeviceActivity = 32
	activityProofClockSkew       = 60 * time.Second
	pushOutboxQueueSize          = 256
)

// ActivityState is a content-free, zero-trust summary of a desktop session's
// attention state. It intentionally carries no prompt text, assistant output,
// tool arguments, file paths, or error stack traces.
type ActivityState struct {
	DeviceID  string `json:"device_id"`
	SessionID string `json:"session_id"`
	RunID     string `json:"run_id,omitempty"`
	Phase     string `json:"phase"`
	UIID      string `json:"ui_id,omitempty"`
	Method    string `json:"method,omitempty"`
	UpdatedAt int64  `json:"updated_at"`
}

type deviceActivityBook struct {
	owner      string
	grants     map[string]bool
	selfHosted bool
	sessions   map[string]ActivityState
	identities map[string]string
	updatedAt  time.Time
}

type pushWebhookConfig struct {
	url        string
	token      string
	allowLocal bool
}

type activityTracker struct {
	mu      sync.Mutex
	devices map[string]*deviceActivityBook
	webhook *pushWebhookConfig
	outbox  chan ActivityState
	once    sync.Once
}

func (h *Hub) ensureActivityTracker() *activityTracker {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.activity == nil {
		h.activity = &activityTracker{
			devices: make(map[string]*deviceActivityBook),
			outbox:  make(chan ActivityState, pushOutboxQueueSize),
		}
	}
	return h.activity
}

// refreshActivityGrants re-stamps the retained activity book for a desktop
// that just republished its device.online allowlist, so a revoked guest
// loses poll access immediately instead of after the retained-book TTL.
// Callers hold h.mu.
func (h *Hub) refreshActivityGrants(p *peer) {
	if h.activity == nil {
		return
	}
	tr := h.activity
	owner := p.id.RemoteUserID()
	if h.selfHosted {
		owner = p.id.DeviceID
	}
	grants := make(map[string]bool, len(p.grants))
	for id := range p.grants {
		grants[id] = true
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	book := tr.devices[p.id.DeviceID]
	if book == nil {
		return
	}
	book.owner, book.grants, book.updatedAt = owner, grants, time.Now()
}

// ConfigurePushWebhook enables forwarding deduplicated, redacted ActivityState
// transitions to an external push bridge (APNs/FCM/ntfy/Gotify webhook). By
// default only HTTPS URLs (or loopback when allowLocal is true) are accepted,
// and HTTP redirects are never followed.
func (h *Hub) ConfigurePushWebhook(rawURL, bearerToken string, allowLocal bool) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("signal: invalid push webhook URL")
	}
	host := u.Hostname()
	addr, addrErr := netip.ParseAddr(host)
	isLoopback := (addrErr == nil && addr.IsLoopback()) || strings.EqualFold(host, "localhost")
	if u.Scheme != "https" && !(allowLocal && isLoopback && u.Scheme == "http") {
		return errors.New("signal: push webhook URL must use HTTPS")
	}
	if !allowLocal && addrErr == nil && (addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsUnspecified()) {
		return errors.New("signal: push webhook URL must not target private or loopback addresses")
	}
	tr := h.ensureActivityTracker()
	tr.mu.Lock()
	tr.webhook = &pushWebhookConfig{
		url:        u.String(),
		token:      strings.TrimSpace(bearerToken),
		allowLocal: allowLocal,
	}
	tr.mu.Unlock()
	return nil
}

func (tr *activityTracker) startWorker(ctx context.Context) {
	if tr == nil {
		return
	}
	tr.once.Do(func() {
		go func() {
			client := &http.Client{
				Timeout: 5 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			for {
				select {
				case <-ctx.Done():
					return
				case item := <-tr.outbox:
					tr.deliverWebhook(ctx, client, item)
				}
			}
		}()
	})
}

func (tr *activityTracker) deliverWebhook(ctx context.Context, client *http.Client, item ActivityState) {
	tr.mu.Lock()
	cfg := tr.webhook
	tr.mu.Unlock()
	if cfg == nil || cfg.url == "" {
		return
	}
	body, err := json.Marshal(item)
	if err != nil {
		return
	}
	delays := []time.Duration{0, time.Second, 2 * time.Second}
	for _, d := range delays {
		if d > 0 {
			timer := time.NewTimer(d)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.url, bytes.NewReader(body))
		if err != nil {
			cancel()
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if cfg.token != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.token)
		}
		resp, err := client.Do(req)
		cancel()
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return
			}
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return
			}
		}
	}
}

func validActivityPhase(phase string) bool {
	switch phase {
	case "running", "awaiting_approval", "awaiting_guest_approval", "completed", "failed", "cancelled", "cleared":
		return true
	default:
		return false
	}
}

func activityPublishIdentity(st ActivityState) string {
	return st.Phase + "\x00" + st.RunID + "\x00" + st.UIID + "\x00" + st.Method
}

func (tr *activityTracker) pruneLocked(now time.Time) {
	cutoff := now.Add(-activityRetentionTTL).UnixMilli()
	for dev, book := range tr.devices {
		for sid, st := range book.sessions {
			if st.UpdatedAt < cutoff {
				delete(book.sessions, sid)
				delete(book.identities, sid)
			}
		}
		if len(book.sessions) == 0 && now.Sub(book.updatedAt) > activityRetentionTTL {
			delete(tr.devices, dev)
		}
	}
}

func (h *Hub) serveActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ip := remoteIPAddr(r.RemoteAddr)
	now := time.Now()
	if !h.gate.allowRequest(ip, now) {
		limitResponse(w, 0)
		return
	}
	if r.Method == http.MethodPost {
		h.serveActivityPublish(w, r)
		return
	}
	if r.Method == http.MethodGet {
		h.serveActivityPoll(w, r)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *Hub) serveActivityPublish(w http.ResponseWriter, r *http.Request) {
	device := strings.TrimSpace(r.Header.Get("Vanora-Desktop"))
	ticket, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	now := time.Now()

	h.mu.Lock()
	host := h.peers[device]
	authorized := hasBearer && host != nil && host.online && host.role == "desktop" && host.pairTicket != "" &&
		subtle.ConstantTimeCompare([]byte(ticket), []byte(host.pairTicket)) == 1 && host.live(now)
	var owner string
	var grants map[string]bool
	if authorized {
		if h.selfHosted {
			// Self-hosted grants are the paired-guest device IDs attached to
			// the desktop's device.online; the owner key never matches a
			// caller (callers are guests), so lookups stay grant-only.
			owner = host.id.DeviceID
		} else {
			owner = host.id.RemoteUserID()
		}
		grants = make(map[string]bool, len(host.grants))
		for k, v := range host.grants {
			grants[k] = v
		}
	}
	h.mu.Unlock()
	if !authorized {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var in ActivityState
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in) != nil {
		http.Error(w, "invalid activity payload", http.StatusBadRequest)
		return
	}
	in.SessionID = strings.TrimSpace(in.SessionID)
	in.RunID = strings.TrimSpace(in.RunID)
	in.Phase = strings.TrimSpace(in.Phase)
	in.UIID = strings.TrimSpace(in.UIID)
	in.Method = strings.TrimSpace(in.Method)
	if in.SessionID == "" || len(in.SessionID) > 128 || len(in.RunID) > 128 || len(in.UIID) > 128 || len(in.Method) > 32 || !validActivityPhase(in.Phase) {
		http.Error(w, "invalid activity fields", http.StatusBadRequest)
		return
	}
	in.DeviceID = device
	in.UpdatedAt = now.UnixMilli()

	tr := h.ensureActivityTracker()
	tr.mu.Lock()
	tr.pruneLocked(now)
	book := tr.devices[device]
	if book == nil {
		book = &deviceActivityBook{
			sessions:   make(map[string]ActivityState),
			identities: make(map[string]string),
		}
		tr.devices[device] = book
	}
	book.selfHosted = h.selfHosted
	book.owner = owner
	book.grants = grants
	book.updatedAt = now

	ident := activityPublishIdentity(in)
	duplicate := book.identities[in.SessionID] == ident
	book.identities[in.SessionID] = ident
	if in.Phase == "cleared" {
		delete(book.sessions, in.SessionID)
	} else {
		if _, exists := book.sessions[in.SessionID]; !exists && len(book.sessions) >= maxSessionsPerDeviceActivity {
			// Evict oldest session state to bound memory.
			var oldestKey string
			var oldestTS int64
			for k, v := range book.sessions {
				if oldestKey == "" || v.UpdatedAt < oldestTS {
					oldestKey, oldestTS = k, v.UpdatedAt
				}
			}
			if oldestKey != "" {
				delete(book.sessions, oldestKey)
				delete(book.identities, oldestKey)
			}
		}
		book.sessions[in.SessionID] = in
	}
	hasWebhook := tr.webhook != nil && tr.webhook.url != ""
	tr.mu.Unlock()

	if !duplicate && in.Phase != "cleared" && hasWebhook {
		select {
		case tr.outbox <- in:
		default:
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Hub) serveActivityPoll(w http.ResponseWriter, r *http.Request) {
	if h.requireToken && !h.authorizedReq(w, r) {
		return
	}
	targetDevice := strings.TrimSpace(r.URL.Query().Get("activity"))
	if targetDevice == "" || len(targetDevice) > 128 {
		http.Error(w, "target device required", http.StatusBadRequest)
		return
	}
	rawProof := strings.TrimSpace(r.Header.Get("X-Vanora-Activity-Proof"))
	if rawProof == "" {
		http.Error(w, "activity proof required", http.StatusUnauthorized)
		return
	}
	decodedProof, err := base64.RawURLEncoding.Strict().DecodeString(rawProof)
	if err != nil {
		http.Error(w, "invalid activity proof", http.StatusUnauthorized)
		return
	}
	var m protocol.Message
	if json.Unmarshal(decodedProof, &m) != nil || m.Type != "activity.poll" || m.To != targetDevice {
		http.Error(w, "invalid activity proof", http.StatusUnauthorized)
		return
	}
	now := time.Now()
	caller := ""
	if h.selfHosted {
		if m.Certificate != "" {
			http.Error(w, "certificate not allowed", http.StatusUnauthorized)
			return
		}
		if !identity.ValidSelfDeviceID(targetDevice) {
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		pubRaw, err := base64.RawURLEncoding.Strict().DecodeString(r.Header.Get("X-Vanora-Public-Key"))
		if err != nil || len(pubRaw) != ed25519.PublicKeySize {
			http.Error(w, "invalid public key", http.StatusUnauthorized)
			return
		}
		devID, err := identity.SelfDeviceID(ed25519.PublicKey(pubRaw))
		if err != nil || m.From != devID || devID == targetDevice {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tsBytes, err := m.Verify(ed25519.PublicKey(pubRaw))
		if err != nil || !validActivityTimestamp(string(tsBytes), now) {
			http.Error(w, "expired or invalid signature", http.StatusUnauthorized)
			return
		}
		caller = devID
	} else {
		p, err := identity.VerifyCertificate(m.Certificate, h.key, now)
		if err != nil || (h.allowedIssuer != "" && p.Issuer != h.allowedIssuer) || m.From != p.DeviceID || p.DeviceID == targetDevice {
			http.Error(w, "invalid certificate", http.StatusUnauthorized)
			return
		}
		tsBytes, err := m.Verify(p.PublicKey)
		if err != nil || !validActivityTimestamp(string(tsBytes), now) {
			http.Error(w, "expired or invalid signature", http.StatusUnauthorized)
			return
		}
		caller = p.RemoteUserID()
	}

	tr := h.ensureActivityTracker()
	tr.mu.Lock()
	tr.pruneLocked(now)
	book := tr.devices[targetDevice]
	var items []ActivityState
	allowed := false
	// Enforce account / guest (official) and paired-device (self-hosted) ACL
	// before returning activity metadata.
	h.mu.Lock()
	liveHost := h.peers[targetDevice]
	if liveHost != nil && liveHost.online && liveHost.live(now) {
		if h.selfHosted {
			allowed = liveHost.grants[caller]
		} else {
			allowed = liveHost.id.RemoteUserID() == caller || liveHost.grants[caller]
		}
	} else if book != nil {
		if h.selfHosted {
			allowed = book.grants[caller]
		} else {
			allowed = book.owner != "" && (book.owner == caller || book.grants[caller])
		}
	}
	h.mu.Unlock()
	if allowed && book != nil {
		items = make([]ActivityState, 0, len(book.sessions))
		for _, st := range book.sessions {
			items = append(items, st)
		}
	}
	tr.mu.Unlock()
	if !allowed {
		// Return empty list or 403 without leaking existence across accounts.
		http.Error(w, "unavailable", http.StatusForbidden)
		return
	}
	if items == nil {
		items = []ActivityState{}
	}
	slices.SortFunc(items, func(a, b ActivityState) int {
		if a.UpdatedAt != b.UpdatedAt {
			if a.UpdatedAt > b.UpdatedAt {
				return -1
			}
			return 1
		}
		return strings.Compare(a.SessionID, b.SessionID)
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_id":  targetDevice,
		"activities": items,
	})
}

func validActivityTimestamp(raw string, now time.Time) bool {
	ms, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return false
	}
	ts := time.UnixMilli(ms)
	diff := now.Sub(ts)
	if diff < 0 {
		diff = -diff
	}
	return diff <= activityProofClockSkew
}
