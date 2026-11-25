package desktop

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
)

//go:embed guard/approval-guard.mjs
var embeddedApprovalGuard []byte

const (
	peerQueueSize      = 1024
	flushDelay         = time.Second
	authorityTick      = time.Second
	processExitTimeout = 3 * time.Second
	maxRunTextBytes    = 8 << 20
)

var errClosed = errors.New("desktop: adapter is closed")

// Adapter implements transport.Handler for one local desktop configuration.
type Adapter struct {
	mu       sync.Mutex
	cfg      *normalizedConfig
	state    *persistedState
	stateDir string

	peers    map[transport.Peer]*peerState
	sessions map[string]*sessionRuntime
	runs     map[string]*run

	authorityOnline bool
	authorityUntil  time.Time
	authorityGen    uint64
	authorityTimer  *time.Timer
	lanAuthority    func(string) bool
	selfAuthority   func(string) bool
	officialOwner   string
	flushTimer      *time.Timer
	dirty           bool

	closed bool
	stopCh chan struct{}
	wg     sync.WaitGroup

	now                  func() time.Time
	buildCommand         func(*normalizedSession) (*exec.Cmd, error)
	logger               *slog.Logger
	observer             func(map[string]any)
	activitySink         func(ActivityEvent)
	activityForceEnabled bool
	maxRequestBytes      int
}

var _ transport.Handler = (*Adapter)(nil)

type peerState struct {
	peer   transport.Peer
	out    chan delivery
	done   chan struct{}
	closed atomic.Bool

	closeOnce sync.Once
	sendMu    sync.Mutex
	// pendingLists counts session.list replies that are queued or in Send.
	// ReloadACL aborts such peers so a list authorized under the old ACL
	// cannot complete after the new ACL takes effect.
	pendingLists atomic.Int64
	// aclStale is set under Adapter.mu when a reload invalidates queued work.
	// Deliveries check it before Send so a stale list cannot be released
	// after the new ACL is published.
	aclStale atomic.Bool
	// subscriptions is guarded by Adapter.mu.
	subscriptions map[string]struct{}
}

type delivery struct {
	data           []byte
	requiresOnline bool
	sessionID      string
	visibility     string
	approvalUser   string
	seq            int64
	// listRequestID, when set, means the session list must be rebuilt under
	// the current ACL at delivery time. This prevents a list snapshot queued
	// before ReloadACL from disclosing sessions the user can no longer read.
	listRequestID string
	workspaceList bool
}

// SetObserver installs an optional callback for host lifecycle notifications
// (such as sidecar JSONL events). The callback is invoked without holding
// Adapter.mu.
func (a *Adapter) SetObserver(fn func(map[string]any)) {
	a.mu.Lock()
	a.observer = fn
	a.mu.Unlock()
}

func (a *Adapter) emitObserve(ev map[string]any) {
	a.mu.Lock()
	fn := a.observer
	a.mu.Unlock()
	if fn != nil {
		fn(ev)
	}
}

type sessionRuntime struct {
	cfg      *normalizedSession
	ps       *persistedSession
	messages []Message
	stamp    fileStamp
	loaded   bool

	// active is guarded by Adapter.mu. At most one Vanora process may own a
	// session file at a time.
	active *run
	runs   map[string]*run
}

// New constructs an adapter from a locally loaded configuration. statePath is
// a directory owned by the desktop app; the adapter persists replay cursors,
// idempotency records, and run status in statePath/state.json.
func New(cfg *Config, statePath string) (*Adapter, error) {
	nc, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(statePath) == "" {
		return nil, errors.New("desktop: state path is empty")
	}
	dir, err := filepath.Abs(statePath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if st, err := os.Stat(dir); err != nil {
		return nil, err
	} else if !st.IsDir() {
		return nil, errors.New("desktop: state path is not a directory")
	}
	st, err := loadState(dir)
	if err != nil {
		return nil, err
	}
	a := &Adapter{
		cfg:      nc,
		state:    st,
		stateDir: dir,
		peers:    make(map[transport.Peer]*peerState),
		sessions: make(map[string]*sessionRuntime),
		runs:     make(map[string]*run),
		// Fail closed until the host supplies a verified deadline through
		// AuthorityUntil. A transport reconnect alone cannot grant authority.
		authorityOnline: false,
		stopCh:          make(chan struct{}),
		now:             time.Now,
		logger:          slog.Default(),
		maxRequestBytes: max(64<<10, nc.maxText+16<<10),
	}
	a.buildCommand = func(s *normalizedSession) (*exec.Cmd, error) {
		return a.defaultCommand(s)
	}
	for _, s := range nc.sessions {
		ps := st.Sessions[s.id]
		if ps == nil {
			ps = newPersistedSession()
			st.Sessions[s.id] = ps
		}
		if err := ps.validateAndNormalize(); err != nil {
			return nil, err
		}
		messages, stamp, err := loadSessionMessages(s.sessionFile)
		if err != nil {
			return nil, err
		}
		a.sessions[s.id] = &sessionRuntime{
			cfg:      s,
			ps:       ps,
			messages: messages,
			stamp:    stamp,
			loaded:   true,
			runs:     make(map[string]*run),
		}
	}
	for id, rec := range st.CreatedSessions {
		if _, exists := a.sessions[id]; exists {
			continue
		}
		w := nc.workspacesByID[rec.WorkspaceID]
		if w == nil || rec.Owner != w.owner {
			continue
		}
		sessionFile, err := resolveSessionFile(rec.SessionFile, w.workDir)
		if err != nil {
			continue
		}
		messages, stamp, err := loadSessionMessages(sessionFile)
		if err != nil {
			continue
		}
		ps := st.Sessions[id]
		if ps == nil {
			ps = newPersistedSession()
			st.Sessions[id] = ps
		}
		if err := ps.validateAndNormalize(); err != nil {
			return nil, err
		}
		a.sessions[id] = &sessionRuntime{
			cfg:      sessionFromWorkspace(w, rec, sessionFile),
			ps:       ps,
			messages: messages,
			stamp:    stamp,
			loaded:   true,
			runs:     make(map[string]*run),
		}
	}
	a.recoverRunRecordsLocked()
	if err := a.saveLocked(); err != nil {
		return nil, err
	}
	a.wg.Add(1)
	go a.authorityLoop()
	return a, nil
}

func sessionFromWorkspace(w *normalizedWorkspace, rec createdSessionRecord, sessionFile string) *normalizedSession {
	grants := make(map[string]Grant, len(w.grants))
	for k, v := range w.grants {
		grants[k] = v
	}
	title := rec.Title
	if title == "" {
		title = rec.ID
	}
	tools := slices.Clone(w.tools)
	if rec.HasToolsLimit {
		tools = intersectTools(tools, rec.ToolsLimit)
	}
	return &normalizedSession{
		id:                 rec.ID,
		workspaceID:        w.id,
		title:              title,
		workDir:            w.workDir,
		sessionFile:        sessionFile,
		owner:              w.owner,
		officialOwner:      w.officialOwner,
		lanAccess:          w.lanAccess,
		selfAccess:         w.selfAccess,
		tools:              tools,
		arguments:          slices.Clone(w.arguments),
		showThinking:       w.showThinking,
		showTools:          w.showTools,
		approvalPolicy:     w.approvalPolicy,
		fencePeerSessions:  w.fencePeerSessions,
		allowGuestRequests: w.allowGuestRequests,
		linkOrigin:         rec.LinkOrigin,
		readOnly:           rec.ReadOnly,
		grants:             grants,
	}
}

func intersectTools(allowed, limit []string) []string {
	if len(allowed) == 0 || len(limit) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(limit))
	for _, t := range limit {
		set[t] = struct{}{}
	}
	var out []string
	for _, t := range allowed {
		if _, ok := set[t]; ok {
			out = append(out, t)
		}
	}
	return out
}

func (a *Adapter) ensureApprovalExtension() (string, error) {
	if a.cfg.approvalExtension != "" {
		return a.cfg.approvalExtension, nil
	}
	if a.stateDir == "" {
		return "", nil
	}
	target := filepath.Join(a.stateDir, "approval-guard.mjs")
	if existing, err := os.ReadFile(target); err == nil && string(existing) == string(embeddedApprovalGuard) {
		return target, nil
	}
	tmp, err := os.CreateTemp(a.stateDir, ".approval-guard-*.mjs")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(embeddedApprovalGuard); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return "", err
	}
	return target, nil
}

func (a *Adapter) defaultCommand(s *normalizedSession) (*exec.Cmd, error) {
	args := make([]string, 0, len(a.cfg.launcherArgs)+len(a.cfg.arguments)+len(s.arguments)+14)
	args = append(args, a.cfg.launcherArgs...)
	args = append(args, a.cfg.arguments...)
	args = append(args, s.arguments...)
	args = append(args, "--mode", "rpc")
	if len(s.tools) > 0 {
		args = append(args, "--tools", strings.Join(s.tools, ","))
	} else {
		// A user with Tools permission may still hold a safe text-only
		// conversation. Extensions, MCP, skills, and templates are always
		// disabled so they cannot reintroduce tools or interactive work.
		args = append(args, "--no-tools")
	}
	args = append(args, "--no-extensions")
	if s.remoteApproval() && len(s.tools) > 0 {
		guardPath, err := a.ensureApprovalExtension()
		if err != nil {
			return nil, err
		}
		if guardPath != "" {
			args = append(args, "-e", guardPath)
		}
	}
	args = append(args,
		"--no-mcp",
		"--no-skills",
		"--no-prompt-templates",
		"--no-approve",
		"--session", s.sessionFile,
	)
	cmd := exec.Command(a.cfg.executable, args...)
	cmd.Dir = s.workDir
	return cmd, nil
}

// Open implements transport.Handler.
func (a *Adapter) Open(peer transport.Peer) {
	if peer == nil {
		return
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		peer.Close()
		return
	}
	if _, exists := a.peers[peer]; exists {
		a.mu.Unlock()
		return
	}
	ps := &peerState{
		peer:          peer,
		out:           make(chan delivery, peerQueueSize),
		done:          make(chan struct{}),
		subscriptions: make(map[string]struct{}),
	}
	a.peers[peer] = ps
	a.wg.Add(1)
	a.mu.Unlock()
	a.emitObserve(map[string]any{"type": "peer.connected", "user_id": peer.UserID()})
	go a.peerWriter(ps)
}

// Message implements transport.Handler.
func (a *Adapter) Message(peer transport.Peer, data []byte) {
	a.mu.Lock()
	ps := a.peers[peer]
	closed := a.closed
	a.mu.Unlock()
	if closed || ps == nil {
		return
	}
	a.handleData(ps, data)
}

// Closed implements transport.Handler.
func (a *Adapter) Closed(peer transport.Peer) {
	a.mu.Lock()
	ps := a.peers[peer]
	delete(a.peers, peer)
	a.mu.Unlock()
	if ps != nil {
		ps.close()
		a.emitObserve(map[string]any{"type": "peer.disconnected", "user_id": peer.UserID()})
	}
}

func (a *Adapter) peerWriter(ps *peerState) {
	defer a.wg.Done()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ps.done:
			return
		case d := <-ps.out:
			a.deliver(ps, d)
		}
	}
}

func (a *Adapter) deliver(ps *peerState, d delivery) {
	if d.listRequestID != "" {
		defer ps.pendingLists.Add(-1)
	}
	if ps.closed.Load() {
		return
	}
	ps.sendMu.Lock()
	defer ps.sendMu.Unlock()
	if ps.closed.Load() {
		return
	}
	a.mu.Lock()
	if a.closed || ps.closed.Load() || ps.aclStale.Load() {
		a.mu.Unlock()
		return
	}
	payload := d.data
	if d.sessionID != "" {
		sr := a.sessions[d.sessionID]
		user := ps.peer.UserID()
		if sr == nil || !sr.cfg.canRead(user) {
			a.mu.Unlock()
			return
		}
		if d.visibility != "" {
			allowed := sr.cfg.canSeeEvent(user, d.visibility)
			if allowed && (d.visibility == visApproval || d.visibility == visGuest) && !sr.cfg.owns(user) && (d.approvalUser == "" || user != d.approvalUser) {
				allowed = false
			}
			if !allowed {
				if d.seq <= 0 {
					a.mu.Unlock()
					return
				}
				syncWire, err := json.Marshal(wireEvent{
					Type:      "event",
					SessionID: d.sessionID,
					Seq:       d.seq,
					Kind:      kindSync,
				})
				if err != nil {
					a.mu.Unlock()
					return
				}
				payload = syncWire
			}
		}
	}
	if d.requiresOnline && !a.userOnlineLocked(ps.peer.UserID()) {
		a.mu.Unlock()
		return
	}
	if d.listRequestID != "" {
		var data any
		if d.workspaceList {
			data = a.workspaceListLocked(ps.peer.UserID())
		} else {
			data = a.sessionListLocked(ps.peer.UserID())
		}
		wire, err := json.Marshal(resultEnvelope{
			Type:      "result",
			RequestID: d.listRequestID,
			Data:      data,
		})
		if err != nil {
			a.logger.Error("encode session list", "request", d.listRequestID, "error", err)
			a.mu.Unlock()
			return
		}
		payload = wire
	}
	a.mu.Unlock()
	if !ps.peer.Allows(d.requiresOnline) {
		return
	}
	if err := ps.peer.Send(payload, d.requiresOnline); err != nil {
		// A failed send is not recoverable at this layer: the client must
		// reconnect and resume from its cursor. Never swallow the failure and
		// leave the phone waiting for a frame that will never arrive.
		a.logger.Warn("peer send failed", "user", ps.peer.UserID(), "error", err)
		ps.abort()
		go a.closePeer(ps)
	}
}

func (ps *peerState) abort() {
	if !ps.closed.CompareAndSwap(false, true) {
		return
	}
	ps.peer.Close()
	ps.closeOnce.Do(func() { close(ps.done) })
}

func (a *Adapter) closePeer(ps *peerState) {
	if ps == nil {
		return
	}
	ps.close()
	a.mu.Lock()
	if a.peers[ps.peer] == ps {
		delete(a.peers, ps.peer)
	}
	a.mu.Unlock()
}

func (ps *peerState) close() {
	if !ps.closed.CompareAndSwap(false, true) {
		return
	}
	// Unblock a Send that is already in progress before waiting for it. After
	// this returns, no further bytes can reach this peer.
	ps.peer.Close()
	ps.sendMu.Lock()
	ps.sendMu.Unlock()
	ps.closeOnce.Do(func() { close(ps.done) })
}

// Close stops local processes, disconnects peers, and persists terminal run
// status. It is safe to call more than once.
func (a *Adapter) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.authorityOnline = false
	a.authorityGen++
	close(a.stopCh)
	if a.flushTimer != nil {
		a.flushTimer.Stop()
		a.flushTimer = nil
	}
	if a.authorityTimer != nil {
		a.authorityTimer.Stop()
		a.authorityTimer = nil
	}
	peers := make([]*peerState, 0, len(a.peers))
	for _, ps := range a.peers {
		peers = append(peers, ps)
	}
	runs := make([]*run, 0, len(a.runs))
	for _, r := range a.runs {
		runs = append(runs, r)
		if r.status == statusRunning {
			r.status = statusCancelling
		}
		r.stopFlag.Store(true)
		if r.stopReason == "" {
			r.stopReason = "shutdown"
		}
		_ = a.cancelRunPendingUILocked(r, "cancelled")
	}
	firstErr := a.saveLocked()
	a.mu.Unlock()

	for _, ps := range peers {
		a.closePeer(ps)
	}
	for _, r := range runs {
		r.kill()
	}
	a.wg.Wait()

	a.mu.Lock()
	lastErr := a.saveLocked()
	a.mu.Unlock()
	if firstErr != nil {
		return firstErr
	}
	return lastErr
}

// ReloadACL applies a newly loaded local configuration. It rejects changes to
// the executable only at normal validation time; execution changes apply to
// future runs. Users who lost Read or Tools lose subscriptions and their
// active runs are cancelled immediately. Sessions removed from the config are
// removed from the exposed allowlist and their runs are cancelled.
func (a *Adapter) ReloadACL(cfg *Config) error {
	nc, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	type loadedSession struct {
		messages []Message
		stamp    fileStamp
	}
	preload := make(map[string]loadedSession, len(nc.sessions))
	for _, s := range nc.sessions {
		messages, stamp, err := loadSessionMessages(s.sessionFile)
		if err != nil {
			return err
		}
		preload[s.id] = loadedSession{messages: messages, stamp: stamp}
	}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return errClosed
	}
	// Snapshot dynamically created sessions for reloading against updated workspaces.
	createdRecords := make([]createdSessionRecord, 0, len(a.state.CreatedSessions))
	for _, rec := range a.state.CreatedSessions {
		createdRecords = append(createdRecords, rec)
	}
	a.mu.Unlock()

	type preloadedCreated struct {
		cfg      *normalizedSession
		messages []Message
		stamp    fileStamp
	}
	createdPreload := make(map[string]preloadedCreated)
	for _, rec := range createdRecords {
		if _, shadowed := nc.byID[rec.ID]; shadowed {
			continue
		}
		w := nc.workspacesByID[rec.WorkspaceID]
		if w == nil || rec.Owner != w.owner {
			continue
		}
		sessionFile, err := resolveSessionFile(rec.SessionFile, w.workDir)
		if err != nil {
			continue
		}
		messages, stamp, err := loadSessionMessages(sessionFile)
		if err != nil {
			continue
		}
		createdPreload[rec.ID] = preloadedCreated{
			cfg:      sessionFromWorkspace(w, rec, sessionFile),
			messages: messages,
			stamp:    stamp,
		}
	}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return errClosed
	}
	var stops []*run
	var uiCancels []uiCancelAction
	stopRun := func(r *run, reason string) {
		if r.terminal || r.status == statusCancelling {
			return
		}
		r.status = statusCancelling
		r.stopReason = reason
		r.stopFlag.Store(true)
		uiCancels = append(uiCancels, a.cancelRunPendingUILocked(r, "cancelled")...)
		stops = append(stops, r)
	}
	next := make(map[string]*sessionRuntime, len(nc.sessions)+len(createdPreload))
	attachSession := func(s *normalizedSession, data loadedSession) error {
		s.officialOwner = a.officialOwner
		sr := a.sessions[s.id]
		if sr == nil {
			ps := a.state.Sessions[s.id]
			if ps == nil {
				ps = newPersistedSession()
				a.state.Sessions[s.id] = ps
			}
			if err := ps.validateAndNormalize(); err != nil {
				return err
			}
			sr = &sessionRuntime{cfg: s, ps: ps, runs: make(map[string]*run)}
		}
		changedExec := !sameExecution(sr.cfg, s)
		sr.cfg = s
		if changedExec {
			for _, r := range sr.runs {
				stopRun(r, "config_changed")
			}
		}
		if sr.active == nil {
			sr.messages = data.messages
			sr.stamp = data.stamp
			sr.loaded = true
		} else {
			sr.loaded = false
		}
		next[s.id] = sr
		return nil
	}
	for _, s := range nc.sessions {
		if err := attachSession(s, preload[s.id]); err != nil {
			a.mu.Unlock()
			return err
		}
	}
	for id, pc := range createdPreload {
		if _, shadowed := next[id]; shadowed {
			continue
		}
		if err := attachSession(pc.cfg, loadedSession{messages: pc.messages, stamp: pc.stamp}); err != nil {
			a.mu.Unlock()
			return err
		}
	}
	for id, sr := range a.sessions {
		if _, keep := next[id]; keep {
			continue
		}
		for _, r := range sr.runs {
			stopRun(r, "session_removed")
		}
		delete(a.sessions, id)
	}
	for _, r := range a.runs {
		sr := next[r.sessionID]
		if sr == nil {
			stopRun(r, "session_removed")
			continue
		}
		if !sr.cfg.canRead(r.userID) || !sr.cfg.canRun(r.userID) {
			stopRun(r, "acl_revoked")
		}
	}
	for _, workspace := range nc.workspaces {
		workspace.officialOwner = a.officialOwner
	}
	var closePeers []*peerState
	for _, ps := range a.peers {
		user := ps.peer.UserID()
		for id := range ps.subscriptions {
			sr := next[id]
			if sr == nil || !sr.cfg.canRead(user) {
				delete(ps.subscriptions, id)
			}
		}
		anyVisible := false
		for _, sr := range next {
			if sr.cfg.canRead(user) {
				anyVisible = true
				break
			}
		}
		if !anyVisible {
			for _, w := range nc.workspaces {
				if w.canCreate(user) {
					anyVisible = true
					break
				}
			}
		}
		if !anyVisible || ps.pendingLists.Load() > 0 {
			// Invalidate queued work before the new ACL is published. The
			// peer is closed after the lock is released; Deliveries check
			// aclStale while holding the lock and drop stale list replies.
			ps.aclStale.Store(true)
			closePeers = append(closePeers, ps)
		}
	}
	a.sessions = next
	a.cfg = nc
	a.maxRequestBytes = max(64<<10, nc.maxText+16<<10)
	a.mu.Unlock()

	flushUICancels(uiCancels)
	for _, r := range stops {
		r.stop(0)
	}
	for _, ps := range closePeers {
		a.closePeer(ps)
	}
	return nil
}

func sameExecution(a, b *normalizedSession) bool {
	if a == nil || b == nil {
		return false
	}
	return a.workDir == b.workDir &&
		a.sessionFile == b.sessionFile &&
		a.approvalPolicy == b.approvalPolicy &&
		a.linkOrigin == b.linkOrigin &&
		a.readOnly == b.readOnly &&
		a.fencePeerSessions == b.fencePeerSessions &&
		a.allowGuestRequests == b.allowGuestRequests &&
		slices.Equal(a.tools, b.tools) &&
		slices.Equal(a.arguments, b.arguments)
}

func (a *Adapter) SetLANAuthority(allows func(string) bool) {
	a.mu.Lock()
	a.lanAuthority = allows
	a.mu.Unlock()
}

func (a *Adapter) SetSelfAuthority(allows func(string) bool) {
	a.mu.Lock()
	a.selfAuthority = allows
	a.mu.Unlock()
}

func (a *Adapter) SetOfficialOwner(user string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.officialOwner == user {
		return
	}
	a.officialOwner = user
	for _, session := range a.sessions {
		session.cfg.officialOwner = user
	}
	for _, workspace := range a.cfg.workspaces {
		workspace.officialOwner = user
	}
}

func (a *Adapter) RefreshLANAccess() {
	a.mu.Lock()
	stops, uiCancels := a.stopRunsLocked("lan_access_revoked", func(r *run) bool {
		return lan.Access(r.userID) != "" && !a.userOnlineLocked(r.userID)
	})
	a.mu.Unlock()
	flushUICancels(uiCancels)
	for _, r := range stops {
		r.stop(0)
	}
}

func (a *Adapter) RefreshSelfAccess() {
	a.mu.Lock()
	stops, uiCancels := a.stopRunsLocked("self_access_revoked", func(r *run) bool {
		return selfrelay.Access(r.userID) != "" && !a.userOnlineLocked(r.userID)
	})
	a.mu.Unlock()
	flushUICancels(uiCancels)
	for _, r := range stops {
		r.stop(0)
	}
}

// AuthorityLost stops acting on behalf of the identity authority. All active
// model jobs are cancelled immediately; disconnected phones do not trigger
// this method. The last validated deadline is retained so AuthorityRestored
// can resume only while that deadline is still in the future.
func (a *Adapter) AuthorityLost() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.authorityOnline = false
	a.authorityGen++
	if a.authorityTimer != nil {
		a.authorityTimer.Stop()
		a.authorityTimer = nil
	}
	stops, uiCancels := a.stopRunsLocked("authority_lost", officialRun)
	a.mu.Unlock()
	flushUICancels(uiCancels)
	for _, r := range stops {
		r.stop(0)
	}
}

// AuthorityRestored resumes accepting work only if a validated, unexpired
// deadline already exists. It never creates an unbounded authority window:
// callers must provide a fresh verified expiry through AuthorityUntil first.
func (a *Adapter) AuthorityRestored() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	now := a.now()
	if a.authorityUntil.IsZero() || !now.Before(a.authorityUntil) {
		a.authorityOnline = false
		a.authorityGen++
		if a.authorityTimer != nil {
			a.authorityTimer.Stop()
			a.authorityTimer = nil
		}
		a.mu.Unlock()
		a.logger.Warn("authority restore ignored without an unexpired deadline")
		return
	}
	a.authorityOnline = true
	a.authorityGen++
	gen := a.authorityGen
	if a.authorityTimer != nil {
		a.authorityTimer.Stop()
		a.authorityTimer = nil
	}
	until := a.authorityUntil
	a.authorityTimer = time.AfterFunc(until.Sub(now), func() {
		a.expireAuthority(gen, until)
	})
	a.mu.Unlock()
}

// AuthorityUntil grants tool authority until the supplied instant. When it
// passes, active jobs are cancelled and new runs are refused, even if no peer
// remains connected to observe the expiry. A zero or past deadline revokes
// authority immediately; there is no unbounded mode.
func (a *Adapter) AuthorityUntil(until time.Time) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.authorityGen++
	gen := a.authorityGen
	if a.authorityTimer != nil {
		a.authorityTimer.Stop()
		a.authorityTimer = nil
	}
	a.authorityUntil = until
	for _, r := range a.runs {
		if !r.terminal && officialRun(r) {
			r.authorityUntil = until
		}
	}
	now := a.now()
	if until.IsZero() || !now.Before(until) {
		a.authorityOnline = false
		stops, uiCancels := a.stopRunsLocked("authority_lost", officialRun)
		a.mu.Unlock()
		flushUICancels(uiCancels)
		for _, r := range stops {
			r.stop(0)
		}
		return
	}
	a.authorityOnline = true
	d := until.Sub(now)
	a.authorityTimer = time.AfterFunc(d, func() { a.expireAuthority(gen, until) })
	a.mu.Unlock()
}

func (a *Adapter) expireAuthority(gen uint64, until time.Time) {
	a.mu.Lock()
	if a.closed || gen != a.authorityGen || !until.Equal(a.authorityUntil) {
		a.mu.Unlock()
		return
	}
	a.authorityTimer = nil
	if a.now().Before(until) {
		a.mu.Unlock()
		return
	}
	a.authorityOnline = false
	stops, uiCancels := a.stopRunsLocked("authority_lost", officialRun)
	a.mu.Unlock()
	flushUICancels(uiCancels)
	for _, r := range stops {
		r.stop(0)
	}
}

func (a *Adapter) authorityLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(authorityTick)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.checkRuns()
		}
	}
}

func (a *Adapter) checkRuns() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	var stops []*run
	var uiCancels []uiCancelAction
	now := a.now()
	for _, r := range a.runs {
		if r.terminal || r.status != statusRunning {
			continue
		}
		reason := ""
		sr := a.sessions[r.sessionID]
		if r.localApproved {
			if sr == nil {
				reason = "acl_revoked"
			}
		} else {
			switch {
			case sr == nil || !sr.cfg.canRead(r.userID) || !sr.cfg.canRun(r.userID):
				reason = "acl_revoked"
			case !a.userOnlineLocked(r.userID):
				reason = "authority_lost"
				if lan.Access(r.userID) != "" {
					reason = "lan_access_revoked"
				} else if selfrelay.Access(r.userID) != "" {
					reason = "self_access_revoked"
				}
			case !r.authorityUntil.IsZero() && !now.Before(r.authorityUntil):
				reason = "authority_lost"
			}
		}
		// Transport peer connectivity is deliberately not part of ongoing
		// authority. A disconnected phone must not cancel accepted local work.
		if reason == "" {
			continue
		}
		r.status = statusCancelling
		r.stopReason = reason
		r.stopFlag.Store(true)
		uiCancels = append(uiCancels, a.cancelRunPendingUILocked(r, "cancelled")...)
		stops = append(stops, r)
	}
	a.mu.Unlock()
	flushUICancels(uiCancels)
	for _, r := range stops {
		r.stop(0)
	}
}

func officialRun(r *run) bool {
	if r.localApproved {
		return false
	}
	return lan.Access(r.userID) == "" && selfrelay.Access(r.userID) == ""
}

func (a *Adapter) stopRunsLocked(reason string, matches func(*run) bool) ([]*run, []uiCancelAction) {
	var stops []*run
	var uiCancels []uiCancelAction
	for _, r := range a.runs {
		if r.terminal || r.status == statusCancelling || !matches(r) {
			continue
		}
		r.status = statusCancelling
		r.stopReason = reason
		r.stopFlag.Store(true)
		uiCancels = append(uiCancels, a.cancelRunPendingUILocked(r, "cancelled")...)
		stops = append(stops, r)
	}
	return stops, uiCancels
}

func (a *Adapter) userOnlineLocked(user string) bool {
	if lan.Access(user) != "" {
		return a.lanAuthority != nil && a.lanAuthority(user)
	}
	if selfrelay.Access(user) != "" {
		return a.selfAuthority != nil && a.selfAuthority(user)
	}
	return a.effectiveOnlineLocked()
}

func (a *Adapter) effectiveOnlineLocked() bool {
	if !a.authorityOnline || a.authorityUntil.IsZero() {
		return false
	}
	return a.now().Before(a.authorityUntil)
}

func (a *Adapter) markDirtyLocked() {
	a.dirty = true
	if a.flushTimer != nil || a.closed {
		return
	}
	a.flushTimer = time.AfterFunc(flushDelay, a.flush)
}

func (a *Adapter) flush() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.flushTimer = nil
	if a.closed || !a.dirty {
		return
	}
	if err := a.saveLocked(); err != nil {
		a.logger.Error("persist desktop state", "error", err)
	}
}

func (a *Adapter) saveLocked() error {
	if err := saveState(a.stateDir, a.state); err != nil {
		a.dirty = true
		return err
	}
	a.dirty = false
	return nil
}

func (a *Adapter) appendEventLocked(sr *sessionRuntime, runID, kind string, data any, requiresOnline bool) *storedEvent {
	return a.appendEventVisibleLocked(sr, runID, kind, data, requiresOnline, visAll, "")
}

func (a *Adapter) appendEventVisibleLocked(sr *sessionRuntime, runID, kind string, data any, requiresOnline bool, visibility, approvalUser string) *storedEvent {
	var raw json.RawMessage
	if data != nil {
		encoded, err := json.Marshal(data)
		if err != nil {
			a.logger.Error("encode event", "session", sr.cfg.id, "kind", kind, "error", err)
			return nil
		}
		raw = encoded
	}
	e := storedEvent{
		Seq:            sr.ps.LastSeq + 1,
		RunID:          runID,
		Kind:           kind,
		Data:           raw,
		RequiresOnline: requiresOnline,
		Visibility:     visibility,
		ApprovalUser:   approvalUser,
	}
	sr.ps.appendEvent(e)
	sr.ps.trim(a.cfg.retention)
	wire, err := json.Marshal(wireEvent{
		Type:      "event",
		SessionID: sr.cfg.id,
		RunID:     e.RunID,
		Seq:       e.Seq,
		Kind:      e.Kind,
		Data:      e.Data,
	})
	if err != nil {
		a.logger.Error("encode event wire", "session", sr.cfg.id, "error", err)
		a.markDirtyLocked()
		return &e
	}
	for peer, ps := range a.peers {
		if !sr.cfg.canRead(peer.UserID()) {
			continue
		}
		if _, subscribed := ps.subscriptions[sr.cfg.id]; !subscribed {
			continue
		}
		a.enqueueLocked(ps, delivery{
			data:           wire,
			requiresOnline: requiresOnline,
			sessionID:      sr.cfg.id,
			visibility:     visibility,
			approvalUser:   approvalUser,
			seq:            e.Seq,
		})
	}
	a.markDirtyLocked()
	return &e
}

func (a *Adapter) orderedSessionsLocked() []*sessionRuntime {
	seen := make(map[string]bool, len(a.sessions))
	out := make([]*sessionRuntime, 0, len(a.sessions))
	for _, s := range a.cfg.sessions {
		if sr := a.sessions[s.id]; sr != nil {
			out = append(out, sr)
			seen[s.id] = true
		}
	}
	var extras []*sessionRuntime
	for id, sr := range a.sessions {
		if !seen[id] {
			extras = append(extras, sr)
		}
	}
	sort.Slice(extras, func(i, j int) bool {
		ci := a.state.CreatedSessions[extras[i].cfg.id].Created
		cj := a.state.CreatedSessions[extras[j].cfg.id].Created
		if ci == cj {
			return extras[i].cfg.id < extras[j].cfg.id
		}
		return ci < cj
	})
	return append(out, extras...)
}

func (sr *sessionRuntime) syncLocked(a *Adapter) {
	if sr.active != nil {
		return
	}
	st, err := os.Stat(sr.cfg.sessionFile)
	if err != nil {
		a.logger.Error("stat session", "session", sr.cfg.id, "error", err)
		return
	}
	if sr.loaded && st.Size() == sr.stamp.size && st.ModTime().Equal(sr.stamp.modTime) {
		return
	}
	messages, stamp, err := loadSessionMessages(sr.cfg.sessionFile)
	if err != nil {
		a.logger.Error("reload session", "session", sr.cfg.id, "error", err)
		return
	}
	sr.messages = messages
	sr.stamp = stamp
	sr.loaded = true
}

func (a *Adapter) recoverRunRecordsLocked() {
	for _, sr := range a.sessions {
		for id, rec := range sr.ps.Runs {
			if rec.Status != statusRunning && rec.Status != statusCancelling {
				continue
			}
			rec.Status = statusFailed
			sr.ps.Runs[id] = rec
			a.appendEventLocked(sr, id, kindRunFailed, runFailedData{Reason: "process_exit"}, rec.Tools)
		}
	}
}

func newRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func payloadHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func requestHash(userID, sessionID, requestID string) string {
	h := sha256.New()
	h.Write([]byte(userID))
	h.Write([]byte{0})
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(requestID))
	return hex.EncodeToString(h.Sum(nil))
}
