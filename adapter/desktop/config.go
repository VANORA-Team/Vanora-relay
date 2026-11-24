package desktop

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode"

	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
)

// Config is the local allowlist. It is the only source of sessions, working
// directories, executables, arguments, and remote users. Nothing in the RPC
// protocol can add a session, choose a path, or change a command line.
type Config struct {
	// Executable is the Vanora binary or a local launcher. Absolute paths are
	// preferred; a bare command is resolved once through PATH at load time.
	Executable string `json:"executable"`

	// Arguments are fixed arguments placed before the adapter's own RPC
	// arguments. They may select a provider, model, or session directory, but
	// may not select a session, enable tools, change the run mode, or contain a
	// positional prompt.
	Arguments []string `json:"arguments,omitempty"`

	// LauncherArgs is an optional local launcher prefix. It is only valid when
	// Executable is node/node.exe: exactly one existing absolute .js or .mjs
	// script path. This runs Vanora's distributed dist/cli.js on Windows,
	// where vanora.cmd is not a directly executable native binary.
	LauncherArgs []string `json:"launcher_args,omitempty"`

	// ApprovalExtension is an optional absolute path to a Vanora extension
	// (.js or .mjs) loaded via `--no-extensions -e <path>` when a session has
	// approval_policy = "remote". When omitted, the built-in approval guard
	// extension is materialized into the adapter state directory.
	ApprovalExtension string `json:"approval_extension,omitempty"`

	Sessions []SessionConfig `json:"sessions,omitempty"`

	// Workspaces is the local allowlist of directories where the owner may
	// remotely create new Vanora sessions via session.create.
	Workspaces []WorkspaceConfig `json:"workspaces,omitempty"`

	// Retention bounds the per-session replay log. Zero values use defaults.
	Retention RetentionConfig `json:"retention,omitempty"`

	// AllowSlashCommands permits prompt text beginning with "/". It is false by
	// default because slash commands can invoke local templates or tools.
	AllowSlashCommands bool `json:"allow_slash_commands,omitempty"`

	// MaxTextBytes limits one prompt. Zero uses the default (64 KiB).
	MaxTextBytes int `json:"max_text_bytes,omitempty"`

	// MaxSnapshotBytes bounds the JSON that session.open may return. Zero uses
	// the default (16 MiB), well below the transport's 64 MiB reassembled frame
	// cap. A larger conversation is refused with snapshot_too_large instead of
	// exhausting memory or silently truncating history.
	MaxSnapshotBytes int `json:"max_snapshot_bytes,omitempty"`
}

// RetentionConfig bounds persisted replay data per session.
type RetentionConfig struct {
	MaxEvents   int   `json:"max_events,omitempty"`
	MaxBytes    int64 `json:"max_bytes,omitempty"`
	MaxRequests int   `json:"max_requests,omitempty"`
}

const (
	approvalNone   = "none"
	approvalRemote = "remote"
	LocalOwner     = "local"
)

// SessionConfig is one explicitly shared conversation.
type SessionConfig struct {
	// ID is the stable identifier exposed to remote clients.
	ID string `json:"id"`
	// Title is display text. It defaults to ID.
	Title string `json:"title,omitempty"`

	// WorkingDir is the project directory used for the subprocess. It must be
	// absolute and must match the session file's recorded cwd.
	WorkingDir string `json:"working_dir"`
	// SessionFile is an existing Vanora JSONL session. It must be absolute.
	SessionFile string `json:"session_file"`

	// Owner always has read and tool access. Only a Tools-enabled user may
	// submit model prompts; a Read-only user can only read shared context.
	Owner string `json:"owner"`

	LANAccess  bool `json:"lan_access,omitempty"`
	SelfAccess bool `json:"self_access,omitempty"`

	// Tools selects the local tool set. Empty means --no-tools: the user may
	// still hold a text-only conversation, with extensions and MCP disabled.
	Tools []string `json:"tools,omitempty"`

	// Arguments are extra local arguments for this session. Same restrictions
	// as Config.Arguments apply.
	Arguments []string `json:"arguments,omitempty"`

	// ShowThinking enables exposing model reasoning blocks and thinking.delta
	// events to the owner. Guests only see thinking if their Grant sets
	// show_thinking: true.
	ShowThinking bool `json:"show_thinking,omitempty"`

	// ShowTools enables exposing tool calls, streaming tool output and tool
	// results to the owner. Guests only see tools if their Grant sets
	// show_tools: true.
	ShowTools bool `json:"show_tools,omitempty"`

	// ApprovalPolicy controls interactive tool approval and extension UI
	// prompts ("none" or "" auto-cancels locally; "remote" forwards dialogs
	// over the encrypted DataChannel and loads the approval guard extension
	// when tools are enabled).
	ApprovalPolicy string `json:"approval_policy,omitempty"`

	// Users are additional explicit grants. Any user absent from this list
	// (and not the owner) has no access at all.
	Users []Grant `json:"users,omitempty"`
}

// WorkspaceConfig is an explicitly allowed project directory where the owner
// can remotely create new Vanora sessions.
type WorkspaceConfig struct {
	ID             string   `json:"id"`
	Title          string   `json:"title,omitempty"`
	WorkingDir     string   `json:"working_dir"`
	SessionDir     string   `json:"session_dir,omitempty"`
	Owner          string   `json:"owner"`
	LANAccess      bool     `json:"lan_access,omitempty"`
	SelfAccess     bool     `json:"self_access,omitempty"`
	Tools          []string `json:"tools,omitempty"`
	Arguments      []string `json:"arguments,omitempty"`
	ShowThinking   bool     `json:"show_thinking,omitempty"`
	ShowTools      bool     `json:"show_tools,omitempty"`
	ApprovalPolicy string   `json:"approval_policy,omitempty"`
	Users          []Grant  `json:"users,omitempty"`
}

// Grant is one remote user's permission for one session.
type Grant struct {
	UserID       string `json:"user_id"`
	Read         bool   `json:"read"`
	Tools        bool   `json:"tools"`
	ShowThinking bool   `json:"show_thinking,omitempty"`
	ShowTools    bool   `json:"show_tools,omitempty"`
	Approve      bool   `json:"approve,omitempty"`
}

const (
	defaultMaxEvents   = 4096
	defaultMaxBytes    = int64(4 << 20)
	defaultMaxRequests = 4096
	defaultMaxText     = 64 << 10
	maxMaxText         = 1 << 20
	defaultMaxSnapshot = 16 << 20
	maxMaxSnapshot     = 48 << 20
)

var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type normalizedConfig struct {
	executable        string
	launcherArgs      []string
	approvalExtension string
	arguments         []string
	sessions          []*normalizedSession
	byID              map[string]*normalizedSession
	workspaces        []*normalizedWorkspace
	workspacesByID    map[string]*normalizedWorkspace
	retention         RetentionConfig
	allowSlash        bool
	maxText           int
	maxSnapshot       int
}

type normalizedWorkspace struct {
	id             string
	title          string
	workDir        string
	sessionDir     string
	owner          string
	officialOwner  string
	lanAccess      bool
	selfAccess     bool
	tools          []string
	arguments      []string
	showThinking   bool
	showTools      bool
	approvalPolicy string
	grants         map[string]Grant
}

type normalizedSession struct {
	id             string
	workspaceID    string
	title          string
	workDir        string
	sessionFile    string
	owner          string
	officialOwner  string
	lanAccess      bool
	selfAccess     bool
	tools          []string
	arguments      []string
	showThinking   bool
	showTools      bool
	approvalPolicy string
	grants         map[string]Grant
}

func (s *normalizedSession) grant(userID string) (Grant, bool) {
	if userID == "" {
		return Grant{}, false
	}
	if access := lan.Access(userID); access != "" {
		if !s.lanAccess {
			return Grant{}, false
		}
		control := access == lan.Control
		return Grant{
			UserID: userID, Read: true, Tools: control,
			ShowThinking: control && s.showThinking,
			ShowTools:    control && s.showTools,
			Approve:      control && s.remoteApproval(),
		}, true
	}
	if access := selfrelay.Access(userID); access != "" {
		if !s.selfAccess {
			return Grant{}, false
		}
		control := access == selfrelay.Control
		return Grant{
			UserID: userID, Read: true, Tools: control,
			ShowThinking: control && s.showThinking,
			ShowTools:    control && s.showTools,
			Approve:      control && s.remoteApproval(),
		}, true
	}
	if s.owns(userID) {
		return Grant{
			UserID:       userID,
			Read:         true,
			Tools:        true,
			ShowThinking: s.showThinking,
			ShowTools:    s.showTools,
			Approve:      s.approvalPolicy == approvalRemote,
		}, true
	}
	g, ok := s.grants[userID]
	return g, ok
}

func (s *normalizedSession) owns(userID string) bool {
	return owns(s.owner, s.officialOwner, userID)
}

func owns(owner, officialOwner, userID string) bool {
	if owner == LocalOwner {
		return officialOwner != "" && officialOwner == userID
	}
	return owner == userID
}

func (w *normalizedWorkspace) canCreate(userID string) bool {
	if access := lan.Access(userID); access != "" {
		return w.lanAccess && access == lan.Control
	}
	if access := selfrelay.Access(userID); access != "" {
		return w.selfAccess && access == selfrelay.Control
	}
	return owns(w.owner, w.officialOwner, userID)
}

func (s *normalizedSession) canRead(userID string) bool {
	g, ok := s.grant(userID)
	return ok && g.Read
}

// canRun is true when the user may submit a model prompt. The local Tools
// list may be empty; that produces a text-only (--no-tools) run, not a denial.
func (s *normalizedSession) canRun(userID string) bool {
	g, ok := s.grant(userID)
	return ok && g.Read && g.Tools
}

func (s *normalizedSession) canSeeThinking(userID string) bool {
	g, ok := s.grant(userID)
	return ok && g.Read && g.ShowThinking
}

func (s *normalizedSession) canSeeTools(userID string) bool {
	g, ok := s.grant(userID)
	return ok && g.Read && g.ShowTools
}

func (s *normalizedSession) canApprove(userID string) bool {
	if s.approvalPolicy != approvalRemote {
		return false
	}
	g, ok := s.grant(userID)
	return ok && g.Read && g.Tools && g.Approve
}

func (s *normalizedSession) remoteApproval() bool {
	return s.approvalPolicy == approvalRemote
}

func (s *normalizedSession) anyThinking() bool {
	if s.showThinking {
		return true
	}
	for _, g := range s.grants {
		if g.Read && g.ShowThinking {
			return true
		}
	}
	return false
}

func (s *normalizedSession) anyTools() bool {
	if s.showTools {
		return true
	}
	for _, g := range s.grants {
		if g.Read && g.ShowTools {
			return true
		}
	}
	return false
}

func (s *normalizedSession) canSeeEvent(userID, visibility string) bool {
	switch visibility {
	case visAll:
		return s.canRead(userID)
	case visThinking:
		return s.canSeeThinking(userID)
	case visTools:
		return s.canSeeTools(userID)
	case visApproval:
		return s.canApprove(userID)
	default:
		return false
	}
}

// LoadConfig reads and validates a local JSON configuration file. URLs and
// non-local paths are rejected; the returned Config can be passed to New.
func LoadConfig(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("desktop: config path is empty")
	}
	if strings.Contains(path, "://") {
		return nil, errors.New("desktop: config must be a local file")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("desktop: config path: %w", err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("desktop: read config: %w", err)
	}
	return ParseConfig(raw)
}

// ParseConfig decodes and validates a single snapshot of the local ACL file.
func ParseConfig(raw []byte) (*Config, error) {
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("desktop: parse config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("desktop: trailing data in config")
		}
		return nil, fmt.Errorf("desktop: trailing data in config: %w", err)
	}
	if _, err := normalizeConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func normalizeConfig(cfg *Config) (*normalizedConfig, error) {
	if cfg == nil {
		return nil, errors.New("desktop: nil config")
	}
	out := &normalizedConfig{
		retention: RetentionConfig{
			MaxEvents:   cfg.Retention.MaxEvents,
			MaxBytes:    cfg.Retention.MaxBytes,
			MaxRequests: cfg.Retention.MaxRequests,
		},
		allowSlash:     cfg.AllowSlashCommands,
		maxText:        cfg.MaxTextBytes,
		maxSnapshot:    cfg.MaxSnapshotBytes,
		byID:           make(map[string]*normalizedSession),
		workspacesByID: make(map[string]*normalizedWorkspace),
	}
	if out.retention.MaxEvents < 0 || out.retention.MaxBytes < 0 || out.retention.MaxRequests < 0 {
		return nil, errors.New("desktop: retention values must not be negative")
	}
	if out.retention.MaxEvents == 0 {
		out.retention.MaxEvents = defaultMaxEvents
	}
	if out.retention.MaxBytes == 0 {
		out.retention.MaxBytes = defaultMaxBytes
	}
	if out.retention.MaxRequests == 0 {
		out.retention.MaxRequests = defaultMaxRequests
	}
	if out.retention.MaxEvents > 1_000_000 {
		return nil, errors.New("desktop: retention.max_events is too large")
	}
	if out.retention.MaxBytes > 256<<20 {
		return nil, errors.New("desktop: retention.max_bytes is too large")
	}
	if out.retention.MaxRequests > 100_000 {
		return nil, errors.New("desktop: retention.max_requests is too large")
	}
	if out.maxText == 0 {
		out.maxText = defaultMaxText
	}
	if out.maxText < 1 || out.maxText > maxMaxText {
		return nil, fmt.Errorf("desktop: max_text_bytes must be between 1 and %d", maxMaxText)
	}
	if out.maxSnapshot == 0 {
		out.maxSnapshot = defaultMaxSnapshot
	}
	if out.maxSnapshot < 1 || out.maxSnapshot > maxMaxSnapshot {
		return nil, fmt.Errorf("desktop: max_snapshot_bytes must be between 1 and %d", maxMaxSnapshot)
	}

	exe, err := resolveExecutable(cfg.Executable)
	if err != nil {
		return nil, err
	}
	out.executable = exe
	out.launcherArgs, err = resolveLauncherArgs(exe, cfg.LauncherArgs)
	if err != nil {
		return nil, err
	}
	if isNodeExecutable(exe) && len(out.launcherArgs) == 0 {
		return nil, errors.New("desktop: node executable requires launcher_args with one dist/cli.js path")
	}
	out.arguments, err = validateArguments(cfg.Arguments)
	if err != nil {
		return nil, fmt.Errorf("desktop: arguments: %w", err)
	}
	if strings.TrimSpace(cfg.ApprovalExtension) != "" {
		extPath, err := resolveScriptFile(cfg.ApprovalExtension)
		if err != nil {
			return nil, fmt.Errorf("desktop: approval_extension: %w", err)
		}
		out.approvalExtension = extPath
	}

	for i := range cfg.Sessions {
		s, err := normalizeSession(&cfg.Sessions[i])
		if err != nil {
			return nil, err
		}
		if _, exists := out.byID[s.id]; exists {
			return nil, fmt.Errorf("desktop: duplicate session id %q", s.id)
		}
		out.byID[s.id] = s
		out.sessions = append(out.sessions, s)
	}
	for i := range cfg.Workspaces {
		w, err := normalizeWorkspace(&cfg.Workspaces[i])
		if err != nil {
			return nil, err
		}
		if _, exists := out.workspacesByID[w.id]; exists {
			return nil, fmt.Errorf("desktop: duplicate workspace id %q", w.id)
		}
		out.workspacesByID[w.id] = w
		out.workspaces = append(out.workspaces, w)
	}
	return out, nil
}

func resolveExecutable(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("desktop: executable is empty")
	}
	if strings.ContainsAny(name, "\x00\r\n") {
		return "", errors.New("desktop: executable contains control characters")
	}
	if !filepath.IsAbs(name) {
		found, err := exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("desktop: executable %q not found: %w", name, err)
		}
		name = found
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", fmt.Errorf("desktop: executable path: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("desktop: executable: %w", err)
	}
	if st.IsDir() {
		return "", fmt.Errorf("desktop: executable %q is a directory", abs)
	}
	return abs, nil
}

func normalizeSession(in *SessionConfig) (*normalizedSession, error) {
	if in == nil {
		return nil, errors.New("desktop: nil session")
	}
	id := strings.TrimSpace(in.ID)
	if !sessionIDPattern.MatchString(id) {
		return nil, fmt.Errorf("desktop: invalid session id %q", in.ID)
	}
	owner := strings.TrimSpace(in.Owner)
	if err := validateUserID("owner", owner); err != nil {
		return nil, fmt.Errorf("desktop: session %q: %w", id, err)
	}
	workDir, err := resolveDir(in.WorkingDir)
	if err != nil {
		return nil, fmt.Errorf("desktop: session %q working_dir: %w", id, err)
	}
	sessionFile, err := resolveSessionFile(in.SessionFile, workDir)
	if err != nil {
		return nil, fmt.Errorf("desktop: session %q session_file: %w", id, err)
	}
	args, err := validateArguments(in.Arguments)
	if err != nil {
		return nil, fmt.Errorf("desktop: session %q arguments: %w", id, err)
	}
	tools, err := validateTools(in.Tools)
	if err != nil {
		return nil, fmt.Errorf("desktop: session %q tools: %w", id, err)
	}
	approvalPolicy, err := validateApprovalPolicy(in.ApprovalPolicy)
	if err != nil {
		return nil, fmt.Errorf("desktop: session %q approval_policy: %w", id, err)
	}
	title := strings.TrimSpace(in.Title)
	if title == "" {
		title = id
	}
	if len(title) > 200 || hasControl(title) {
		return nil, fmt.Errorf("desktop: session %q title is invalid", id)
	}
	grants, err := normalizeGrants(id, owner, in.Users)
	if err != nil {
		return nil, fmt.Errorf("desktop: session %q: %w", id, err)
	}
	return &normalizedSession{
		id:             id,
		title:          title,
		workDir:        workDir,
		sessionFile:    sessionFile,
		owner:          owner,
		lanAccess:      in.LANAccess,
		selfAccess:     in.SelfAccess,
		tools:          tools,
		arguments:      args,
		showThinking:   in.ShowThinking,
		showTools:      in.ShowTools,
		approvalPolicy: approvalPolicy,
		grants:         grants,
	}, nil
}

func normalizeWorkspace(in *WorkspaceConfig) (*normalizedWorkspace, error) {
	if in == nil {
		return nil, errors.New("desktop: nil workspace")
	}
	id := strings.TrimSpace(in.ID)
	if !sessionIDPattern.MatchString(id) {
		return nil, fmt.Errorf("desktop: invalid workspace id %q", in.ID)
	}
	owner := strings.TrimSpace(in.Owner)
	if err := validateUserID("owner", owner); err != nil {
		return nil, fmt.Errorf("desktop: workspace %q: %w", id, err)
	}
	workDir, err := resolveDir(in.WorkingDir)
	if err != nil {
		return nil, fmt.Errorf("desktop: workspace %q working_dir: %w", id, err)
	}
	sessionDir, err := resolveWorkspaceSessionDir(in.SessionDir, workDir)
	if err != nil {
		return nil, fmt.Errorf("desktop: workspace %q session_dir: %w", id, err)
	}
	args, err := validateArguments(in.Arguments)
	if err != nil {
		return nil, fmt.Errorf("desktop: workspace %q arguments: %w", id, err)
	}
	tools, err := validateTools(in.Tools)
	if err != nil {
		return nil, fmt.Errorf("desktop: workspace %q tools: %w", id, err)
	}
	approvalPolicy, err := validateApprovalPolicy(in.ApprovalPolicy)
	if err != nil {
		return nil, fmt.Errorf("desktop: workspace %q approval_policy: %w", id, err)
	}
	title := strings.TrimSpace(in.Title)
	if title == "" {
		title = id
	}
	if len(title) > 200 || hasControl(title) {
		return nil, fmt.Errorf("desktop: workspace %q title is invalid", id)
	}
	grants, err := normalizeGrants(id, owner, in.Users)
	if err != nil {
		return nil, fmt.Errorf("desktop: workspace %q: %w", id, err)
	}
	return &normalizedWorkspace{
		id:             id,
		title:          title,
		workDir:        workDir,
		sessionDir:     sessionDir,
		owner:          owner,
		lanAccess:      in.LANAccess,
		selfAccess:     in.SelfAccess,
		tools:          tools,
		arguments:      args,
		showThinking:   in.ShowThinking,
		showTools:      in.ShowTools,
		approvalPolicy: approvalPolicy,
		grants:         grants,
	}, nil
}

func normalizeGrants(scopeID, owner string, in []Grant) (map[string]Grant, error) {
	grants := make(map[string]Grant, len(in))
	for i, g := range in {
		uid := strings.TrimSpace(g.UserID)
		if err := validateUserID(fmt.Sprintf("users[%d].user_id", i), uid); err != nil {
			return nil, err
		}
		if uid == owner {
			return nil, errors.New("owner must not also be listed in users")
		}
		if _, dup := grants[uid]; dup {
			return nil, fmt.Errorf("duplicate user %q", uid)
		}
		if !g.Read && !g.Tools && !g.ShowThinking && !g.ShowTools && !g.Approve {
			return nil, fmt.Errorf("user %q has no permissions", uid)
		}
		if (g.Tools || g.ShowThinking || g.ShowTools) && !g.Read {
			return nil, fmt.Errorf("user %q requires read permission", uid)
		}
		if g.Approve && (!g.Read || !g.Tools) {
			return nil, fmt.Errorf("user %q has approve without read and tools", uid)
		}
		grants[uid] = Grant{
			UserID:       uid,
			Read:         g.Read,
			Tools:        g.Tools,
			ShowThinking: g.ShowThinking,
			ShowTools:    g.ShowTools,
			Approve:      g.Approve,
		}
	}
	_ = scopeID
	return grants, nil
}

func validateApprovalPolicy(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", approvalNone:
		return approvalNone, nil
	case approvalRemote:
		return approvalRemote, nil
	default:
		return "", fmt.Errorf("unsupported policy %q (want \"none\" or \"remote\")", raw)
	}
}

func resolveWorkspaceSessionDir(dir, workDir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return defaultVanoraSessionDir(workDir)
	}
	if !filepath.IsAbs(dir) {
		return "", errors.New("must be absolute")
	}
	clean := filepath.Clean(dir)
	if st, err := os.Stat(clean); err == nil {
		if !st.IsDir() {
			return "", errors.New("is not a directory")
		}
		if resolved, err := filepath.EvalSymlinks(clean); err == nil {
			return resolved, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return clean, nil
}

// defaultVanoraSessionDir mirrors Vanora's session directory convention:
// VANORA_SESSION_DIR if set, otherwise <VANORA_AGENT_DIR or ~/.vanora/agent>/sessions/--<encoded-cwd>--.
func defaultVanoraSessionDir(workDir string) (string, error) {
	if explicit := strings.TrimSpace(os.Getenv("VANORA_SESSION_DIR")); explicit != "" {
		return filepath.Abs(explicit)
	}
	agentDir := strings.TrimSpace(os.Getenv("VANORA_AGENT_DIR"))
	if agentDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		agentDir = filepath.Join(home, ".vanora", "agent")
	} else {
		var err error
		agentDir, err = filepath.Abs(agentDir)
		if err != nil {
			return "", err
		}
	}
	encoded := encodeVanoraSessionDirName(workDir)
	return filepath.Join(agentDir, "sessions", "--"+encoded+"--"), nil
}

func encodeVanoraSessionDirName(workDir string) string {
	trimmed := strings.TrimLeft(workDir, `/\`)
	replacer := strings.NewReplacer("/", "-", `\`, "-", ":", "-")
	return replacer.Replace(trimmed)
}

func resolveScriptFile(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || !filepath.IsAbs(name) {
		return "", errors.New("script must be an absolute path")
	}
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".js" && ext != ".mjs" {
		return "", errors.New("script must end in .js or .mjs")
	}
	st, err := os.Stat(name)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("script is not a regular file")
	}
	return filepath.Abs(name)
}

func resolveDir(dir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", errors.New("is empty")
	}
	if !filepath.IsAbs(dir) {
		return "", errors.New("must be absolute")
	}
	abs, err := filepath.EvalSymlinks(filepath.Clean(dir))
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", errors.New("is not a directory")
	}
	return abs, nil
}

func resolveSessionFile(name, workDir string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("is empty")
	}
	if !filepath.IsAbs(name) {
		return "", errors.New("must be absolute")
	}
	abs, err := filepath.EvalSymlinks(filepath.Clean(name))
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("is not a regular file")
	}
	header, err := readSessionHeader(abs)
	if err != nil {
		return "", err
	}
	if !samePath(header.CWD, workDir) {
		return "", fmt.Errorf("session cwd %q does not match working_dir %q", header.CWD, workDir)
	}
	return abs, nil
}

func validateUserID(field, id string) error {
	if id == "" {
		return fmt.Errorf("%s is empty", field)
	}
	if len(id) > 256 {
		return fmt.Errorf("%s is too long", field)
	}
	if hasControl(id) {
		return fmt.Errorf("%s contains control characters", field)
	}
	return nil
}

func validateTools(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, tool := range in {
		tool = strings.TrimSpace(tool)
		if tool == "" {
			return nil, errors.New("empty tool name")
		}
		if strings.ContainsAny(tool, ", \t\r\n\x00") {
			return nil, fmt.Errorf("invalid tool name %q", tool)
		}
		if _, dup := seen[tool]; dup {
			return nil, fmt.Errorf("duplicate tool %q", tool)
		}
		seen[tool] = struct{}{}
		out = append(out, tool)
	}
	return out, nil
}

// allowedValueArgument is the complete set of local arguments the adapter
// forwards. Everything else, including tool/resource/session/mode controls and
// positional prompts, is rejected. Model selection and display options are
// local configuration; they are not reachable through the RPC protocol.
var allowedValueArgument = map[string]bool{
	"--provider":             true,
	"--model":                true,
	"--models":               true,
	"--thinking":             true,
	"--session-dir":          true,
	"--name":                 true,
	"--system-prompt":        true,
	"--append-system-prompt": true,
}

func validateArguments(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(in))
	for i := 0; i < len(in); i++ {
		arg := in[i]
		if arg == "" || arg == "--" {
			return nil, errors.New("empty or bare -- argument")
		}
		if hasControl(arg) {
			return nil, errors.New("argument contains control characters")
		}
		if !strings.HasPrefix(arg, "--") {
			return nil, fmt.Errorf("argument %q is not a long option (positional prompts and short flags are not allowed)", arg)
		}
		key, value, hasValue := strings.Cut(arg, "=")
		if !allowedValueArgument[key] {
			return nil, fmt.Errorf("argument %q is not in the local allowlist", key)
		}
		if hasValue {
			if value == "" {
				return nil, fmt.Errorf("argument %q has an empty value", key)
			}
			if hasControl(value) {
				return nil, fmt.Errorf("argument %q value contains control characters", key)
			}
			out = append(out, arg)
			continue
		}
		if i+1 >= len(in) {
			return nil, fmt.Errorf("argument %q is missing its value", key)
		}
		i++
		value = in[i]
		if value == "" || value == "--" || strings.HasPrefix(value, "--") {
			return nil, fmt.Errorf("argument %q has an invalid value %q", key, value)
		}
		if hasControl(value) {
			return nil, fmt.Errorf("argument %q value contains control characters", key)
		}
		out = append(out, key, value)
	}
	return out, nil
}

func isNodeExecutable(executable string) bool {
	base := strings.ToLower(filepath.Base(executable))
	return base == "node" || base == "node.exe"
}

func resolveLauncherArgs(executable string, in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if !isNodeExecutable(executable) {
		return nil, errors.New("desktop: launcher_args are only valid when executable is node or node.exe")
	}
	if len(in) != 1 {
		return nil, errors.New("desktop: launcher_args must contain exactly one script path")
	}
	name := strings.TrimSpace(in[0])
	if name == "" || !filepath.IsAbs(name) {
		return nil, errors.New("desktop: launcher script must be an absolute path")
	}
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".js" && ext != ".mjs" {
		return nil, errors.New("desktop: launcher script must end in .js or .mjs")
	}
	st, err := os.Stat(name)
	if err != nil {
		return nil, fmt.Errorf("desktop: launcher script: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("desktop: launcher script is not a regular file")
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	return []string{abs}, nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ca, errA := filepath.Abs(a)
	cb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	ca = filepath.Clean(ca)
	cb = filepath.Clean(cb)
	if resolved, err := filepath.EvalSymlinks(ca); err == nil {
		ca = resolved
	}
	if resolved, err := filepath.EvalSymlinks(cb); err == nil {
		cb = resolved
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(ca, cb)
	}
	return ca == cb
}
