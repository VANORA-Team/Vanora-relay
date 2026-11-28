package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/remote"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
)

type noopHandler struct{}

func (noopHandler) Open(transport.Peer)            {}
func (noopHandler) Message(transport.Peer, []byte) {}
func (noopHandler) Closed(transport.Peer)          {}

type ctlProvider struct {
	ctx       context.Context
	dir       string
	name      string
	slots     map[string]*officialSlotConfig
	tokens    map[string]string
	selfURL   string
	selfToken string

	mu         sync.Mutex
	selfServer *selfrelay.Server
	lanServer  *lan.Server
}

func (p *ctlProvider) DesktopName() string { return strings.TrimSpace(p.name) }

func (p *ctlProvider) ListOfficialChannels() []string {
	out := make([]string, 0, len(p.slots))
	for k, slot := range p.slots {
		if slot != nil && slot.account != nil && slot.signalURL != "" {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func (p *ctlProvider) Official(channel string) (*remote.OfficialChannel, error) {
	ch := strings.ToLower(strings.TrimSpace(channel))
	slot := p.slots[ch]
	if slot == nil || slot.account == nil || slot.signalURL == "" {
		return nil, fmt.Errorf("official relay channel %s is not configured", ch)
	}
	if tok := strings.TrimSpace(p.tokens[ch]); tok != "" {
		if slot.account.UserID() == "" {
			enrollCtx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
			err := slot.account.Enroll(enrollCtx, tok)
			cancel()
			if err != nil {
				return nil, err
			}
		} else {
			if err := slot.account.UpdateToken(tok); err != nil {
				return nil, err
			}
		}
	}
	return &remote.OfficialChannel{
		Channel:   ch,
		SignalURL: slot.signalURL,
		Account:   slot.account,
		Source:    slot.account,
	}, nil
}

func (p *ctlProvider) Self() (*remote.SelfChannel, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.selfServer == nil {
		srv, err := selfrelay.OpenServer(namedVault(p.dir, "self.enc", "self"), noopHandler{})
		if err != nil {
			return nil, err
		}
		p.selfServer = srv
	}
	return &remote.SelfChannel{
		SignalURL: p.selfURL,
		Token:     p.selfToken,
		Server:    p.selfServer,
	}, nil
}

func (p *ctlProvider) LAN() (*remote.LANChannel, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lanServer == nil {
		srv, err := lan.OpenServer(namedVault(p.dir, "lan.enc", "lan"), noopHandler{})
		if err != nil {
			return nil, err
		}
		p.lanServer = srv
	}
	return &remote.LANChannel{Server: p.lanServer}, nil
}

func runCtl(args []string) error {
	const usage = "usage: vanora-desktop ctl pair|peers|workspaces|sessions|create|open|run|cancel [flags]"
	if len(args) == 0 {
		return errors.New(usage)
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	switch action {
	case "pair", "peers", "workspaces", "sessions", "create", "open", "run", "cancel":
	default:
		return errors.New(usage)
	}
	if strings.TrimSpace(os.Getenv("VANORA_LINK_ORIGIN")) != "" &&
		(action == "pair" || action == "create" || action == "run" || action == "cancel") {
		return errTransitiveDelegation
	}
	fs := flag.NewFlagSet("ctl "+action, flag.ContinueOnError)
	channelFlag := fs.String("channel", envOrDefault("VANORA_RELAY_CHANNEL", ""), "channel: cn, global, self, or lan")
	chFlags := registerChannelFlags(fs, "self-hosted relay WebSocket URL (or LAN IP:PORT for bare LAN pairing code)")

	root := fs.String("state-dir", "", "profile directory (defaults to user config)")
	hostname, _ := os.Hostname()
	name := fs.String("name", hostname, "local desktop name")
	tokenFlag := fs.String("token", envOrDefault("VANORA_CLIENT_TOKEN", ""), "existing client auth token")
	tokenStdin := fs.Bool("token-stdin", false, "read client auth token from stdin")
	jsonOutput := fs.Bool("json", false, "emit structured JSON lines on stdout")

	inputFlag := fs.String("input", "", "pairing link or 16-character pairing code")
	grantAccess := fs.String("grant-access", "", "for self/lan pairing: reverse access granted to peer (read or control)")
	peerFlag := fs.String("peer", "", "target remote desktop peer_id")
	workspaceFlag := fs.String("workspace", "", "target workspace_id for session creation")
	titleFlag := fs.String("title", "", "optional session title")
	sessionFlag := fs.String("session", "", "target session_id")
	runFlag := fs.String("run", "", "target run_id for cancel")
	textFlag := fs.String("text", "", "prompt text for run")
	requestIDFlag := fs.String("request-id", "", "optional idempotency request_id")
	namespaceFlag := fs.String("namespace", "", "optional idempotency namespace for multi-agent delegation")
	linkOriginFlag := fs.String("link-origin", "", "optional link_origin session fence tag")
	readOnlyFlag := fs.Bool("read-only", false, "monotonically narrow delegated session/run to read-only")
	noToolsFlag := fs.Bool("no-tools", false, "monotonically narrow delegated session/run to text-only (--no-tools)")
	toolsFlag := fs.String("tools", "", "comma-separated tool subset for monotonic narrowing")
	queuePolicyFlag := fs.String("queue-policy", "", "queue behavior when target session is busy: enqueue (default) or reject")

	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *tokenStdin && *chFlags.selfTokenStdin {
		return errors.New("-token-stdin and -self-token-stdin cannot be combined")
	}

	channel := strings.ToLower(strings.TrimSpace(*channelFlag))
	if channel != "" && channel != "cn" && channel != "global" && channel != "self" && channel != "lan" {
		return fmt.Errorf("unknown channel %q (want cn, global, self or lan)", channel)
	}
	if *root == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		*root = filepath.Join(dir, "Vanora", "relay")
	}
	dir, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(dir, "profile.lock"))
	ok, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("desktop profile is already open (use Sidecar remote.* commands while serve is running, or specify another -state-dir)")
	}
	defer lock.Unlock()

	slots, resolvedSelfSignal, resolvedSelfToken, err := chFlags.resolve(dir, channel, false, os.Stdin)
	if err != nil {
		return err
	}

	tok := strings.TrimSpace(*tokenFlag)
	if *tokenStdin {
		tok, err = readTokenInput("", true, os.Stdin)
		if err != nil {
			return err
		}
	}
	tokens := map[string]string{}
	if tok != "" {
		if channel == "cn" || channel == "global" {
			tokens[channel] = tok
		} else if len(slots) == 1 {
			for k := range slots {
				tokens[k] = tok
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var emitter *jsonEmitter
	if *jsonOutput {
		emitter = &jsonEmitter{out: os.Stdout}
	}
	runDone := make(chan string, 1)
	var activeRunID string
	var runMu sync.Mutex

	provider := &ctlProvider{
		ctx:       ctx,
		dir:       dir,
		name:      *name,
		slots:     slots,
		tokens:    tokens,
		selfURL:   resolvedSelfSignal,
		selfToken: resolvedSelfToken,
	}
	rm := remote.NewManager(ctx, provider, func(ev map[string]any) {
		if action == "run" && ev["type"] == "remote.event" {
			kind, _ := ev["kind"].(string)
			runID, _ := ev["run_id"].(string)
			if emitter != nil {
				emitter.Emit(ev)
			} else {
				printCtlEvent(kind, ev["data"])
			}
			runMu.Lock()
			targetRun := activeRunID
			runMu.Unlock()
			if (targetRun == "" || runID == targetRun) &&
				(kind == "run.completed" || kind == "run.cancelled" || kind == "run.failed") {
				select {
				case runDone <- kind:
				default:
				}
			}
		}
	})
	defer rm.Close()

	printJSON := func(v any) error {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	switch action {
	case "pair":
		info, err := rm.Pair(ctx, remote.PairOptions{
			Channel:     channel,
			Input:       *inputFlag,
			SignalURL:   resolvedSelfSignal,
			SignalToken: resolvedSelfToken,
			GrantAccess: *grantAccess,
		})
		if err != nil {
			return err
		}
		if emitter != nil {
			emitter.Emit(map[string]any{"type": "remote.paired", "peer": info})
			return nil
		}
		return printJSON(info)
	case "peers":
		peers, err := rm.ListPeers(ctx, channel)
		if err != nil {
			return err
		}
		if emitter != nil {
			emitter.Emit(map[string]any{"type": "remote.peers", "peers": peers})
			return nil
		}
		return printJSON(peers)
	default:
		if strings.TrimSpace(*peerFlag) == "" {
			return errors.New("-peer is required")
		}
		info, err := rm.Connect(ctx, channel, *peerFlag)
		if err != nil {
			return err
		}
		ch := info.Channel
		peerID := info.PeerID
		buildOpts := func() remote.RequestOptions {
			var ml *remote.ModeLimit
			if *readOnlyFlag || *noToolsFlag || strings.TrimSpace(*toolsFlag) != "" {
				ml = &remote.ModeLimit{
					ReadOnly: *readOnlyFlag,
					NoTools:  *noToolsFlag,
				}
				if raw := strings.TrimSpace(*toolsFlag); raw != "" {
					for _, part := range strings.Split(raw, ",") {
						if t := strings.TrimSpace(part); t != "" {
							ml.Tools = append(ml.Tools, t)
						}
					}
				}
			}
			return remote.RequestOptions{
				Namespace:   *namespaceFlag,
				LinkOrigin:  *linkOriginFlag,
				ModeLimit:   ml,
				QueuePolicy: *queuePolicyFlag,
			}
		}
		switch action {
		case "workspaces":
			data, err := rm.ListWorkspaces(ctx, ch, peerID)
			if err != nil {
				return err
			}
			if emitter != nil {
				emitter.Emit(map[string]any{"type": "remote.result", "peer_id": peerID, "data": data})
				return nil
			}
			fmt.Println(string(data))
			return nil
		case "sessions":
			data, err := rm.ListSessions(ctx, ch, peerID)
			if err != nil {
				return err
			}
			if emitter != nil {
				emitter.Emit(map[string]any{"type": "remote.result", "peer_id": peerID, "data": data})
				return nil
			}
			fmt.Println(string(data))
			return nil
		case "create":
			if strings.TrimSpace(*workspaceFlag) == "" {
				return errors.New("-workspace is required")
			}
			data, err := rm.CreateSessionWithOptions(ctx, ch, peerID, *workspaceFlag, *requestIDFlag, *titleFlag, buildOpts())
			if err != nil {
				return err
			}
			if emitter != nil {
				emitter.Emit(map[string]any{"type": "remote.result", "peer_id": peerID, "data": data})
				return nil
			}
			fmt.Println(string(data))
			return nil
		case "open":
			if strings.TrimSpace(*sessionFlag) == "" {
				return errors.New("-session is required")
			}
			data, err := rm.OpenSession(ctx, ch, peerID, *sessionFlag)
			if err != nil {
				return err
			}
			if emitter != nil {
				emitter.Emit(map[string]any{"type": "remote.result", "peer_id": peerID, "data": data})
				return nil
			}
			fmt.Println(string(data))
			return nil
		case "cancel":
			if strings.TrimSpace(*sessionFlag) == "" || strings.TrimSpace(*runFlag) == "" {
				return errors.New("-session and -run are required")
			}
			data, err := rm.CancelRunWithOrigin(ctx, ch, peerID, *sessionFlag, *runFlag, *linkOriginFlag)
			if err != nil {
				return err
			}
			if emitter != nil {
				emitter.Emit(map[string]any{"type": "remote.result", "peer_id": peerID, "data": data})
				return nil
			}
			fmt.Println(string(data))
			return nil
		case "run":
			if strings.TrimSpace(*sessionFlag) == "" || strings.TrimSpace(*textFlag) == "" {
				return errors.New("-session and -text are required")
			}
			if _, err := rm.OpenSession(ctx, ch, peerID, *sessionFlag); err != nil {
				return err
			}
			data, err := rm.StartRunWithOptions(ctx, ch, peerID, *sessionFlag, *requestIDFlag, *textFlag, buildOpts())
			if err != nil {
				return err
			}
			var started struct {
				RunID string `json:"run_id"`
			}
			_ = json.Unmarshal(data, &started)
			runMu.Lock()
			activeRunID = started.RunID
			runMu.Unlock()
			if emitter != nil {
				emitter.Emit(map[string]any{"type": "remote.result", "peer_id": peerID, "data": data})
			}
			select {
			case kind := <-runDone:
				if emitter == nil {
					fmt.Println()
				}
				if kind == "run.failed" {
					return errors.New("remote run failed")
				}
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

func printCtlEvent(kind string, raw any) {
	b, ok := raw.(json.RawMessage)
	if !ok {
		return
	}
	switch kind {
	case "text.delta":
		var d struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(b, &d) == nil {
			fmt.Print(d.Text)
		}
	case "thinking.delta":
		var d struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(b, &d) == nil {
			fmt.Fprint(os.Stderr, d.Text)
		}
	case "run.failed":
		fmt.Fprintf(os.Stderr, "\n[run.failed] %s\n", string(b))
	case "run.cancelled":
		fmt.Fprintln(os.Stderr, "\n[run.cancelled]")
	}
}
