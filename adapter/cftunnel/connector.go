package cftunnel

import (
	"bufio"
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

const (
	protocolQUIC  = "quic"
	protocolHTTP2 = "http2"
	readyMessage  = "Registered tunnel connection"
)

type ConnectorOptions struct {
	Binary         string
	Token          string
	PinnedHostname string
	PinnedOrigin   string
	StartupTimeout time.Duration
	StopGrace      time.Duration
	BackoffMin     time.Duration
	BackoffMax     time.Duration
	Observe        func(ConnectorEvent)
}

type ConnectorEvent struct {
	Protocol string
	State    string
	Line     string
}

type Connector struct {
	cancel context.CancelFunc
	done   chan struct{}
	events chan ConnectorEvent
	ready  atomic.Bool
}

type processControl struct {
	wait func()
	stop func(exited <-chan struct{}, grace time.Duration)
}

type connectorChild struct {
	processControl
	exited chan struct{}
	ready  chan struct{}
	logs   chan struct{}
	output *os.File
}

// StartConnector starts cloudflared. Stop or cancellation ends supervision
// and terminates the current process tree.
func StartConnector(ctx context.Context, opts ConnectorOptions) (*Connector, error) {
	return startConnector(ctx, opts, nil)
}

func startConnector(ctx context.Context, opts ConnectorOptions, argsPrefix []string) (*Connector, error) {
	if opts.Token == "" || strings.ContainsFunc(opts.Token, func(char rune) bool {
		return unicode.IsSpace(char) || unicode.IsControl(char)
	}) {
		return nil, errors.New("cftunnel: invalid connector token")
	}
	if opts.PinnedHostname != "" || opts.PinnedOrigin != "" {
		origin, err := netip.ParseAddrPort(opts.PinnedOrigin)
		if !validHostname(opts.PinnedHostname) || err != nil || !literalLoopback(origin.Addr()) ||
			origin.Port() == 0 || origin.String() != opts.PinnedOrigin {
			return nil, errors.New("cftunnel: invalid restricted connector pins")
		}
	}
	if opts.Binary == "" {
		opts.Binary = "cloudflared"
	}
	binary, err := exec.LookPath(opts.Binary)
	if err != nil {
		return nil, errors.New("cftunnel: connector executable unavailable")
	}
	if opts.StartupTimeout <= 0 {
		opts.StartupTimeout = 15 * time.Second
	}
	if opts.StopGrace <= 0 {
		opts.StopGrace = 2 * time.Second
	}
	if opts.BackoffMin <= 0 {
		opts.BackoffMin = time.Second
	}
	if opts.BackoffMax <= 0 {
		opts.BackoffMax = 30 * time.Second
	}
	opts.BackoffMax = max(opts.BackoffMin, opts.BackoffMax)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	connector := &Connector{cancel: cancel, done: make(chan struct{})}
	if opts.Observe != nil {
		connector.events = make(chan ConnectorEvent, 128)
	}
	child, err := connector.launch(binary, opts, argsPrefix, protocolQUIC)
	if err != nil {
		cancel()
		return nil, err
	}
	if opts.Observe != nil {
		go func() {
			for event := range connector.events {
				opts.Observe(event)
			}
		}()
	}
	go connector.supervise(ctx, binary, opts, argsPrefix, child)
	return connector, nil
}

func (c *Connector) Ready() bool { return c.ready.Load() }

func (c *Connector) Stop() {
	c.cancel()
	<-c.done
}

func (c *Connector) emit(event ConnectorEvent) {
	select {
	case c.events <- event:
	default:
	}
}

func (c *Connector) launch(binary string, opts ConnectorOptions, prefix []string, protocol string) (*connectorChild, error) {
	args := append(append([]string(nil), prefix...), "tunnel", "--no-autoupdate", "--protocol", protocol)
	if opts.PinnedHostname != "" {
		args = append(args, "--vanora-pin-hostname", opts.PinnedHostname, "--vanora-pin-origin", opts.PinnedOrigin)
	}
	cmd := exec.Command(binary, append(args, "run")...)
	for _, entry := range cmd.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "TUNNEL_TOKEN", "TUNNEL_TOKEN_FILE":
		default:
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "TUNNEL_TOKEN="+opts.Token)
	output, writer, err := os.Pipe()
	if err != nil {
		return nil, errors.New("cftunnel: connector diagnostics pipe failed")
	}
	process, err := launchProcess(cmd, writer)
	_ = writer.Close()
	if err != nil {
		_ = output.Close()
		return nil, errors.New("cftunnel: connector process launch failed")
	}
	child := &connectorChild{
		processControl: process, output: output, exited: make(chan struct{}),
		ready: make(chan struct{}, 1), logs: make(chan struct{}),
	}
	c.emit(ConnectorEvent{Protocol: protocol, State: "starting"})
	go func() {
		child.wait()
		close(child.exited)
	}()
	go func() {
		defer close(child.logs)
		c.readLogs(child, opts, protocol)
	}()
	return child, nil
}

func (c *Connector) supervise(ctx context.Context, binary string, opts ConnectorOptions, prefix []string, child *connectorChild) {
	defer close(c.done)
	if c.events != nil {
		defer close(c.events)
	}
	protocol, backoff := protocolQUIC, opts.BackoffMin
	for {
		if child != nil {
			state, wasReady := c.watch(ctx, child, opts.StartupTimeout, protocol)
			c.ready.Store(false)
			child.stop(child.exited, opts.StopGrace)
			<-child.exited
			child.drainLogs()
			c.emit(ConnectorEvent{Protocol: protocol, State: state})
			if wasReady {
				backoff = opts.BackoffMin
			} else if protocol == protocolQUIC {
				protocol = protocolHTTP2
			}
		}
		if ctx.Err() != nil {
			return
		}
		delay := time.NewTimer(rand.N(backoff))
		select {
		case <-ctx.Done():
			delay.Stop()
			return
		case <-delay.C:
		}
		backoff += min(backoff, opts.BackoffMax-backoff)
		var err error
		child, err = c.launch(binary, opts, prefix, protocol)
		if err != nil {
			c.emit(ConnectorEvent{Protocol: protocol, State: "start_failed"})
		}
	}
}

func (child *connectorChild) drainLogs() {
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-child.logs:
		_ = child.output.Close()
	case <-timer.C:
		_ = child.output.Close()
		<-child.logs
	}
}

func (c *Connector) watch(ctx context.Context, child *connectorChild, timeout time.Duration, protocol string) (string, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-child.ready:
		c.ready.Store(true)
		c.emit(ConnectorEvent{Protocol: protocol, State: "ready"})
	case <-child.exited:
		return "exited", false
	case <-timer.C:
		return "startup_timeout", false
	case <-ctx.Done():
		return "stopped", false
	}
	select {
	case <-child.exited:
		return "exited", true
	case <-ctx.Done():
		return "stopped", true
	}
}

var sensitiveLog = regexp.MustCompile(`(?i)\b(?:tunnel[-_]token(?:[-_]file)?|connector[-_]token|tunnel[-_]secret|authorization|token[-_]file|token|credentials(?:-contents|-file)?|vanora-edge-ticket|vanora-client-proof)\b\s*["']?\s*(?:[:= ]|\s)|\bbearer\s+`)

func (c *Connector) readLogs(child *connectorChild, opts ConnectorOptions, protocol string) {
	reader := bufio.NewReaderSize(child.output, 64<<10)
	discard := false
	for {
		raw, err := reader.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			discard = true
			continue
		}
		if !discard && len(raw) != 0 {
			line := strings.TrimSpace(string(raw))
			if strings.Contains(line, readyMessage) {
				select {
				case child.ready <- struct{}{}:
				default:
				}
			}
			line = strings.ReplaceAll(line, opts.Token, "[redacted]")
			if opts.PinnedOrigin != "" {
				line = strings.ReplaceAll(line, opts.PinnedOrigin, "[redacted]")
			}
			if sensitiveLog.MatchString(line) {
				line = "[redacted connector diagnostic]"
			}
			c.emit(ConnectorEvent{Protocol: protocol, State: "log", Line: line})
		}
		discard = false
		if err != nil {
			return
		}
	}
}
