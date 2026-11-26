//go:build windows || (unix && !android && !ios)

package cftunnel

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	helperMode   = "VANORA_TEST_CONNECTOR_MODE"
	helperSocket = "VANORA_TEST_CONNECTOR_SOCKET"
	helperToken  = "phase2-connector-test-only"
)

var helperArgs = []string{"-test.run=^TestConnectorHelperProcess$"}

func TestConnectorHelperProcess(t *testing.T) {
	mode := os.Getenv(helperMode)
	if mode == "" {
		return
	}
	if mode == "descendant" {
		socket, err := net.Dial("tcp", os.Getenv(helperSocket))
		if err != nil {
			os.Exit(1)
		}
		_, _ = io.WriteString(socket, "alive\n")
		_, _ = io.Copy(io.Discard, socket)
		os.Exit(0)
	}
	start := slices.Index(os.Args, "tunnel")
	if start < 0 || len(os.Args[start:]) != 9 || strings.Contains(strings.Join(os.Args, " "), helperToken) ||
		os.Getenv("TUNNEL_TOKEN") != helperToken || os.Getenv("TUNNEL_TOKEN_FILE") != "" {
		os.Exit(2)
	}
	args := os.Args[start:]
	if args[1] != "--no-autoupdate" || args[2] != "--protocol" || args[4] != "--vanora-pin-hostname" ||
		args[5] != "pinned.example" || args[6] != "--vanora-pin-origin" || args[7] != "127.0.0.1:12345" || args[8] != "run" {
		os.Exit(3)
	}
	fmt.Fprintln(os.Stderr, "connector log from "+args[3]+" received "+os.Getenv("TUNNEL_TOKEN"))
	fmt.Fprintln(os.Stdout, `{"tunnel_secret":"some-other-sensitive-value"}`)
	if args[3] == "quic" && mode == "fail-quic" {
		os.Exit(4)
	}
	if args[3] == "quic" && mode == "stall-quic" {
		for {
			time.Sleep(time.Second)
		}
	}
	if address := os.Getenv(helperSocket); address != "" {
		descendant := exec.Command(os.Args[0], helperArgs...)
		descendant.Env = append(descendant.Environ(), helperMode+"=descendant")
		if err := descendant.Start(); err != nil {
			os.Exit(5)
		}
	}
	fmt.Fprintln(os.Stdout, readyMessage)
	for {
		time.Sleep(time.Second)
	}
}

func TestConnectorFallbackAndRedaction(t *testing.T) {
	for _, mode := range []string{"fail-quic", "stall-quic"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv(helperMode, mode)
			t.Setenv("TUNNEL_TOKEN", "different-parent-token")
			t.Setenv("TUNNEL_TOKEN_FILE", "different-parent-token-file")
			events := make(chan ConnectorEvent, 32)
			opts := helperConnectorOptions(events)
			if mode == "stall-quic" {
				opts.StartupTimeout = time.Second
			}
			connector, err := startConnector(t.Context(), opts, helperArgs)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(connector.Stop)
			wantQUIC := "exited"
			if mode == "stall-quic" {
				wantQUIC = "startup_timeout"
			}
			seenQUIC, seenHTTP2, seenLocalRedaction, seenPatternRedaction := false, false, false, false
			for !seenHTTP2 || !seenQUIC || !seenLocalRedaction || !seenPatternRedaction {
				event := await(t, events)
				if strings.Contains(event.Line, helperToken) || strings.Contains(event.Line, "some-other-sensitive-value") {
					t.Fatal("connector observer received credentials")
				}
				seenQUIC = seenQUIC || event.Protocol == "quic" && event.State == wantQUIC
				seenHTTP2 = seenHTTP2 || event.Protocol == "http2" && event.State == "ready"
				seenLocalRedaction = seenLocalRedaction || strings.Contains(event.Line, "received [redacted]")
				seenPatternRedaction = seenPatternRedaction || event.Line == "[redacted connector diagnostic]"
			}
			connector.Stop()
			if connector.Ready() {
				t.Fatal("stopped connector remained ready")
			}
		})
	}
}

func TestConnectorStopTerminatesProcessTree(t *testing.T) {
	t.Setenv(helperMode, "ready")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv(helperSocket, listener.Addr().String())
	events := make(chan ConnectorEvent, 32)
	connector, err := startConnector(t.Context(), helperConnectorOptions(events), helperArgs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connector.Stop)
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	socket, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = socket.SetDeadline(time.Now().Add(5 * time.Second))
	marker := make([]byte, len("alive\n"))
	if _, err := io.ReadFull(socket, marker); err != nil || !bytes.Equal(marker, []byte("alive\n")) {
		t.Fatalf("descendant did not start: %v", err)
	}
	eventually(t, connector.Ready)
	start := time.Now()
	connector.Stop()
	if time.Since(start) > 3*time.Second || connector.Ready() {
		t.Fatal("connector did not stop promptly")
	}
	_ = socket.SetReadDeadline(time.Now().Add(time.Second))
	_, err = socket.Read(marker)
	var networkError net.Error
	if err == nil || (errors.As(err, &networkError) && networkError.Timeout()) {
		t.Fatalf("descendant remained connected: %v", err)
	}
}

func TestConnectorLaunchErrorRedactsToken(t *testing.T) {
	_, err := StartConnector(t.Context(), ConnectorOptions{Binary: helperToken, Token: helperToken})
	if err == nil || strings.Contains(err.Error(), helperToken) {
		t.Fatal("launch error exposed credentials or accepted a missing binary")
	}
}

func helperConnectorOptions(events chan<- ConnectorEvent) ConnectorOptions {
	return ConnectorOptions{
		Binary: os.Args[0], Token: helperToken, PinnedHostname: "pinned.example", PinnedOrigin: "127.0.0.1:12345",
		StartupTimeout: 4 * time.Second, StopGrace: 300 * time.Millisecond,
		BackoffMin: 15 * time.Millisecond, BackoffMax: 60 * time.Millisecond,
		Observe: func(event ConnectorEvent) { events <- event },
	}
}
