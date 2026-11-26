package cftunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/routes"
)

type racePeer struct {
	transport.Peer
	closed chan struct{}
}

func (p *racePeer) Close()           { close(p.closed) }
func (p *racePeer) Allows(bool) bool { return true }

func TestDialFallbackClosesLatePeer(t *testing.T) {
	late := &racePeer{closed: make(chan struct{})}
	winner := &racePeer{closed: make(chan struct{})}
	var starts atomic.Int32
	dialStarted := make(chan struct{})
	webRTC := func(ctx context.Context) (Candidate, error) {
		close(dialStarted)
		<-ctx.Done()
		return Candidate{Peer: late, Start: func() { starts.Add(100) }}, nil
	}
	tunnel := func(context.Context) (Candidate, error) {
		<-dialStarted
		return Candidate{Peer: winner, Start: func() { starts.Add(1) }}, nil
	}
	candidate, err := DialFallback(t.Context(), routes.NewTracker(), "signal", time.Millisecond, webRTC, tunnel)
	if err != nil || candidate.Peer != winner || starts.Load() != 0 {
		t.Fatalf("invalid deferred winner: %v", err)
	}
	await(t, late.closed)
	candidate.Start()
	if starts.Load() != 1 {
		t.Fatal("more than one candidate started")
	}
	candidate.Close()
}

func TestDialFallbackPreservesPrimaryErrorsAndBacksOff(t *testing.T) {
	tracker := routes.NewTracker()
	var tunnelCalls int
	tunnel := func(context.Context) (Candidate, error) {
		tunnelCalls++
		return Candidate{}, ErrTunnelUnavailable
	}
	primaryErrors := []error{
		selfrelay.ErrUnpaired, selfrelay.ErrUnauthorized, pairing.ErrInvalid, transport.ErrUnauthorized,
		transport.ErrIdentityChanged, &transport.ClosedError{Reason: "access_denied"},
		&transport.ClosedError{Reason: "access_revoked"}, account.ErrCredential, account.ErrAlreadyEnrolled,
	}
	for _, primary := range primaryErrors {
		webRTC := func(context.Context) (Candidate, error) { return Candidate{}, primary }
		_, err := DialFallback(t.Context(), tracker, "signal", time.Second, webRTC, tunnel)
		if !errors.Is(err, primary) || tunnelCalls != 0 {
			t.Fatalf("authentication error changed or triggered a tunnel: %v", err)
		}
	}
	webRTC := func(context.Context) (Candidate, error) { return Candidate{}, transport.ErrHandshakeTimeout }
	for range 2 {
		_, err := DialFallback(t.Context(), tracker, "signal", time.Second, webRTC, tunnel)
		if !errors.Is(err, transport.ErrHandshakeTimeout) || tunnelCalls != 1 {
			t.Fatalf("primary error or tunnel backoff lost: %v (%d tunnel calls)", err, tunnelCalls)
		}
	}
}
