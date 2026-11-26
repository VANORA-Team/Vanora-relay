package cftunnel

import (
	"context"
	"errors"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/pairnet"
	"vanora-relay/internal/routes"
)

// Candidate owns a deferred peer and, when applicable, its signaling socket.
type Candidate struct {
	Peer       transport.Peer
	Start      func()
	Socket     *transport.Client
	OwnsSocket bool
}

func (c Candidate) Close() {
	if c.Peer != nil {
		c.Peer.Close()
	}
	if c.OwnsSocket && c.Socket != nil {
		c.Socket.Close()
	}
}

type CandidateDial func(context.Context) (Candidate, error)

func isWebRTCAuthError(err error) bool {
	var closed *transport.ClosedError
	var signal transport.SignalError
	return errors.Is(err, selfrelay.ErrUnpaired) || errors.Is(err, selfrelay.ErrUnauthorized) ||
		errors.Is(err, pairing.ErrInvalid) || errors.Is(err, pairnet.ErrRemoved) ||
		errors.Is(err, transport.ErrUnauthorized) || errors.Is(err, transport.ErrIdentityChanged) ||
		errors.Is(err, account.ErrNotEnrolled) || errors.Is(err, account.ErrExpired) ||
		errors.Is(err, account.ErrCredential) || errors.Is(err, account.ErrStateInvalid) ||
		errors.Is(err, account.ErrAuthorityChanged) || errors.Is(err, account.ErrAlreadyEnrolled) ||
		(errors.As(err, &closed) && (closed.Reason == "access_denied" || closed.Reason == "access_revoked")) ||
		(errors.As(err, &signal) && (signal == "authorization_expired" || signal == "identity_changed"))
}

// DialFallback gives WebRTC a head start and returns one authenticated candidate.
// Dial functions use their contexts for setup only. The caller attaches the
// winner before invoking its Start function.
func DialFallback(ctx context.Context, tracker *routes.Tracker, key string, headStart time.Duration, webRTC, tunnel CandidateDial) (Candidate, error) {
	if tunnel == nil || !tracker.ShouldAttemptTunnel(key, time.Now()) {
		candidate, err := webRTC(ctx)
		if err != nil {
			candidate.Close()
			return Candidate{}, err
		}
		return candidate, nil
	}
	if headStart <= 0 {
		headStart = routes.CFTunnelHeadStart
	}

	type result struct {
		candidate Candidate
		err       error
		tunnel    bool
	}
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result)
	launch := func(dial CandidateDial, isTunnel bool) {
		go func() {
			candidate, err := dial(dialCtx)
			if err == nil && (candidate.Peer == nil || !candidate.Peer.Allows(true)) {
				err = transport.ErrPeerClosed
			}
			if err != nil {
				candidate.Close()
				candidate = Candidate{}
			}
			select {
			case results <- result{candidate, err, isTunnel}:
			case <-dialCtx.Done():
				candidate.Close()
			}
		}()
	}
	launch(webRTC, false)
	timer := time.NewTimer(headStart)
	defer timer.Stop()
	headStartDone := timer.C
	tunnelPending := false
	startTunnel := func() {
		headStartDone = nil
		timer.Stop()
		tunnelPending = true
		launch(tunnel, true)
	}
	var primaryErr error
	for {
		var res result
		select {
		case <-ctx.Done():
			return Candidate{}, ctx.Err()
		case <-headStartDone:
			select {
			case res = <-results:
			default:
				startTunnel()
				continue
			}
		case res = <-results:
		}
		if err := ctx.Err(); err != nil {
			res.candidate.Close()
			return Candidate{}, err
		}
		if !res.tunnel {
			if res.err == nil || isWebRTCAuthError(res.err) {
				return res.candidate, res.err
			}
			primaryErr = res.err
			if headStartDone != nil {
				startTunnel()
			} else if !tunnelPending {
				return Candidate{}, primaryErr
			}
			continue
		}
		if res.err == nil {
			tracker.RecordTunnelSuccess(key)
			return res.candidate, nil
		}
		if errors.Is(res.err, ErrTunnelUnavailable) {
			tracker.RecordTunnelUnavailable(key, time.Now())
		}
		tunnelPending = false
		if primaryErr != nil {
			return Candidate{}, primaryErr
		}
	}
}
