package selfrelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"vanora-relay/adapter/transport"
	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

// Dial connects a mobile device to a desktop through a self-hosted relay.
// When target.Pair is set, Dial proves possession of the one-time pairing token
// via HMAC without sending the raw token over the relay; subsequent connections
// omit target.Pair and authenticate directly with the persisted device key.
//
// Dial returns once the encrypted WebRTC DataChannel is open. The caller must
// invoke the returned start function after recording the Peer so handler.Open
// and handler.Message run in order.
func Dial(ctx context.Context, target Target, seed, clientName string, handler transport.Handler) (transport.Peer, func(), error) {
	return DialWithRole(ctx, target, seed, clientName, "mobile", handler)
}

// DialWithRole connects a mobile or desktop peer to a target desktop through a
// self-hosted relay using the caller's Ed25519 key seed.
func DialWithRole(ctx context.Context, target Target, seed, clientName, role string, handler transport.Handler) (transport.Peer, func(), error) {
	return DialWithRoleFor(ctx, ctx, target, seed, clientName, role, handler)
}

// DialWithRoleFor separates setup cancellation from the connected peer's lifetime.
func DialWithRoleFor(ctx, lifetime context.Context, target Target, seed, clientName, role string, handler transport.Handler) (transport.Peer, func(), error) {
	if role == "" {
		role = "mobile"
	}
	if role != "mobile" && role != "desktop" {
		return nil, nil, errors.New("selfrelay: invalid client role")
	}
	if _, err := NormalizeSignalURL(target.SignalURL); err != nil {
		return nil, nil, err
	}
	if err := ValidateRelayToken(target.Token); err != nil {
		return nil, nil, err
	}
	desktopPub, err := parsePublicKeyB64(target.Pin)
	if err != nil {
		return nil, nil, errors.New("selfrelay: invalid desktop pin")
	}
	desktopDevID, err := identity.SelfDeviceID(desktopPub)
	if err != nil {
		return nil, nil, err
	}
	if !validName(clientName) {
		return nil, nil, errors.New("selfrelay: invalid device name")
	}
	mobilePriv, mobilePub, mobilePubB64, mobileDevID, err := parseKeySeed(seed)
	if err != nil {
		return nil, nil, err
	}
	if desktopDevID == mobileDevID {
		return nil, nil, errors.New("selfrelay: cannot connect to self")
	}

	ws, err := dialSignalFor(ctx, target.SignalURL, target.Token, role, mobilePriv, mobilePub, mobileDevID, desktopDevID, nil)
	if err != nil {
		return nil, nil, err
	}

	linkCtx, linkCancel := context.WithCancel(lifetime)
	var writeMu sync.Mutex
	send := func(m protocol.Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeSignal(linkCtx, ws, m)
	}

	connID := protocol.NewID()
	body := connectRequestBody{
		PublicKey: mobilePubB64,
		Name:      clientName,
	}
	if role == "desktop" {
		body.Role = role
	}
	if target.Pair != "" {
		rawPair, err := base64.RawURLEncoding.Strict().DecodeString(target.Pair)
		if err != nil || len(rawPair) != 32 {
			linkCancel()
			ws.CloseNow()
			return nil, nil, errors.New("selfrelay: invalid pairing token")
		}
		proof, err := identity.SelfPairProof(rawPair, connID, mobilePub, desktopPub)
		if err != nil {
			linkCancel()
			ws.CloseNow()
			return nil, nil, err
		}
		body.PairProof = base64.RawURLEncoding.EncodeToString(proof)
	}

	sess := &selfSession{
		connID:    connID,
		localID:   mobileDevID,
		remoteID:  desktopDevID,
		localKey:  mobilePriv,
		remotePub: desktopPub,
		desktop:   false,
	}
	req, err := sess.sign("connect.request", protocol.Encode(body))
	if err != nil {
		linkCancel()
		ws.CloseNow()
		return nil, nil, err
	}

	l := newPeerLink(
		linkCtx,
		sess,
		target.Pin,
		false,
		false,
		true,
		func() bool { return linkCtx.Err() == nil },
		send,
		func(*peerLink) {
			linkCancel()
			_ = ws.CloseNow()
		},
		handler,
	)

	go l.run()
	go func() {
		for {
			m, err := readSignal(linkCtx, ws)
			if err != nil {
				l.close(err, false)
				return
			}
			switch m.Type {
			case "ice.config":
				if m.Connection != connID {
					continue
				}
				var servers []iceServer
				if json.Unmarshal(m.Data, &servers) == nil {
					l.setICE(servers)
				} else {
					l.close(errors.New("selfrelay: invalid ice.config"), false)
					return
				}
			case "connect.accept", "connect.closed", "rtc.offer", "rtc.answer", "rtc.candidate", "error":
				if m.Connection == connID || m.Connection == "" {
					l.route(m)
				}
			}
		}
	}()

	if err := send(req); err != nil {
		l.close(err, false)
		return nil, nil, err
	}

	waitCtx, stopWait := context.WithTimeout(ctx, handshakeTimeout)
	defer stopWait()
	select {
	case <-l.ready:
		if l.closed.Load() {
			return nil, nil, transport.ErrPeerClosed
		}
		go func() {
			first := time.NewTimer(minICERefreshAge)
			defer first.Stop()
			select {
			case <-l.done:
				return
			case <-first.C:
			}
			_ = send(protocol.Message{Type: "ice.refresh", Connection: connID})
			ticker := time.NewTicker(iceRefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-l.done:
					return
				case <-ticker.C:
					if err := send(protocol.Message{Type: "ice.refresh", Connection: connID}); err != nil {
						return
					}
				}
			}
		}()
		return l.peer, l.peer.start, nil
	case err := <-l.errCh:
		l.close(err, false)
		return nil, nil, err
	case <-waitCtx.Done():
		l.close(waitCtx.Err(), true)
		return nil, nil, waitCtx.Err()
	}
}
