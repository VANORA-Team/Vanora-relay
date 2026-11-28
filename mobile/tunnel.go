package mobile

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/cftunnel"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairing"
)

type tunnelDialOptions struct {
	url        string
	headStart  time.Duration
	httpClient *http.Client
}

func tunnelRouteKey(signalURL, hostID string) string {
	return signalURL + "\x00" + hostID
}

func (c *Client) dialPeer(dialCtx context.Context, device, owner string) (transport.Peer, func(), error) {
	c.mu.Lock()
	lanTarget, selfTarget, selfName := c.lanTarget, c.selfTarget, c.selfName
	invite, channel := c.officialInvite, c.channel
	c.mu.Unlock()
	if lanTarget != nil {
		return c.dialLANPeer(dialCtx)
	}
	if selfTarget != nil {
		return c.dialSelfPeer(dialCtx, *selfTarget, selfName)
	}
	return c.dialOfficialPeer(dialCtx, device, owner, invite, channel)
}

func (c *Client) dialSelfPeer(dialCtx context.Context, target selfrelay.Target, name string) (transport.Peer, func(), error) {
	options := c.tunnel
	webRTC := func(ctx context.Context) (cftunnel.Candidate, error) {
		peer, start, err := selfrelay.DialWithRoleFor(ctx, c.ctx, target, c.selfKey, name, "mobile", (*handler)(c))
		return cftunnel.Candidate{Peer: peer, Start: start}, err
	}
	var tunnel cftunnel.CandidateDial
	if target.Pair == "" {
		group, local, _, _ := c.networkBinding(target.Pin)
		tunnel = func(ctx context.Context) (cftunnel.Candidate, error) {
			key, err := selfrelay.ClientPrivateKey(c.selfKey)
			if err != nil {
				return cftunnel.Candidate{}, err
			}
			pin, err := base64.RawURLEncoding.Strict().DecodeString(target.Pin)
			if err != nil || len(pin) != ed25519.PublicKeySize {
				return cftunnel.Candidate{}, pairing.ErrInvalid
			}
			peer, start, err := cftunnel.ConnectSelfDeferred(ctx, cftunnel.SelfConnectOptions{
				SignalURL: target.SignalURL, SelfToken: target.Token, PrivateKey: key, HostPublicKey: pin,
				Role: "mobile", Handler: (*handler)(c), DialURL: options.url, HTTPClient: options.httpClient,
				Allows: func() bool {
					desktop, knownDesktop := group.Get(target.Pin)
					phone, knownPhone := group.Get(local.ID)
					return c.ctx.Err() == nil && (!knownDesktop || desktop.Active()) && (!knownPhone || phone.Active())
				},
			})
			return cftunnel.Candidate{Peer: peer, Start: start}, err
		}
	}
	winner, err := cftunnel.DialFallback(dialCtx, c.routeTracker, tunnelRouteKey(target.SignalURL, target.Pin), options.headStart, webRTC, tunnel)
	return winner.Peer, winner.Start, err
}

func (c *Client) dialOfficialPeer(dialCtx context.Context, device, owner string, invite *pairing.Official, channel string) (transport.Peer, func(), error) {
	options := c.tunnel
	var pin, token []byte
	var bound account.PeerBinding
	if invite != nil {
		pin, token = invite.Pin, invite.Token
	} else if c.identity != nil {
		var ok bool
		bound, ok = c.desktopBinding(device)
		if !ok || bound.Owner != owner {
			return nil, nil, pairing.ErrInvalid
		}
		var err error
		pin, err = base64.RawURLEncoding.Strict().DecodeString(bound.Pin)
		if err != nil || len(pin) != ed25519.PublicKeySize {
			return nil, nil, pairing.ErrInvalid
		}
	}

	existing := c.socket
	c.socket = nil
	webRTC := func(ctx context.Context) (cftunnel.Candidate, error) {
		socket, err := c.dialOfficialSocket(ctx, existing)
		if err != nil {
			return cftunnel.Candidate{}, err
		}
		connectCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		defer stop()
		peer, start, err := socket.ConnectPairedDeferred(connectCtx, device, owner, transport.ConnectOptions{Pin: pin, Token: token})
		return cftunnel.Candidate{Peer: peer, Start: start, Socket: socket, OwnsSocket: true}, err
	}
	var tunnel cftunnel.CandidateDial
	if c.identity != nil && invite == nil && officialChannel(channel) {
		tunnel = func(ctx context.Context) (cftunnel.Candidate, error) {
			peer, start, err := cftunnel.ConnectOfficialDeferred(ctx, cftunnel.OfficialConnectOptions{
				SignalURL: c.url, Channel: channel, HostDeviceID: device, HostPublicKey: pin, OwnerID: owner,
				Role: "mobile", CA: c.identity.CA(), LeaseSource: c.source,
				Handler: (*handler)(c), DialURL: options.url, HTTPClient: options.httpClient,
				Allows: func() bool {
					current, ok := c.desktopBinding(device)
					return c.ctx.Err() == nil && ok && current == bound
				},
			})
			return cftunnel.Candidate{Peer: peer, Start: start}, err
		}
	}
	winner, err := cftunnel.DialFallback(dialCtx, c.routeTracker, tunnelRouteKey(c.url, device), options.headStart, webRTC, tunnel)
	if err != nil {
		return nil, nil, err
	}
	if invite != nil {
		group, _ := c.identity.PairingIdentity(c.url, "mobile")
		bound := account.PeerBinding{Owner: owner, Pin: base64.RawURLEncoding.EncodeToString(pin)}
		if err := c.identity.BindNetworkPeer(group, device, bound); err != nil {
			winner.Close()
			return nil, nil, err
		}
	}
	c.socket = winner.Socket
	return winner.Peer, winner.Start, nil
}
