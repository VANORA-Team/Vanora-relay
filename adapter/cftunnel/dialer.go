package cftunnel

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/coder/websocket"

	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
)

type DialOptions struct {
	ConnectionContext
	PrivateKey         ed25519.PrivateKey
	HostPublicKey      ed25519.PublicKey
	UserID             string
	AccessUntil        time.Time
	Allows             func() bool
	Handler            transport.Handler
	AssemblyBudget     *AssemblyBudget
	DialURL            string
	EdgeTicket         string
	CA                 ed25519.PublicKey
	LocalPrincipal     identity.Principal
	RemotePrincipal    identity.Principal
	LocalLeaseProvider func(context.Context) (endpoint.LeaseProof, error)
}

var outerTransport = &http.Transport{
	Proxy:               http.ProxyFromEnvironment,
	TLSHandshakeTimeout: handshakeTimeout,
	DisableKeepAlives:   true,
}

// Dial uses ctx during connection setup. The returned peer owns its lifetime.
func Dial(ctx context.Context, opts DialOptions) (transport.Peer, error) {
	peer, start, err := DialDeferred(ctx, opts)
	if err == nil {
		start()
	}
	return peer, err
}

// DialDeferred authenticates a peer that starts handling frames on start.
func DialDeferred(ctx context.Context, opts DialOptions) (transport.Peer, func(), error) {
	if !validPrivateKey(opts.PrivateKey) || opts.UserID == "" || opts.Allows == nil {
		return nil, nil, errors.New("cftunnel: dial requires a device key, user and local authorization")
	}
	if !time.Now().Before(opts.AccessUntil) || !opts.Allows() {
		return nil, nil, transport.ErrUnauthorized
	}
	binding := opts.ConnectionContext
	key, pin := slices.Clone(opts.PrivateKey), slices.Clone(opts.HostPublicKey)
	if err := binding.validate(pin, key.Public().(ed25519.PublicKey)); err != nil {
		return nil, nil, err
	}
	if binding.official() && opts.UserID != opts.RemotePrincipal.RemoteUserID() {
		return nil, nil, errors.New("cftunnel: dial host identity mismatch")
	}
	access, err := leaseAccess(binding, false, opts.CA, opts.LocalPrincipal, opts.RemotePrincipal, opts.LocalLeaseProvider)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := tlsConfig(key, pin, false)
	if err != nil {
		return nil, nil, err
	}
	proof, err := SignClientUpgradeProof(key, binding)
	if err != nil {
		return nil, nil, err
	}
	target, err := dialTarget(binding.Hostname, opts.DialURL)
	if err != nil {
		return nil, nil, err
	}
	headers := make(http.Header)
	headers.Set(ticketHeader, binding.JTI)
	headers.Set(proofHeader, proof)
	if opts.EdgeTicket != "" {
		headers.Set(edgeHeader, opts.EdgeTicket)
	}
	client := &http.Client{
		Transport:     outerTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	handshake, stop := context.WithTimeout(ctx, handshakeTimeout)
	defer stop()
	ws, response, err := websocket.Dial(handshake, target, &websocket.DialOptions{
		HTTPClient: client, Host: binding.Hostname, HTTPHeader: headers, Subprotocols: []string{Subprotocol},
	})
	if err != nil {
		if response != nil {
			return nil, nil, fmt.Errorf("cftunnel: WebSocket upgrade failed (HTTP %d)", response.StatusCode)
		}
		if handshake.Err() != nil {
			return nil, nil, handshake.Err()
		}
		return nil, nil, errors.New("cftunnel: WebSocket dial failed")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	ready := false
	defer func() {
		if !ready {
			cancel()
			_ = ws.CloseNow()
		}
	}()
	if ws.Subprotocol() != Subprotocol {
		return nil, nil, errors.New("cftunnel: WebSocket subprotocol missing")
	}
	conn, err := innerHandshake(handshake, lifetime, ws, cfg, binding, false, access, opts.LocalLeaseProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("cftunnel: inner handshake: %w", err)
	}
	if !time.Now().Before(opts.AccessUntil) || !opts.Allows() {
		return nil, nil, transport.ErrUnauthorized
	}
	if opts.AssemblyBudget == nil {
		opts.AssemblyBudget = processAssemblyBudget
	}
	context.AfterFunc(lifetime, func() { _ = ws.CloseNow() })
	peer := newPeer(lifetime, cancel, conn, opts.UserID, opts.Allows, opts.AccessUntil, access, opts.Handler, opts.AssemblyBudget)
	peer.deviceID = binding.HostDeviceID
	ready = true
	return peer, sync.OnceFunc(func() {
		if lifetime.Err() == nil {
			go peer.run()
		}
	}), nil
}

func dialTarget(host, override string) (string, error) {
	if override == "" {
		return (&url.URL{Scheme: "wss", Host: host, Path: tunnelPath}).String(), nil
	}
	target, err := url.Parse(override)
	if err != nil || target.Hostname() == "" || target.User != nil || target.Opaque != "" ||
		target.RawPath != "" || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" ||
		(target.Path != "" && target.Path != tunnelPath) {
		return "", errors.New("cftunnel: invalid dial URL")
	}
	if target.Scheme != "wss" {
		address, err := netip.ParseAddr(target.Hostname())
		if target.Scheme != "ws" || err != nil || !address.IsLoopback() || address.Zone() != "" {
			return "", errors.New("cftunnel: outer WebSocket requires TLS outside loopback")
		}
	}
	target.Path = tunnelPath
	return target.String(), nil
}
