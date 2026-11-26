package remote

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/pairnet"
	"vanora-relay/internal/routes"
	"vanora-relay/internal/testtunnel"
)

type tunnelTestProvider struct {
	self     *SelfChannel
	official *OfficialChannel
}

func (tunnelTestProvider) DesktopName() string { return "Remote controller" }

func (p tunnelTestProvider) Official(channel string) (*OfficialChannel, error) {
	if p.official != nil && p.official.Channel == channel {
		return p.official, nil
	}
	return nil, errors.New("official test channel unavailable")
}

func (p tunnelTestProvider) Self() (*SelfChannel, error) { return p.self, nil }
func (tunnelTestProvider) LAN() (*LANChannel, error)     { return nil, nil }

func (p tunnelTestProvider) ListOfficialChannels() []string {
	if p.official == nil {
		return nil
	}
	return []string{p.official.Channel}
}

func TestManagedTunnelDesktopFailover(t *testing.T) {
	for _, channel := range []string{ChannelSelf, ChannelCN} {
		t.Run(channel, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
			defer cancel()
			rig := testtunnel.New(t, channel)
			desktop := testtunnel.NewDesktop()
			provider, peerID := pairedTunnelDesktops(t, rig, desktop, channel)
			events := make(chan int64, 8)
			mgr := NewManager(ctx, provider, func(event map[string]any) {
				if event["type"] == "remote.event" {
					events <- event["seq"].(int64)
				}
			})
			t.Cleanup(mgr.Close)
			mgr.tunnel = tunnelDialOptions{url: rig.EdgeURL, headStart: 750 * time.Millisecond}

			if channel == ChannelSelf {
				rig.FailICE.Store(true)
			} else {
				rig.StallRTC.Store(true)
			}
			info, err := mgr.Connect(ctx, channel, peerID)
			testtunnel.Must(t, err)
			expected := []routes.Entry{{Address: rig.SignalURL, Kind: routes.KindRelay}, {Address: rig.SignalURL, Kind: routes.KindCFTunnel}}
			if info.Path != "cf_tunnel" || !slices.Equal(info.Routes, expected) || info.Generation != 1 {
				t.Fatalf("unexpected managed tunnel connection: %+v", info)
			}
			rp, err := mgr.lookupPeer(channel, peerID)
			testtunnel.Must(t, err)
			rp.mu.Lock()
			ownsSocket := rp.socket != nil || rp.ownsSocket
			rp.mu.Unlock()
			if ownsSocket {
				t.Fatal("the tunnel retained the WebRTC signaling socket")
			}
			if channel == ChannelCN {
				testtunnel.Wait(t, func() bool { return rig.ClosedStalled.Load() == 1 })
				if !rig.TURNSuppressed.Load() || rig.StalledOffers.Load() != 1 {
					t.Fatal("official WebRTC did not stall without TURN as expected")
				}
			}
			workspaces, err := mgr.ListWorkspaces(ctx, channel, peerID)
			testtunnel.Must(t, err)
			if !strings.Contains(string(workspaces), "tunnel-workspace") {
				t.Fatalf("unexpected workspace list: %s", workspaces)
			}
			desktop.AwaitRequest(t, "workspace.list", "cf_tunnel")
			const session = "remote-fixture-session"
			_, err = mgr.OpenSession(ctx, channel, peerID, session)
			testtunnel.Must(t, err)
			desktop.AwaitRequest(t, "session.open", "cf_tunnel")
			desktop.AwaitRequest(t, "events.resume", "cf_tunnel")
			if seq := testtunnel.Await(t, events); seq != 1 {
				t.Fatalf("unexpected initial event %d", seq)
			}
			testtunnel.Must(t, mgr.Acknowledge(channel, peerID, session, 1))
			woke, err := mgr.Wakeup(ctx, channel, peerID, true)
			testtunnel.Must(t, err)
			desktop.AwaitRequest(t, "ping", "cf_tunnel")
			if woke.Generation != info.Generation || woke.Path != "cf_tunnel" {
				t.Fatal("wakeup replaced a healthy desktop tunnel")
			}

			rig.FailICE.Store(false)
			rig.StallRTC.Store(false)
			mgr.tunnel.headStart = 8 * time.Second
			rig.BlackholeLatestEdge()
			started := time.Now()
			woke, err = mgr.Wakeup(ctx, channel, peerID, false)
			testtunnel.Must(t, err)
			if woke.Generation != info.Generation+1 || woke.Path != "direct" || time.Since(started) > remoteProbeTimeout {
				t.Fatalf("wakeup did not replace a silent tunnel with direct WebRTC: %+v", woke)
			}
			if request := desktop.AwaitRequest(t, "events.resume", "direct"); request.After != 1 {
				t.Fatalf("desktop resumed after %d, want 1", request.After)
			}
			if seq := testtunnel.Await(t, events); seq != 2 {
				t.Fatalf("unexpected resumed event %d", seq)
			}
		})
	}
}

func pairedTunnelDesktops(t *testing.T, rig *testtunnel.Rig, desktop *testtunnel.Desktop, channel string) (tunnelTestProvider, string) {
	t.Helper()
	if channel == ChannelSelf {
		host, err := selfrelay.OpenServer(&testtunnel.Store{}, desktop)
		testtunnel.Must(t, err)
		local, err := selfrelay.OpenServer(&testtunnel.Store{}, testtunnel.NewDesktop())
		testtunnel.Must(t, err)
		for _, pair := range [][2]*selfrelay.Server{{host, local}, {local, host}} {
			group, member, err := pair[0].GroupFor(rig.SignalURL, "Test desktop")
			testtunnel.Must(t, err)
			pin := pair[1].Pin()
			testtunnel.Must(t, group.Admit(member, pairnet.Member{ID: pin, Pin: pin, Role: "desktop", Name: "Peer"}, true))
			testtunnel.Must(t, pair[0].SetPeerAccessFor(rig.SignalURL, pin, selfrelay.Control))
		}
		rig.StartSelfHost(t, host)
		return tunnelTestProvider{self: &SelfChannel{SignalURL: rig.SignalURL, Token: rig.Token, Server: local}}, host.Pin()
	}
	host, visitor := rig.NewAccount(t), rig.NewAccount(t)
	testtunnel.AdmitOfficial(t, rig.SignalURL, host, visitor, "desktop")
	socket := rig.StartOfficialHost(t, host, desktop,
		func(_ string, principal identity.Principal, role, _ string, proof []byte) bool {
			return principal.DeviceID == visitor.DeviceID() && (role == "desktop" || role == "") && proof == nil
		})
	testtunnel.Must(t, visitor.BindPeer(socket.DeviceID(), account.PeerBinding{
		Owner: socket.UserID(), Pin: base64.RawURLEncoding.EncodeToString(socket.PublicKey()),
	}))
	return tunnelTestProvider{official: &OfficialChannel{Channel: channel, SignalURL: rig.SignalURL, Account: visitor}}, socket.DeviceID()
}
