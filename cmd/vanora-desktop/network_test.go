package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/pairnet"
	"vanora-relay/internal/signal"
	"vanora-relay/mobile"
	"vanora-relay/protocol"
)

type namedDesktop string

func (namedDesktop) Open(transport.Peer)   {}
func (namedDesktop) Closed(transport.Peer) {}
func (name namedDesktop) Message(peer transport.Peer, raw []byte) {
	var req struct {
		Request string `json:"request_id"`
	}
	if json.Unmarshal(raw, &req) == nil {
		_ = peer.Send(protocol.Encode(map[string]string{"type": "result", "request_id": req.Request, "data": string(name)}), false)
	}
}

func requireNetwork[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

type networkHost struct {
	group   *pairnet.Group
	invite  func() pairing.Display
	manager *accessManager
}

func TestPairingNetwork(t *testing.T) {
	for _, channel := range []string{"lan", "self", "cn", "global"} {
		t.Run(channel, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			var service string
			token := strings.Repeat("local-test-", 4)
			var phone func(*memVault) *mobile.Client
			var host func(string) networkHost
			if channel == "lan" {
				phone = func(store *memVault) *mobile.Client { return requireNetwork(mobile.NewLANClient(store)) }
				host = func(name string) networkHost {
					server := requireNetwork(lan.OpenServer(&memVault{}, namedDesktop(name)))
					if err := server.Listen(ctx, "127.0.0.1:0"); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(server.Stop)
					return networkHost{server.Network(), func() pairing.Display {
						_, display, err := server.InvitePairing(lan.Control)
						return requireNetwork(display, err)
					}, &accessManager{ctx: ctx, local: server}}
				}
			} else if channel == "self" {
				hub := signal.NewSelfHosted(token, directICE{})
				go hub.Run(ctx)
				server := httptest.NewServer(hub)
				t.Cleanup(server.Close)
				service = "ws" + strings.TrimPrefix(server.URL, "http")
				phone = func(store *memVault) *mobile.Client { return requireNetwork(mobile.NewSelfRelayClient(store)) }
				host = func(name string) networkHost {
					desk := requireNetwork(selfrelay.OpenServer(&memVault{}, namedDesktop(name)))
					if err := desk.Connect(ctx, service, token, name); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(desk.Stop)
					awaitNetwork(t, func() bool { return desk.Status().Online })
					return networkHost{desk.Network(), func() pairing.Display {
						_, display, err := desk.InvitePairing(ctx, selfrelay.Control, true)
						return requireNetwork(display, err)
					}, &accessManager{ctx: ctx, selfServer: desk}}
				}
			} else {
				issuer, auth := newTestTokenAuthority(t, map[string]string{"test-token": "owner"})
				ca := hex.EncodeToString(auth.PublicKey())
				hub := signal.New(auth.PublicKey(), nil, directICE{})
				go hub.Run(ctx)
				server := httptest.NewServer(hub)
				t.Cleanup(server.Close)
				service = "ws" + strings.TrimPrefix(server.URL, "http")
				phone = func(store *memVault) *mobile.Client {
					client := requireNetwork(mobile.NewClient(issuer.URL, service, ca, store))
					if err := client.Enroll("test-token"); err != nil {
						t.Fatal(err)
					}
					return client
				}
				host = func(name string) networkHost {
					acc := requireNetwork(account.New(issuer.URL, ca, &memVault{}))
					if err := acc.Enroll(ctx, "test-token"); err != nil {
						t.Fatal(err)
					}
					slot := &officialSlot{name: channel, desktopName: name, url: service, account: acc}
					socket := requireNetwork(transport.DialPairedDesktopWithRole(ctx, service, acc, namedDesktop(name), slot.authorize))
					if err := socket.Publish(ctx, name, nil); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(socket.Close)
					slot.socket.Store(socket)
					slot.online.Store(true)
					group, _ := acc.PairingIdentity(service, "desktop")
					return networkHost{group, func() pairing.Display {
						_, display, err := slot.invite(ctx)
						return requireNetwork(display, err)
					}, &accessManager{ctx: ctx, slots: map[string]*officialSlot{channel: slot}}}
				}
			}
			first, second := host("first"), host("second")
			storeB := &memVault{}
			phoneA, phoneB := phone(&memVault{}), phone(storeB)
			defer phoneA.Close()
			defer phoneB.Close()
			for _, step := range []struct {
				client      *mobile.Client
				input, name string
			}{
				{phoneA, first.invite().Code, "A"}, {phoneB, second.invite().Link, "B"}, {phoneA, second.invite().Code, "A"},
			} {
				input, address := step.input, service
				if channel == "lan" && step.client == phoneA && strings.Count(requireNetwork(phoneA.PairingNetwork()), `"id":`) >= 2 {
					input, address, _ = strings.Cut(input, "@")
				}
				if err := step.client.Pair(input, address, "", step.name); err != nil {
					t.Fatal(err)
				}
			}
			awaitNetwork(t, func() bool {
				return len(first.group.Snapshot().Members()) == 4 && len(second.group.Snapshot().Members()) == 4 && strings.Count(requireNetwork(phoneB.PairingNetwork()), `"id":`) == 4
			})
			ch := make(chan error, 4)
			for _, client := range []*mobile.Client{phoneA, phoneB} {
				for want, desk := range map[string]networkHost{"first": first, "second": second} {
					handle := requireNetwork(client.OpenNetworkDesktop(desk.group.Self()))
					go func() {
						got, err := handle.ListSessions()
						if err == nil && got != `"`+want+`"` {
							err = fmt.Errorf("expected %s; got %s", want, got)
						}
						ch <- err
					}()
				}
			}
			for range 4 {
				if err := <-ch; err != nil {
					t.Fatal(err)
				}
			}
			phoneB.Close()
			restored := phone(storeB)
			for name, desk := range map[string]networkHost{"first": first, "second": second} {
				handle := requireNetwork(restored.OpenNetworkDesktop(desk.group.Self()))
				if got := requireNetwork(handle.ListSessions()); got != `"`+name+`"` {
					t.Fatal(got)
				}
			}
			restored.Close()
			var removed string
			for id, member := range second.group.Snapshot() {
				if member.Name == "B" {
					removed = id
				}
			}
			if err := phoneA.RemoveNetworkDevice(removed); err != nil {
				t.Fatal(err)
			}
			awaitNetwork(t, func() bool { return !first.group.Allows(removed) && !second.group.Allows(removed) })
			stale := phone(storeB)
			defer stale.Close()
			if _, err := stale.OpenNetworkDesktop(first.group.Self()); err == nil {
				t.Fatal("removed offline phone reconnected")
			}
			if err := stale.Pair(first.invite().Code, service, "", "B"); err != nil {
				t.Fatal(err)
			}
			awaitNetwork(t, func() bool { return second.group.Allows(removed) })
			rejoined := requireNetwork(stale.OpenNetworkDesktop(second.group.Self()))
			if result := requireNetwork(rejoined.ListSessions()); result != `"second"` {
				t.Fatal(result)
			}
			var output bytes.Buffer
			second.manager.emitter = &jsonEmitter{out: &output}
			for _, action := range []string{"list", "remove"} {
				output.Reset()
				second.manager.command(accessCommand{Type: "access.network." + action, Channel: channel, ID: second.group.Self()})
				var response struct {
					Type    string           `json:"type"`
					Members []pairnet.Member `json:"members"`
				}
				if err := json.NewDecoder(&output).Decode(&response); err != nil || response.Type != "access.network" {
					t.Fatalf("desktop network %s: %s", action, output.String())
				}
				if action == "list" && len(response.Members) != 4 || action == "remove" && len(response.Members) != 0 {
					t.Fatalf("%s returned %d members", action, len(response.Members))
				}
			}
			awaitNetwork(t, func() bool {
				return !first.group.Allows(second.group.Self()) && !second.group.Allows(second.group.Self())
			})
			awaitNetwork(t, func() bool {
				_, err := rejoined.ListSessions()
				return err != nil
			})
			handle := requireNetwork(phoneA.OpenNetworkDesktop(first.group.Self()))
			if result := requireNetwork(handle.ListSessions()); result != `"first"` {
				t.Fatal(result)
			}
		})
	}
}

func TestSelfNetworkSwitch(t *testing.T) {
	ctx := t.Context()
	token := strings.Repeat("local-test-", 4)
	newRelay := func() string {
		hub := signal.NewSelfHosted(token, directICE{})
		go hub.Run(ctx)
		server := httptest.NewServer(hub)
		t.Cleanup(server.Close)
		return "ws" + strings.TrimPrefix(server.URL, "http")
	}
	first, second := newRelay(), newRelay()
	store := &memVault{}
	desktop := requireNetwork(selfrelay.OpenServer(store, namedDesktop("desktop")))
	defer desktop.Stop()
	connect := func(url string) {
		desktop.Stop()
		if err := desktop.Connect(ctx, url, token, "desktop"); err != nil {
			t.Fatal(err)
		}
		awaitNetwork(t, func() bool { return desktop.Status().Online })
	}
	connect(first)
	phone := requireNetwork(mobile.NewSelfRelayClient(&memVault{}))
	defer phone.Close()
	_, invitation, err := desktop.InvitePairing(ctx, selfrelay.Control, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := phone.Pair(invitation.Code, first, "", "phone"); err != nil {
		t.Fatal(err)
	}
	id := desktop.Status().Clients[0].ID
	phone.Disconnect()
	connect(second)
	if len(desktop.Status().Clients) != 0 || desktop.Network().Allows(id) {
		t.Fatal("new relay inherited devices from the previous relay")
	}
	connect(first)
	if !desktop.Network().Allows(id) || desktop.Status().Clients[0].Access != selfrelay.Control {
		t.Fatal("returning to the original relay lost its stored permission")
	}
	desktop.Stop()
	reopened := requireNetwork(selfrelay.OpenServer(store, namedDesktop("desktop")))
	if err := reopened.RemoveDevice(id); err != nil || reopened.Network().Allows(id) {
		t.Fatalf("offline removal after restart: %v", err)
	}
}

func awaitNetwork(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("network did not converge")
		}
		time.Sleep(15 * time.Millisecond)
	}
}
