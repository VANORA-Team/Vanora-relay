package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image/png"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/signal"
	"vanora-relay/mobile"
)

type directICE struct{}

func (directICE) Config(string, string, time.Time) ([]ice.ICEServer, error) {
	return []ice.ICEServer{}, nil
}
func (directICE) Revoke(string) {}

type pairingHandler struct{}

func (pairingHandler) Open(transport.Peer)            {}
func (pairingHandler) Closed(transport.Peer)          {}
func (pairingHandler) Message(transport.Peer, []byte) {}

func TestOfficialRelayPairing(t *testing.T) {
	for _, site := range []string{"cn", "global"} {
		t.Run(site, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			issuer, authority := newTestTokenAuthority(t, map[string]string{"host-token": "owner"})
			ca := hex.EncodeToString(authority.PublicKey())
			desktopStore := &memVault{}
			host, err := account.New(issuer.URL, ca, desktopStore)
			if err != nil {
				t.Fatal(err)
			}
			if err := host.Enroll(ctx, "host-token"); err != nil {
				t.Fatal(err)
			}
			hub := signal.New(authority.PublicKey(), nil, directICE{})
			go hub.Run(ctx)
			server := httptest.NewServer(hub)
			defer server.Close()
			relay := "ws" + strings.TrimPrefix(server.URL, "http")
			slot := &officialSlot{name: site, url: relay, account: host}
			socket, err := transport.DialPairedDesktopWithRole(ctx, relay, host, pairingHandler{}, slot.authorize)
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			if err := socket.Publish(ctx, "Office", nil); err != nil {
				t.Fatal(err)
			}
			slot.socket.Store(socket)
			slot.online.Store(true)
			var stdout bytes.Buffer
			manager := &accessManager{ctx: ctx, activeChannel: site, activeSlot: slot, slots: map[string]*officialSlot{site: slot}, emitter: &jsonEmitter{out: &stdout}}
			unpaired, err := account.New(issuer.URL, ca, &memVault{})
			if err != nil {
				t.Fatal(err)
			}
			if err := unpaired.Enroll(ctx, "host-token"); err != nil {
				t.Fatal(err)
			}
			legacy, err := transport.Dial(ctx, relay, transport.RoleMobile, unpaired, pairingHandler{})
			if err != nil {
				t.Fatal(err)
			}
			defer legacy.Close()
			_, err = legacy.Connect(ctx, host.DeviceID(), host.UserID())
			var closed *transport.ClosedError
			if !errors.As(err, &closed) || closed.Reason != "access_denied" {
				t.Fatalf("unpaired owner connection: %v", err)
			}

			for _, entry := range []string{"qr", "code"} {
				stdout.Reset()
				manager.command(accessCommand{Type: "access.relay.invite.create", Channel: site})
				var invitation struct {
					Type string `json:"type"`
					Link string `json:"link"`
					Code string `json:"pairing_code"`
					QR   string `json:"qr_code"`
				}
				decoder := json.NewDecoder(&stdout)
				if err := decoder.Decode(&invitation); err != nil || invitation.Type != "access.relay.invite.created" {
					t.Fatalf("create invitation: %v (%s)", err, invitation.Type)
				}
				var status json.RawMessage
				if err := decoder.Decode(&status); err != nil || bytes.Contains(status, []byte(invitation.Code)) || bytes.Contains(status, []byte(invitation.Link)) {
					t.Fatal("invalid or unredacted status")
				}
				image, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(invitation.QR, "data:image/png;base64,"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := png.Decode(bytes.NewReader(image)); err != nil {
					t.Fatal(err)
				}
				resolved, err := pairing.Resolve(ctx, relay, strings.ToLower(invitation.Code))
				if err != nil || resolved != invitation.Link {
					t.Fatalf("code and QR disagree: %v", err)
				}
				phoneStore := &memVault{}
				phone, err := mobile.NewClient(issuer.URL, relay, ca, phoneStore)
				if err != nil {
					t.Fatal(err)
				}
				defer phone.Close()
				if err := phone.Enroll("host-token"); err != nil {
					t.Fatal(err)
				}
				if err := phone.Connect(host.DeviceID(), host.UserID()); !errors.Is(err, pairing.ErrInvalid) {
					t.Fatalf("directory-only SDK connect: %v", err)
				}
				input := invitation.Link
				if entry == "code" {
					input = invitation.Code
				}
				if err := phone.Pair(input, "", "", "Phone"); err != nil {
					t.Fatal(err)
				}
				phoneID := phone.DeviceID()
				phone.Close()
				restored, err := mobile.NewClient(issuer.URL, relay, ca, phoneStore)
				if err != nil {
					t.Fatal(err)
				}
				defer restored.Close()
				if err := restored.Connect(host.DeviceID(), host.UserID()); err != nil {
					t.Fatal(err)
				}
				restored.Close()
				reloaded, err := account.New(issuer.URL, ca, desktopStore)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := reloaded.PairedPeer(phoneID); !ok {
					t.Fatal("desktop lost binding")
				}
				if err := slot.revokeClients(phoneID, false); err != nil {
					t.Fatal(err)
				}
				reused, err := mobile.NewClient(issuer.URL, relay, ca, phoneStore)
				if err != nil {
					t.Fatal(err)
				}
				if err := reused.Pair(invitation.Link, "", "", "Phone"); !errors.As(err, &closed) || closed.Reason != "access_denied" {
					t.Fatalf("consumed invitation: %v", err)
				}
				reused.Close()
			}
			for _, invalidation := range []string{"revoke", "expire"} {
				info, display, err := slot.invite(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if invalidation == "revoke" {
					if err := slot.revokeInvite(info.ID); err != nil {
						t.Fatal(err)
					}
				} else {
					slot.pairMu.Lock()
					invite := slot.invites[info.ID]
					invite.Expires = time.Now().Add(-time.Second)
					slot.invites[info.ID] = invite
					slot.pairMu.Unlock()
				}
				newPhone, err := mobile.NewClient(issuer.URL, relay, ca, &memVault{})
				if err != nil {
					t.Fatal(err)
				}
				if err := newPhone.Enroll("host-token"); err != nil {
					t.Fatal(err)
				}
				for _, input := range []string{display.Code, display.Link} {
					err := newPhone.Pair(input, "", "", "New phone")
					if !errors.Is(err, pairing.ErrInvalid) && !(errors.As(err, &closed) && closed.Reason == "access_denied") {
						t.Fatalf("%s invitation: %v", invalidation, err)
					}
				}
				newPhone.Close()
			}
		})
	}
}
