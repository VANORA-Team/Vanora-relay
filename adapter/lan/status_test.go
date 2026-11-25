package lan

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"vanora-relay/adapter/transport"
	"vanora-relay/internal/pairnet"
)

type memStore struct{ val string }

func (m *memStore) Load() (string, error) { return m.val, nil }
func (m *memStore) Save(v string) error   { m.val = v; return nil }

type noopHandler struct{}

func (noopHandler) Open(transport.Peer)            {}
func (noopHandler) Message(transport.Peer, []byte) {}
func (noopHandler) Closed(transport.Peer)          {}

func TestStatusIncludesIndirectPairNetMembers(t *testing.T) {
	srv, err := OpenServer(&memStore{}, noopHandler{})
	if err != nil {
		t.Fatal(err)
	}
	rawPin := sha256.Sum256([]byte("indirect-peer-1"))
	indirectID := base64.RawURLEncoding.EncodeToString(rawPin[:])
	localMember := pairnet.Member{ID: srv.pin, Role: "desktop", Pin: srv.pin, Name: "Host"}
	indirectMember := pairnet.Member{ID: indirectID, Role: "desktop", Pin: indirectID, Name: "IndirectDesk"}
	if err := srv.group.Admit(localMember, indirectMember, true); err != nil {
		t.Fatal(err)
	}

	status := srv.Status()
	if len(status.Clients) != 1 {
		t.Fatalf("Status().Clients = %+v, want 1 indirect pairnet client", status.Clients)
	}
	if status.Clients[0].ID != indirectID || status.Clients[0].Name != "IndirectDesk" || status.Clients[0].Access != Read || status.Clients[0].Role != "desktop" {
		t.Fatalf("unexpected indirect client info: %+v", status.Clients[0])
	}

	// Upgrading access persists an explicit grant without duplicating the entry.
	if err := srv.SetClientAccess(indirectID, Control); err != nil {
		t.Fatal(err)
	}
	status = srv.Status()
	if len(status.Clients) != 1 || status.Clients[0].Access != Control {
		t.Fatalf("expected single upgraded control client, got %+v", status.Clients)
	}

	// Removing from PairNet drops it from Status().Clients.
	if err := srv.RemoveDevice(indirectID); err != nil {
		t.Fatal(err)
	}
	status = srv.Status()
	if len(status.Clients) != 0 {
		t.Fatalf("expected removed member omitted from Status().Clients, got %+v", status.Clients)
	}
}
