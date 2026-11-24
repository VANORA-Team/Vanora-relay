package security_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"vanora-relay/adapter/lan"
	"vanora-relay/adapter/transport"
)

type lanMemStore struct {
	mu  sync.Mutex
	val string
}

func (s *lanMemStore) Load() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.val, nil
}

func (s *lanMemStore) Save(v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.val = v
	return nil
}

type lanRecordingHandler struct {
	opened chan transport.Peer
	closed chan transport.Peer
}

func newLANRecordingHandler() *lanRecordingHandler {
	return &lanRecordingHandler{
		opened: make(chan transport.Peer, 8),
		closed: make(chan transport.Peer, 8),
	}
}

func (h *lanRecordingHandler) Open(p transport.Peer)          { h.opened <- p }
func (h *lanRecordingHandler) Message(transport.Peer, []byte) {}
func (h *lanRecordingHandler) Closed(p transport.Peer)        { h.closed <- p }

func TestLANPairedReadDeviceCannotUpgradeViaControlInvite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	deskHandler := newLANRecordingHandler()
	srv, err := lan.OpenServer(&lanMemStore{}, deskHandler)
	mustOK(t, err)
	defer srv.Stop()
	mustOK(t, srv.Listen(ctx, "127.0.0.1:0"))

	// Pair a Read-only device.
	_, readLink, err := srv.Invite(lan.Read)
	mustOK(t, err)
	readTarget, err := lan.ParseTarget(readLink)
	mustOK(t, err)
	readerKey, err := lan.LoadClientKey(&lanMemStore{})
	mustOK(t, err)

	p1, start1, err := lan.Dial(ctx, readTarget, readerKey, "ReaderPhone", newLANRecordingHandler())
	mustOK(t, err)
	start1()
	deskPeer1 := <-deskHandler.opened
	if got := lan.Access(deskPeer1.UserID()); got != lan.Read {
		t.Fatalf("initial access = %q, want %q", got, lan.Read)
	}
	p1.Close()
	<-deskHandler.closed

	// Create a Control invite and present its token using the already-paired Read device key.
	ctrlInv, ctrlLink, err := srv.Invite(lan.Control)
	mustOK(t, err)
	ctrlTarget, err := lan.ParseTarget(ctrlLink)
	mustOK(t, err)

	p2, start2, err := lan.Dial(ctx, ctrlTarget, readerKey, "ReaderPhone", newLANRecordingHandler())
	mustOK(t, err)
	start2()
	defer p2.Close()

	deskPeer2 := <-deskHandler.opened
	if got := lan.Access(deskPeer2.UserID()); got != lan.Read {
		t.Fatalf("paired read device upgraded to %q using control invite", got)
	}

	// Control invitation must remain unconsumed and still usable by an unpaired device.
	var foundCtrl bool
	for _, inv := range srv.Status().Invitations {
		if inv.ID == ctrlInv.ID {
			foundCtrl = true
		}
	}
	if !foundCtrl {
		t.Fatal("control invitation was consumed when an already-paired read device connected")
	}

	otherKey, err := lan.LoadClientKey(&lanMemStore{})
	mustOK(t, err)
	p3, start3, err := lan.Dial(ctx, ctrlTarget, otherKey, "ControllerPhone", newLANRecordingHandler())
	mustOK(t, err)
	start3()
	defer p3.Close()
	deskPeer3 := <-deskHandler.opened
	if got := lan.Access(deskPeer3.UserID()); got != lan.Control {
		t.Fatalf("new device access = %q, want %q", got, lan.Control)
	}
}
