package signal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

// newSelfDesktopPeer builds an online self-hosted desktop peer ready to be
// inserted into the hub.
func newSelfDesktopPeer(t *testing.T, name string) (*peer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devID, err := identity.SelfDeviceID(pub)
	if err != nil {
		t.Fatal(err)
	}
	card := protocol.Message{Type: "device.card", From: devID, To: "self"}
	if err := card.Sign(priv, []byte(name)); err != nil {
		t.Fatal(err)
	}
	p := &peer{
		id:         identity.Principal{Issuer: "self", Subject: devID, DeviceID: devID, PublicKey: pub},
		role:       "desktop",
		selfHosted: true,
		online:     true,
		card:       card,
		grants:     make(map[string]bool),
		ctx:        context.Background(),
		out:        make(chan protocol.Message, 4),
		pairTicket: "tkt-" + devID,
	}
	return p, pub
}

// selfPollProof builds the signed activity.poll proof headers for a
// self-hosted caller identified by priv/pub.
func selfPollProof(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, target string, now time.Time) (pubB64, proofB64 string) {
	t.Helper()
	devID, err := identity.SelfDeviceID(pub)
	if err != nil {
		t.Fatal(err)
	}
	m := protocol.Message{Type: "activity.poll", From: devID, To: target}
	if err := m.Sign(priv, []byte(strconv.FormatInt(now.UnixMilli(), 10))); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(pub), base64.RawURLEncoding.EncodeToString(raw)
}

func mustSelfDeviceID(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	devID, err := identity.SelfDeviceID(pub)
	if err != nil {
		t.Fatal(err)
	}
	return devID
}

// TestSelfHostedActivityPollEnforcesGuestACL pins the self-hosted activity
// read ACL: only devices listed in the desktop's device.online guests may
// poll, and the offline fallback book follows the last published grants.
func TestSelfHostedActivityPollEnforcesGuestACL(t *testing.T) {
	token := strings.Repeat("S", 40)
	h := NewSelfHosted(token, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	host, _ := newSelfDesktopPeer(t, "desk")
	h.mu.Lock()
	h.peers[host.id.DeviceID] = host
	h.mu.Unlock()

	guestPub, guestPriv, _ := ed25519.GenerateKey(rand.Reader)
	strangerPub, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	guestDev := mustSelfDeviceID(t, guestPub)

	publish := func() int {
		t.Helper()
		body := `{"session_id":"s1","run_id":"r1","phase":"awaiting_approval","uiid":"ui-1","method":"run.start"}`
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/signal?activity=1", strings.NewReader(body))
		req.Header.Set("Vanora-Desktop", host.id.DeviceID)
		req.Header.Set("Authorization", "Bearer "+host.pairTicket)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	poll := func(pub ed25519.PublicKey, priv ed25519.PrivateKey, target string) int {
		t.Helper()
		pubB64, proofB64 := selfPollProof(t, pub, priv, target, time.Now())
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/signal?activity="+target, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Vanora-Public-Key", pubB64)
		req.Header.Set("X-Vanora-Activity-Proof", proofB64)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := publish(); code != http.StatusNoContent {
		t.Fatalf("publish without grants status = %d, want 204", code)
	}

	// Neither guest nor stranger is paired yet: both are refused.
	if code := poll(guestPub, guestPriv, host.id.DeviceID); code != http.StatusForbidden {
		t.Fatalf("unpaired guest poll status = %d, want 403", code)
	}
	if code := poll(strangerPub, strangerPriv, host.id.DeviceID); code != http.StatusForbidden {
		t.Fatalf("stranger poll status = %d, want 403", code)
	}

	// Pair the guest: republish grants and confirm read access.
	host.grants[guestDev] = true
	if code := publish(); code != http.StatusNoContent {
		t.Fatalf("publish with grants status = %d, want 204", code)
	}
	if code := poll(guestPub, guestPriv, host.id.DeviceID); code != http.StatusOK {
		t.Fatalf("paired guest poll status = %d, want 200", code)
	}
	if code := poll(strangerPub, strangerPriv, host.id.DeviceID); code != http.StatusForbidden {
		t.Fatalf("stranger poll status = %d, want 403", code)
	}

	// Revoke: grants empty again; the live peer ACL refuses immediately.
	host.grants = make(map[string]bool)
	if code := poll(guestPub, guestPriv, host.id.DeviceID); code != http.StatusForbidden {
		t.Fatalf("revoked guest poll status = %d, want 403", code)
	}

	// Desktop goes offline: the last published book (which still listed the
	// guest) keeps serving reads until the retention TTL.
	h.mu.Lock()
	delete(h.peers, host.id.DeviceID)
	h.mu.Unlock()
	if code := poll(guestPub, guestPriv, host.id.DeviceID); code != http.StatusOK {
		t.Fatalf("offline fallback for recently paired guest status = %d, want 200", code)
	}
	if code := poll(strangerPub, strangerPriv, host.id.DeviceID); code != http.StatusForbidden {
		t.Fatalf("offline fallback stranger status = %d, want 403", code)
	}
}
