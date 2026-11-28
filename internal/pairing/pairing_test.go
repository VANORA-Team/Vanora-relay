package pairing

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestResolveAtPreservesCallerURL(t *testing.T) {
	code, record, err := Seal("vanora://pair/cn", time.Now().Add(Lifetime))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("pairing") != record.Locator || query.Get("route") != "original" {
			t.Errorf("ResolveAt sent query %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(record.Box))
	}))
	defer server.Close()
	target, err := url.Parse(server.URL + "?route=original")
	if err != nil {
		t.Fatal(err)
	}
	link, err := ResolveAt(t.Context(), server.Client(), target, code)
	if err != nil || link != "vanora://pair/cn" || target.RawQuery != "route=original" {
		t.Fatalf("ResolveAt returned %q, %v with URL %s", link, err, target)
	}
}

func TestParseOfficialNormalizesRelayAndValidatesIdentities(t *testing.T) {
	const relay = "wss://relay.example/ws"
	invite := NewOfficial("cn", "WSS://RELAY.EXAMPLE:443/ws/", "dev_"+strings.Repeat("a", 26),
		"usr_"+strings.Repeat("b", 26), make(ed25519.PublicKey, ed25519.PublicKeySize))
	if got, err := ParseOfficial(invite.Link(), relay); err != nil || got.Relay != relay {
		t.Fatalf("normalized relay comparison = %+v, %v", got, err)
	}
	for _, test := range []Official{
		{Relay: "wss://relay.example:8443/ws", Device: invite.Device, Owner: invite.Owner},
		{Relay: "wss://relay.example/w%2Fs", Device: invite.Device, Owner: invite.Owner},
		{Relay: relay, Device: "dev_abc", Owner: invite.Owner},
		{Relay: relay, Device: invite.Device, Owner: invite.Device},
	} {
		test.Channel, test.Pin, test.Token = invite.Channel, invite.Pin, invite.Token
		if _, err := ParseOfficial(test.Link(), relay); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ParseOfficial accepted relay %q, device %q, owner %q: %v", test.Relay, test.Device, test.Owner, err)
		}
	}
}

func TestPresentRetiresOnlyOnce(t *testing.T) {
	records := make(chan Record, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var record Record
		if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
			t.Errorf("decode record: %v", err)
		}
		records <- record
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	_, retire, err := Present(t.Context(), server.URL, "desktop", "ticket", "vanora://pair/cn", time.Now().Add(Lifetime))
	if err != nil {
		t.Fatal(err)
	}
	published := <-records
	retire()
	retire()
	select {
	case retired := <-records:
		if retired != (Record{Locator: published.Locator}) {
			t.Fatalf("retired record = %+v", retired)
		}
	case <-time.After(time.Second):
		t.Fatal("retirement was not published")
	}
	select {
	case duplicate := <-records:
		t.Fatalf("duplicate retirement: %+v", duplicate)
	case <-time.After(50 * time.Millisecond):
	}
}
