package pairnet

import (
	"encoding/base64"
	"strings"
	"testing"
)

func testMember(id, role string, epoch uint64) Member {
	pin := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("p", 32)))
	return Member{ID: id, Role: role, Pin: pin, Epoch: epoch}
}

type memStore struct{ data string }

func (s *memStore) Load() (string, error) { return s.data, nil }
func (s *memStore) Save(v string) error   { s.data = v; return nil }
func (s *memStore) String() string        { return "mem" }

func newTestDB(t *testing.T, self string, roster Roster) *Database {
	t.Helper()
	db, err := Open(&memStore{data: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	db.state.Groups["net\x00"+self] = roster
	return db
}

// seedRoster builds a network with a desktop and mobile guests.
func seedRoster(desktop string, guests ...string) Roster {
	r := Roster{
		desktop: testMember(desktop, "desktop", 1),
	}
	for _, g := range guests {
		r[g] = testMember(g, "mobile", 1)
	}
	return r
}

func TestMergeMobileVouchesNewMemberForTransitivePairing(t *testing.T) {
	desktop, guestA, guestB := "desk-1", "mobile-a", "mobile-b"
	db := newTestDB(t, desktop, seedRoster(desktop, guestA))
	g := db.Group("net", desktop)
	key := "net\x00" + desktop

	incoming := Roster{
		desktop: testMember(desktop, "desktop", 1),
		guestA:  testMember(guestA, "mobile", 1),
		guestB:  testMember(guestB, "mobile", 1),
	}
	changed, err := g.Merge(guestA, incoming)
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if !changed {
		t.Fatal("transitive phone-relayed pairing must admit the new member")
	}
	if _, ok := db.state.Groups[key][guestB]; !ok {
		t.Fatal("vouched member was not persisted")
	}
}

func TestMergeDesktopCanVouchNewMember(t *testing.T) {
	desktop, guestB := "desk-1", "mobile-b"
	db := newTestDB(t, desktop, seedRoster(desktop, "mobile-a"))
	g := db.Group("net", desktop)
	key := "net\x00" + desktop

	incoming := Roster{
		desktop: testMember(desktop, "desktop", 1),
		guestB:  testMember(guestB, "mobile", 1),
	}
	changed, err := g.Merge(desktop, incoming)
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if !changed {
		t.Fatal("desktop admission of a new member was ignored")
	}
	if _, ok := db.state.Groups[key][guestB]; !ok {
		t.Fatal("vouched member was not persisted")
	}
}

func TestMergeMobileCannotWipeRoster(t *testing.T) {
	desktop, guestA, guestB := "desk-1", "mobile-a", "mobile-b"
	db := newTestDB(t, desktop, seedRoster(desktop, guestA, guestB))
	g := db.Group("net", desktop)
	key := "net\x00" + desktop

	// guestA claims the desktop re-joined with a higher epoch, which
	// previously wiped every member except self and sender. The epoch
	// bump itself may propagate (documented roster management), but the
	// wipe path must stay desktop-gated.
	incoming := Roster{
		desktop: testMember(desktop, "desktop", 3),
		guestA:  testMember(guestA, "mobile", 1),
	}
	if _, err := g.Merge(guestA, incoming); err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	after := db.state.Groups[key]
	if len(after) != 3 || !after[guestB].Active() {
		t.Fatalf("roster wiped: %d members left, want 3 active with %s present", len(after), guestB)
	}
}

func TestMergeDesktopRejoinStillWipes(t *testing.T) {
	desktop, guestA, guestB := "desk-1", "mobile-a", "mobile-b"
	roster := seedRoster(desktop, guestA, guestB)
	db := newTestDB(t, desktop, roster)
	key := "net\x00" + desktop

	// The desktop itself reports a re-join with a higher self epoch.
	incoming := Roster{
		desktop: testMember(desktop, "desktop", 3),
	}
	g := db.Group("net", desktop)
	if _, err := g.Merge(desktop, incoming); err != nil {
		t.Fatalf("desktop merge failed: %v", err)
	}
	after := db.state.Groups[key]
	for _, id := range []string{guestA, guestB} {
		if _, ok := after[id]; ok {
			t.Fatalf("rejoin wipe kept removed member %q", id)
		}
	}
}

func TestMergeMobileCanUpdateOwnEntry(t *testing.T) {
	desktop, guestA := "desk-1", "mobile-a"
	db := newTestDB(t, desktop, seedRoster(desktop, guestA))
	g := db.Group("net", desktop)
	key := "net\x00" + desktop

	incoming := Roster{
		desktop: testMember(desktop, "desktop", 1),
		guestA: Member{
			ID: guestA, Role: "mobile", Pin: db.state.Groups[key][guestA].Pin,
			Epoch: 1, Change: 9, Name: "renamed",
		},
	}
	changed, err := g.Merge(guestA, incoming)
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if !changed {
		t.Fatal("mobile self-rename was rejected")
	}
	if got := db.state.Groups[key][guestA].Name; got != "renamed" {
		t.Fatalf("own-entry rename not applied, got %q", got)
	}
}

func TestMergeMobileEvictsThirdParty(t *testing.T) {
	desktop, guestA, guestB := "desk-1", "mobile-a", "mobile-b"
	roster := seedRoster(desktop, guestA, guestB)
	db := newTestDB(t, desktop, roster)
	g := db.Group("net", desktop)
	key := "net\x00" + desktop

	// Documented semantics ("every member manages the roster"): a phone
	// must be able to evict another member by advancing their epoch.
	outgoing := Roster{
		desktop: testMember(desktop, "desktop", 1),
		guestA:  testMember(guestA, "mobile", 1),
		guestB:  Member{ID: guestB, Role: "mobile", Pin: roster[guestB].Pin, Epoch: 2},
	}
	changed, err := g.Merge(guestA, outgoing)
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if !changed || db.state.Groups[key][guestB].Epoch != 2 {
		t.Fatal("mobile eviction did not propagate")
	}
}

func TestMergeDesktopCanAdvanceThirdPartyEpoch(t *testing.T) {
	desktop, guestB := "desk-1", "mobile-b"
	roster := seedRoster(desktop, "mobile-a", guestB)
	db := newTestDB(t, desktop, roster)
	g := db.Group("net", desktop)
	key := "net\x00" + desktop

	incoming := Roster{
		desktop: testMember(desktop, "desktop", 1),
		guestB:  Member{ID: guestB, Role: "mobile", Pin: roster[guestB].Pin, Epoch: 2},
	}
	changed, err := g.Merge(desktop, incoming)
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if !changed || db.state.Groups[key][guestB].Epoch != 2 {
		t.Fatal("desktop must retain full roster authority")
	}
}
