package pairnet

import (
	"encoding/base64"
	"errors"
	"maps"
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

func TestMergeRejectsInvalidCountersAndUnknownTombstones(t *testing.T) {
	const self, sender = "self", "sender"
	for _, test := range []struct {
		name   string
		id     string
		epoch  uint64
		change uint64
	}{
		{name: "epoch jump", id: sender, epoch: 1003},
		{name: "epoch limit", id: sender, epoch: epochLimit - 1},
		{name: "change jump", id: sender, epoch: 1, change: 1001},
		{name: "change limit", id: sender, epoch: 1, change: epochLimit - 2},
		{name: "unknown tombstone", id: "unknown", epoch: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := seedRoster(self, sender)
			db := newTestDB(t, self, before)
			group := db.Group("net", self)
			incoming := maps.Clone(before)
			member := testMember(test.id, "mobile", test.epoch)
			member.Change = test.change
			incoming[test.id] = member
			if changed, err := group.Merge(sender, incoming); changed || err == nil {
				t.Fatalf("Merge = %v, %v, want error without changes", changed, err)
			}
			if !maps.Equal(group.Snapshot(), before) {
				t.Fatal("rejected merge changed the roster")
			}
			if err := group.Remove(sender); err != nil || group.Allows(sender) {
				t.Fatalf("sender removal failed after rejected update: %v", err)
			}
		})
	}
}

func TestMergeValidatesBeforeDesktopRejoinWipesRoster(t *testing.T) {
	const self, sender, third = "self", "sender", "third"
	before := seedRoster(sender, self, third)
	group := newTestDB(t, self, before).Group("net", self)
	incoming := maps.Clone(before)
	incoming[self] = testMember(self, "mobile", 3)
	incoming[third] = testMember(third, "mobile", 1)
	altered := incoming[third]
	altered.Owner = "new owner"
	incoming[third] = altered
	if changed, err := group.Merge(sender, incoming); changed || err == nil || !maps.Equal(group.Snapshot(), before) {
		t.Fatalf("invalid rejoin = %v, %v, roster %v", changed, err, group.Snapshot())
	}
}

func TestMergeCounterTiesPreferSenderMetadata(t *testing.T) {
	const self, sender, third = "self", "sender", "third"
	before := seedRoster(self, sender, third)
	for _, id := range []string{sender, third} {
		member := before[id]
		member.Change = 7
		member.Name = "Zoe"
		member.Address = "address-z"
		before[id] = member
	}
	group := newTestDB(t, self, before).Group("net", self)
	incoming := maps.Clone(before)
	for _, id := range []string{sender, third} {
		member := incoming[id]
		member.Name = "Alice"
		member.Address = "address-a"
		incoming[id] = member
	}
	if changed, err := group.Merge(sender, incoming); !changed || err != nil {
		t.Fatalf("Merge = %v, %v, want sender metadata update", changed, err)
	}
	after := group.Snapshot()
	if after[sender] != incoming[sender] || after[third] != before[third] {
		t.Fatalf("unexpected metadata after merge: %v", after)
	}
}

func TestLocalMutationsGuardCounterOverflow(t *testing.T) {
	const self, peer = "self", "peer"
	for _, test := range []struct {
		name   string
		epoch  uint64
		change uint64
		mutate func(*Group, Member, Member) error
	}{
		{"remove epoch", epochLimit - 1, 0, func(group *Group, _, peer Member) error {
			return group.Remove(peer.ID)
		}},
		{"admit epoch", epochLimit - 2, 0, func(group *Group, local, peer Member) error {
			return group.Admit(local, peer, true)
		}},
		{"admit change", 1, epochLimit - 1, func(group *Group, local, peer Member) error {
			peer.Name = "new name"
			return group.Admit(local, peer, false)
		}},
		{"update self change", 1, epochLimit - 1, func(group *Group, local, _ Member) error {
			local.Name = "new name"
			return group.UpdateSelf(local)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := testMember(self, "desktop", 1)
			local.Change = epochLimit - 1
			member := testMember(peer, "mobile", test.epoch)
			member.Change = test.change
			before := Roster{self: local, peer: member}
			group := newTestDB(t, self, before).Group("net", self)
			if err := test.mutate(group, local, member); !errors.Is(err, errNetworkCounterLimit) {
				t.Fatalf("%s returned %v, want counter limit error", test.name, err)
			}
			if !maps.Equal(group.Snapshot(), before) {
				t.Fatal("rejected mutation changed the roster")
			}
		})
	}
}

func TestReceiveRemovalRejectsCounterPoisoning(t *testing.T) {
	const self, sender = "self", "sender"
	before := seedRoster(self, sender)
	group := newTestDB(t, self, before).Group("net", self)
	for _, epoch := range []uint64{1002, epochLimit - 2} {
		if changed, err := group.ReceiveRemoval(sender, true, epoch); changed || !errors.Is(err, ErrRemoved) {
			t.Fatalf("ReceiveRemoval(%d) = %v, %v", epoch, changed, err)
		}
	}
	if !maps.Equal(group.Snapshot(), before) {
		t.Fatal("rejected removal changed the roster")
	}
	if changed, err := group.ReceiveRemoval(sender, true, 2); !changed || err != nil || group.Allows(self) {
		t.Fatalf("valid removal = %v, %v", changed, err)
	}
}

func TestProfilePersistsBeforeAnyGroupExists(t *testing.T) {
	store := &memStore{data: "legacy identity"}
	db, err := Open(store)
	if err != nil {
		t.Fatal(err)
	}
	profile := Profile{Service: "https://relay.example", Name: "saved relay"}
	if err := db.SetProfile(profile); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(store)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Profile(); got != profile || len(reopened.state.Groups) != 0 {
		t.Fatalf("reopened profile = %+v, groups = %v", got, reopened.state.Groups)
	}
	if got, err := reopened.Load(); err != nil || got != "legacy identity" {
		t.Fatalf("reopened identity = %q, %v", got, err)
	}
	if err := reopened.SetProfile(Profile{}); err != nil || store.data != "legacy identity" {
		t.Fatalf("clearing last profile kept unexpected on-disk state: %q, %v", store.data, err)
	}
}
