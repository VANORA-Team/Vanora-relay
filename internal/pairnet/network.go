package pairnet

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
)

type Store interface {
	Load() (string, error)
	Save(string) error
}

type Member struct {
	ID      string `json:"id"`
	Role    string `json:"role"`
	Pin     string `json:"pin"`
	Owner   string `json:"owner,omitempty"`
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
	Epoch   uint64 `json:"epoch"`
	Change  uint64 `json:"change,omitempty"`
}

func (m Member) Active() bool { return m.Epoch%2 == 1 }

func (m Member) valid() bool {
	pin, err := base64.RawURLEncoding.Strict().DecodeString(m.Pin)
	return err == nil && len(pin) == 32 && m.ID != "" && len(m.ID) <= 128 &&
		(m.Role == "desktop" || m.Role == "mobile") && len(m.Owner) <= 128 &&
		len(m.Name) <= 128 && len(m.Address) <= 256 && m.Epoch > 0 && m.Epoch < 1<<53 && m.Change < 1<<53
}

type Roster map[string]Member

func (r Roster) Members() []Member {
	var out = make([]Member, 0, len(r))
	for _, id := range slices.Sorted(maps.Keys(r)) {
		if member := r[id]; member.Active() {
			out = append(out, member)
		}
	}
	return out
}

type stored struct {
	Identity   string            `json:"identity_state"`
	Groups     map[string]Roster `json:"pairing_networks"`
	Connection Profile           `json:"last_connection,omitzero"`
}

type Profile struct {
	Service string `json:"service,omitempty"`
	Token   string `json:"token,omitempty"`
	Name    string `json:"name,omitempty"`
}

func (db *Database) Profile() Profile {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.state.Connection
}

func (db *Database) SetProfile(profile Profile) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.state.Connection == profile {
		return nil
	}
	next := db.state
	next.Connection = profile
	return db.write(next)
}

type Database struct {
	mu    sync.Mutex
	store Store
	state stored
}

func Open(store Store) (*Database, error) {
	if store == nil {
		return nil, errors.New("pairing network requires secure storage")
	}
	raw, err := store.Load()
	if err != nil {
		return nil, err
	}
	state := stored{Identity: raw}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &fields) == nil && fields["pairing_networks"] != nil {
		if err := json.Unmarshal([]byte(raw), &state); err != nil {
			return nil, err
		}
	}
	if state.Groups == nil {
		state.Groups = make(map[string]Roster)
	}
	return &Database{store: store, state: state}, nil
}

func (db *Database) Load() (string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.state.Identity, nil
}

func (db *Database) write(next stored) error {
	value := next.Identity
	if len(next.Groups) != 0 {
		raw, err := json.Marshal(next)
		if err != nil {
			return err
		}
		value = string(raw)
	}
	if err := db.store.Save(value); err != nil {
		return err
	}
	db.state = next
	return nil
}

func (db *Database) Save(value string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	next := db.state
	next.Identity = value
	return db.write(next)
}

func (db *Database) Reset(identity string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.write(stored{Identity: identity, Groups: make(map[string]Roster)})
}

type Group struct {
	db    *Database
	scope string
	self  string
}

func (db *Database) Group(scope, self string) *Group {
	return &Group{db, scope + "\x00" + self, self}
}

func (g *Group) Self() string { return g.self }

func (g *Group) Snapshot() Roster {
	g.db.mu.Lock()
	defer g.db.mu.Unlock()
	return maps.Clone(g.db.state.Groups[g.scope])
}

func (g *Group) Get(id string) (Member, bool) {
	g.db.mu.Lock()
	defer g.db.mu.Unlock()
	record, ok := g.db.state.Groups[g.scope][id]
	return record, ok
}

func (g *Group) Allows(id string) bool {
	g.db.mu.Lock()
	defer g.db.mu.Unlock()
	r := g.db.state.Groups[g.scope]
	return r[g.self].Active() && r[id].Active()
}

func (g *Group) GrantExpired(id string, localEpoch, peerEpoch uint64) bool {
	g.db.mu.Lock()
	defer g.db.mu.Unlock()
	r := g.db.state.Groups[g.scope]
	local, peer := r[g.self], r[id]
	return local.Epoch != 0 && local.Epoch != max(1, localEpoch) ||
		peer.Epoch != 0 && peer.Epoch != max(1, peerEpoch)
}

var ErrRemoved = errors.New("device removed from pairing network")

func (g *Group) update(fn func(Roster) error) (bool, error) {
	g.db.mu.Lock()
	defer g.db.mu.Unlock()
	before := g.db.state.Groups[g.scope]
	after := make(Roster, len(before)+2)
	maps.Copy(after, before)
	if err := fn(after); err != nil {
		return false, err
	}
	if maps.Equal(before, after) {
		return false, nil
	}
	if len(after) > 2048 || len(after.Members()) > 128 {
		return false, errors.New("pairing network is full")
	}
	next := g.db.state
	next.Groups = maps.Clone(next.Groups)
	next.Groups[g.scope] = after
	if err := g.db.write(next); err != nil {
		return false, err
	}
	return true, nil
}

func (g *Group) Admit(local, peer Member, invited bool) error {
	_, err := g.update(func(r Roster) error {
		if local.ID != g.self || peer.ID == local.ID || (local.Role == "mobile" && peer.Role == "mobile") {
			return errors.New("invalid pairing identities")
		}
		if self, ok := r[g.self]; ok && !self.Active() {
			if !invited {
				return ErrRemoved
			}
			clear(r)
			r[g.self] = self
		}
		for _, member := range []Member{local, peer} {
			old := r[member.ID]
			member.Epoch = old.Epoch
			member.Change = old.Change
			if !old.Active() {
				if old.Epoch != 0 && !invited {
					return ErrRemoved
				}
				member.Epoch++
			}
			if old.Epoch != 0 && (member.Pin != old.Pin || member.Role != old.Role || member.Owner != old.Owner) {
				return errors.New("pairing identity changed")
			}
			if member.Name == "" {
				member.Name = old.Name
			}
			if member.Address == "" {
				member.Address = old.Address
			}
			if !member.valid() {
				return errors.New("invalid pairing member")
			}
			if member != old {
				member.Change++
				r[member.ID] = member
			}
		}
		return nil
	})
	return err
}

func (g *Group) UpdateSelf(member Member) error {
	_, err := g.update(func(r Roster) error {
		if member.ID != g.self {
			return errors.New("invalid pairing identities")
		}
		old, ok := r[g.self]
		if !ok || !old.Active() {
			return nil
		}
		next := old
		if member.Name != "" {
			next.Name = member.Name
		}
		if member.Address != "" {
			next.Address = member.Address
		}
		if !next.valid() {
			return errors.New("invalid pairing member")
		}
		if next != old {
			next.Change++
			r[g.self] = next
		}
		return nil
	})
	return err
}

func (g *Group) Remove(ids ...string) error {
	_, err := g.update(func(r Roster) error {
		if !r[g.self].Active() {
			return ErrRemoved
		}
		for _, id := range ids {
			member, ok := r[id]
			if !ok {
				return errors.New("unknown network member")
			}
			if member.Active() {
				member.Epoch++
				r[id] = member
			}
		}
		return nil
	})
	return err
}

func (g *Group) Merge(sender string, incoming Roster) (bool, error) {
	return g.update(func(r Roster) error {
		if !r[g.self].Active() || !r[sender].Active() {
			return ErrRemoved
		}
		if incoming[sender].ID != sender || incoming[g.self].ID != g.self {
			return errors.New("missing authenticated network members")
		}
		if incoming[sender].Epoch < r[sender].Epoch {
			return nil
		}
		rejoining := incoming[g.self].Active() && incoming[g.self].Epoch > r[g.self].Epoch
		if rejoining {
			local, peer := r[g.self], r[sender]
			clear(r)
			r[g.self], r[sender] = local, peer
		}
		for id, next := range incoming {
			old := r[id]
			if id != next.ID || !next.valid() || (old.Epoch != 0 && (old.Pin != next.Pin || old.Owner != next.Owner || old.Role != next.Role)) {
				return errors.New("invalid pairing network update")
			}
			if next.Epoch > old.Epoch || next.Epoch == old.Epoch && (next.Change > old.Change ||
				next.Change == old.Change && strings.Compare(next.Name+"\x00"+next.Address, old.Name+"\x00"+old.Address) > 0) {
				r[id] = next
			}
		}
		return nil
	})
}

func (g *Group) ReceiveRemoval(sender string, own bool, epoch uint64) (bool, error) {
	return g.update(func(r Roster) error {
		if epoch == 0 || epoch%2 != 0 || epoch >= 1<<53 || !r[sender].Active() {
			return ErrRemoved
		}
		id := sender
		if own {
			id = g.self
		}
		member := r[id]
		if member.Epoch < epoch {
			member.Epoch = epoch
			r[id] = member
		}
		return nil
	})
}
