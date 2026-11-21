package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// ErrChallengeInvalid is returned for unknown, expired or already consumed
// challenges. The single error avoids telling callers which of those applies.
var ErrChallengeInvalid = errors.New("identity: challenge invalid or expired")

// maxOutstandingChallenges bounds memory used by unauthenticated challenge
// requests. The oldest entries are evicted first.
const maxOutstandingChallenges = 4096

// challenge is one in-flight OIDC login plus proof-of-possession request. A
// challenge is single use and expires after a short lifetime.
type challenge struct {
	id           string
	nonce        string
	state        string
	codeVerifier string
	purpose      string
	redirectURI  string
	publicKey    ed25519.PublicKey
	expires      time.Time
}

// challengeStore is a bounded, expiry-aware, goroutine-safe challenge set.
type challengeStore struct {
	mu    sync.Mutex
	items map[string]*challenge
	order []string
	max   int
}

func newChallengeStore(max int) *challengeStore {
	if max <= 0 {
		max = maxOutstandingChallenges
	}
	return &challengeStore{
		items: make(map[string]*challenge, max/8+1),
		max:   max,
	}
}

func (s *challengeStore) add(c *challenge, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	for len(s.items) >= s.max {
		id, ok := s.popOldestLocked()
		if !ok {
			break
		}
		delete(s.items, id)
	}
	s.items[c.id] = c
	s.order = append(s.order, c.id)
}

// get returns a live challenge without consuming it. Callers must still call
// take to consume it before acting on the result.
func (s *challengeStore) get(id string, now time.Time) (*challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.items[id]
	if !ok || !c.expires.After(now) {
		return nil, ErrChallengeInvalid
	}
	return c, nil
}

// take atomically consumes a live challenge. A second take of the same id
// always fails, which makes replay of an enrollment request useless.
func (s *challengeStore) take(id string, now time.Time) (*challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.items[id]
	if !ok {
		return nil, ErrChallengeInvalid
	}
	delete(s.items, id)
	if !c.expires.After(now) {
		return nil, ErrChallengeInvalid
	}
	return c, nil
}

func (s *challengeStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

func (s *challengeStore) purgeExpiredLocked(now time.Time) {
	for id, c := range s.items {
		if !c.expires.After(now) {
			delete(s.items, id)
		}
	}
}

func (s *challengeStore) popOldestLocked() (string, bool) {
	for len(s.order) > 0 {
		id := s.order[0]
		s.order = s.order[1:]
		if _, ok := s.items[id]; ok {
			return id, true
		}
	}
	return "", false
}

func newSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
