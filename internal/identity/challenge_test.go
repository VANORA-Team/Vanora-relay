package identity

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func testChallenge(id string, expires time.Time) *challenge {
	return &challenge{
		id:        id,
		nonce:     "nonce-" + id,
		state:     "state-" + id,
		purpose:   "enroll",
		publicKey: make(ed25519.PublicKey, ed25519.PublicKeySize),
		expires:   expires,
	}
}

func TestChallengeOneTimeAndExpiry(t *testing.T) {
	store := newChallengeStore(4)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	store.add(testChallenge("a", now.Add(time.Minute)), now)

	if _, err := store.get("a", now); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := store.get("a", now); err != nil {
		t.Fatalf("second get: %v", err)
	}
	if _, err := store.take("a", now); err != nil {
		t.Fatalf("take: %v", err)
	}
	if _, err := store.take("a", now); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("replayed take error = %v, want invalid", err)
	}

	store.add(testChallenge("b", now.Add(time.Minute)), now)
	if _, err := store.take("b", now.Add(time.Minute)); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("expired take error = %v, want invalid", err)
	}
	store.add(testChallenge("c", now.Add(time.Minute)), now.Add(2*time.Minute))
	if store.count() != 1 {
		t.Fatalf("expired entries were not purged: %d", store.count())
	}
}

func TestChallengeStoreBounded(t *testing.T) {
	const max = 8
	store := newChallengeStore(max)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	for i := range max * 3 {
		store.add(testChallenge(string(rune('a'+i)), now.Add(time.Minute)), now)
	}
	if got := store.count(); got != max {
		t.Fatalf("store holds %d challenges, want %d", got, max)
	}
	if _, err := store.get("a", now); !errors.Is(err, ErrChallengeInvalid) {
		t.Fatalf("oldest challenge was not evicted")
	}
}
