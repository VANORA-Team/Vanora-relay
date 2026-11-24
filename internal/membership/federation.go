package membership

import (
	"context"
	"sync"
	"time"
)

// Sites checks relay entitlement with every configured Vanora site. An account
// exists on one site only, and the other sites answer "not entitled" for it, so
// a check succeeds when any site grants the account. Queries run concurrently
// and share the caller's deadline, which keeps a cross-site account on the same
// latency budget as a single-site one.
type Sites []*Client

// Check returns the latest entitlement end granted by any configured site.
//
// A zero time with a nil error means every configured site definitively
// reported no entitlement. Any other error means no site granted access and at
// least one site could not answer, so the caller must treat the identity as
// unentitled.
func (s Sites) Check(ctx context.Context, issuer, subject string) (time.Time, error) {
	var zero time.Time
	switch len(s) {
	case 0:
		return zero, ErrNotConfigured
	case 1:
		return s[0].Check(ctx, issuer, subject)
	}
	type result struct {
		until time.Time
		err   error
	}
	results := make([]result, len(s))
	var wg sync.WaitGroup
	for i, client := range s {
		wg.Add(1)
		go func(i int, client *Client) {
			defer wg.Done()
			results[i].until, results[i].err = client.Check(ctx, issuer, subject)
		}(i, client)
	}
	wg.Wait()

	var latest time.Time
	var firstErr error
	for _, r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		if r.until.After(latest) {
			latest = r.until
		}
	}
	if !latest.IsZero() {
		return latest, nil
	}
	if firstErr != nil {
		return zero, firstErr
	}
	return zero, nil
}
