package cftunnel

import (
	"strconv"
	"testing"
	"time"
)

func TestHTTPLimitAdmitsNewClientAtCapacity(t *testing.T) {
	gate := httpLimit{entries: make(map[string]*httpLimitEntry)}
	now := time.Now()
	for index := range httpLimitMaxEntries {
		if retry := gate.check(strconv.Itoa(index), now, true, false); retry != 0 {
			t.Fatalf("new bucket %d was throttled: %s", index, retry)
		}
	}
	for range 64 {
		if retry := gate.check("0", now, false, false); retry != 0 {
			t.Fatalf("request burst was throttled early: %s", retry)
		}
	}
	if retry := gate.check("0", now, false, false); retry == 0 {
		t.Fatal("authenticated request exceeded the burst allowance")
	}
	if retry := gate.check("new", now, true, false); retry != 0 {
		t.Fatalf("new client was throttled by a full table: %s", retry)
	}
	if len(gate.entries) != httpLimitMaxEntries || gate.entries["1"] != nil || gate.entries["0"] == nil {
		t.Fatal("eviction did not preserve the recently used bucket")
	}
	if retry := gate.check("0", now.Add(time.Second), false, false); retry != 0 {
		t.Fatalf("authenticated request allowance did not refill: %s", retry)
	}
}
