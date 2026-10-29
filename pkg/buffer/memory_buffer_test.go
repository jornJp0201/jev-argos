package buffer

import (
	"context"
	"testing"
	"time"
)

func TestMemoryBuffer(t *testing.T) {
	runContractTests(t, func(_ *testing.T, now func() time.Time, maxEvents int) Buffer {
		return newMemoryBuffer(now, maxEvents)
	})
}

func TestMemoryBuffer_Cleanup(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBuffer(clk.now, DefaultMaxEventsPerIP)

	record(t, b, signal("1.1.1.1", "/a", codeDenied, 10))
	clk.advance(3 * time.Minute)
	record(t, b, signal("2.2.2.2", "/a", codeDenied, 10))
	clk.advance(2 * time.Minute) // 1.1.1.1 のエラーはちょうど 5 分前

	b.Cleanup()
	if _, ok := b.errors["1.1.1.1"]; ok {
		t.Error("1.1.1.1 should be removed after 5 minutes")
	}
	if got := len(b.errors["2.2.2.2"]); got != 1 {
		t.Errorf("2.2.2.2 events = %d, want 1", got)
	}
}

func TestMemoryBuffer_StartCleanup(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBuffer(clk.now, DefaultMaxEventsPerIP)
	record(t, b, signal("1.1.1.1", "/a", codeDenied, 10))
	clk.advance(retention)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.StartCleanup(ctx, time.Millisecond)

	deadline := time.Now().Add(time.Second)
	for {
		b.mu.RLock()
		n := len(b.errors)
		b.mu.RUnlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("StartCleanup did not remove expired IP within 1s")
		}
		time.Sleep(time.Millisecond)
	}
}
