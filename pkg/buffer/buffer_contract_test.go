package buffer

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
)

// Buffer 実装が共通で満たすべき振る舞いのテスト。各実装のテストから runContractTests を呼ぶ。

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// bufferFactory は時計と保持上限を指定して空の Buffer を作る。
type bufferFactory func(t *testing.T, now func() time.Time, maxEvents int) Buffer

const (
	codeOK       = 0
	codeInternal = 13
	codeDenied   = 7
)

func signal(ip, method string, status int32, latencyMs int64) *jevargosv1.SecuritySignal {
	return &jevargosv1.SecuritySignal{
		UserContext:     &jevargosv1.UserContext{ClientIp: ip},
		RequestContext:  &jevargosv1.RequestContext{Method: method},
		ResponseContext: &jevargosv1.ResponseContext{StatusCode: status, LatencyMs: latencyMs},
	}
}

func record(t *testing.T, b Buffer, s *jevargosv1.SecuritySignal) {
	t.Helper()
	if err := b.RecordSignal(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

func stats(t *testing.T, b Buffer, ip string, window int) WindowStats {
	t.Helper()
	s, err := b.GetStats(context.Background(), ip, window)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ratio(t *testing.T, b Buffer, method string, latencyMs int64) float64 {
	t.Helper()
	r, err := b.GetLatencySpikeRatio(context.Background(), method, latencyMs)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func runContractTests(t *testing.T, newBuffer bufferFactory) {
	t.Run("ErrorCount1m", func(t *testing.T) {
		clk := newFakeClock()
		b := newBuffer(t, clk.now, DefaultMaxEventsPerIP)

		record(t, b, signal("1.1.1.1", "/a", codeInternal, 10))
		clk.advance(30 * time.Second)
		record(t, b, signal("1.1.1.1", "/a", codeOK, 10)) // 正常応答は数えない
		record(t, b, signal("1.1.1.1", "/a", codeDenied, 10))
		record(t, b, signal("2.2.2.2", "/a", codeInternal, 10)) // 別 IP

		if got := stats(t, b, "1.1.1.1", 60).ErrorCount; got != 2 {
			t.Errorf("ErrorCount = %d, want 2", got)
		}
		if got := stats(t, b, "2.2.2.2", 60).ErrorCount; got != 1 {
			t.Errorf("other IP ErrorCount = %d, want 1", got)
		}

		clk.advance(30 * time.Second) // 最初のエラーはちょうど 60 秒前 → 窓の外
		if got := stats(t, b, "1.1.1.1", 60).ErrorCount; got != 1 {
			t.Errorf("ErrorCount after expiry = %d, want 1", got)
		}
		if got := stats(t, b, "1.1.1.1", 300).ErrorCount; got != 2 {
			t.Errorf("5m ErrorCount = %d, want 2", got)
		}
	})

	t.Run("UniqueDeniedMethods5m", func(t *testing.T) {
		clk := newFakeClock()
		b := newBuffer(t, clk.now, DefaultMaxEventsPerIP)

		record(t, b, signal("1.1.1.1", "/a", codeDenied, 10))
		clk.advance(4 * time.Minute)
		record(t, b, signal("1.1.1.1", "/b", codeDenied, 10))
		record(t, b, signal("1.1.1.1", "/b", codeDenied, 10))   // 同一メソッドは 1 件
		record(t, b, signal("1.1.1.1", "/c", codeInternal, 10)) // DENIED 以外は数えない

		if got := stats(t, b, "1.1.1.1", 300).UniqueDeniedMethods; got != 2 {
			t.Errorf("UniqueDeniedMethods = %d, want 2", got)
		}
		if got := stats(t, b, "1.1.1.1", 60).UniqueDeniedMethods; got != 1 {
			t.Errorf("1m UniqueDeniedMethods = %d, want 1", got)
		}

		clk.advance(61 * time.Second) // /a が 300 秒窓から外れる
		if got := stats(t, b, "1.1.1.1", 300).UniqueDeniedMethods; got != 1 {
			t.Errorf("UniqueDeniedMethods after expiry = %d, want 1", got)
		}
	})

	t.Run("WindowBounds", func(t *testing.T) {
		clk := newFakeClock()
		b := newBuffer(t, clk.now, DefaultMaxEventsPerIP)
		record(t, b, signal("1.1.1.1", "/a", codeDenied, 10))
		clk.advance(10 * time.Second)

		tests := []struct {
			window, wantWindow, wantErrors int
		}{
			{0, 0, 0},
			{-5, 0, 0},
			{10, 10, 0},
			{11, 11, 1},
			{3600, RetentionSeconds, 1}, // 保持期間で頭打ち
		}
		for _, tt := range tests {
			got := stats(t, b, "1.1.1.1", tt.window)
			if got.WindowSeconds != tt.wantWindow || got.ErrorCount != tt.wantErrors {
				t.Errorf("GetStats(window=%d) = %+v; want WindowSeconds %d, ErrorCount %d",
					tt.window, got, tt.wantWindow, tt.wantErrors)
			}
		}
		if got := stats(t, b, "9.9.9.9", 60); got.ErrorCount != 0 || got.UniqueDeniedMethods != 0 {
			t.Errorf("unknown IP = %+v, want zero counts", got)
		}
	})

	t.Run("LatencySpikeRatio", func(t *testing.T) {
		b := newBuffer(t, newFakeClock().now, DefaultMaxEventsPerIP)

		if got := ratio(t, b, "/a", 500); got != 1 {
			t.Errorf("ratio without baseline = %v, want 1", got)
		}
		record(t, b, signal("1.1.1.1", "/a", codeOK, 100))
		record(t, b, signal("1.1.1.1", "/a", codeInternal, 9999)) // 異常応答は基準に含めない
		if got := ratio(t, b, "/a", 500); got != 5 {
			t.Errorf("ratio = %v, want 5", got)
		}
		record(t, b, signal("1.1.1.1", "/a", codeOK, 200)) // EWMA: 100 + 0.1*(200-100) = 110
		if got := ratio(t, b, "/a", 220); got != 2 {
			t.Errorf("ratio after EWMA update = %v, want 2", got)
		}
		if got := ratio(t, b, "/b", 500); got != 1 {
			t.Errorf("other method ratio = %v, want 1", got)
		}
	})

	t.Run("Observe", func(t *testing.T) {
		clk := newFakeClock()
		b := newBuffer(t, clk.now, DefaultMaxEventsPerIP)
		record(t, b, signal("1.1.1.1", "/a", codeOK, 100))
		record(t, b, signal("1.1.1.1", "/a", codeDenied, 10))
		clk.advance(2 * time.Minute)

		got, err := Observe(context.Background(), b, signal("1.1.1.1", "/b", codeDenied, 300))
		if err != nil {
			t.Fatal(err)
		}
		want := Features{IPErrorCount1m: 1, UniqueDeniedMethods5m: 2, LatencySpikeRatio: 1}
		if got != want {
			t.Errorf("Observe = %+v, want %+v", got, want)
		}

		// 今回のシグナル自身は比率の基準に含まれない
		got, err = Observe(context.Background(), b, signal("1.1.1.1", "/a", codeOK, 300))
		if err != nil {
			t.Fatal(err)
		}
		if got.LatencySpikeRatio != 3 {
			t.Errorf("LatencySpikeRatio = %v, want 3", got.LatencySpikeRatio)
		}
	})

	t.Run("MaxEventsPerIP", func(t *testing.T) {
		b := newBuffer(t, newFakeClock().now, 3)
		for _, m := range []string{"/a", "/b", "/c", "/d", "/e"} {
			record(t, b, signal("1.1.1.1", m, codeDenied, 10))
		}
		got := stats(t, b, "1.1.1.1", 60)
		if got.ErrorCount != 3 || got.UniqueDeniedMethods != 3 {
			t.Errorf("got %+v, want 3 errors / 3 denied methods (oldest dropped)", got)
		}
	})

	t.Run("Concurrent", func(t *testing.T) {
		b := newBuffer(t, time.Now, DefaultMaxEventsPerIP)
		ctx := context.Background()

		var wg sync.WaitGroup
		for i := range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range 20 {
					method := fmt.Sprintf("/m%d", (i+j)%10)
					if _, err := Observe(ctx, b, signal("1.1.1.1", method, codeDenied, 10)); err != nil {
						t.Error(err)
						return
					}
					if _, err := Observe(ctx, b, signal("1.1.1.1", method, codeOK, 10)); err != nil {
						t.Error(err)
						return
					}
				}
			}()
		}
		wg.Wait()

		got := stats(t, b, "1.1.1.1", 300)
		if got.ErrorCount != 1000 || got.UniqueDeniedMethods != 10 {
			t.Errorf("got %+v, want 1000 errors and 10 denied methods", got)
		}
	})
}
