package buffer

import (
	"context"
	"sort"
	"sync"
	"time"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
)

const retention = RetentionSeconds * time.Second

// errorEvent は 1 件の異常応答。
type errorEvent struct {
	at     time.Time
	method string
	denied bool // PERMISSION_DENIED か
}

// MemoryBuffer はプロセス内メモリで集計する Buffer 実装。
// 複数 goroutine (並列 gRPC リクエスト) から安全に使える。
//
// ウィンドウの時刻はシグナルの timestamp ではなくサーバーでの受信時刻を使う
// (送信側の時計ずれや改ざんの影響を受けないため)。
type MemoryBuffer struct {
	mu        sync.RWMutex
	now       func() time.Time
	maxEvents int
	errors    map[string][]errorEvent // IP -> 異常応答 (受信時刻の昇順)
	latency   map[string]float64      // メソッド -> 平常時レイテンシの EWMA (ms)
}

var _ Buffer = (*MemoryBuffer)(nil)

// NewMemoryBuffer はシステム時計を使う MemoryBuffer を返す。
func NewMemoryBuffer() *MemoryBuffer {
	return newMemoryBuffer(time.Now, DefaultMaxEventsPerIP)
}

func newMemoryBuffer(now func() time.Time, maxEvents int) *MemoryBuffer {
	return &MemoryBuffer{
		now:       now,
		maxEvents: maxEvents,
		errors:    make(map[string][]errorEvent),
		latency:   make(map[string]float64),
	}
}

// RecordSignal はシグナルを記録する。
// 異常応答はウィンドウ集計用に保持し、正常応答はレイテンシの基準値の更新にだけ使う。
func (b *MemoryBuffer) RecordSignal(_ context.Context, signal *jevargosv1.SecuritySignal) error {
	ip := signal.GetUserContext().GetClientIp()
	method := signal.GetRequestContext().GetMethod()
	resp := signal.GetResponseContext()

	b.mu.Lock()
	defer b.mu.Unlock()

	if resp.GetStatusCode() == 0 {
		// 異常応答は平常時の基準を汚さないよう平均に含めない。
		latency := float64(resp.GetLatencyMs())
		if baseline, ok := b.latency[method]; ok {
			b.latency[method] = baseline + latencyAlpha*(latency-baseline)
		} else {
			b.latency[method] = latency
		}
		return nil
	}

	now := b.now()
	events := append(b.errors[ip], errorEvent{
		at:     now,
		method: method,
		denied: resp.GetStatusCode() == codePermissionDenied,
	})
	events = events[expiredPrefix(events, now.Add(-retention)):]
	if len(events) > b.maxEvents {
		events = events[len(events)-b.maxEvents:]
	}
	b.errors[ip] = events
	return nil
}

// GetStats は clientIP について直近 windowSeconds 秒の統計を返す。
func (b *MemoryBuffer) GetStats(_ context.Context, clientIP string, windowSeconds int) (WindowStats, error) {
	windowSeconds = clampWindow(windowSeconds)
	if windowSeconds == 0 {
		return WindowStats{}, nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	events := b.errors[clientIP]
	events = events[expiredPrefix(events, b.now().Add(-time.Duration(windowSeconds)*time.Second)):]

	denied := make(map[string]struct{})
	for _, e := range events {
		if e.denied {
			denied[e.method] = struct{}{}
		}
	}
	return WindowStats{
		WindowSeconds:       windowSeconds,
		ErrorCount:          len(events),
		UniqueDeniedMethods: len(denied),
	}, nil
}

// GetLatencySpikeRatio は method の平常時平均レイテンシに対する latencyMs の比率を返す。
func (b *MemoryBuffer) GetLatencySpikeRatio(_ context.Context, method string, latencyMs int64) (float64, error) {
	b.mu.RLock()
	baseline, ok := b.latency[method]
	b.mu.RUnlock()
	return spikeRatio(baseline, ok, latencyMs), nil
}

func spikeRatio(baseline float64, ok bool, latencyMs int64) float64 {
	if !ok || baseline <= 0 {
		return 1.0
	}
	return float64(latencyMs) / baseline
}

// Cleanup は保持期間 (5 分) を過ぎた異常応答を削除し、空になった IP をマップから取り除く。
func (b *MemoryBuffer) Cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := b.now().Add(-retention)
	for ip, events := range b.errors {
		events = events[expiredPrefix(events, cutoff):]
		if len(events) == 0 {
			delete(b.errors, ip)
			continue
		}
		// 先頭を切り詰めただけでは古い要素の領域が解放されないため、コピーし直す。
		b.errors[ip] = append([]errorEvent(nil), events...)
	}
}

// StartCleanup は interval ごとに Cleanup を実行する goroutine を起動する。
// ctx がキャンセルされると停止する。
func (b *MemoryBuffer) StartCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				b.Cleanup()
			}
		}
	}()
}

// expiredPrefix は時刻が cutoff 以前のイベント数を返す (events は昇順)。
func expiredPrefix(events []errorEvent, cutoff time.Time) int {
	return sort.Search(len(events), func(i int) bool { return events[i].at.After(cutoff) })
}
