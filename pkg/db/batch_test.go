package db

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jornJp0201/jev-argos/pkg/approval"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
)

// fakeBatchStore はまとめて保存された判定ログを記録する BatchStore / AnalysisStore。
type fakeBatchStore struct {
	mu       sync.Mutex
	batches  [][]string // 保存された signal_id (保存 1 回ごと)
	saved    map[string]bool
	analyzed map[string]bool // SaveAnalysis の時点で判定ログが保存済みだったか
	block    chan struct{}   // nil でなければ、閉じられるまで SaveDecisions を止める
	entered  chan struct{}
}

func newFakeBatchStore() *fakeBatchStore {
	return &fakeBatchStore{saved: map[string]bool{}, analyzed: map[string]bool{}}
}

func (f *fakeBatchStore) SaveDecision(ctx context.Context, log DecisionLog) error {
	return f.SaveDecisions(ctx, []DecisionLog{log})
}

func (f *fakeBatchStore) SaveDecisions(_ context.Context, logs []DecisionLog) error {
	if f.block != nil {
		f.entered <- struct{}{}
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []string
	for _, l := range logs {
		ids = append(ids, l.SignalID)
		f.saved[l.SignalID] = true
	}
	f.batches = append(f.batches, ids)
	return nil
}

func (f *fakeBatchStore) SaveAnalysis(_ context.Context, signalID string, _ approval.Analysis) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.analyzed[signalID] = f.saved[signalID]
	return nil
}

func (f *fakeBatchStore) batchSizes() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	var sizes []int
	for _, b := range f.batches {
		sizes = append(sizes, len(b))
	}
	return sizes
}

func logOf(id string) DecisionLog { return DecisionLog{SignalID: id, Level: guardrail.Level3} }

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestBatchWriter_BatchesByCount(t *testing.T) {
	f := newFakeBatchStore()
	w := NewBatchWriter(f, f, BatchOptions{MaxBatch: 3, FlushInterval: time.Hour, Logger: quiet})
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		w.SaveDecision(context.Background(), logOf(id))
	}
	waitFor(t, func() bool { return len(f.batchSizes()) == 2 })
	w.Close() // 残りを保存してから止まる
	if got := f.batchSizes(); len(got) != 3 || got[0] != 3 || got[1] != 3 || got[2] != 1 {
		t.Errorf("batches = %v, want [3 3 1]", got)
	}
}

func TestBatchWriter_FlushesOnInterval(t *testing.T) {
	f := newFakeBatchStore()
	w := NewBatchWriter(f, f, BatchOptions{FlushInterval: 20 * time.Millisecond, Logger: quiet})
	defer w.Close()
	w.SaveDecision(context.Background(), logOf("a"))
	w.SaveDecision(context.Background(), logOf("b"))
	waitFor(t, func() bool { got := f.batchSizes(); return len(got) == 1 && got[0] == 2 })
}

// LLM 分析は判定ログの行を更新するため、保存待ちの判定ログを先に保存する。
func TestBatchWriter_SaveAnalysisAfterPendingDecisions(t *testing.T) {
	f := newFakeBatchStore()
	w := NewBatchWriter(f, f, BatchOptions{FlushInterval: time.Hour, Logger: quiet})
	defer w.Close()
	ctx := context.Background()
	w.SaveDecision(ctx, logOf("sig-1"))
	if err := w.SaveAnalysis(ctx, "sig-1", approval.Analysis{Status: "done"}); err != nil {
		t.Fatal(err)
	}
	if !f.analyzed["sig-1"] {
		t.Error("analysis was saved before its decision log")
	}
}

func TestBatchWriter_DropsWhenQueueFull(t *testing.T) {
	f := newFakeBatchStore()
	f.block, f.entered = make(chan struct{}), make(chan struct{}, 1)
	w := NewBatchWriter(f, f, BatchOptions{MaxBatch: 1, QueueSize: 1, Logger: quiet})
	ctx := context.Background()

	w.SaveDecision(ctx, logOf("a")) // 保存中のまま止まる
	<-f.entered
	w.SaveDecision(ctx, logOf("b")) // 保存待ちに入る
	w.SaveDecision(ctx, logOf("c")) // あふれる
	if got := w.Dropped(); got != 1 {
		t.Errorf("dropped = %d, want 1", got)
	}
	close(f.block)
	w.Close()
	if got := f.batchSizes(); len(got) != 2 {
		t.Errorf("batches = %v, want a and b saved", got)
	}

	w.SaveDecision(ctx, logOf("d")) // Close 後は捨てる (panic しない)
	if got := w.Dropped(); got != 2 {
		t.Errorf("dropped after close = %d, want 2", got)
	}
}

// batched は BatchWriter を通して保存し、履歴を読む前に保存待ちを保存する (共通テスト用)。
type batched struct {
	*BatchWriter
	history HistoryProvider
}

func (b batched) RecentByIP(ctx context.Context, clientIP string, limit int) ([]HistoryEntry, error) {
	b.Flush(ctx)
	return b.history.RecentByIP(ctx, clientIP, limit)
}

// まとめて保存しても、重複の除外と受け取った順序 (received_at) は 1 件ずつ保存したときと同じ。
func TestSQLiteStore_Batched(t *testing.T) {
	s, err := OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "jev.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w := NewBatchWriter(s, s, BatchOptions{FlushInterval: time.Hour, Logger: quiet})
	defer w.Close()
	runHistoryContract(t, batched{w, s})
}
