package db

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jornJp0201/jev-argos/pkg/approval"
)

// BatchStore はまとめて保存できる DecisionStore。PostgresStore と SQLiteStore が実装する。
type BatchStore interface {
	DecisionStore
	// SaveDecisions は判定ログをまとめて保存する。同じ signal_id が既にあれば、その行は何もしない。
	SaveDecisions(ctx context.Context, logs []DecisionLog) error
}

// BatchOptions は BatchWriter の設定。
type BatchOptions struct {
	MaxBatch      int           // 1 回にまとめる件数の上限 (既定 500)
	FlushInterval time.Duration // たまった判定ログを保存する間隔 (既定 500ms)
	QueueSize     int           // 保存待ちの上限。超えた分は捨てる (既定 10000)
	WriteTimeout  time.Duration // 1 回の保存の上限時間 (既定 5 秒)
	Logger        *slog.Logger  // nil なら slog.Default()
}

// BatchWriter は判定ログをまとめて保存する DecisionStore / AnalysisStore。
//
// 攻撃中は Level 2 以上の判定が続くため、1 件ごとに INSERT すると攻撃を受けるほど DB が重くなる。
// SaveDecision はキューに積んですぐに戻り、別の goroutine が MaxBatch 件たまるか FlushInterval が経つたびに
// 1 回の SQL でまとめて保存する。DB への書き込みの回数は、判定の件数ではなく時間に比例する。
//
// SaveAnalysis は判定ログの行を更新するため、キューに残っている判定ログを先に保存してから実行する。
// 使い終わったら、判定の処理を止めた後に Close を呼ぶ (残りを保存してから停止する)。
type BatchWriter struct {
	store    BatchStore
	analyses AnalysisStore
	opts     BatchOptions

	mu       sync.RWMutex // closed と queue の close を保護する
	closed   bool
	queue    chan DecisionLog
	flushReq chan chan struct{}
	done     chan struct{}
	dropped  atomic.Uint64
}

var (
	_ DecisionStore = (*BatchWriter)(nil)
	_ AnalysisStore = (*BatchWriter)(nil)
)

// NewBatchWriter は store にまとめて保存する BatchWriter を返し、保存用の goroutine を起動する。
// analyses は SaveAnalysis の保存先 (nil なら SaveAnalysis は何もしない)。
func NewBatchWriter(store BatchStore, analyses AnalysisStore, opts BatchOptions) *BatchWriter {
	if opts.MaxBatch <= 0 {
		opts.MaxBatch = 500
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 500 * time.Millisecond
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = 10000
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 5 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	w := &BatchWriter{
		store:    store,
		analyses: analyses,
		opts:     opts,
		queue:    make(chan DecisionLog, opts.QueueSize),
		flushReq: make(chan chan struct{}),
		done:     make(chan struct{}),
	}
	go w.run()
	return w
}

// SaveDecision は判定ログを保存待ちに積む。保存待ちが上限に達している場合は捨てる (Dropped で数える)。
func (w *BatchWriter) SaveDecision(_ context.Context, log DecisionLog) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		w.dropped.Add(1)
		return nil
	}
	select {
	case w.queue <- log:
	default:
		w.dropped.Add(1)
	}
	return nil
}

// SaveAnalysis は保存待ちの判定ログを保存してから、LLM 分析を保存する。
func (w *BatchWriter) SaveAnalysis(ctx context.Context, signalID string, a approval.Analysis) error {
	if w.analyses == nil {
		return nil
	}
	w.Flush(ctx)
	return w.analyses.SaveAnalysis(ctx, signalID, a)
}

// Flush は保存待ちの判定ログを保存し終えるまで待つ。
func (w *BatchWriter) Flush(ctx context.Context) {
	ack := make(chan struct{})
	select {
	case w.flushReq <- ack:
	case <-w.done:
		return
	case <-ctx.Done():
		return
	}
	select {
	case <-ack:
	case <-ctx.Done():
	}
}

// Dropped は保存待ちが上限に達していたため、または Close 後のために捨てた判定ログの数を返す。
func (w *BatchWriter) Dropped() uint64 {
	return w.dropped.Load()
}

// Close は新しい判定ログの受付を止め、保存待ちを保存し終えるまで待つ。
func (w *BatchWriter) Close() {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.queue)
	}
	w.mu.Unlock()
	<-w.done
}

func (w *BatchWriter) run() {
	defer close(w.done)
	ticker := time.NewTicker(w.opts.FlushInterval)
	defer ticker.Stop()
	buf := make([]DecisionLog, 0, w.opts.MaxBatch)
	var reportedDrops uint64
	add := func(log DecisionLog) {
		buf = append(buf, log)
		if len(buf) >= w.opts.MaxBatch {
			w.write(buf)
			buf = buf[:0]
		}
	}
	for {
		select {
		case log, ok := <-w.queue:
			if !ok {
				w.write(buf)
				return
			}
			add(log)
		case <-ticker.C:
			w.write(buf)
			buf = buf[:0]
			if d := w.dropped.Load(); d > reportedDrops {
				w.opts.Logger.Warn("decision log queue full; decisions dropped", "count", d-reportedDrops)
				reportedDrops = d
			}
		case ack := <-w.flushReq:
			for n := len(w.queue); n > 0; n-- {
				log, ok := <-w.queue
				if !ok {
					break
				}
				add(log)
			}
			w.write(buf)
			buf = buf[:0]
			close(ack)
		}
	}
}

func (w *BatchWriter) write(logs []DecisionLog) {
	if len(logs) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), w.opts.WriteTimeout)
	defer cancel()
	if err := w.store.SaveDecisions(ctx, logs); err != nil {
		w.opts.Logger.Error("persist decisions failed", "count", len(logs), "err", err)
	}
}
