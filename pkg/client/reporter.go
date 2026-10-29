// Package client は Go の BFF / バックエンドに組み込む jev-argos のアダプター。
//
//	reporter, _ := client.NewReporter(conn, client.ReporterOptions{})        // 送信 (非同期)
//	blocklist := client.NewBlocklistWatcher(ctx, conn, nil)                  // 遮断リストの購読 (任意)
//
//	// gRPC サーバー
//	grpc.NewServer(grpc.ChainUnaryInterceptor(client.UnaryServerInterceptor(reporter, client.Options{SourceService: "main-bff", Blocklist: blocklist})))
//	// net/http
//	http.ListenAndServe(":8080", client.Middleware(reporter, client.Options{SourceService: "main-bff", Blocklist: blocklist})(mux))
//
// conn はコントロールサーバー (jev-argos-server) への *grpc.ClientConn。
// 送信はすべてバックグラウンドで行い、失敗してもアプリの処理には影響しない (Fire-and-Forget)。
package client

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
)

// ReporterOptions は Reporter の設定。
type ReporterOptions struct {
	// Timeout は 1 回の送信のタイムアウト (既定 500ms)。
	Timeout time.Duration
	// QueueSize は送信待ちの上限。超えた分は破棄する (アプリのメモリを守るため。既定 10000)。
	QueueSize int
	// Workers は 1 件ずつ送る場合の並列数 (既定 4)。
	Workers int

	// Batch を true にすると、設計書 4 章 Phase 2 のバッチ送信を行う:
	// BatchSize 件たまるか FlushInterval が経過するたびに StreamSignals でまとめて送る。
	// 送信回数が減るため高トラフィック時に向くが、OnResponse はバッチ単位
	// (immediate_action_level はバッチ内の最大値) になる。遮断には BlocklistWatcher を使うこと。
	Batch         bool
	BatchSize     int           // 既定 50
	FlushInterval time.Duration // 既定 100ms

	// OnResponse はサーバーの応答を受け取る (例: immediate_action_level が 4 なら遮断)。
	// バッチ送信ではバッチの最後のシグナルとともに呼ばれる。
	OnResponse func(*jevargosv1.ReportResponse, *jevargosv1.SecuritySignal)
	// OnError は送信の失敗を受け取る (ログやメトリクス用)。
	OnError func(error)
	Logger  *slog.Logger
}

// Stats は送信の状況。
type Stats struct {
	Sent, Failed, Dropped uint64
}

// Reporter はシグナルをコントロールサーバーへ非同期に送る。
type Reporter struct {
	client  jevargosv1.SignalServiceClient
	opts    ReporterOptions
	queue   chan *jevargosv1.SecuritySignal
	wg      sync.WaitGroup
	closed  atomic.Bool
	mu      sync.RWMutex // queue の close と送信を排他する
	sent    atomic.Uint64
	failed  atomic.Uint64
	dropped atomic.Uint64
}

// NewReporter は Reporter を作り、送信用の goroutine を起動する。使い終わったら Close を呼ぶこと。
func NewReporter(conn grpc.ClientConnInterface, opts ReporterOptions) *Reporter {
	if opts.Timeout <= 0 {
		opts.Timeout = 500 * time.Millisecond
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = 10000
	}
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 50
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 100 * time.Millisecond
	}
	r := &Reporter{
		client: jevargosv1.NewSignalServiceClient(conn),
		opts:   opts,
		queue:  make(chan *jevargosv1.SecuritySignal, opts.QueueSize),
	}
	if opts.Batch {
		r.wg.Add(1)
		go r.runBatch()
	} else {
		for range opts.Workers {
			r.wg.Add(1)
			go r.runSingle()
		}
	}
	return r
}

// Report はシグナルを送信待ちに入れてすぐに戻る。待ちが満杯なら破棄する。
func (r *Reporter) Report(s *jevargosv1.SecuritySignal) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed.Load() {
		r.dropped.Add(1)
		return
	}
	select {
	case r.queue <- s:
	default:
		r.dropped.Add(1)
	}
}

// Stats は送信の状況を返す。
func (r *Reporter) Stats() Stats {
	return Stats{Sent: r.sent.Load(), Failed: r.failed.Load(), Dropped: r.dropped.Load()}
}

// Close は新しい送信を止め、送信待ちを送り終えるまで待つ (ctx の期限まで)。
func (r *Reporter) Close(ctx context.Context) error {
	r.mu.Lock()
	if !r.closed.Swap(true) {
		close(r.queue)
	}
	r.mu.Unlock()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Reporter) runSingle() {
	defer r.wg.Done()
	for s := range r.queue {
		ctx, cancel := context.WithTimeout(context.Background(), r.opts.Timeout)
		resp, err := r.client.ReportSignal(ctx, s)
		cancel()
		r.done(resp, s, err, 1)
	}
}

func (r *Reporter) runBatch() {
	defer r.wg.Done()
	batch := make([]*jevargosv1.SecuritySignal, 0, r.opts.BatchSize)
	ticker := time.NewTicker(r.opts.FlushInterval)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		resp, err := r.sendBatch(batch)
		r.done(resp, batch[len(batch)-1], err, len(batch))
		batch = batch[:0]
	}
	for {
		select {
		case s, ok := <-r.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, s)
			if len(batch) >= r.opts.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (r *Reporter) sendBatch(batch []*jevargosv1.SecuritySignal) (*jevargosv1.ReportResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.opts.Timeout*time.Duration(max(1, len(batch)/10)))
	defer cancel()
	stream, err := r.client.StreamSignals(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range batch {
		if err := stream.Send(s); err != nil {
			return nil, err
		}
	}
	return stream.CloseAndRecv()
}

func (r *Reporter) done(resp *jevargosv1.ReportResponse, last *jevargosv1.SecuritySignal, err error, n int) {
	if err != nil {
		r.failed.Add(uint64(n))
		if r.opts.OnError != nil {
			safely(func() { r.opts.OnError(err) })
		}
		return
	}
	r.sent.Add(uint64(n))
	if r.opts.OnResponse != nil {
		safely(func() { r.opts.OnResponse(resp, last) })
	}
}

// safely は利用側のコールバックの panic がアダプターを止めないようにする。
func safely(fn func()) {
	defer func() { _ = recover() }()
	fn()
}
