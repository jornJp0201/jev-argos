package stream

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
)

// PublisherOptions は Publisher の設定。
type PublisherOptions struct {
	Stream          string        // ストリームのキー (既定 DefaultStream)
	MaxLen          int64         // ストリームに残すエントリ数の目安 (既定 DefaultMaxLen)
	BatchSize       int           // 1 回の往復で追加する件数の上限 (既定 200)
	FlushInterval   time.Duration // たまった判定を追加する間隔 (既定 20ms)
	QueueSize       int           // 追加待ちの上限。超えた分は捨てる (既定 10000)
	SummaryInterval time.Duration // Level 1 の集計を追加する間隔 (既定 1 秒)
	Logger          *slog.Logger
}

// Publisher は判定結果をストリームに追加する receiver.Emitter。判定サーバー側で使う。
//
//   - Level 2 以上: receiver.Lane の Emitter にする。追加待ちに積んですぐ戻り、別の goroutine がまとめて 1 回の往復で追加する
//   - Level 1: receiver.Options.Observer に Observe を渡す。件数だけを数え、SummaryInterval ごとに 1 件の summary として追加する
//
// 使い終わったら、判定の処理を止めた後に Close を呼ぶ (残りを追加してから停止する)。
type Publisher struct {
	client redis.UniversalClient
	opts   PublisherOptions

	mu      sync.RWMutex // closed と queue の close を保護する
	closed  bool
	queue   chan string
	done    chan struct{}
	dropped atomic.Uint64

	level1Count atomic.Uint64 // 件数 × countScale
	level1Score atomic.Uint64 // スコアの合計 × scoreScale
}

const (
	countScale = 1000
	scoreScale = 1e6
)

var _ receiver.Emitter = (*Publisher)(nil)

// NewPublisher は Publisher を返し、追加用の goroutine を起動する。
func NewPublisher(client redis.UniversalClient, opts PublisherOptions) *Publisher {
	if opts.Stream == "" {
		opts.Stream = DefaultStream
	}
	if opts.MaxLen <= 0 {
		opts.MaxLen = DefaultMaxLen
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 200
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 20 * time.Millisecond
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = 10000
	}
	if opts.SummaryInterval <= 0 {
		opts.SummaryInterval = time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	p := &Publisher{
		client: client,
		opts:   opts,
		queue:  make(chan string, opts.QueueSize),
		done:   make(chan struct{}),
	}
	go p.run()
	return p
}

// Emit は Level 2 以上の判定を追加待ちに積む。追加待ちが上限に達している場合は捨てる (Dropped で数える)。
func (p *Publisher) Emit(_ context.Context, e receiver.Event) {
	if e.Decision.Level < guardrail.Level2 {
		return
	}
	data, err := encodeEvent(e)
	if err != nil {
		p.opts.Logger.Error("encode event failed", "signal_id", e.Signal.GetSignalId(), "err", err)
		return
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		p.dropped.Add(1)
		return
	}
	select {
	case p.queue <- data:
	default:
		p.dropped.Add(1)
	}
}

// Observe は Level 1 の判定を数える。receiver.Options.Observer に渡す (すべての判定で同期的に呼ばれるため、数えるだけ)。
func (p *Publisher) Observe(e receiver.Event) {
	if e.Decision.Level >= guardrail.Level2 {
		return
	}
	w := buffer.SampleWeight(e.Signal)
	p.level1Count.Add(uint64(math.Round(w * countScale)))
	p.level1Score.Add(uint64(math.Round(e.Assessment.Score * w * scoreScale)))
}

// Dropped は追加待ちがあふれたため、追加に失敗したため、または Close 後のために捨てた判定の数を返す。
func (p *Publisher) Dropped() uint64 { return p.dropped.Load() }

// Close は新しい判定の受付を止め、追加待ちと Level 1 の集計を追加し終えるまで待つ。
func (p *Publisher) Close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.queue)
	}
	p.mu.Unlock()
	<-p.done
}

func (p *Publisher) run() {
	defer close(p.done)
	flush := time.NewTicker(p.opts.FlushInterval)
	defer flush.Stop()
	summary := time.NewTicker(p.opts.SummaryInterval)
	defer summary.Stop()
	buf := make([]string, 0, p.opts.BatchSize)
	var reportedDrops uint64
	for {
		select {
		case data, ok := <-p.queue:
			if !ok {
				p.write(buf)
				p.writeSummary()
				return
			}
			buf = append(buf, data)
			if len(buf) >= p.opts.BatchSize {
				p.write(buf)
				buf = buf[:0]
			}
		case <-flush.C:
			p.write(buf)
			buf = buf[:0]
		case <-summary.C:
			p.writeSummary()
			if d := p.dropped.Load(); d > reportedDrops {
				p.opts.Logger.Warn("stream publish failed or queue full; events dropped", "count", d-reportedDrops)
				reportedDrops = d
			}
		}
	}
}

// write は events をまとめて 1 回の往復で追加する。
func (p *Publisher) write(events []string) {
	if len(events) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		for _, data := range events {
			pipe.XAdd(ctx, p.xadd(kindEvent, data))
		}
		return nil
	})
	if err != nil {
		p.dropped.Add(uint64(len(events)))
		p.opts.Logger.Error("stream publish failed", "count", len(events), "err", err)
	}
}

func (p *Publisher) writeSummary() {
	count := p.level1Count.Swap(0)
	score := p.level1Score.Swap(0)
	if count == 0 {
		return
	}
	data, _ := json.Marshal(Summary{Count: float64(count) / countScale, ScoreSum: float64(score) / scoreScale})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.client.XAdd(ctx, p.xadd(kindSummary, string(data))).Err(); err != nil {
		p.opts.Logger.Error("stream publish summary failed", "err", err)
	}
}

func (p *Publisher) xadd(kind, data string) *redis.XAddArgs {
	return &redis.XAddArgs{
		Stream: p.opts.Stream,
		MaxLen: p.opts.MaxLen,
		Approx: true, // 正確に切り詰めるより速い (MAXLEN ~)
		Values: []any{fieldKind, kind, fieldData, data},
	}
}
