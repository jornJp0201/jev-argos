package stream

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func newRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })
	return mr, client
}

func event(id string, level guardrail.Level) receiver.Event {
	return receiver.Event{
		Signal: &jevargosv1.SecuritySignal{
			SignalId:        id,
			UserContext:     &jevargosv1.UserContext{ClientIp: "192.0.2.1"},
			RequestContext:  &jevargosv1.RequestContext{Method: "/a"},
			ResponseContext: &jevargosv1.ResponseContext{StatusCode: 7, LatencyMs: 12},
		},
		Features:   buffer.Features{IPErrorCount1m: 8, UniqueDeniedMethods5m: 3, LatencySpikeRatio: 1.5},
		Assessment: classifier.Assessment{Score: 2.7, Confidence: 0.6},
		Decision:   guardrail.Decision{Level: level, Downgraded: level == guardrail.Level3},
	}
}

// recorder は受け取った signal_id を記録する Emitter。
type recorder struct {
	mu     sync.Mutex
	ids    []string
	events []receiver.Event
	block  chan struct{} // nil でなければ、閉じられるまで Emit を止める
}

func (r *recorder) Emit(_ context.Context, e receiver.Event) {
	if r.block != nil {
		<-r.block
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, e.Signal.GetSignalId())
	r.events = append(r.events, e)
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ids)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// run は Consumer を起動し、テストの終わりに止めて戻るのを待つ。
func run(t *testing.T, client redis.UniversalClient, opts ConsumerOptions) {
	t.Helper()
	if opts.Name == "" {
		opts.Name = opts.Group
	}
	opts.Block, opts.Logger = 20*time.Millisecond, quiet
	c, err := NewConsumer(client, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	// group は起動後に追加された分から読むため、作られるまで待つ
	waitFor(t, "consumer group", func() bool {
		groups, _ := client.XInfoGroups(context.Background(), DefaultStream).Result()
		for _, g := range groups {
			if g.Name == opts.Group {
				return true
			}
		}
		return false
	})
}

func newPublisher(client redis.UniversalClient) *Publisher {
	return NewPublisher(client, PublisherOptions{FlushInterval: 5 * time.Millisecond, SummaryInterval: time.Hour, Logger: quiet})
}

// 判定サーバーで追加した判定が、そのままの内容で worker に届く。
func TestPublishAndConsume(t *testing.T) {
	_, client := newRedis(t)
	rec := &recorder{}
	run(t, client, ConsumerOptions{Group: "persist", Emitter: rec})

	p := newPublisher(client)
	want := event("sig-1", guardrail.Level3)
	p.Emit(context.Background(), want)
	p.Emit(context.Background(), event("l1", guardrail.Level1)) // Level 1 は追加しない (Observe で数える)
	p.Close()

	waitFor(t, "event", func() bool { return rec.count() == 1 })
	got := rec.events[0]
	if got.Signal.GetSignalId() != "sig-1" || got.Signal.GetUserContext().GetClientIp() != "192.0.2.1" ||
		got.Features != want.Features || got.Assessment != want.Assessment || got.Decision != want.Decision {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// 後続処理ごとの group はそれぞれ全件を受け取り、同じ group の Consumer 同士は重複せずに分け合う。
func TestGroups(t *testing.T) {
	_, client := newRedis(t)
	notify, persistA, persistB := &recorder{}, &recorder{}, &recorder{}
	run(t, client, ConsumerOptions{Group: "notify", Emitter: notify})
	run(t, client, ConsumerOptions{Group: "persist", Name: "a", Emitter: persistA, BatchSize: 5})
	run(t, client, ConsumerOptions{Group: "persist", Name: "b", Emitter: persistB, BatchSize: 5})

	p := newPublisher(client)
	const n = 200
	for i := range n {
		p.Emit(context.Background(), event(fmt.Sprint(i), guardrail.Level2))
	}
	p.Close()

	waitFor(t, "all events", func() bool { return notify.count() == n && persistA.count()+persistB.count() == n })
	seen := map[string]bool{}
	for _, id := range append(persistA.ids, persistB.ids...) {
		if seen[id] {
			t.Fatalf("signal %s was processed twice in one group", id)
		}
		seen[id] = true
	}
}

// 遅い後続処理があっても、他の group は止まらない。遅れた分は捨てられず、後から処理される。
func TestSlowGroupDoesNotBlockOthersAndKeepsBacklog(t *testing.T) {
	_, client := newRedis(t)
	slow, fast := &recorder{block: make(chan struct{})}, &recorder{}
	run(t, client, ConsumerOptions{Group: "notify", Emitter: slow})
	run(t, client, ConsumerOptions{Group: "persist", Emitter: fast})

	p := newPublisher(client)
	const n = 5000 // プロセス内のキュー (既定 1,024 件) よりずっと多い
	for i := range n {
		p.Emit(context.Background(), event(fmt.Sprint(i), guardrail.Level3))
	}
	p.Close()

	waitFor(t, "fast group", func() bool { return fast.count() == n })
	if slow.count() != 0 {
		t.Fatalf("slow group processed %d while blocked", slow.count())
	}
	close(slow.block)
	waitFor(t, "slow group to catch up", func() bool { return slow.count() == n })
}

// MinLevel 未満は渡さない。Flush は処理済みにする前に呼ぶ。
func TestConsumer_MinLevelAndFlushBeforeAck(t *testing.T) {
	_, client := newRedis(t)
	rec := &recorder{}
	var pendingAtFlush []int64
	var mu sync.Mutex
	run(t, client, ConsumerOptions{Group: "notify", Emitter: rec, MinLevel: guardrail.Level3, Flush: func(ctx context.Context) {
		p, _ := client.XPending(ctx, DefaultStream, "notify").Result()
		mu.Lock()
		pendingAtFlush = append(pendingAtFlush, p.Count)
		mu.Unlock()
	}})

	p := newPublisher(client)
	p.Emit(context.Background(), event("l2", guardrail.Level2))
	p.Emit(context.Background(), event("l3", guardrail.Level3))
	p.Close()

	waitFor(t, "level 3", func() bool { return rec.count() == 1 })
	if rec.ids[0] != "l3" {
		t.Errorf("got %v, want only l3", rec.ids)
	}
	waitFor(t, "ack", func() bool {
		p, _ := client.XPending(context.Background(), DefaultStream, "notify").Result()
		return p.Count == 0
	})
	mu.Lock()
	defer mu.Unlock()
	if len(pendingAtFlush) == 0 || pendingAtFlush[0] == 0 {
		t.Errorf("pending at flush = %v, want entries still pending (not acked yet)", pendingAtFlush)
	}
}

// 読んだまま処理済みにせずに落ちた Consumer のエントリは、他の Consumer が引き取って処理する。
func TestConsumer_ClaimsEntriesOfCrashedConsumer(t *testing.T) {
	_, client := newRedis(t)
	ctx := context.Background()
	if err := client.XGroupCreateMkStream(ctx, DefaultStream, "persist", "$").Err(); err != nil {
		t.Fatal(err)
	}
	p := newPublisher(client)
	p.Emit(ctx, event("orphan", guardrail.Level3))
	p.Close()
	// 落ちる Consumer: 読むだけで処理済みにしない
	if err := client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: "persist", Consumer: "crashed", Streams: []string{DefaultStream, ">"}}).Err(); err != nil {
		t.Fatal(err)
	}

	rec := &recorder{}
	run(t, client, ConsumerOptions{Group: "persist", Name: "alive", Emitter: rec, ClaimIdle: 30 * time.Millisecond})
	waitFor(t, "claimed entry", func() bool { return rec.count() == 1 })
	if rec.ids[0] != "orphan" {
		t.Errorf("got %v", rec.ids)
	}
}

// Level 1 は件数だけを数え、summary として追加する。Tail は全件を受け取る (ダッシュボード用)。
func TestTail_EventsAndSummaries(t *testing.T) {
	_, client := newRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var events []string
	var summaries []Summary
	done := make(chan struct{})
	go func() {
		Tail(ctx, client, "", Handlers{
			Event:   func(e receiver.Event) { mu.Lock(); events = append(events, e.Signal.GetSignalId()); mu.Unlock() },
			Summary: func(s Summary) { mu.Lock(); summaries = append(summaries, s); mu.Unlock() },
		}, nil)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond) // Tail は開始後に追加された分から読む

	p := newPublisher(client)
	sampled := event("l1-sampled", guardrail.Level1)
	sampled.Assessment.Score = 0.1
	sampled.Signal.SampleRate = 0.1 // 10 件ぶん
	p.Observe(sampled)
	p.Observe(event("l3", guardrail.Level3)) // Level 2 以上は数えない
	p.Emit(ctx, event("l3", guardrail.Level3))
	p.Close() // 残りの集計を追加する

	waitFor(t, "tail", func() bool { mu.Lock(); defer mu.Unlock(); return len(events) == 1 && len(summaries) == 1 })
	mu.Lock()
	if events[0] != "l3" || summaries[0].Count != 10 || summaries[0].ScoreSum != 1 {
		t.Errorf("events = %v, summaries = %+v", events, summaries)
	}
	mu.Unlock()
	cancel()
	<-done
}

// Redis に追加できなかった判定は捨てて数える (判定サーバーは止めない)。
func TestPublisher_CountsFailures(t *testing.T) {
	mr, client := newRedis(t)
	mr.Close()
	p := newPublisher(client)
	p.Emit(context.Background(), event("x", guardrail.Level3))
	p.Close()
	p.Emit(context.Background(), event("after-close", guardrail.Level3))
	if got := p.Dropped(); got != 2 {
		t.Errorf("dropped = %d, want 2", got)
	}
}
