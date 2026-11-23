package stream

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
)

// JEV_ARGOS_TEST_REDIS_URL を指定すると実際の Redis で測る (未指定なら miniredis)。
//
//	JEV_ARGOS_TEST_REDIS_URL=redis://localhost:6379/15 go test -run '^$' -bench . -benchtime 1x ./pkg/stream/
func newBenchRedis(b *testing.B) redis.UniversalClient {
	b.Helper()
	opts := &redis.Options{}
	if url := os.Getenv("JEV_ARGOS_TEST_REDIS_URL"); url != "" {
		var err error
		if opts, err = redis.ParseURL(url); err != nil {
			b.Fatal(err)
		}
	} else {
		opts.Addr = miniredis.RunT(b).Addr()
	}
	client := redis.NewClient(opts)
	b.Cleanup(func() { client.Close() })
	if err := client.FlushDB(context.Background()).Err(); err != nil {
		b.Fatal(err)
	}
	return client
}

// 判定サーバーが Level 2 以上の判定をストリームに追加できる速さ (Emit から Redis に追加し終えるまで)。
func BenchmarkPublisher(b *testing.B) {
	client := newBenchRedis(b)
	p := NewPublisher(client, PublisherOptions{Logger: quiet, QueueSize: 1 << 20})
	e := event("sig", guardrail.Level3)
	start := time.Now()
	for b.Loop() {
		p.Emit(context.Background(), e)
	}
	p.Close()
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "events/s")
	if p.Dropped() > 0 {
		b.Errorf("dropped %d", p.Dropped())
	}
}

// 攻撃中 (Level 3 が毎秒 2,500 件を 2 秒間、送信元はすべて別) に、通知が 1 件 10ms かかる場合に、
// 通知まで届いた割合を比べる。プロセス内のキュー (receiver.Lane) はあふれた分を捨て、Redis Streams は後から処理する。
//
//	go test -run '^$' -bench SlowNotifier -benchtime 1x ./pkg/stream/
func BenchmarkSlowNotifier(b *testing.B) {
	const (
		rate     = 2500
		duration = 2 * time.Second
		notifyIn = 10 * time.Millisecond
		workers  = 4
	)
	total := int(rate * duration / time.Second)
	send := func(emit func(receiver.Event)) {
		start := time.Now()
		for i := range total {
			if d := time.Until(start.Add(time.Duration(i) * time.Second / rate)); d > 0 {
				time.Sleep(d)
			}
			e := event(fmt.Sprint(i), guardrail.Level3)
			e.Signal.UserContext.ClientIp = fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)
			emit(e)
		}
	}
	report := func(b *testing.B, notified int64, start time.Time) {
		b.ReportMetric(100*float64(notified)/float64(total), "notified%")
		b.ReportMetric(time.Since(start).Seconds(), "drain-s")
	}

	// 改善前: receiver.Lane と同じ動き (キュー 1,024 件、満杯なら捨てる、ワーカー 4)
	b.Run("InProcessLane", func(b *testing.B) {
		for b.Loop() {
			var notified atomic.Int64
			queue := make(chan receiver.Event, 1024)
			var wg sync.WaitGroup
			for range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range queue {
						time.Sleep(notifyIn)
						notified.Add(1)
					}
				}()
			}
			start := time.Now()
			send(func(e receiver.Event) {
				select {
				case queue <- e:
				default: // あふれた分は捨てる
				}
			})
			close(queue)
			wg.Wait()
			report(b, notified.Load(), start)
		}
	})
	// 改善後: Redis Streams (同じ group の Consumer 4 つ)
	b.Run("RedisStream", func(b *testing.B) {
		for b.Loop() {
			client := newBenchRedis(b)
			var notified atomic.Int64
			notify := receiver.EmitterFunc(func(context.Context, receiver.Event) { time.Sleep(notifyIn); notified.Add(1) })
			ctx, cancel := context.WithCancel(context.Background())
			for i := range workers {
				c, _ := NewConsumer(client, ConsumerOptions{Group: "notify", Name: fmt.Sprint(i), Emitter: notify, BatchSize: 10, Block: 20 * time.Millisecond, Logger: quiet})
				go c.Run(ctx)
			}
			time.Sleep(100 * time.Millisecond) // group を作り終えるまで待つ
			p := NewPublisher(client, PublisherOptions{Logger: quiet})
			start := time.Now()
			send(func(e receiver.Event) { p.Emit(context.Background(), e) })
			p.Close()
			for notified.Load() < int64(total) && time.Since(start) < time.Minute {
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			report(b, notified.Load(), start)
		}
	})
}
