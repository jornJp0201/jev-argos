package receiver

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
)

func eventAt(level guardrail.Level, i int) Event {
	return Event{Signal: sig(fmt.Sprintf("10.0.%d.%d", i/256%256, i%256), "/m", 7, 1), Decision: guardrail.Decision{Level: level}}
}

// 通知が止まっていても、遮断の Lane は捨てられずに処理される。
func TestLanes_SlowLaneDoesNotBlockOthers(t *testing.T) {
	stuck := make(chan struct{})
	var blocked atomic.Int64
	srv := NewServer(buffer.NewMemoryBuffer(), classifier.NewDefault(), nil, Options{Logger: quietLogger, Lanes: []Lane{
		{Name: "block", MinLevel: guardrail.Level4, Emitter: EmitterFunc(func(context.Context, Event) { blocked.Add(1) })},
		{Name: "notify", MinLevel: guardrail.Level3, QueueSize: 1, Emitter: EmitterFunc(func(context.Context, Event) { <-stuck })},
	}})
	for i := range 2000 {
		level := guardrail.Level3
		if i%10 == 0 {
			level = guardrail.Level4
		}
		srv.dispatch(eventAt(level, i))
	}
	close(stuck)
	srv.Close()

	if got := blocked.Load(); got != 200 {
		t.Errorf("blocked = %d, want 200 (every Level 4)", got)
	}
	dropped := srv.DroppedByLane()
	if dropped["block"] != 0 || dropped["notify"] == 0 {
		t.Errorf("dropped = %v, want block=0 and notify>0", dropped)
	}
	if srv.Dropped() != dropped["notify"] {
		t.Errorf("Dropped = %d, want sum of lanes %v", srv.Dropped(), dropped)
	}
}

// MinLevel 未満のイベントはキューに積まない (Level 2・3 で遮断のキューが埋まらない)。
func TestLanes_MinLevel(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]guardrail.Level{}
	rec := func(name string) Emitter {
		return EmitterFunc(func(_ context.Context, e Event) {
			mu.Lock()
			defer mu.Unlock()
			got[name] = append(got[name], e.Decision.Level)
		})
	}
	srv := NewServer(buffer.NewMemoryBuffer(), classifier.NewDefault(), rec("default"), Options{Lanes: []Lane{
		{Name: "block", MinLevel: guardrail.Level4, Emitter: rec("block")},
		{Name: "notify", MinLevel: guardrail.Level3, Emitter: rec("notify")},
	}})
	for i, level := range []guardrail.Level{guardrail.Level2, guardrail.Level3, guardrail.Level4} {
		srv.dispatch(eventAt(level, i))
	}
	srv.Close()

	if len(got["default"]) != 3 || len(got["notify"]) != 2 || len(got["block"]) != 1 || got["block"][0] != guardrail.Level4 {
		t.Errorf("got = %v, want default=3, notify=2 (L3, L4), block=1 (L4)", got)
	}
}

// 攻撃中に通知先 (Slack 等) の応答が遅い場合に、Level 4 の自動遮断がどれだけ行われ、どれだけ遅れるかを測る。
// Level 3 / 4 が 9:1 で毎秒 5,000 件 (送信元はすべて異なる)、通知は 1 件 200ms かかるとする。
//
//	go test -run '^$' -bench SlowNotifier -benchtime 1x ./pkg/receiver/
func BenchmarkAttack_SlowNotifier(b *testing.B) {
	const (
		rate     = 5000
		duration = 2 * time.Second
		notifyIn = 200 * time.Millisecond
	)
	run := func(b *testing.B, lanes func(block, notify Emitter) (Emitter, []Lane)) {
		var mu sync.Mutex
		sentAt := map[string]time.Time{}
		var delays []time.Duration
		block := EmitterFunc(func(_ context.Context, e Event) {
			if e.Decision.Level != guardrail.Level4 {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			delays = append(delays, time.Since(sentAt[e.Signal.GetSignalId()]))
		})
		notify := EmitterFunc(func(_ context.Context, e Event) {
			if e.Decision.Level >= guardrail.Level3 {
				time.Sleep(notifyIn)
			}
		})
		for b.Loop() {
			mu.Lock()
			clear(sentAt)
			delays = delays[:0]
			mu.Unlock()
			emitter, ls := lanes(block, notify)
			srv := NewServer(buffer.NewMemoryBuffer(), classifier.NewDefault(), emitter, Options{Lanes: ls, Logger: quietLogger})
			total, level4 := int(rate*duration/time.Second), 0
			start := time.Now()
			for i := range total {
				// 一定の間隔で送る
				if d := time.Until(start.Add(time.Duration(i) * time.Second / rate)); d > 0 {
					time.Sleep(d)
				}
				level := guardrail.Level3
				if i%10 == 0 {
					level = guardrail.Level4
					level4++
				}
				e := eventAt(level, i)
				e.Signal.SignalId = fmt.Sprint(i)
				mu.Lock()
				sentAt[e.Signal.SignalId] = time.Now()
				mu.Unlock()
				srv.dispatch(e)
			}
			srv.Close()

			mu.Lock()
			b.ReportMetric(100*float64(len(delays))/float64(level4), "blocked%")
			b.ReportMetric(float64(percentile(delays, 0.99).Microseconds())/1000, "block-p99-ms")
			mu.Unlock()
		}
	}
	// 改善前: 1 つのキューを 4 つのワーカーが順に処理する
	b.Run("SharedQueue", func(b *testing.B) {
		run(b, func(block, notify Emitter) (Emitter, []Lane) { return Emitters{block, notify}, nil })
	})
	// 改善後: 処理ごとに Lane を分ける
	b.Run("Lanes", func(b *testing.B) {
		run(b, func(block, notify Emitter) (Emitter, []Lane) {
			return nil, []Lane{
				{Name: "block", Emitter: block, MinLevel: guardrail.Level4, Workers: 2},
				{Name: "notify", Emitter: notify, MinLevel: guardrail.Level3, Workers: 4},
			}
		})
	})
}

func percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	return s[int(p*float64(len(s)-1))]
}
