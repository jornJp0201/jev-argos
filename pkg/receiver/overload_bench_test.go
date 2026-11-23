package receiver

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
)

// limitedBuffer は同時に slots 件まで、1 件 latency かかるバッファ (Redis の接続数と往復時間の模擬)。
type limitedBuffer struct {
	*buffer.MemoryBuffer
	sem     chan struct{}
	latency time.Duration
}

func (b *limitedBuffer) ObserveSignal(ctx context.Context, s *jevargosv1.SecuritySignal) (buffer.Features, error) {
	b.sem <- struct{}{}
	defer func() { <-b.sem }()
	time.Sleep(b.latency)
	return buffer.Observe(ctx, b.MemoryBuffer, s)
}

// 処理能力 (32 件 × 1ms = 毎秒 32,000 件) を超える正常なシグナル (毎秒 48,000 件) が 2 秒間届く中で、
// 攻撃者の権限エラー (毎秒 100 件) がどれだけの時間で判定されるかを測る。
//
//	go test -run '^$' -bench Overload -benchtime 1x ./pkg/receiver/
func BenchmarkOverload(b *testing.B) {
	const (
		okRate   = 48000
		duration = 2 * time.Second
		every    = 480 // okRate / 毎秒 100 件
	)
	run := func(b *testing.B, limits Limits) {
		for b.Loop() {
			buf := &limitedBuffer{MemoryBuffer: buffer.NewMemoryBuffer(), sem: make(chan struct{}, 32), latency: time.Millisecond}
			srv := NewServer(buf, classifier.NewDefault(), nil, Options{Logger: quietLogger, Limits: limits})
			var mu sync.Mutex
			var attack []time.Duration
			var wg sync.WaitGroup
			total := int(okRate * duration / time.Second)
			start := time.Now()
			for i := range total {
				if d := time.Until(start.Add(time.Duration(i) * time.Second / okRate)); d > 0 {
					time.Sleep(d)
				}
				s := sig(fmt.Sprintf("198.51.%d.%d", i>>8&255, i&255), "/shop.Shop/List", 0, 20)
				isAttack := i%every == 0
				if isAttack {
					s = sig("203.0.113.66", fmt.Sprintf("/admin.Admin/Op%d", i/every%6), 7, 20)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					t := time.Now()
					_, err := srv.Evaluate(context.Background(), s)
					if isAttack && err == nil {
						mu.Lock()
						attack = append(attack, time.Since(t))
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			srv.Close()
			st := srv.Stats()
			slices.Sort(attack)
			b.ReportMetric(100*float64(len(attack))/float64(total/every), "attack-accepted%")
			b.ReportMetric(float64(attack[len(attack)*99/100].Microseconds())/1000, "attack-p99-ms")
			b.ReportMetric(100*float64(st.OverloadedOK)/float64(total-total/every), "ok-rejected%")
		}
	}
	b.Run("NoLimit", func(b *testing.B) { run(b, Limits{}) })
	b.Run("MaxInFlight_NoPriority", func(b *testing.B) { run(b, Limits{MaxInFlight: 64, ShedRatio: 1}) }) // 正常な応答もエラーも同じに断る
	b.Run("MaxInFlight", func(b *testing.B) { run(b, Limits{MaxInFlight: 64}) })
}
