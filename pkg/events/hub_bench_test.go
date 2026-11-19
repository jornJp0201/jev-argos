package events

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
)

// PublishDecision は全シグナルの判定のたびに同期的に呼ばれる (receiver.Options.Observer)。
// 判定の応答時間に直接効くため、ダッシュボードの購読者がいない場合といる場合の両方を測る。
//
//	go test -run '^$' -bench . -benchmem ./pkg/events/

func benchPublish(b *testing.B, level guardrail.Level, subscribed bool) {
	h := NewHub(0, nil)
	if subscribed {
		_, updates, cancel := h.Subscribe()
		defer cancel()
		go func() {
			for range updates {
			}
		}()
	}
	e := event("bench", level)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		h.PublishDecision(e)
	}
}

func BenchmarkPublishDecision_Level1_NoSubscriber(b *testing.B) {
	benchPublish(b, guardrail.Level1, false)
}

func BenchmarkPublishDecision_Level1_Subscribed(b *testing.B) {
	benchPublish(b, guardrail.Level1, true)
}

func BenchmarkPublishDecision_Level3_NoSubscriber(b *testing.B) {
	benchPublish(b, guardrail.Level3, false)
}

func BenchmarkPublishDecision_Level3_Subscribed(b *testing.B) {
	benchPublish(b, guardrail.Level3, true)
}

// 並列の gRPC リクエストから同時に呼ばれる場合 (ロックの競合を含む)。
func BenchmarkPublishDecision_Level1_Parallel(b *testing.B) {
	h := NewHub(0, nil)
	e := event("bench", guardrail.Level1)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			h.PublishDecision(e)
		}
	})
}

// 判定 1 回 (バッファ → Jev → ガードレール) の中で、ダッシュボードへの配信が占める割合を見る。
func benchEvaluate(b *testing.B, observer func(receiver.Event)) {
	srv := receiver.NewServer(buffer.NewMemoryBuffer(), classifier.NewDefault(), receiver.EmitterFunc(func(context.Context, receiver.Event) {}),
		receiver.Options{Observer: observer, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	defer srv.Close()
	signal := event("bench", guardrail.Level1).Signal
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := srv.Evaluate(ctx, signal); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEvaluate_WithoutHub(b *testing.B) { benchEvaluate(b, nil) }

func BenchmarkEvaluate_WithHub(b *testing.B) { benchEvaluate(b, NewHub(0, nil).PublishDecision) }
