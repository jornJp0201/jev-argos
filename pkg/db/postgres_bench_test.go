package db

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jornJp0201/jev-argos/pkg/guardrail"
)

// 攻撃中 (Level 2 以上の判定が続く) に、判定ログ 1 件の保存にかかる時間と SQL の数を測る。
// JEV_ARGOS_TEST_POSTGRES_URL が未設定ならスキップする。
//
//	JEV_ARGOS_TEST_POSTGRES_URL=postgres://... go test -run '^$' -bench . -benchmem ./pkg/db/

// queryCounter は実行した SQL の数を数える pgx のトレーサー。
type queryCounter struct{ n atomic.Int64 }

func (q *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	q.n.Add(1)
	return ctx
}

func (q *queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func BenchmarkEmitter_Postgres(b *testing.B) {
	url := os.Getenv("JEV_ARGOS_TEST_POSTGRES_URL")
	if url == "" {
		b.Skip("JEV_ARGOS_TEST_POSTGRES_URL not set")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		b.Fatal(err)
	}
	qc := &queryCounter{}
	cfg.ConnConfig.Tracer = qc
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		b.Fatal(err)
	}
	defer pool.Close()
	store := NewPostgresStore(pool)
	if err := store.Migrate(ctx); err != nil {
		b.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE jev_decision_logs"); err != nil {
		b.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := NewBatchWriter(store, store, BatchOptions{Logger: logger, QueueSize: 1 << 20}) // 計測中に捨てないよう大きくする
	em := Emitter{Store: w, Logger: logger}
	i := 0
	qc.n.Store(0)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		i++
		em.Emit(ctx, event("bench-"+strconv.Itoa(i), guardrail.Level3))
	}
	w.Close() // 保存し終えるまでを含める
	if n := w.Dropped(); n > 0 {
		b.Fatalf("dropped %d decisions", n)
	}
	b.ReportMetric(float64(qc.n.Load())/float64(b.N), "queries/op")
}
