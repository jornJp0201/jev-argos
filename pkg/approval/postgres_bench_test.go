package approval

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jornJp0201/jev-argos/pkg/guardrail"
)

// 攻撃中 (同じ送信元から Level 3 の判定が連続する) に、承認キューへの提案 1 件にかかる時間と SQL の数を測る。
// JEV_ARGOS_TEST_POSTGRES_URL が未設定ならスキップする。
//
//	JEV_ARGOS_TEST_POSTGRES_URL=postgres://... go test -run '^$' -bench . -benchmem ./pkg/approval/

// queryCounter は実行した SQL の数を数える pgx のトレーサー。
type queryCounter struct{ n atomic.Int64 }

func (q *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	q.n.Add(1)
	return ctx
}

func (q *queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func newBenchPostgresStore(b *testing.B) (*PostgresStore, *queryCounter) {
	b.Helper()
	url := os.Getenv("JEV_ARGOS_TEST_POSTGRES_URL")
	if url == "" {
		b.Skip("JEV_ARGOS_TEST_POSTGRES_URL not set")
	}
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
	b.Cleanup(pool.Close)
	s := NewPostgresStore(pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.Migrate(ctx); err != nil {
		b.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE jev_actions"); err != nil {
		b.Fatal(err)
	}
	return s, qc
}

func BenchmarkProposeEmitter_Attack(b *testing.B) {
	s, qc := newBenchPostgresStore(b)
	em := &ProposeEmitter{Store: s, Window: DefaultProposeWindow}
	e := event(guardrail.Level3, true)
	qc.n.Store(0)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		em.Emit(ctx, e)
	}
	em.Flush(ctx) // まとめた分を書くまでを含める (計測は 1 つの Window に収まる)
	b.ReportMetric(float64(qc.n.Load())/float64(b.N), "queries/op")
}
