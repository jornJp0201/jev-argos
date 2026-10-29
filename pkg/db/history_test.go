package db

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jev-argos/jev-argos/pkg/approval"
	"github.com/jev-argos/jev-argos/pkg/guardrail"
)

// 判定ログ + 分析 + 履歴の共通の振る舞い (SQLite は常に、PostgreSQL は環境変数があるときに実行する)。
type fullStore interface {
	DecisionStore
	AnalysisStore
	HistoryProvider
}

func runHistoryContract(t *testing.T, s fullStore) {
	ctx := context.Background()
	for i, level := range []guardrail.Level{guardrail.Level2, guardrail.Level3, guardrail.Level4} {
		e := event("sig-h"+string(rune('0'+i)), level)
		log, err := NewDecisionLog(e)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SaveDecision(ctx, log); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond) // received_at の順序をはっきりさせる
	}
	// 同じ signal_id の再送は無視される
	dup, _ := NewDecisionLog(event("sig-h0", guardrail.Level2))
	if err := s.SaveDecision(ctx, dup); err != nil {
		t.Fatal(err)
	}

	hist, err := s.RecentByIP(ctx, "203.0.113.9", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 || hist[0].Level != 4 || hist[1].Level != 3 {
		t.Fatalf("history = %+v, want newest first (L4, L3)", hist)
	}
	if hist[0].Method != "/admin.AdminService/Delete" || hist[0].StatusCode != 7 || hist[0].Score != 3.8 || hist[0].At.IsZero() {
		t.Errorf("entry = %+v", hist[0])
	}
	if other, _ := s.RecentByIP(ctx, "10.9.9.9", 5); len(other) != 0 {
		t.Errorf("other IP history = %+v", other)
	}

	if err := s.SaveAnalysis(ctx, "sig-h2", approval.Analysis{Status: "done", Summary: "probing"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAnalysis(ctx, "sig-missing", approval.Analysis{Status: "done"}); err != nil {
		t.Errorf("analysis for a missing log should be a no-op: %v", err)
	}
}

func TestSQLiteStore(t *testing.T) {
	s, err := OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "jev.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	runHistoryContract(t, s)

	var n int
	s.db.QueryRow(`SELECT count(*) FROM jev_decision_logs`).Scan(&n)
	if n != 3 {
		t.Errorf("rows = %d, want 3", n)
	}
	var summary string
	s.db.QueryRow(`SELECT json_extract(llm_analysis, '$.summary') FROM jev_decision_logs WHERE signal_id = 'sig-h2'`).Scan(&summary)
	if summary != "probing" {
		t.Errorf("analysis = %q", summary)
	}
	assertSafeViewColumns(t, func() ([]string, error) {
		rows, err := s.db.Query(`SELECT name FROM pragma_table_info('jev_decision_logs_safe')`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var cols []string
		for rows.Next() {
			var c string
			rows.Scan(&c)
			cols = append(cols, c)
		}
		return cols, nil
	})
}

func TestPostgresHistory_Integration(t *testing.T) {
	url := os.Getenv("JEV_ARGOS_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("JEV_ARGOS_TEST_POSTGRES_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	pool.Exec(ctx, "DROP VIEW IF EXISTS jev_decision_logs_safe")
	pool.Exec(ctx, "DROP TABLE IF EXISTS jev_decision_logs")
	store := NewPostgresStore(pool)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil { // 2 回目も成功する
		t.Fatal(err)
	}

	pg := struct {
		*PostgresStore
		PostgresHistory
	}{store, PostgresHistory{Pool: pool}}
	runHistoryContract(t, pg)

	var summary string
	pool.QueryRow(ctx, `SELECT llm_analysis->>'summary' FROM jev_decision_logs WHERE signal_id = 'sig-h2'`).Scan(&summary)
	if summary != "probing" {
		t.Errorf("analysis = %q", summary)
	}
	assertSafeViewColumns(t, func() ([]string, error) {
		rows, err := pool.Query(ctx, `SELECT column_name FROM information_schema.columns WHERE table_name = 'jev_decision_logs_safe'`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var cols []string
		for rows.Next() {
			var c string
			rows.Scan(&c)
			cols = append(cols, c)
		}
		return cols, nil
	})
}

// Safe View に個人情報の列が無いこと。
func assertSafeViewColumns(t *testing.T, columns func() ([]string, error)) {
	t.Helper()
	cols, err := columns()
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) == 0 {
		t.Fatal("safe view has no columns")
	}
	for _, banned := range []string{"user_id", "raw_signal_json", "llm_analysis"} {
		if slices.Contains(cols, banned) {
			t.Errorf("safe view exposes %s: %v", banned, cols)
		}
	}
}
