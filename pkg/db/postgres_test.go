package db

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pashagolub/pgxmock/v4"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
)

func event(id string, level guardrail.Level) receiver.Event {
	return receiver.Event{
		Signal: &jevargosv1.SecuritySignal{
			SignalId:      id,
			Timestamp:     "2026-10-29T12:34:56.789Z",
			SourceService: "main-bff",
			TraceId:       "trace-1",
			UserContext: &jevargosv1.UserContext{
				UserId:   "user-42",
				UserRole: "user",
				ClientIp: "203.0.113.9",
			},
			RequestContext: &jevargosv1.RequestContext{
				Protocol:       "grpc",
				Method:         "/admin.AdminService/Delete",
				MetadataMasked: map[string]string{"authorization": "***"},
			},
			ResponseContext: &jevargosv1.ResponseContext{StatusCode: 7, LatencyMs: 15},
		},
		Assessment: classifier.Assessment{Score: 3.8, Confidence: 0.7},
		Decision:   guardrail.Decision{Level: level, Downgraded: level == guardrail.Level3},
	}
}

func newMock(t *testing.T) pgxmock.PgxPoolIface {
	t.Helper()
	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
		mock.Close()
	})
	return mock
}

func TestNewDecisionLog(t *testing.T) {
	log, err := NewDecisionLog(event("sig-1", guardrail.Level3))
	if err != nil {
		t.Fatal(err)
	}

	wantTS := time.Date(2026, 10, 29, 12, 34, 56, 789_000_000, time.UTC)
	if log.SignalID != "sig-1" || log.ClientIP != "203.0.113.9" || log.UserID != "user-42" ||
		log.RiskScore != 3.8 || log.Confidence != 0.7 || log.Level != guardrail.Level3 || !log.Downgraded ||
		log.SignalTimestamp == nil || !log.SignalTimestamp.Equal(wantTS) {
		t.Errorf("unexpected log: %+v (ts=%v)", log, log.SignalTimestamp)
	}

	// raw_signal_json は proto のフィールド名 (snake_case) で保存する
	var raw map[string]any
	if err := json.Unmarshal(log.RawSignalJSON, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["signal_id"] != "sig-1" || raw["user_context"].(map[string]any)["client_ip"] != "203.0.113.9" {
		t.Errorf("raw_signal_json = %s", log.RawSignalJSON)
	}
}

func TestNewDecisionLog_InvalidTimestampIsNull(t *testing.T) {
	for _, ts := range []string{"", "yesterday", "2026-10-29 12:34:56"} {
		e := event("sig-1", guardrail.Level2)
		e.Signal.Timestamp = ts
		log, err := NewDecisionLog(e)
		if err != nil {
			t.Fatal(err)
		}
		if log.SignalTimestamp != nil {
			t.Errorf("timestamp %q parsed as %v, want NULL", ts, log.SignalTimestamp)
		}
	}
}

func TestMigrate(t *testing.T) {
	mock := newMock(t)
	mock.ExpectExec(Schema).WillReturnResult(pgxmock.NewResult("CREATE", 0))

	if err := NewPostgresStore(mock).Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPersistDecision_SavesLevel2To4(t *testing.T) {
	for _, level := range []guardrail.Level{guardrail.Level2, guardrail.Level3, guardrail.Level4} {
		t.Run(fmt.Sprintf("level %d", level), func(t *testing.T) {
			mock := newMock(t)
			e := event("sig-1", level)
			ts := time.Date(2026, 10, 29, 12, 34, 56, 789_000_000, time.UTC)
			mock.ExpectExec(insertSQL).
				WithArgs("sig-1", &ts, "203.0.113.9", "user-42", 3.8, 0.7, int16(level), level == guardrail.Level3, pgxmock.AnyArg()).
				WillReturnResult(pgxmock.NewResult("INSERT", 1))

			if err := PersistDecision(context.Background(), NewPostgresStore(mock), e); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPersistDecision_SkipsLevel1(t *testing.T) {
	mock := newMock(t) // Exec を期待しない: 呼ばれればエラーになる

	if err := PersistDecision(context.Background(), NewPostgresStore(mock), event("sig-1", guardrail.Level1)); err != nil {
		t.Fatal(err)
	}
}

func TestSaveDecision_ReturnsDBError(t *testing.T) {
	mock := newMock(t)
	dbErr := errors.New("connection reset")
	mock.ExpectExec(insertSQL).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(),
		pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnError(dbErr)

	err := PersistDecision(context.Background(), NewPostgresStore(mock), event("sig-1", guardrail.Level4))
	if !errors.Is(err, dbErr) {
		t.Errorf("err = %v, want wrapping %v", err, dbErr)
	}
}

type storeFunc func(ctx context.Context, log DecisionLog) error

func (f storeFunc) SaveDecision(ctx context.Context, log DecisionLog) error { return f(ctx, log) }

func TestEmitter_AppliesTimeoutAndLogsErrors(t *testing.T) {
	var gotDeadline bool
	store := storeFunc(func(ctx context.Context, _ DecisionLog) error {
		_, gotDeadline = ctx.Deadline()
		return errors.New("db down")
	})
	var logs bytes.Buffer
	em := Emitter{Store: store, Logger: slog.New(slog.NewTextHandler(&logs, nil))}

	em.Emit(context.Background(), event("sig-1", guardrail.Level4))

	if !gotDeadline {
		t.Error("store was called without a deadline")
	}
	if !bytes.Contains(logs.Bytes(), []byte("persist decision failed")) {
		t.Errorf("logs = %q, want failure logged", logs.String())
	}
}

// 実 PostgreSQL での結合テスト。JEV_ARGOS_TEST_POSTGRES_URL が未設定ならスキップする。
//
//	JEV_ARGOS_TEST_POSTGRES_URL=postgres://localhost:5432/jevargos_test?sslmode=disable go test ./pkg/db/
func TestPostgresStore_Integration(t *testing.T) {
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

	if _, err := pool.Exec(ctx, "DROP TABLE IF EXISTS jev_decision_logs CASCADE"); err != nil {
		t.Fatal(err)
	}
	store := NewPostgresStore(pool)
	for range 2 { // 2 回目も成功する (冪等)
		if err := store.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}

	em := Emitter{Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	em.Emit(ctx, event("sig-1", guardrail.Level4))
	em.Emit(ctx, event("sig-1", guardrail.Level4)) // 再送: 重複しない
	em.Emit(ctx, event("sig-2", guardrail.Level1)) // Level 1: 保存しない
	noTS := event("sig-3", guardrail.Level3)
	noTS.Signal.Timestamp = "invalid"
	em.Emit(ctx, noTS)

	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM jev_decision_logs").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("rows = %d, want 2 (sig-1 once, sig-3)", count)
	}

	var (
		level      int16
		downgraded bool
		ts         *time.Time
		method     string
	)
	err = pool.QueryRow(ctx, `
		SELECT level, downgraded, signal_timestamp, raw_signal_json->'request_context'->>'method'
		FROM jev_decision_logs WHERE signal_id = 'sig-1'`).Scan(&level, &downgraded, &ts, &method)
	if err != nil {
		t.Fatal(err)
	}
	wantTS := time.Date(2026, 10, 29, 12, 34, 56, 789_000_000, time.UTC)
	if level != 4 || downgraded || ts == nil || !ts.Equal(wantTS) || method != "/admin.AdminService/Delete" {
		t.Errorf("sig-1 row = level %d, downgraded %v, ts %v, method %q", level, downgraded, ts, method)
	}

	if err := pool.QueryRow(ctx, "SELECT signal_timestamp FROM jev_decision_logs WHERE signal_id = 'sig-3'").Scan(&ts); err != nil {
		t.Fatal(err)
	}
	if ts != nil {
		t.Errorf("sig-3 signal_timestamp = %v, want NULL", ts)
	}
}
