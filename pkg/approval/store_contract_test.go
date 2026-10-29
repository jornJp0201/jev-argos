package approval

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 実装が共通で満たすべき振る舞い。MemoryStore は常に、PostgresStore は
// JEV_ARGOS_TEST_POSTGRES_URL が設定されているときに実行する。

func runStoreContract(t *testing.T, newStore func(t *testing.T) Store) {
	p := func(target, signal string) Proposal {
		return Proposal{SignalID: signal, ProposedAction: ActionBlockIP, Target: target, Reason: "r", Evidence: Evidence{Score: 3.6, ClientIP: target}}
	}

	t.Run("ProposeDedupesPending", func(t *testing.T) {
		s := newStore(t)
		a, err := s.Propose(ctx, p("10.0.0.1", "s1"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := s.Propose(ctx, Proposal{SignalID: "s2", ProposedAction: ActionBlockIP, Target: "10.0.0.1", Reason: "r2", Evidence: Evidence{Score: 3.9}})
		other, _ := s.Propose(ctx, Proposal{ProposedAction: ActionDeleteAccount, Target: "10.0.0.1", Reason: "r", Source: SourceAdmin})
		if b.ID != a.ID || b.EventCount != 2 || b.SignalID != "s2" || b.Evidence.Score != 3.9 || b.Reason != "r2" {
			t.Errorf("second proposal = %+v", b)
		}
		if a.Source != SourceJev || a.Irreversible || a.Status != StatusPending {
			t.Errorf("first = %+v", a)
		}
		if other.ID == a.ID || !other.Irreversible || other.Source != SourceAdmin {
			t.Errorf("different action type must be separate: %+v", other)
		}
	})

	t.Run("Decide", func(t *testing.T) {
		s := newStore(t)
		a, _ := s.Propose(ctx, p("10.0.0.1", "s1"))
		got, err := s.Decide(ctx, a.ID, true, "alice", "ok")
		if err != nil || got.Status != StatusApproved || got.DecidedBy != "alice" || got.DecisionNote != "ok" || got.DecidedAt == nil {
			t.Fatalf("decide = %+v, %v", got, err)
		}
		again, err := s.Decide(ctx, a.ID, false, "bob", "")
		if !errors.Is(err, ErrAlreadyDecided) || again.Status != StatusApproved || again.DecidedBy != "alice" {
			t.Errorf("second decision = %+v, %v", again, err)
		}
		if _, err := s.Decide(ctx, "act_missing", true, "a", ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing: %v", err)
		}
		if _, err := s.Get(ctx, "act_missing"); !errors.Is(err, ErrNotFound) {
			t.Errorf("get missing: %v", err)
		}
		// 決定後の新しい提案は別の承認待ちになる
		next, _ := s.Propose(ctx, p("10.0.0.1", "s3"))
		if next.ID == a.ID || next.Status != StatusPending || next.EventCount != 1 {
			t.Errorf("proposal after decision = %+v", next)
		}
	})

	t.Run("RecordExecution", func(t *testing.T) {
		s := newStore(t)
		a, _ := s.Propose(ctx, p("10.0.0.1", "s1"))
		s.Decide(ctx, a.ID, true, "alice", "")
		failed, err := s.RecordExecution(ctx, a.ID, errors.New("webhook 503"))
		if err != nil || failed.ExecutedAt == nil || failed.ExecutionError != "webhook 503" {
			t.Fatalf("failed execution = %+v, %v", failed, err)
		}
		ok, _ := s.RecordExecution(ctx, a.ID, nil)
		if ok.ExecutionError != "" {
			t.Errorf("retry success should clear error: %+v", ok)
		}
		if _, err := s.RecordExecution(ctx, "act_missing", nil); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing: %v", err)
		}
	})

	t.Run("ListFiltersAndOrders", func(t *testing.T) {
		s := newStore(t)
		a, _ := s.Propose(ctx, p("10.0.0.1", "s1"))
		time.Sleep(5 * time.Millisecond)
		b, _ := s.Propose(ctx, p("10.0.0.2", "s2"))
		time.Sleep(5 * time.Millisecond)
		s.Decide(ctx, a.ID, false, "alice", "")
		all, _ := s.List(ctx, "")
		if len(all) != 2 || all[0].ID != a.ID || all[1].ID != b.ID {
			t.Errorf("all = %v", ids(all))
		}
		pending, _ := s.List(ctx, StatusPending)
		if len(pending) != 1 || pending[0].ID != b.ID {
			t.Errorf("pending = %v", ids(pending))
		}
		if rejected, _ := s.List(ctx, StatusRejected); len(rejected) != 1 {
			t.Errorf("rejected = %v", ids(rejected))
		}
	})

	t.Run("Subscribe", func(t *testing.T) {
		s := newStore(t)
		updates, cancel := s.Subscribe()
		defer cancel()
		a, _ := s.Propose(ctx, p("10.0.0.1", "s1"))
		s.Decide(ctx, a.ID, true, "alice", "")
		s.RecordExecution(ctx, a.ID, nil)
		for _, want := range []Status{StatusPending, StatusApproved, StatusApproved} {
			select {
			case got := <-updates:
				if got.ID != a.ID || got.Status != want {
					t.Errorf("update = %s/%s, want %s", got.ID, got.Status, want)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("no update for %s", want)
			}
		}
	})
}

func TestMemoryStore_Contract(t *testing.T) {
	runStoreContract(t, func(*testing.T) Store { return NewMemoryStore() })
}

func newTestPostgresStore(t *testing.T) (*PostgresStore, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("JEV_ARGOS_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("JEV_ARGOS_TEST_POSTGRES_URL not set")
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	s := NewPostgresStore(pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE jev_actions"); err != nil {
		t.Fatal(err)
	}
	lctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	s.Start(lctx)
	time.Sleep(100 * time.Millisecond) // LISTEN の開始を待つ
	return s, pool
}

func TestPostgresStore_Contract(t *testing.T) {
	runStoreContract(t, func(t *testing.T) Store {
		s, _ := newTestPostgresStore(t)
		return s
	})
}

// 2 つのインスタンス (別プロセス相当) が同じ承認キューを共有し、変更が互いに通知される。
func TestPostgresStore_SharedAcrossInstances(t *testing.T) {
	a, pool := newTestPostgresStore(t)
	b := NewPostgresStore(pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	b.Start(lctx)
	time.Sleep(100 * time.Millisecond)
	updatesB, cancelB := b.Subscribe()
	defer cancelB()

	created, _ := a.Propose(ctx, Proposal{ProposedAction: ActionBlockIP, Target: "10.0.0.9", Reason: "r"})
	select {
	case got := <-updatesB:
		if got.ID != created.ID {
			t.Errorf("instance b got %s, want %s", got.ID, created.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("instance b was not notified")
	}
	if _, err := b.Decide(ctx, created.ID, true, "alice", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Decide(ctx, created.ID, false, "bob", ""); !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("decision on instance a after b: %v", err)
	}
}

func TestPostgresStore_StoreFull(t *testing.T) {
	s, _ := newTestPostgresStore(t)
	s.maxPending = 1
	if _, err := s.Propose(ctx, Proposal{ProposedAction: ActionBlockIP, Target: "10.0.0.1", Reason: "r"}); err != nil {
		t.Fatal(err)
	}
	// 既存の承認待ちの更新は上限でも受け付ける
	if a, err := s.Propose(ctx, Proposal{ProposedAction: ActionBlockIP, Target: "10.0.0.1", Reason: "r"}); err != nil || a.EventCount != 2 {
		t.Errorf("update at limit: %+v %v", a, err)
	}
	if _, err := s.Propose(ctx, Proposal{ProposedAction: ActionBlockIP, Target: "10.0.0.2", Reason: "r"}); !errors.Is(err, ErrStoreFull) {
		t.Errorf("new at limit: %v", err)
	}
}
