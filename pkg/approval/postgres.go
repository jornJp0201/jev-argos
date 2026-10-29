package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore は PostgreSQL に承認キューを保存する Store。
//
//   - 再起動しても承認待ち・決定の履歴 (監査ログ) が残る。決定済みのアクションは削除しない。
//   - 複数インスタンスで同じ承認キューを共有する。「同じ対象への承認待ちは 1 件」は部分ユニーク
//     インデックスで保証するため、複数インスタンスが同時に提案しても重複しない。
//   - 変更は LISTEN/NOTIFY でインスタンス間に通知し、どのインスタンスの SSE にも即座に届く。
//
// 使い終わったら Start に渡した ctx をキャンセルして通知の受信を止める。
type PostgresStore struct {
	pool       *pgxpool.Pool
	now        func() time.Time
	maxPending int
	logger     *slog.Logger

	mu   sync.Mutex
	subs map[chan Action]struct{}
}

var _ Store = (*PostgresStore)(nil)

// PostgresSchema は承認キューのテーブル定義。何度実行しても安全。
const PostgresSchema = `
CREATE TABLE IF NOT EXISTS jev_actions (
    id              TEXT        PRIMARY KEY,
    signal_id       TEXT        NOT NULL DEFAULT '',
    proposed_action TEXT        NOT NULL,
    target          TEXT        NOT NULL,
    reason          TEXT        NOT NULL,
    source          TEXT        NOT NULL,
    irreversible    BOOLEAN     NOT NULL DEFAULT false,
    status          TEXT        NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    evidence        JSONB       NOT NULL,
    event_count     INTEGER     NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    decided_at      TIMESTAMPTZ,
    decided_by      TEXT        NOT NULL DEFAULT '',
    decision_note   TEXT        NOT NULL DEFAULT '',
    executed_at     TIMESTAMPTZ,
    execution_error TEXT        NOT NULL DEFAULT '',
    analysis        JSONB
);
ALTER TABLE jev_actions ADD COLUMN IF NOT EXISTS analysis JSONB;
-- 同じ種類・対象の承認待ちは 1 件だけ (2 件目以降の提案は既存の件数と根拠を更新する)
CREATE UNIQUE INDEX IF NOT EXISTS jev_actions_pending_key
    ON jev_actions (proposed_action, target) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS jev_actions_status_idx
    ON jev_actions (status, updated_at DESC);
`

const (
	notifyChannel     = "jev_argos_actions"
	listLimit         = 1000
	actionColumns     = `id, signal_id, proposed_action, target, reason, source, irreversible, status, evidence, event_count, created_at, updated_at, decided_at, decided_by, decision_note, executed_at, execution_error, analysis`
	DefaultMaxPending = 5000 // 承認待ちの上限 (MemoryStore の DefaultMaxActions に相当)
)

// NewPostgresStore は PostgresStore を返す。Migrate と Start を呼んでから使うこと。
func NewPostgresStore(pool *pgxpool.Pool, logger *slog.Logger) *PostgresStore {
	if logger == nil {
		logger = slog.Default()
	}
	return &PostgresStore{pool: pool, now: time.Now, maxPending: DefaultMaxPending, logger: logger, subs: make(map[chan Action]struct{})}
}

// Migrate はテーブルとインデックスを作成する (既にあれば何もしない)。
func (s *PostgresStore) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, PostgresSchema); err != nil {
		return fmt.Errorf("migrate jev_actions: %w", err)
	}
	return nil
}

// Start は他のインスタンスを含む変更通知 (LISTEN) の受信を始める。ctx のキャンセルで止まる。
// 接続が切れた場合は再接続し、その間に起きた変更はクライアントの一覧再取得で補われる。
func (s *PostgresStore) Start(ctx context.Context) {
	go func() {
		delay := time.Second
		for ctx.Err() == nil {
			err := s.listen(ctx)
			if ctx.Err() != nil {
				return
			}
			s.logger.Warn("approval store: notification listener disconnected; reconnecting", "err", err, "in", delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			delay = min(delay*2, 30*time.Second)
		}
	}()
}

func (s *PostgresStore) listen(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+notifyChannel); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var a Action
		if strings.HasPrefix(n.Payload, "{") {
			err = json.Unmarshal([]byte(n.Payload), &a)
		} else {
			a, err = s.Get(ctx, n.Payload) // 通知に収まらない大きさのため ID だけが届いた
		}
		if err != nil {
			s.logger.Warn("approval store: decode notified action", "err", err)
			continue
		}
		s.publish(a)
	}
}

func (s *PostgresStore) Propose(ctx context.Context, p Proposal) (Action, error) {
	evidence, err := json.Marshal(p.Evidence)
	if err != nil {
		return Action{}, err
	}
	id, err := newID()
	if err != nil {
		return Action{}, err
	}
	now := s.now()

	var a Action
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var pending int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM jev_actions WHERE status = 'pending'`).Scan(&pending); err != nil {
			return err
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO jev_actions (id, signal_id, proposed_action, target, reason, source, irreversible, status, evidence, event_count, created_at, updated_at)
			SELECT $1, $2, $3, $4, $5, $6, $7, 'pending', $8, 1, $9, $9
			WHERE $10 OR EXISTS (SELECT 1 FROM jev_actions WHERE status = 'pending' AND proposed_action = $3 AND target = $4)
			ON CONFLICT (proposed_action, target) WHERE status = 'pending' DO UPDATE SET
			    signal_id   = EXCLUDED.signal_id,
			    reason      = EXCLUDED.reason,
			    evidence    = EXCLUDED.evidence,
			    event_count = jev_actions.event_count + 1,
			    updated_at  = EXCLUDED.updated_at
			RETURNING `+actionColumns,
			id, p.SignalID, string(p.ProposedAction), p.Target, p.Reason, sourceOrDefault(p.Source),
			p.ProposedAction.Irreversible(), evidence, now, pending < s.maxPending)
		if a, err = scanAction(row); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrStoreFull // 上限に達していて、既存の承認待ちの更新でもない
			}
			return err
		}
		return notify(ctx, tx, a)
	})
	return a, err
}

func (s *PostgresStore) List(ctx context.Context, status Status) ([]Action, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+actionColumns+` FROM jev_actions
		WHERE $1 = '' OR status = $1 ORDER BY updated_at DESC LIMIT `+fmt.Sprint(listLimit), string(status))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Action{}
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Action, error) {
	a, err := scanAction(s.pool.QueryRow(ctx, `SELECT `+actionColumns+` FROM jev_actions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Action{}, ErrNotFound
	}
	return a, err
}

func (s *PostgresStore) Decide(ctx context.Context, id string, approve bool, decidedBy, note string) (Action, error) {
	status := StatusRejected
	if approve {
		status = StatusApproved
	}
	var a Action
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		a, err = scanAction(tx.QueryRow(ctx, `
			UPDATE jev_actions SET status = $2, decided_at = $3, decided_by = $4, decision_note = $5, updated_at = $3
			WHERE id = $1 AND status = 'pending'
			RETURNING `+actionColumns, id, string(status), s.now(), decidedBy, note))
		if err != nil {
			return err
		}
		return notify(ctx, tx, a)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// 承認待ちでない: 存在しないか、他の管理者が先に決定した
		current, getErr := s.Get(ctx, id)
		if getErr != nil {
			return Action{}, getErr
		}
		return current, ErrAlreadyDecided
	}
	return a, err
}

func (s *PostgresStore) RecordExecution(ctx context.Context, id string, execErr error) (Action, error) {
	msg := ""
	if execErr != nil {
		msg = execErr.Error()
	}
	var a Action
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		a, err = scanAction(tx.QueryRow(ctx, `
			UPDATE jev_actions SET executed_at = $2, execution_error = $3, updated_at = $2
			WHERE id = $1 RETURNING `+actionColumns, id, s.now(), msg))
		if err != nil {
			return err
		}
		return notify(ctx, tx, a)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Action{}, ErrNotFound
	}
	return a, err
}

func (s *PostgresStore) AttachAnalysis(ctx context.Context, actionType ActionType, target string, an Analysis) (Action, error) {
	data, err := json.Marshal(an)
	if err != nil {
		return Action{}, err
	}
	var a Action
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		a, err = scanAction(tx.QueryRow(ctx, `
			UPDATE jev_actions SET analysis = $3, updated_at = $4
			WHERE status = 'pending' AND proposed_action = $1 AND target = $2
			RETURNING `+actionColumns, string(actionType), target, data, s.now()))
		if err != nil {
			return err
		}
		return notify(ctx, tx, a)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Action{}, ErrNotFound
	}
	return a, err
}

func (s *PostgresStore) Subscribe() (<-chan Action, func()) {
	ch := make(chan Action, 64)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.subs, ch)
			s.mu.Unlock()
			close(ch)
		})
	}
}

func (s *PostgresStore) publish(a Action) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- a:
		default:
		}
	}
}

// notify は変更をコミット時に全インスタンスへ通知する (自インスタンスにも届く)。
// 変更時点の内容を通知に載せ、連続した変更 (承認 → 実行結果の記録など) も順に届くようにする。
// NOTIFY の上限 (8000 バイト) に収まらない場合は ID だけを送り、受信側で読み直す。
func notify(ctx context.Context, tx pgx.Tx, a Action) error {
	payload := a.ID
	if data, err := json.Marshal(a); err == nil && len(data) < maxNotifyPayload {
		payload = string(data)
	}
	_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, notifyChannel, payload)
	return err
}

const maxNotifyPayload = 7900

func scanAction(row pgx.Row) (Action, error) {
	var (
		a                    Action
		proposed, status     string
		evidence             []byte
		decidedAt, executeAt *time.Time
		analysis             []byte
	)
	err := row.Scan(&a.ID, &a.SignalID, &proposed, &a.Target, &a.Reason, &a.Source, &a.Irreversible, &status, &evidence,
		&a.EventCount, &a.CreatedAt, &a.UpdatedAt, &decidedAt, &a.DecidedBy, &a.DecisionNote, &executeAt, &a.ExecutionError, &analysis)
	if err != nil {
		return Action{}, err
	}
	a.ProposedAction, a.Status = ActionType(proposed), Status(status)
	a.DecidedAt, a.ExecutedAt = decidedAt, executeAt
	if err := json.Unmarshal(evidence, &a.Evidence); err != nil {
		return Action{}, fmt.Errorf("decode evidence of %s: %w", a.ID, err)
	}
	if len(analysis) > 0 {
		a.Analysis = new(Analysis)
		if err := json.Unmarshal(analysis, a.Analysis); err != nil {
			return Action{}, fmt.Errorf("decode analysis of %s: %w", a.ID, err)
		}
	}
	return a, nil
}
