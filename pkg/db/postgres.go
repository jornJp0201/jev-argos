// Package db は Jev 判定ログの永続化 (設計書 7.2 の本番構成: PostgreSQL) を提供する。
//
// Level 2〜4 と判定されたシグナルを判定結果とともに保存し、
// LLM 深層解析や運用管理 UI (Human-in-the-Loop) から参照できるようにする。
// Level 1 (静観 / 記録のみ) は量が多く、Sliding Window Buffer の統計で十分なため保存しない。
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
	"github.com/jev-argos/jev-argos/pkg/approval"
	"github.com/jev-argos/jev-argos/pkg/guardrail"
	"github.com/jev-argos/jev-argos/pkg/receiver"
)

// Schema は判定ログテーブルの定義。何度実行しても安全 (IF NOT EXISTS)。
const Schema = `
CREATE TABLE IF NOT EXISTS jev_decision_logs (
    id               BIGSERIAL        PRIMARY KEY,
    signal_id        TEXT             NOT NULL,
    signal_timestamp TIMESTAMPTZ,                          -- シグナルの timestamp (解釈できなければ NULL)
    received_at      TIMESTAMPTZ      NOT NULL DEFAULT now(),
    client_ip        TEXT             NOT NULL,
    user_id          TEXT             NOT NULL DEFAULT '',
    risk_score       DOUBLE PRECISION NOT NULL CHECK (risk_score BETWEEN 0 AND 4),
    confidence       DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    level            SMALLINT         NOT NULL CHECK (level BETWEEN 1 AND 4),
    downgraded       BOOLEAN          NOT NULL DEFAULT false, -- C < 0.8 で Level 4 → 3 に下げたか
    raw_signal_json  JSONB            NOT NULL
);

-- 同じシグナルの再送で重複行を作らない (signal_id が空のシグナルは対象外)
CREATE UNIQUE INDEX IF NOT EXISTS jev_decision_logs_signal_id_key
    ON jev_decision_logs (signal_id) WHERE signal_id <> '';
CREATE INDEX IF NOT EXISTS jev_decision_logs_client_ip_idx
    ON jev_decision_logs (client_ip, received_at DESC);
CREATE INDEX IF NOT EXISTS jev_decision_logs_level_idx
    ON jev_decision_logs (level, received_at DESC);

-- LLM 分析の結果 (pkg/llm)
ALTER TABLE jev_decision_logs ADD COLUMN IF NOT EXISTS llm_analysis JSONB;

-- LLM が参照してよい列だけを公開するビュー (設計書 6.1 "Safe View")。
-- user_id・User-Agent・元のシグナル (raw_signal_json) を含めない。
--
-- [差し替えポイント] 本番では LLM 用の DB ユーザーを作り、このビューの SELECT だけを許可すること:
--   CREATE ROLE jev_argos_llm LOGIN PASSWORD '...';
--   GRANT SELECT ON jev_decision_logs_safe TO jev_argos_llm;
-- その接続先を JEV_ARGOS_LLM_HISTORY_URL (分析専用のリードレプリカ) に指定する。
CREATE OR REPLACE VIEW jev_decision_logs_safe AS
SELECT received_at,
       client_ip,
       raw_signal_json -> 'request_context' ->> 'method'                         AS method,
       COALESCE((raw_signal_json -> 'response_context' ->> 'status_code')::int, 0) AS status_code,
       level,
       risk_score,
       confidence,
       downgraded
FROM jev_decision_logs;
`

const insertSQL = `
INSERT INTO jev_decision_logs
    (signal_id, signal_timestamp, client_ip, user_id, risk_score, confidence, level, downgraded, raw_signal_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (signal_id) WHERE signal_id <> '' DO NOTHING`

// DecisionLog は jev_decision_logs の 1 行。
type DecisionLog struct {
	SignalID        string
	SignalTimestamp *time.Time // nil なら NULL
	ClientIP        string
	UserID          string
	RiskScore       float64
	Confidence      float64
	Level           guardrail.Level
	Downgraded      bool
	RawSignalJSON   []byte
}

// NewDecisionLog は判定結果から DecisionLog を組み立てる。
func NewDecisionLog(e receiver.Event) (DecisionLog, error) {
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(e.Signal)
	if err != nil {
		return DecisionLog{}, fmt.Errorf("marshal signal: %w", err)
	}
	log := DecisionLog{
		SignalID:      e.Signal.GetSignalId(),
		ClientIP:      e.Signal.GetUserContext().GetClientIp(),
		UserID:        e.Signal.GetUserContext().GetUserId(),
		RiskScore:     e.Assessment.Score,
		Confidence:    e.Assessment.Confidence,
		Level:         e.Decision.Level,
		Downgraded:    e.Decision.Downgraded,
		RawSignalJSON: raw,
	}
	if ts, ok := parseTimestamp(e.Signal); ok {
		log.SignalTimestamp = &ts
	}
	return log, nil
}

// parseTimestamp はシグナルの ISO8601 timestamp を解釈する。送信側の値なので不正な場合もある。
func parseTimestamp(s *jevargosv1.SecuritySignal) (time.Time, bool) {
	ts, err := time.Parse(time.RFC3339Nano, s.GetTimestamp())
	return ts, err == nil
}

// Execer は SQL を実行できる接続。*pgxpool.Pool / *pgx.Conn / pgx.Tx が満たす。
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// DecisionStore は判定ログの保存先。
type DecisionStore interface {
	SaveDecision(ctx context.Context, log DecisionLog) error
}

// AnalysisStore は LLM 分析の結果を判定ログに保存する。
type AnalysisStore interface {
	SaveAnalysis(ctx context.Context, signalID string, a approval.Analysis) error
}

// HistoryEntry は LLM に渡す過去の判定 1 件 (Safe View の列だけ)。
type HistoryEntry struct {
	At         time.Time `json:"at"`
	Method     string    `json:"method"`
	StatusCode int       `json:"status_code"`
	Level      int       `json:"level"`
	Score      float64   `json:"score"`
	Confidence float64   `json:"confidence"`
	Downgraded bool      `json:"downgraded"`
}

// HistoryProvider は同じ送信元の過去の判定を返す (LLM 分析の文脈として使う)。
type HistoryProvider interface {
	RecentByIP(ctx context.Context, clientIP string, limit int) ([]HistoryEntry, error)
}

// DefaultHistoryTimeout は履歴の問い合わせの上限時間 (設計書 6.1: 最大 2 秒)。
const DefaultHistoryTimeout = 2 * time.Second

// PostgresStore は PostgreSQL に判定ログを保存する DecisionStore。
type PostgresStore struct {
	db Execer
}

var _ DecisionStore = (*PostgresStore)(nil)

// NewPostgresStore は db を使う PostgresStore を返す。
func NewPostgresStore(db Execer) *PostgresStore {
	return &PostgresStore{db: db}
}

// Migrate はテーブルとインデックスを作成する (既にあれば何もしない)。
func (s *PostgresStore) Migrate(ctx context.Context) error {
	if _, err := s.db.Exec(ctx, Schema); err != nil {
		return fmt.Errorf("migrate jev_decision_logs: %w", err)
	}
	return nil
}

// SaveAnalysis は判定ログに LLM 分析を保存する。判定ログがまだ無ければ何もしない。
func (s *PostgresStore) SaveAnalysis(ctx context.Context, signalID string, a approval.Analysis) error {
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(ctx, `UPDATE jev_decision_logs SET llm_analysis = $2 WHERE signal_id = $1`, signalID, data); err != nil {
		return fmt.Errorf("save analysis (signal_id=%q): %w", signalID, err)
	}
	return nil
}

// SaveDecision は判定ログを 1 行保存する。同じ signal_id が既にあれば何もしない。
func (s *PostgresStore) SaveDecision(ctx context.Context, log DecisionLog) error {
	_, err := s.db.Exec(ctx, insertSQL,
		log.SignalID, log.SignalTimestamp, log.ClientIP, log.UserID,
		log.RiskScore, log.Confidence, int16(log.Level), log.Downgraded, log.RawSignalJSON,
	)
	if err != nil {
		return fmt.Errorf("insert jev_decision_logs (signal_id=%q): %w", log.SignalID, err)
	}
	return nil
}

// PersistDecision は Level 2〜4 の判定結果を store に保存する。Level 1 は保存せず nil を返す。
func PersistDecision(ctx context.Context, store DecisionStore, e receiver.Event) error {
	if e.Decision.Level < guardrail.Level2 {
		return nil
	}
	log, err := NewDecisionLog(e)
	if err != nil {
		return err
	}
	return store.SaveDecision(ctx, log)
}

// DefaultWriteTimeout は Emitter が 1 件の保存に使う時間の上限。
const DefaultWriteTimeout = 2 * time.Second

// Emitter は判定結果を PostgreSQL に保存する receiver.Emitter。
// receiver のワーカーから呼ばれるため、保存が遅くても RPC の応答には影響しない。
type Emitter struct {
	Store   DecisionStore
	Timeout time.Duration // 0 なら DefaultWriteTimeout
	Logger  *slog.Logger  // nil なら slog.Default()
}

var _ receiver.Emitter = Emitter{}

func (em Emitter) Emit(ctx context.Context, e receiver.Event) {
	timeout := em.Timeout
	if timeout <= 0 {
		timeout = DefaultWriteTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := PersistDecision(ctx, em.Store, e); err != nil {
		logger := em.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("persist decision failed", "signal_id", e.Signal.GetSignalId(), "err", err)
	}
}

// PostgresHistory は Safe View から過去の判定を読む HistoryProvider (設計書 6.1)。
//
//   - 読み取り専用トランザクションで実行する (誤って書き込むことはない)。
//   - statement_timeout で問い合わせ時間に上限を設け、LLM 経由の処理が DB を圧迫しないようにする。
//   - Pool には分析専用のリードレプリカへの接続を渡すことを推奨する (本番 DB の負荷を避けるため)。
type PostgresHistory struct {
	Pool    *pgxpool.Pool
	Timeout time.Duration // 0 なら DefaultHistoryTimeout
}

var _ HistoryProvider = PostgresHistory{}

func (h PostgresHistory) RecentByIP(ctx context.Context, clientIP string, limit int) ([]HistoryEntry, error) {
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = DefaultHistoryTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout+500*time.Millisecond)
	defer cancel()

	var out []HistoryEntry
	err := pgx.BeginTxFunc(ctx, h.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", timeout.Milliseconds())); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT received_at, COALESCE(method, ''), status_code, level, risk_score, confidence, downgraded
			FROM jev_decision_logs_safe WHERE client_ip = $1 ORDER BY received_at DESC LIMIT $2`, clientIP, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e HistoryEntry
			var level int16
			if err := rows.Scan(&e.At, &e.Method, &e.StatusCode, &level, &e.Score, &e.Confidence, &e.Downgraded); err != nil {
				return err
			}
			e.Level = int(level)
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("history (safe view): %w", err)
	}
	return out, nil
}
