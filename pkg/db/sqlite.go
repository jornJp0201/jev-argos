package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // CGO 不要の純 Go ドライバ (distroless イメージでも動く)

	"github.com/jornJp0201/jev-argos/pkg/approval"
)

// SQLiteStore は SQLite に判定ログを保存する (設計書 7.2: 開発用の Zero Config 構成)。
// DecisionStore / AnalysisStore / HistoryProvider を実装する。
//
// 1 プロセスからの利用を想定している。複数インスタンスで共有する場合は PostgreSQL を使うこと。
type SQLiteStore struct {
	db *sql.DB
}

var (
	_ DecisionStore   = (*SQLiteStore)(nil)
	_ AnalysisStore   = (*SQLiteStore)(nil)
	_ HistoryProvider = (*SQLiteStore)(nil)
)

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS jev_decision_logs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    signal_id        TEXT    NOT NULL,
    signal_timestamp TEXT,
    received_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    client_ip        TEXT    NOT NULL,
    user_id          TEXT    NOT NULL DEFAULT '',
    risk_score       REAL    NOT NULL CHECK (risk_score BETWEEN 0 AND 4),
    confidence       REAL    NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    level            INTEGER NOT NULL CHECK (level BETWEEN 1 AND 4),
    downgraded       INTEGER NOT NULL DEFAULT 0,
    raw_signal_json  TEXT    NOT NULL,
    llm_analysis     TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS jev_decision_logs_signal_id_key ON jev_decision_logs (signal_id) WHERE signal_id <> '';
CREATE INDEX IF NOT EXISTS jev_decision_logs_client_ip_idx ON jev_decision_logs (client_ip, received_at DESC);
CREATE VIEW IF NOT EXISTS jev_decision_logs_safe AS
SELECT received_at, client_ip,
       json_extract(raw_signal_json, '$.request_context.method') AS method,
       COALESCE(json_extract(raw_signal_json, '$.response_context.status_code'), 0) AS status_code,
       level, risk_score, confidence, downgraded
FROM jev_decision_logs;
`

// OpenSQLite は path の SQLite データベースを開き、テーブルを作成する。
func OpenSQLite(ctx context.Context, path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite の書き込みは 1 本に絞る (ロック競合を避ける)
	if _, err := db.ExecContext(ctx, sqliteSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate sqlite %s: %w", path, err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) SaveDecision(ctx context.Context, log DecisionLog) error {
	var ts any
	if log.SignalTimestamp != nil {
		ts = log.SignalTimestamp.UTC().Format(time.RFC3339Nano)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO jev_decision_logs
		    (signal_id, signal_timestamp, client_ip, user_id, risk_score, confidence, level, downgraded, raw_signal_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.SignalID, ts, log.ClientIP, log.UserID, log.RiskScore, log.Confidence, int(log.Level), log.Downgraded, string(log.RawSignalJSON))
	if err != nil {
		return fmt.Errorf("sqlite insert (signal_id=%q): %w", log.SignalID, err)
	}
	return nil
}

func (s *SQLiteStore) SaveAnalysis(ctx context.Context, signalID string, a approval.Analysis) error {
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE jev_decision_logs SET llm_analysis = ? WHERE signal_id = ?`, string(data), signalID)
	return err
}

func (s *SQLiteStore) RecentByIP(ctx context.Context, clientIP string, limit int) ([]HistoryEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultHistoryTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
		SELECT received_at, COALESCE(method, ''), status_code, level, risk_score, confidence, downgraded
		FROM jev_decision_logs_safe WHERE client_ip = ? ORDER BY received_at DESC LIMIT ?`, clientIP, limit)
	if err != nil {
		return nil, fmt.Errorf("sqlite history: %w", err)
	}
	defer rows.Close()
	var out []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		var at string
		if err := rows.Scan(&at, &e.Method, &e.StatusCode, &e.Level, &e.Score, &e.Confidence, &e.Downgraded); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, e)
	}
	return out, rows.Err()
}
