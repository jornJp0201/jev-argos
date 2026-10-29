// Package approval は Human-in-the-Loop の承認待ちアクション (設計書 6.2) を管理する。
//
// 確信度不足で自動遮断を見送った判定 (Level 3、格下げを含む) について、
// 送信元 IP の一時遮断を「承認待ち」として提案し、管理者の承認 / 拒否を記録する。
// 同じ対象への承認待ちが既にあれば新規作成せず、最新の根拠と件数で更新する。
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/jev-argos/jev-argos/pkg/guardrail"
	"github.com/jev-argos/jev-argos/pkg/receiver"
)

// Status はアクションの状態。
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// ActionType は提案する対処の種類。
type ActionType string

const (
	// ActionBlockIP は送信元 IP の一時遮断。
	ActionBlockIP ActionType = "block_ip"
)

// Evidence は提案の根拠となった判定結果のスナップショット。
type Evidence struct {
	Score                 float64 `json:"score"`
	Confidence            float64 `json:"confidence"`
	Level                 int     `json:"level"`
	Downgraded            bool    `json:"downgraded"`
	IPErrorCount1m        int     `json:"ip_error_count_1m"`
	UniqueDeniedMethods5m int     `json:"unique_denied_methods_5m"`
	LatencySpikeRatio     float64 `json:"latency_spike_ratio"`
	ClientIP              string  `json:"client_ip"`
	UserID                string  `json:"user_id"`
	Method                string  `json:"method"`
	SourceService         string  `json:"source_service"`
	SignalTimestamp       string  `json:"signal_timestamp"`
}

// Action は承認待ちアクション。
type Action struct {
	ID             string     `json:"action_id"`
	SignalID       string     `json:"signal_id"` // 最新の根拠シグナル
	ProposedAction ActionType `json:"proposed_action"`
	Target         string     `json:"target"` // 対処の対象 (block_ip なら IP)
	Reason         string     `json:"reason"`
	Status         Status     `json:"status"`
	Evidence       Evidence   `json:"evidence"`
	EventCount     int        `json:"event_count"` // 承認待ちの間に同じ対象で発生した判定数
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	DecidedBy      string     `json:"decided_by,omitempty"`
	DecisionNote   string     `json:"decision_note,omitempty"`
}

// Proposal は新しいアクションの提案。
type Proposal struct {
	SignalID       string
	ProposedAction ActionType
	Target         string
	Reason         string
	Evidence       Evidence
}

var (
	ErrNotFound       = errors.New("action not found")
	ErrAlreadyDecided = errors.New("action already decided")
	ErrStoreFull      = errors.New("too many pending actions")
)

// Store はアクションの保存先。
type Store interface {
	// Propose は提案を登録する。同じ種類・対象の承認待ちがあればそれを更新して返す。
	Propose(ctx context.Context, p Proposal) (Action, error)
	// List は status のアクションを新しい順に返す。status が空なら全件。
	List(ctx context.Context, status Status) ([]Action, error)
	Get(ctx context.Context, id string) (Action, error)
	// Decide は承認待ちのアクションを承認 / 拒否する。
	// 決定済みなら ErrAlreadyDecided と現在のアクションを返す。
	Decide(ctx context.Context, id string, approve bool, decidedBy, note string) (Action, error)
	// Subscribe はアクションの作成・更新の通知を受け取るチャネルを返す。cancel で購読を解除する。
	Subscribe() (updates <-chan Action, cancel func())
}

// DefaultMaxActions は MemoryStore が保持するアクション数の上限。
const DefaultMaxActions = 5000

// MemoryStore はプロセス内メモリの Store。プロセス再起動で内容は失われる。
type MemoryStore struct {
	mu          sync.Mutex
	now         func() time.Time
	maxActions  int
	actions     map[string]*Action
	pendingKeys map[string]string // 種類+対象 -> 承認待ちのアクション ID
	subscribers map[chan Action]struct{}
}

var _ Store = (*MemoryStore)(nil)

func NewMemoryStore() *MemoryStore {
	return newMemoryStore(time.Now, DefaultMaxActions)
}

func newMemoryStore(now func() time.Time, maxActions int) *MemoryStore {
	return &MemoryStore{
		now:         now,
		maxActions:  maxActions,
		actions:     make(map[string]*Action),
		pendingKeys: make(map[string]string),
		subscribers: make(map[chan Action]struct{}),
	}
}

func pendingKey(t ActionType, target string) string { return string(t) + "\x00" + target }

func (s *MemoryStore) Propose(_ context.Context, p Proposal) (Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	key := pendingKey(p.ProposedAction, p.Target)
	if id, ok := s.pendingKeys[key]; ok {
		a := s.actions[id]
		a.SignalID = p.SignalID
		a.Reason = p.Reason
		a.Evidence = p.Evidence
		a.EventCount++
		a.UpdatedAt = now
		s.notify(*a)
		return *a, nil
	}

	if len(s.actions) >= s.maxActions && !s.evictOldestDecided() {
		return Action{}, ErrStoreFull
	}
	id, err := newID()
	if err != nil {
		return Action{}, err
	}
	a := &Action{
		ID:             id,
		SignalID:       p.SignalID,
		ProposedAction: p.ProposedAction,
		Target:         p.Target,
		Reason:         p.Reason,
		Status:         StatusPending,
		Evidence:       p.Evidence,
		EventCount:     1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	s.actions[id] = a
	s.pendingKeys[key] = id
	s.notify(*a)
	return *a, nil
}

func (s *MemoryStore) List(_ context.Context, status Status) ([]Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Action, 0, len(s.actions))
	for _, a := range s.actions {
		if status == "" || a.Status == status {
			out = append(out, *a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.actions[id]
	if !ok {
		return Action{}, ErrNotFound
	}
	return *a, nil
}

func (s *MemoryStore) Decide(_ context.Context, id string, approve bool, decidedBy, note string) (Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.actions[id]
	if !ok {
		return Action{}, ErrNotFound
	}
	if a.Status != StatusPending {
		return *a, ErrAlreadyDecided
	}
	now := s.now()
	a.Status = StatusRejected
	if approve {
		a.Status = StatusApproved
	}
	a.DecidedAt = &now
	a.DecidedBy = decidedBy
	a.DecisionNote = note
	a.UpdatedAt = now
	delete(s.pendingKeys, pendingKey(a.ProposedAction, a.Target))
	s.notify(*a)
	return *a, nil
}

func (s *MemoryStore) Subscribe() (<-chan Action, func()) {
	ch := make(chan Action, 64)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.subscribers, ch)
			s.mu.Unlock()
			close(ch)
		})
	}
}

// notify は購読者に変更を通知する。受信が追いつかない購読者への通知は捨てる
// (購読者は一覧の再取得で最新状態に戻れるため)。s.mu を保持して呼ぶこと。
func (s *MemoryStore) notify(a Action) {
	for ch := range s.subscribers {
		select {
		case ch <- a:
		default:
		}
	}
}

// evictOldestDecided は最も古い決定済みアクションを 1 件削除する。s.mu を保持して呼ぶこと。
func (s *MemoryStore) evictOldestDecided() bool {
	var oldest *Action
	for _, a := range s.actions {
		if a.Status != StatusPending && (oldest == nil || a.UpdatedAt.Before(oldest.UpdatedAt)) {
			oldest = a
		}
	}
	if oldest == nil {
		return false
	}
	delete(s.actions, oldest.ID)
	return true
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate action id: %w", err)
	}
	return "act_" + hex.EncodeToString(b), nil
}

// ProposeEmitter は Level 3 の判定から IP 一時遮断の承認待ちアクションを提案する receiver.Emitter。
// Level 4 は自動遮断の対象、Level 2 以下は遮断を提案するほどの根拠が無いため対象外。
type ProposeEmitter struct {
	Store  Store
	Logger *slog.Logger // nil なら slog.Default()
}

var _ receiver.Emitter = ProposeEmitter{}

func (em ProposeEmitter) Emit(ctx context.Context, e receiver.Event) {
	if e.Decision.Level != guardrail.Level3 {
		return
	}
	ip := e.Signal.GetUserContext().GetClientIp()
	_, err := em.Store.Propose(ctx, Proposal{
		SignalID:       e.Signal.GetSignalId(),
		ProposedAction: ActionBlockIP,
		Target:         ip,
		Reason:         reason(e),
		Evidence: Evidence{
			Score:                 e.Assessment.Score,
			Confidence:            e.Assessment.Confidence,
			Level:                 int(e.Decision.Level),
			Downgraded:            e.Decision.Downgraded,
			IPErrorCount1m:        e.Features.IPErrorCount1m,
			UniqueDeniedMethods5m: e.Features.UniqueDeniedMethods5m,
			LatencySpikeRatio:     e.Features.LatencySpikeRatio,
			ClientIP:              ip,
			UserID:                e.Signal.GetUserContext().GetUserId(),
			Method:                e.Signal.GetRequestContext().GetMethod(),
			SourceService:         e.Signal.GetSourceService(),
			SignalTimestamp:       e.Signal.GetTimestamp(),
		},
	})
	if err != nil {
		logger := em.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("propose action failed", "signal_id", e.Signal.GetSignalId(), "err", err)
	}
}

func reason(e receiver.Event) string {
	// 数値は Evidence に入っているため、ここでは判断の理由だけを述べる
	if e.Decision.Downgraded {
		return fmt.Sprintf("リスクスコアは遮断域 (S ≥ %.1f) ですが、確信度が %.1f 未満のため自動遮断を保留しました。",
			guardrail.BlockScoreThreshold, guardrail.BlockConfidenceThreshold)
	}
	return fmt.Sprintf("リスクスコアが Level 3 の範囲 (%.1f ≤ S < %.1f) のため、遮断の要否について人間の確認が必要です。",
		guardrail.Level3ScoreThreshold, guardrail.BlockScoreThreshold)
}

// Executor は承認されたアクションを実行する。
type Executor interface {
	Execute(ctx context.Context, a Action) error
}

// LogExecutor は承認されたアクションをログに出すだけの Executor。
// 遮断コマンドの発行先 (BFF・ゲートウェイ等) と連携するまでの暫定実装。
type LogExecutor struct {
	Logger *slog.Logger
}

func (l LogExecutor) Execute(_ context.Context, a Action) error {
	logger := l.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("approved action (not executed: no action emitter configured)",
		"action_id", a.ID, "proposed_action", a.ProposedAction, "target", a.Target, "decided_by", a.DecidedBy)
	return nil
}
