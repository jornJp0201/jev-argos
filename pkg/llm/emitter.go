package llm

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jev-argos/jev-argos/pkg/approval"
	"github.com/jev-argos/jev-argos/pkg/db"
	"github.com/jev-argos/jev-argos/pkg/guardrail"
	"github.com/jev-argos/jev-argos/pkg/receiver"
)

// Sink は分析結果の配信先。
//
// [差し替えポイント] 分析結果を独自の保存先・通知先 (例: チケット起票、SIEM) に送る場合は実装し、Emitter.Sinks に足す。
type Sink interface {
	HandleAnalysis(ctx context.Context, e receiver.Event, a approval.Analysis)
}

// SinkFunc は関数を Sink として使うためのアダプター。
type SinkFunc func(ctx context.Context, e receiver.Event, a approval.Analysis)

func (f SinkFunc) HandleAnalysis(ctx context.Context, e receiver.Event, a approval.Analysis) {
	f(ctx, e, a)
}

// DBSink は分析結果を判定ログ (jev_decision_logs.llm_analysis) に保存する。
type DBSink struct {
	Store  db.AnalysisStore
	Logger *slog.Logger
}

func (s DBSink) HandleAnalysis(ctx context.Context, e receiver.Event, a approval.Analysis) {
	if err := s.Store.SaveAnalysis(ctx, e.Signal.GetSignalId(), a); err != nil {
		loggerOr(s.Logger).Error("save analysis failed", "signal_id", e.Signal.GetSignalId(), "err", err)
	}
}

// ApprovalSink は分析結果を承認キューに反映する。
//   - 同じ送信元の IP 遮断が承認待ちなら、分析結果を添付する (管理者が判断の材料にできる)。
//   - LLM が対処を推奨したら、承認待ちのアクションとして提案する (出どころ "llm")。
//     対象は LLM に選ばせず、判定結果から決める (IP / ユーザー ID / サービス名)。
type ApprovalSink struct {
	Store  approval.Store
	Logger *slog.Logger
}

func (s ApprovalSink) HandleAnalysis(ctx context.Context, e receiver.Event, a approval.Analysis) {
	logger := loggerOr(s.Logger)
	ip := e.Signal.GetUserContext().GetClientIp()

	if a.Status == "done" && a.RecommendedAction != "" {
		if target := recommendationTarget(e, a.RecommendedAction); target != "" {
			// 同じ対処が既に承認待ちなら (例: Jev が提案した IP 遮断)、提案は増やさず分析だけを添付する
			_, err := s.Store.AttachAnalysis(ctx, a.RecommendedAction, target, a)
			if errors.Is(err, approval.ErrNotFound) {
				_, err = s.Store.Propose(ctx, approval.Proposal{
					SignalID:       e.Signal.GetSignalId(),
					ProposedAction: a.RecommendedAction,
					Target:         target,
					Reason:         "LLM の推奨: " + a.Recommendation,
					Source:         approval.SourceLLM,
					Evidence:       approval.EvidenceFromEvent(e),
				})
				if err == nil {
					_, err = s.Store.AttachAnalysis(ctx, a.RecommendedAction, target, a)
				}
			}
			if err != nil {
				logger.Error("apply llm recommendation failed", "action", a.RecommendedAction, "err", err)
			}
		}
	}
	if a.RecommendedAction != approval.ActionBlockIP {
		if _, err := s.Store.AttachAnalysis(ctx, approval.ActionBlockIP, ip, a); err != nil && !errors.Is(err, approval.ErrNotFound) {
			logger.Error("attach analysis failed", "err", err)
		}
	}
}

// recommendationTarget は推奨された対処の対象を判定結果から決める。対象が無ければ空文字。
func recommendationTarget(e receiver.Event, t approval.ActionType) string {
	switch t {
	case approval.ActionBlockIP:
		return e.Signal.GetUserContext().GetClientIp()
	case approval.ActionRevokeSession, approval.ActionSuspendAccount:
		return e.Signal.GetUserContext().GetUserId()
	case approval.ActionEnableFallback:
		return e.Signal.GetSourceService()
	}
	return ""
}

// Emitter は判定結果を非同期に LLM で分析する receiver.Emitter。
//
// コストを抑えるため、同じ送信元は Cooldown の間に 1 回だけ分析する (Level が上がった場合は再分析する)。
// LLM の呼び出しは遅いため、receiver のワーカーを止めないよう専用のキューとワーカーで処理し、
// キューが満杯なら分析を見送る (判定と遮断には影響しない)。
type Emitter struct {
	Analyzer *Analyzer
	Sinks    []Sink
	MinLevel guardrail.Level // この Level 以上を分析する (0 なら Level 2)
	// [差し替えポイント] Cooldown と Workers は LLM のコストと処理能力に合わせて調整する。
	Cooldown  time.Duration // 0 なら 5 分
	QueueSize int           // 0 なら 64
	Workers   int           // 0 なら 2
	Logger    *slog.Logger
	Now       func() time.Time

	once    sync.Once
	queue   chan receiver.Event
	mu      sync.Mutex
	last    map[string]analyzed
	dropped atomic.Uint64
}

type analyzed struct {
	at    time.Time
	level guardrail.Level
}

// Start は分析のワーカーを起動する。ctx のキャンセルで止まる (キューに残った分析は捨てる)。
func (em *Emitter) Start(ctx context.Context) {
	em.init()
	workers := em.Workers
	if workers <= 0 {
		workers = 2
	}
	for range workers {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case e := <-em.queue:
					em.process(ctx, e)
				}
			}
		}()
	}
}

func (em *Emitter) init() {
	em.once.Do(func() {
		size := em.QueueSize
		if size <= 0 {
			size = 64
		}
		em.queue = make(chan receiver.Event, size)
		em.last = make(map[string]analyzed)
	})
}

// Dropped はキューが満杯で見送った分析の数。
func (em *Emitter) Dropped() uint64 { return em.dropped.Load() }

func (em *Emitter) Emit(_ context.Context, e receiver.Event) {
	em.init()
	minLevel := em.MinLevel
	if minLevel == 0 {
		minLevel = guardrail.Level2
	}
	if e.Decision.Level < minLevel || !em.due(e) {
		return
	}
	select {
	case em.queue <- e:
	default:
		em.dropped.Add(1)
	}
}

// due は送信元ごとの間引きを行い、今回分析すべきかを返す。
func (em *Emitter) due(e receiver.Event) bool {
	now := time.Now()
	if em.Now != nil {
		now = em.Now()
	}
	cooldown := em.Cooldown
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}
	ip := e.Signal.GetUserContext().GetClientIp()
	em.mu.Lock()
	defer em.mu.Unlock()
	if prev, ok := em.last[ip]; ok && now.Sub(prev.at) < cooldown && e.Decision.Level <= prev.level {
		return false
	}
	em.last[ip] = analyzed{at: now, level: e.Decision.Level}
	if len(em.last) > 10000 {
		for k, v := range em.last {
			if now.Sub(v.at) >= cooldown {
				delete(em.last, k)
			}
		}
	}
	return true
}

func (em *Emitter) process(ctx context.Context, e receiver.Event) {
	defer func() {
		if r := recover(); r != nil {
			loggerOr(em.Logger).Error("llm analysis panicked", "signal_id", e.Signal.GetSignalId(), "panic", r)
		}
	}()
	a := em.Analyzer.Analyze(ctx, e)
	if a.Status != "done" {
		loggerOr(em.Logger).Warn("llm analysis failed", "signal_id", e.Signal.GetSignalId(), "provider", a.Provider, "err", a.Error)
	}
	sinkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	for _, s := range em.Sinks {
		s.HandleAnalysis(sinkCtx, e, a)
	}
}

func loggerOr(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.Default()
	}
	return l
}
