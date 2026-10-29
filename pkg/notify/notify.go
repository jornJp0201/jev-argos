// Package notify は Level 3 以上の判定を外部へ通知する (設計書 2 章: Slack / Webhook)。
//
// 同じ送信元から判定が続いても通知が溢れないよう、送信元 IP ごとに Cooldown の間は 1 回だけ通知する。
// ただし Level が上がった場合 (例: 3 → 4) は Cooldown 中でもすぐに通知する。
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
	"github.com/jornJp0201/jev-argos/pkg/webhook"
)

// Alert は通知 1 件の内容。Webhook ではこの JSON がそのまま送られる。
type Alert struct {
	Type                  string    `json:"type"` // 常に "alert"
	Level                 int       `json:"level"`
	Downgraded            bool      `json:"downgraded"`
	Score                 float64   `json:"score"`
	Confidence            float64   `json:"confidence"`
	ClientIP              string    `json:"client_ip"`
	UserID                string    `json:"user_id"`
	Method                string    `json:"method"`
	SourceService         string    `json:"source_service"`
	SignalID              string    `json:"signal_id"`
	IPErrorCount1m        int       `json:"ip_error_count_1m"`
	UniqueDeniedMethods5m int       `json:"unique_denied_methods_5m"`
	LatencySpikeRatio     float64   `json:"latency_spike_ratio"`
	At                    time.Time `json:"at"`
	DashboardURL          string    `json:"dashboard_url,omitempty"`
}

// AlertFromEvent は判定結果から Alert を作る。
func AlertFromEvent(e receiver.Event, now time.Time) Alert {
	s := e.Signal
	return Alert{
		Type:                  "alert",
		Level:                 int(e.Decision.Level),
		Downgraded:            e.Decision.Downgraded,
		Score:                 e.Assessment.Score,
		Confidence:            e.Assessment.Confidence,
		ClientIP:              s.GetUserContext().GetClientIp(),
		UserID:                s.GetUserContext().GetUserId(),
		Method:                s.GetRequestContext().GetMethod(),
		SourceService:         s.GetSourceService(),
		SignalID:              s.GetSignalId(),
		IPErrorCount1m:        e.Features.IPErrorCount1m,
		UniqueDeniedMethods5m: e.Features.UniqueDeniedMethods5m,
		LatencySpikeRatio:     e.Features.LatencySpikeRatio,
		At:                    now,
	}
}

// Notifier は通知の送信先。
//
// [差し替えポイント] Slack / 汎用 Webhook 以外 (PagerDuty、Teams、メール、社内チャット等) に通知する場合は
// このインターフェースを実装し、cmd/jev-argos-server の newNotifiers で登録する。
type Notifier interface {
	Notify(ctx context.Context, a Alert) error
}

// SlackNotifier は Slack の Incoming Webhook に通知する。
type SlackNotifier struct {
	WebhookURL string
	Client     *http.Client
}

func (n SlackNotifier) Notify(ctx context.Context, a Alert) error {
	return webhook.Post(ctx, n.Client, n.WebhookURL, "", time.Now(), map[string]string{"text": SlackText(a)})
}

// SlackText は Slack に送る本文を組み立てる。
//
// [差し替えポイント] 通知の文面を変える場合はここを変更する (Block Kit を使う場合は SlackNotifier ごと差し替える)。
func SlackText(a Alert) string {
	title := fmt.Sprintf(":rotating_light: *jev-argos Level %d*", a.Level)
	switch {
	case a.Level >= 4:
		title += " — 自動遮断しました"
	case a.Downgraded:
		title += " — 確信度不足のため自動遮断を保留 (承認待ち)"
	default:
		title += " — 管理者の確認が必要です"
	}
	var b strings.Builder
	b.WriteString(title + "\n")
	fmt.Fprintf(&b, "• 送信元: `%s`", a.ClientIP)
	if a.UserID != "" {
		fmt.Fprintf(&b, " (user: `%s`)", a.UserID)
	}
	fmt.Fprintf(&b, "\n• API: `%s` (%s)\n", a.Method, a.SourceService)
	fmt.Fprintf(&b, "• スコア S=%.2f / 確信度 C=%.2f\n", a.Score, a.Confidence)
	fmt.Fprintf(&b, "• 1 分間のエラー %d 件 / 5 分間に拒否された API %d 種類 / レイテンシ ×%.1f",
		a.IPErrorCount1m, a.UniqueDeniedMethods5m, a.LatencySpikeRatio)
	if a.DashboardURL != "" {
		fmt.Fprintf(&b, "\n<%s|ダッシュボードで確認>", a.DashboardURL)
	}
	return b.String()
}

// WebhookNotifier は Alert の JSON を署名付きで POST する (受信側は pkg/webhook の Verify で検証する)。
type WebhookNotifier struct {
	URL    string
	Secret string
	Client *http.Client
}

func (n WebhookNotifier) Notify(ctx context.Context, a Alert) error {
	return webhook.Post(ctx, n.Client, n.URL, n.Secret, time.Now(), a)
}

// DefaultCooldown は同じ送信元への通知の最小間隔。
const DefaultCooldown = 10 * time.Minute

// Emitter は判定結果から通知を送る receiver.Emitter。
type Emitter struct {
	Notifiers    []Notifier
	MinLevel     guardrail.Level // この Level 以上を通知する (0 なら Level 3)
	Cooldown     time.Duration   // 0 なら DefaultCooldown
	DashboardURL string          // 通知に載せるダッシュボードの URL (任意)
	Timeout      time.Duration   // 1 件の送信のタイムアウト (0 なら 5 秒)
	Logger       *slog.Logger
	Now          func() time.Time

	mu   sync.Mutex
	last map[string]sent // 送信元 IP -> 最後の通知
}

type sent struct {
	at    time.Time
	level guardrail.Level
}

func (em *Emitter) Emit(ctx context.Context, e receiver.Event) {
	minLevel := em.MinLevel
	if minLevel == 0 {
		minLevel = guardrail.Level3
	}
	if e.Decision.Level < minLevel || len(em.Notifiers) == 0 {
		return
	}
	now := time.Now()
	if em.Now != nil {
		now = em.Now()
	}
	if !em.shouldNotify(e.Signal.GetUserContext().GetClientIp(), e.Decision.Level, now) {
		return
	}

	a := AlertFromEvent(e, now)
	a.DashboardURL = em.DashboardURL
	timeout := em.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var errs []error
	for _, n := range em.Notifiers {
		if err := n.Notify(ctx, a); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		logger := em.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("notify failed", "client_ip", a.ClientIP, "err", err)
	}
}

func (em *Emitter) shouldNotify(ip string, level guardrail.Level, now time.Time) bool {
	cooldown := em.Cooldown
	if cooldown <= 0 {
		cooldown = DefaultCooldown
	}
	em.mu.Lock()
	defer em.mu.Unlock()
	if em.last == nil {
		em.last = make(map[string]sent)
	}
	prev, ok := em.last[ip]
	if ok && now.Sub(prev.at) < cooldown && level <= prev.level {
		return false
	}
	em.last[ip] = sent{at: now, level: level}
	// 古い記録を掃除する (Cooldown を過ぎたものは不要)
	if len(em.last) > 10000 {
		for k, v := range em.last {
			if now.Sub(v.at) >= cooldown {
				delete(em.last, k)
			}
		}
	}
	return true
}
