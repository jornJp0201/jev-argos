package action

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jev-argos/jev-argos/pkg/approval"
	"github.com/jev-argos/jev-argos/pkg/guardrail"
	"github.com/jev-argos/jev-argos/pkg/receiver"
	"github.com/jev-argos/jev-argos/pkg/webhook"
)

// BlocklistExecutor は承認された block_ip を遮断リストに登録する approval.Executor。
type BlocklistExecutor struct {
	Blocklist Blocklist
	TTL       time.Duration // 0 なら DefaultBlockTTL
	Now       func() time.Time
}

func (x BlocklistExecutor) Execute(ctx context.Context, a approval.Action) error {
	if a.ProposedAction != approval.ActionBlockIP {
		return fmt.Errorf("blocklist executor: unsupported action %q", a.ProposedAction)
	}
	now := time.Now
	if x.Now != nil {
		now = x.Now
	}
	ttl := x.TTL
	if ttl <= 0 {
		ttl = DefaultBlockTTL
	}
	t := now()
	return x.Blocklist.Block(ctx, Entry{
		TargetType: TargetIP,
		Target:     a.Target,
		Reason:     fmt.Sprintf("承認 (%s): %s", a.DecidedBy, a.Reason),
		Source:     SourceApproval,
		CreatedAt:  t,
		ExpiresAt:  t.Add(ttl),
	})
}

// WebhookExecutor は承認されたアクションの実行をアプリへ Webhook で依頼する approval.Executor。
//
// [差し替えポイント] セッション無効化・アカウント停止 / 削除・データ削除・縮小運転への切り替え・サービス停止は、
// 実行方法がアプリごとに異なるため jev-argos は直接実行しない。アプリ側に受信エンドポイントを用意し、
// JEV_ARGOS_ACTION_WEBHOOK_URL に指定すること。リクエストは次の形式:
//
//	POST <URL>
//	Content-Type: application/json
//	X-Jev-Argos-Timestamp: <UNIX 秒>
//	X-Jev-Argos-Signature: sha256=<hex(HMAC-SHA256(secret, timestamp + "." + body))>
//
//	{"type": "action.approved", "action": { ...approval.Action の JSON... }}
//
// 受信側は署名とタイムスタンプ (例: 5 分以内) を検証し、2xx を返すこと。2xx 以外は実行失敗として記録される。
// 署名の検証は pkg/webhook の Verify / VerifyRequest (Go) を参考にする。
type WebhookExecutor struct {
	URL    string
	Secret string // HMAC 署名の鍵。空なら署名しない (本番では必ず設定すること)
	Client *http.Client
	Now    func() time.Time
}

// WebhookPayload は WebhookExecutor / Notifier が送る JSON。
type WebhookPayload struct {
	Type   string          `json:"type"`
	Action approval.Action `json:"action"`
}

func (x WebhookExecutor) Execute(ctx context.Context, a approval.Action) error {
	if x.URL == "" {
		return errors.New("webhook executor: URL is not configured (set JEV_ARGOS_ACTION_WEBHOOK_URL)")
	}
	now := time.Now
	if x.Now != nil {
		now = x.Now
	}
	return webhook.Post(ctx, x.Client, x.URL, x.Secret, now(), WebhookPayload{Type: "action.approved", Action: a})
}

// Router はアクションの種類ごとに Executor を振り分ける approval.Executor。
//
// [差し替えポイント] アクションの種類ごとの実行方法はここで決まる。既定 (cmd/jev-argos-server) では
// block_ip → BlocklistExecutor、それ以外 → WebhookExecutor。独自の実行方法を使う場合は
// Routes に approval.Executor の実装を登録する。
type Router struct {
	Routes   map[approval.ActionType]approval.Executor
	Fallback approval.Executor // Routes に無い種類 (nil ならエラー)
}

func (r Router) Execute(ctx context.Context, a approval.Action) error {
	if x, ok := r.Routes[a.ProposedAction]; ok {
		return x.Execute(ctx, a)
	}
	if r.Fallback != nil {
		return r.Fallback.Execute(ctx, a)
	}
	return fmt.Errorf("no executor for action %q", a.ProposedAction)
}

// AutoBlockEmitter は Level 4 の判定で送信元 IP を自動遮断する receiver.Emitter。
// 設計書 6.2 で自動化が許可された「一時的なアクセス遮断」に当たる (期限付きで自動的に解除される)。
type AutoBlockEmitter struct {
	Blocklist Blocklist
	TTL       time.Duration // 0 なら DefaultBlockTTL
	Logger    *slog.Logger
	Now       func() time.Time
}

var _ receiver.Emitter = AutoBlockEmitter{}

func (em AutoBlockEmitter) Emit(ctx context.Context, e receiver.Event) {
	if e.Decision.Level != guardrail.Level4 {
		return
	}
	now := time.Now
	if em.Now != nil {
		now = em.Now
	}
	ttl := em.TTL
	if ttl <= 0 {
		ttl = DefaultBlockTTL
	}
	t := now()
	err := em.Blocklist.Block(ctx, Entry{
		TargetType: TargetIP,
		Target:     e.Signal.GetUserContext().GetClientIp(),
		Reason:     fmt.Sprintf("Level 4 (S=%.2f, C=%.2f) による自動遮断", e.Assessment.Score, e.Assessment.Confidence),
		Source:     SourceLevel4,
		CreatedAt:  t,
		ExpiresAt:  t.Add(ttl),
	})
	if err != nil {
		logger := em.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("auto block failed", "client_ip", e.Signal.GetUserContext().GetClientIp(), "err", err)
	}
}
