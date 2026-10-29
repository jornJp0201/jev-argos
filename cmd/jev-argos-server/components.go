package main

// サーバーを構成する部品の組み立て。
//
// [差し替えポイント] jev-argos をライブラリとして自前のサーバーに組み込む場合は、この main パッケージを
// 参考に pkg/ の部品を組み立てる。部品はすべてインターフェース (buffer.Buffer / classifier.Model /
// receiver.Emitter / approval.Store / approval.Executor / action.Blocklist) を介してつながっているため、
// 必要な部分だけ独自の実装に置き換えられる。

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/jornJp0201/jev-argos/pkg/action"
	"github.com/jornJp0201/jev-argos/pkg/api"
	"github.com/jornJp0201/jev-argos/pkg/approval"
	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/db"
	"github.com/jornJp0201/jev-argos/pkg/llm"
	"github.com/jornJp0201/jev-argos/pkg/notify"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
)

const cleanupInterval = 30 * time.Second

// connectRedis は redisURL に接続する。空なら nil を返す (インメモリで動かす)。
func connectRedis(ctx context.Context, redisURL string) (*redis.Client, error) {
	if redisURL == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := redis.NewClient(opts)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("connect redis %s: %w", opts.Addr, err)
	}
	return client, nil
}

// connectPostgres は postgresURL に接続する。空なら nil を返す。
func connectPostgres(ctx context.Context, postgresURL string) (*pgxpool.Pool, error) {
	if postgresURL == "" {
		return nil, nil
	}
	pool, err := pgxpool.New(ctx, postgresURL)
	if err != nil {
		return nil, fmt.Errorf("parse postgres url: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect postgres %s: %w", pool.Config().ConnConfig.Host, err)
	}
	return pool, nil
}

// newBuffer は Redis があれば Redis、無ければインメモリの Sliding Window Buffer を返す。
func newBuffer(ctx context.Context, rdb *redis.Client, logger *slog.Logger) (buffer.Buffer, error) {
	if rdb == nil {
		b := buffer.NewMemoryBuffer()
		b.StartCleanup(ctx, cleanupInterval)
		logger.Info("using in-memory buffer")
		return b, nil
	}
	b, err := buffer.NewRedisBuffer(rdb, buffer.RedisOptions{})
	if err != nil {
		return nil, err
	}
	logger.Info("using redis buffer", "addr", rdb.Options().Addr)
	return b, nil
}

// newBlocklist は Redis があれば Redis (インスタンス間で共有)、無ければインメモリの遮断リストを返す。
func newBlocklist(ctx context.Context, rdb *redis.Client, logger *slog.Logger) action.Blocklist {
	if rdb == nil {
		b := action.NewMemoryBlocklist()
		b.StartSweeper(ctx, 5*time.Second)
		return b
	}
	return action.NewRedisBlocklist(ctx, rdb, "", logger)
}

// newApprovalStore は PostgreSQL があれば PostgreSQL (再起動後も残り、インスタンス間で共有)、
// 無ければメモリの承認キューを返す。
func newApprovalStore(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) (approval.Store, error) {
	if pool == nil {
		logger.Warn("approval queue is in memory; it is lost on restart (set JEV_ARGOS_POSTGRES_URL to persist)")
		return approval.NewMemoryStore(), nil
	}
	s := approval.NewPostgresStore(pool, logger)
	migrateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.Migrate(migrateCtx); err != nil {
		return nil, err
	}
	s.Start(ctx)
	return s, nil
}

// newExecutor は承認されたアクションの実行方法を組み立てる。
//
// [差し替えポイント] アクションの種類ごとの実行方法。既定では block_ip を遮断リストに登録し、
// それ以外はアプリの Webhook (JEV_ARGOS_ACTION_WEBHOOK_URL) に実行を依頼する。
func newExecutor(cfg config, blocklist action.Blocklist) approval.Executor {
	return action.Router{
		Routes: map[approval.ActionType]approval.Executor{
			approval.ActionBlockIP: action.BlocklistExecutor{Blocklist: blocklist, TTL: cfg.blockTTL},
		},
		Fallback: action.WebhookExecutor{URL: cfg.actionWebhookURL, Secret: cfg.actionWebhookSecret},
	}
}

// newEmitters は Level 2 以上のイベントの後続処理を組み立てる (receiver のワーカーで順に実行される)。
//
// [差し替えポイント] 判定後の処理を追加・削除する場合はここを変える (receiver.Emitter を実装して足す)。
func newEmitters(cfg config, stores decisionStores, actions approval.Store, blocklist action.Blocklist, llmEmitter *llm.Emitter, logger *slog.Logger) receiver.Emitters {
	emitters := receiver.Emitters{
		receiver.LogEmitter{Logger: logger},
		action.AutoBlockEmitter{Blocklist: blocklist, TTL: cfg.blockTTL, Logger: logger}, // Level 4 → 自動遮断
		approval.ProposeEmitter{Store: actions, Logger: logger},                          // Level 3 → 承認キュー
	}
	if stores.decisions != nil {
		emitters = append(emitters, db.Emitter{Store: stores.decisions, Logger: logger}) // Level 2〜4 → 判定ログ
	}
	if ns := newNotifiers(cfg); len(ns) > 0 {
		emitters = append(emitters, &notify.Emitter{Notifiers: ns, DashboardURL: cfg.dashboardURL, Logger: logger}) // Level 3〜4 → 通知
		logger.Info("alert notifications enabled", "notifiers", len(ns))
	}
	if llmEmitter != nil {
		emitters = append(emitters, llmEmitter) // Level 2〜4 → LLM 分析 (専用のキューで非同期)
	}
	return emitters
}

// startAPI は管理 HTTP API を起動し、停止用の関数を返す。
func startAPI(cfg config, apiCfg api.Config, serveErr chan<- error, logger *slog.Logger) (func(), error) {
	apiCfg.AdminToken = cfg.adminToken
	if apiCfg.AdminToken == "" {
		apiCfg.AdminToken = rand.Text()
		logger.Warn("admin token not configured; generated a one-time token (set JEV_ARGOS_ADMIN_TOKEN to fix it)", "admin_token", apiCfg.AdminToken)
	}
	apiCfg.Logger = logger
	handler, err := api.NewHandler(apiCfg)
	if err != nil {
		return nil, err
	}
	lis, err := net.Listen("tcp", cfg.apiAddr)
	if err != nil {
		return nil, fmt.Errorf("listen admin api: %w", err)
	}

	// SSE の接続は Shutdown では終わらないため、停止時にリクエストのコンテキストをキャンセルする
	baseCtx, cancelRequests := context.WithCancel(context.Background())
	hs := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
	}
	go func() {
		if err := hs.Serve(lis); !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	logger.Info("admin API listening", "addr", lis.Addr().String())

	return func() {
		cancelRequests()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdownCtx)
	}, nil
}

// decisionStores は判定ログの保存先と、LLM 用の履歴の取得元。
type decisionStores struct {
	decisions db.DecisionStore   // nil なら保存しない
	analyses  db.AnalysisStore   // nil なら保存しない
	history   db.HistoryProvider // nil なら履歴を使わない
	closers   []func()
}

// newDecisionStores は PostgreSQL があれば PostgreSQL、無ければ SQLite (指定時) を判定ログの保存先にする。
// LLM の履歴は Safe View から読み、JEV_ARGOS_LLM_HISTORY_URL があればそのリードレプリカを使う (設計書 6.1)。
func newDecisionStores(ctx context.Context, cfg config, pool *pgxpool.Pool, logger *slog.Logger) (decisionStores, error) {
	var s decisionStores
	switch {
	case pool != nil:
		store := db.NewPostgresStore(pool)
		migrateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := store.Migrate(migrateCtx); err != nil {
			return s, err
		}
		logger.Info("persisting decisions to postgres", "host", pool.Config().ConnConfig.Host)
		s.decisions, s.analyses, s.history = store, store, db.PostgresHistory{Pool: pool}
	case cfg.sqlitePath != "":
		store, err := db.OpenSQLite(ctx, cfg.sqlitePath)
		if err != nil {
			return s, err
		}
		logger.Info("persisting decisions to sqlite", "path", cfg.sqlitePath)
		s.decisions, s.analyses, s.history = store, store, store
		s.closers = append(s.closers, func() { store.Close() })
	default:
		logger.Info("decision logs are not persisted (set JEV_ARGOS_POSTGRES_URL or JEV_ARGOS_SQLITE_PATH)")
	}
	if cfg.llmHistoryURL != "" {
		replica, err := connectPostgres(ctx, cfg.llmHistoryURL)
		if err != nil {
			return s, fmt.Errorf("llm history replica: %w", err)
		}
		s.history = db.PostgresHistory{Pool: replica}
		s.closers = append(s.closers, replica.Close)
	}
	return s, nil
}

func (s decisionStores) close() {
	for _, c := range s.closers {
		c()
	}
}

// newLLMProvider は設定に応じた LLM を返す。"none" なら nil (LLM 分析を行わない)。
//
// [差し替えポイント] 他の LLM (OpenAI 等) を使う場合は llm.Provider を実装し、ここに case を足す。
func newLLMProvider(ctx context.Context, cfg config, logger *slog.Logger) (llm.Provider, error) {
	switch cfg.llmProvider {
	case "none", "":
		logger.Info("llm analysis disabled")
		return nil, nil
	case "ollama":
		url := cfg.ollamaURL
		if url != "" && !strings.Contains(url, "://") {
			url = "http://" + url // OLLAMA_HOST は "127.0.0.1:11434" の形式のことがある
		}
		p := llm.OllamaProvider{BaseURL: url, Model: cfg.llmModel}
		checkOllama(ctx, url, logger)
		logger.Info("llm analysis enabled", "provider", p.Name())
		return p, nil
	case "anthropic":
		p := llm.NewAnthropicProvider(cfg.llmModel) // API キーは ANTHROPIC_API_KEY など SDK の既定の方法で解決する
		logger.Info("llm analysis enabled", "provider", p.Name())
		return p, nil
	}
	return nil, fmt.Errorf("unknown JEV_ARGOS_LLM_PROVIDER %q (ollama | anthropic | none)", cfg.llmProvider)
}

// checkOllama は起動時に Ollama に接続できるかを確認し、できなければ警告だけ出す (起動は続ける)。
func checkOllama(ctx context.Context, url string, logger *slog.Logger) {
	if url == "" {
		url = llm.DefaultOllamaURL
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(url, "/")+"/api/tags", nil)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
		return
	}
	logger.Warn("ollama is not reachable; LLM analyses will fail until it is running (or set JEV_ARGOS_LLM_PROVIDER=none)", "url", url, "err", err)
}

// newMasker は LLM に送る前に IP・ユーザー ID を伏せるかを決める。
func newMasker(cfg config, p llm.Provider) (llm.Masker, error) {
	mask := false
	switch cfg.llmMask {
	case "auto", "":
		mask = !p.Local() // 外部の LLM に送る場合だけ伏せる
	case "always":
		mask = true
	case "never":
	default:
		return nil, fmt.Errorf("unknown JEV_ARGOS_LLM_MASK %q (auto | always | never)", cfg.llmMask)
	}
	if !mask {
		return nil, nil
	}
	key := []byte(cfg.llmMaskKey)
	if len(key) == 0 {
		key = []byte(rand.Text()) // 起動ごとに変わる (仮名は再起動をまたいで一致しない)
	}
	return llm.HashMasker{Key: key}, nil
}

// newNotifiers は Level 3 以上の通知先を組み立てる。
//
// [差し替えポイント] 独自の通知先は notify.Notifier を実装してここに足す。
func newNotifiers(cfg config) []notify.Notifier {
	var ns []notify.Notifier
	if cfg.slackWebhookURL != "" {
		ns = append(ns, notify.SlackNotifier{WebhookURL: cfg.slackWebhookURL})
	}
	if cfg.alertWebhookURL != "" {
		ns = append(ns, notify.WebhookNotifier{URL: cfg.alertWebhookURL, Secret: cfg.alertWebhookSecret})
	}
	return ns
}
