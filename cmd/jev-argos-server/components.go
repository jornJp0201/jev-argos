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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/jev-argos/jev-argos/pkg/action"
	"github.com/jev-argos/jev-argos/pkg/api"
	"github.com/jev-argos/jev-argos/pkg/approval"
	"github.com/jev-argos/jev-argos/pkg/buffer"
	"github.com/jev-argos/jev-argos/pkg/db"
	"github.com/jev-argos/jev-argos/pkg/receiver"
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
func newEmitters(ctx context.Context, cfg config, pool *pgxpool.Pool, actions approval.Store, blocklist action.Blocklist, logger *slog.Logger) (receiver.Emitters, error) {
	emitters := receiver.Emitters{
		receiver.LogEmitter{Logger: logger},
		action.AutoBlockEmitter{Blocklist: blocklist, TTL: cfg.blockTTL, Logger: logger}, // Level 4 → 自動遮断
		approval.ProposeEmitter{Store: actions, Logger: logger},                          // Level 3 → 承認キュー
	}
	if pool != nil {
		store := db.NewPostgresStore(pool)
		migrateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := store.Migrate(migrateCtx); err != nil {
			return nil, err
		}
		logger.Info("persisting decisions to postgres", "host", pool.Config().ConnConfig.Host)
		emitters = append(emitters, db.Emitter{Store: store, Logger: logger})
	}
	return emitters, nil
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
