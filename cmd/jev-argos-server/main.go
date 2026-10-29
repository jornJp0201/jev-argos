// Command jev-argos-server は jev-argos コントロールサーバーのエントリポイント。
//
//	jev-argos-server [flags]         gRPC サーバー (シグナル受信) と管理 HTTP API を起動する
//	jev-argos-server -demo [flags]   疑似シグナルを送って判定パイプラインの動作を確認する。
//	                                 管理 API が有効なら、デモ後もダッシュボード確認用に起動し続ける
//	jev-argos-server -healthcheck    起動中のサーバーの gRPC / HTTP ヘルスチェックを行い、終了コードで結果を返す
//	                                 (シェルの無いコンテナイメージの HEALTHCHECK 用)
//
// 設定はフラグまたは環境変数で行う (詳細は README.md):
//   - -addr (JEV_ARGOS_GRPC_ADDR): gRPC の待受アドレス。
//
// 設計書 7.2 に従い、指定が無ければ外部依存なし (Zero Config) で動く:
//   - -redis-url (JEV_ARGOS_REDIS_URL): Redis バッファを使い、複数インスタンスで統計を共有する。未指定ならインメモリ。
//   - -postgres-url (JEV_ARGOS_POSTGRES_URL): Level 2〜4 の判定ログを PostgreSQL に保存する。未指定なら保存しない。
//   - -api-addr (JEV_ARGOS_API_ADDR): 管理 HTTP API (承認待ちアクション) の待受アドレス。空なら無効。
//   - -admin-token (JEV_ARGOS_ADMIN_TOKEN): 管理 API の Bearer トークン。未指定なら起動ごとに生成してログに出す。
//   - -demo (JEV_ARGOS_DEMO=true): 起動時に疑似シグナルを流す。
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
	"github.com/jev-argos/jev-argos/pkg/action"
	"github.com/jev-argos/jev-argos/pkg/api"
	"github.com/jev-argos/jev-argos/pkg/classifier"
	"github.com/jev-argos/jev-argos/pkg/receiver"
)

func main() {
	cfg, healthcheck := parseConfig()
	if healthcheck {
		if err := checkHealth(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		fmt.Println("healthy")
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	if err := run(cfg, logger); err != nil {
		logger.Error("jev-argos-server failed", "err", err)
		os.Exit(1)
	}
}

func run(cfg config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- 外部サービス (どちらも任意) ---
	rdb, err := connectRedis(ctx, cfg.redisURL)
	if err != nil {
		return err
	}
	if rdb != nil {
		defer rdb.Close()
	}
	pool, err := connectPostgres(ctx, cfg.postgresURL)
	if err != nil {
		return err
	}
	if pool != nil {
		defer pool.Close()
	}

	// --- 部品の組み立て ---
	buf, err := newBuffer(ctx, rdb, logger)
	if err != nil {
		return err
	}
	blocklist := newBlocklist(ctx, rdb, logger)
	actions, err := newApprovalStore(ctx, pool, logger)
	if err != nil {
		return err
	}
	emitters, err := newEmitters(ctx, cfg, pool, actions, blocklist, logger)
	if err != nil {
		return err
	}

	// --- gRPC: シグナル受信・遮断リスト配信・ヘルスチェック ---
	srv := receiver.NewServer(buf, classifier.NewDefault(), emitters, receiver.Options{Logger: logger})
	gs := grpc.NewServer()
	jevargosv1.RegisterSignalServiceServer(gs, srv)
	jevargosv1.RegisterControlServiceServer(gs, &action.ControlServer{Blocklist: blocklist})
	// 標準の gRPC Health Checking Protocol (Kubernetes の grpc プローブ・grpc_health_probe 用)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(gs, hs)
	hs.SetServingStatus(jevargosv1.SignalService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)

	lis, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return err
	}
	serveErr := make(chan error, 2)
	go func() { serveErr <- gs.Serve(lis) }()
	logger.Info("jev-argos-server listening", "addr", lis.Addr().String())

	// --- 管理 HTTP API ---
	stopAPI := func() {}
	if cfg.apiAddr != "" {
		apiCfg := api.Config{Store: actions, Executor: newExecutor(cfg, blocklist), Blocklist: blocklist}
		if stopAPI, err = startAPI(cfg, apiCfg, serveErr, logger); err != nil {
			gs.Stop()
			return err
		}
	}

	if cfg.demo {
		err = runDemo(ctx, lis.Addr().String())
	}
	if err == nil && (!cfg.demo || cfg.apiAddr != "") {
		if cfg.demo {
			logger.Info("demo finished; serving admin API until interrupted (Ctrl+C)")
		}
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
		case err = <-serveErr:
		}
	}

	hs.Shutdown() // 停止中は NOT_SERVING を返し、新しいトラフィックを受けないようにする
	stopAPI()
	gs.GracefulStop()
	srv.Close()
	if n := srv.Dropped(); n > 0 {
		logger.Warn("events dropped before reaching emitter", "count", n)
	}
	return err
}
