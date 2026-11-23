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
//
// 判定と後続処理を別のプロセスに分けることもできる (-role / JEV_ARGOS_ROLE、Redis が必須):
//   - all (既定): 1 つのプロセスで受信・判定・後続処理をすべて行う
//   - receiver: シグナルの受信・判定・自動遮断だけを行い、判定結果を Redis Streams に流す。状態を持たないため台数で増やせる
//   - worker: Redis Streams を読み、承認キュー・判定ログ・LLM 分析・通知・ダッシュボードへの配信を行う
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
	"github.com/jornJp0201/jev-argos/pkg/stream"
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

	// --- 外部サービス (どちらも任意。役割を分ける場合は Redis が必須) ---
	rdb, err := connectRedis(ctx, cfg.redisURL)
	if err != nil {
		return err
	}
	if rdb != nil {
		defer rdb.Close()
	}
	if cfg.role != roleAll && rdb == nil {
		return fmt.Errorf("JEV_ARGOS_ROLE=%s requires JEV_ARGOS_REDIS_URL (judgments are passed through Redis Streams)", cfg.role)
	}
	pool, err := connectPostgres(ctx, cfg.postgresURL)
	if err != nil {
		return err
	}
	if pool != nil {
		defer pool.Close()
	}
	logger.Info("starting jev-argos-server", "role", cfg.role)

	blocklist := newBlocklist(ctx, rdb, logger)
	serveErr := make(chan error, 2)

	// --- 後続処理 (承認キュー・判定ログ・LLM・通知) とダッシュボードへの配信: all / worker ---
	var w *workers
	if cfg.role != roleReceiver {
		if w, err = newWorkers(ctx, cfg, pool, logger); err != nil {
			return err
		}
		defer w.stores.close() // 判定ログの残りを保存してから閉じる (pool.Close より先)
	}

	// --- シグナルの受信と判定: all / receiver ---
	var sig *signalServer
	var publisher *stream.Publisher
	if cfg.role != roleWorker {
		lanes := receiverLanes(cfg, blocklist, logger)
		var observer func(receiver.Event)
		if cfg.role == roleAll {
			lanes = append(lanes, w.lanes...)
			observer = w.hub.PublishDecision
		} else {
			// 後続処理は worker に任せる: Level 2 以上の判定と Level 1 の件数を Redis Streams に流す
			publisher = stream.NewPublisher(rdb, stream.PublisherOptions{Logger: logger})
			lanes = append(lanes, receiver.Lane{Name: "stream", Emitter: publisher, MinLevel: guardrail.Level2})
			observer = publisher.Observe
		}
		buf, err := newBuffer(ctx, rdb, logger)
		if err != nil {
			return err
		}
		if sig, err = startSignalServer(cfg, buf, blocklist, lanes, observer, serveErr, logger); err != nil {
			return err
		}
	}

	// --- worker: Redis Streams を後続処理ごとの consumer group で読む ---
	stopConsumers := func() {}
	if cfg.role == roleWorker {
		if stopConsumers, err = startConsumers(ctx, rdb, w, logger); err != nil {
			return err
		}
	}

	// --- 管理 HTTP API ---
	stopAPI := func() {}
	if cfg.apiAddr != "" {
		var handler http.Handler
		if cfg.role == roleReceiver {
			handler = ingestOnlyHandler(cfg, sig) // 管理 API とダッシュボードは worker が提供する
		} else if handler, err = adminHandler(cfg, w, blocklist, sig, logger); err != nil {
			return err
		}
		if stopAPI, err = startAPI(cfg, handler, serveErr, logger); err != nil {
			if sig != nil {
				sig.gs.Stop()
			}
			return err
		}
	}

	if cfg.demo && sig != nil {
		err = runDemo(ctx, sig.addr)
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

	// 停止の順序: 新しい受信を止める → 判定を処理し終える → 後続処理に渡し終える → 後続処理を書き出す
	if sig != nil {
		sig.hs.Shutdown() // 停止中は NOT_SERVING を返し、新しいトラフィックを受けないようにする
	}
	stopAPI()
	if sig != nil {
		sig.gs.GracefulStop()
		sig.srv.Close()
		for name, n := range sig.srv.DroppedByLane() {
			if n > 0 {
				logger.Warn("events dropped before reaching emitter", "lane", name, "count", n)
			}
		}
	}
	if publisher != nil {
		publisher.Close() // 残りの判定と Level 1 の件数を Redis Streams に追加する
	}
	stopConsumers() // 読んだ分を処理し終えるまで待つ
	if w != nil {
		// 判定の処理を止めた後に、まとめている提案を書く (判定ログの残りは stores.close で保存する)
		flushCtx, cancelFlush := context.WithTimeout(context.Background(), 5*time.Second)
		w.proposer.Flush(flushCtx)
		cancelFlush()
	}
	return err
}
