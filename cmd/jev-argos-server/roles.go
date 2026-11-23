package main

// 役割 (all / receiver / worker) ごとの部品の組み立て。

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
	"github.com/jornJp0201/jev-argos/pkg/action"
	"github.com/jornJp0201/jev-argos/pkg/api"
	"github.com/jornJp0201/jev-argos/pkg/approval"
	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
	"github.com/jornJp0201/jev-argos/pkg/db"
	"github.com/jornJp0201/jev-argos/pkg/events"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/llm"
	"github.com/jornJp0201/jev-argos/pkg/notify"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
	"github.com/jornJp0201/jev-argos/pkg/stream"
)

// 役割。
const (
	roleAll      = "all"
	roleReceiver = "receiver"
	roleWorker   = "worker"
)

// workers は判定後の処理 (承認キュー・判定ログ・LLM 分析・通知) と、ダッシュボードへの配信。all と worker で使う。
type workers struct {
	actions  approval.Store
	stores   decisionStores
	proposer *approval.ProposeEmitter
	hub      *events.Hub
	lanes    []receiver.Lane // all ではプロセス内のキュー、worker では consumer group になる
}

func newWorkers(ctx context.Context, cfg config, pool *pgxpool.Pool, logger *slog.Logger) (*workers, error) {
	actions, err := newApprovalStore(ctx, pool, logger)
	if err != nil {
		return nil, err
	}
	stores, err := newDecisionStores(ctx, cfg, pool, logger)
	if err != nil {
		return nil, err
	}
	w := &workers{actions: actions, stores: stores, hub: events.NewHub(0, logger)}
	w.hub.Start(ctx) // Level 1 の判定を 1 秒ごとに集計して配信する

	var llmEmitter *llm.Emitter
	provider, err := newLLMProvider(ctx, cfg, logger)
	if err != nil {
		stores.close()
		return nil, err
	}
	if provider != nil {
		masker, err := newMasker(cfg, provider)
		if err != nil {
			stores.close()
			return nil, err
		}
		sinks := []llm.Sink{
			llm.ApprovalSink{Store: actions, Logger: logger},
			llm.SinkFunc(func(_ context.Context, e receiver.Event, a approval.Analysis) { w.hub.PublishAnalysis(e, a) }),
		}
		if stores.analyses != nil {
			sinks = append(sinks, llm.DBSink{Store: stores.analyses, Logger: logger})
		}
		llmEmitter = &llm.Emitter{
			Analyzer: &llm.Analyzer{Provider: provider, Masker: masker, History: stores.history},
			Sinks:    sinks,
			Logger:   logger,
		}
		llmEmitter.Start(ctx)
	}
	w.proposer = &approval.ProposeEmitter{Store: actions, Logger: logger, Window: approval.DefaultProposeWindow}
	w.proposer.Start(ctx)
	w.lanes = workerLanes(cfg, stores, w.proposer, llmEmitter, logger)
	return w, nil
}

// receiverLanes は判定サーバーで行う後続処理。自動遮断は最優先なので、役割を分けても判定サーバーで行う。
func receiverLanes(cfg config, blocklist action.Blocklist, logger *slog.Logger) []receiver.Lane {
	return []receiver.Lane{
		// Level 4 → 自動遮断。Level 4 だけが入るため、Level 2・3 がどれだけ来ても埋まらない
		{Name: "block", Emitter: action.AutoBlockEmitter{Blocklist: blocklist, TTL: cfg.blockTTL, Logger: logger}, MinLevel: guardrail.Level4, Workers: 2},
		{Name: "log", Emitter: receiver.LogEmitter{Logger: logger}, MinLevel: guardrail.Level2},
	}
}

// workerLanes は判定後の残りの処理。後続処理ごとに専用のキュー (worker では consumer group) を持つため、
// どれかが遅れても (例: Slack の応答が遅い) 他は止まらない。
//
// [差し替えポイント] 判定後の処理を追加・削除する場合はここを変える (receiver.Emitter を実装して Lane を足す)。
func workerLanes(cfg config, stores decisionStores, proposer *approval.ProposeEmitter, llmEmitter *llm.Emitter, logger *slog.Logger) []receiver.Lane {
	lanes := []receiver.Lane{
		// Level 3 → 承認キュー (同じ送信元の提案はまとめて書く)
		{Name: "approval", Emitter: proposer, MinLevel: guardrail.Level3},
	}
	// Level 2〜4 → 判定ログと LLM 分析。分析は判定ログの行を更新するため、同じ Lane で判定ログを先に渡す
	// (どちらもキューに積むだけなので、この Lane は遅くならない)
	var persist receiver.Emitters
	if stores.decisions != nil {
		persist = append(persist, db.Emitter{Store: stores.decisions, Logger: logger})
	}
	if llmEmitter != nil {
		persist = append(persist, llmEmitter) // 専用のキューで非同期に分析する
	}
	if len(persist) > 0 {
		lanes = append(lanes, receiver.Lane{Name: "persist", Emitter: persist, MinLevel: guardrail.Level2})
	}
	if ns := newNotifiers(cfg); len(ns) > 0 {
		// Level 3〜4 → 通知。外部への HTTP 呼び出しで遅いため、ワーカーを多めにする
		lanes = append(lanes, receiver.Lane{Name: "notify", Emitter: &notify.Emitter{Notifiers: ns, DashboardURL: cfg.dashboardURL, Logger: logger}, MinLevel: guardrail.Level3, Workers: 4})
		logger.Info("alert notifications enabled", "notifiers", len(ns))
	}
	return lanes
}

// signalServer はシグナルの受信 (gRPC) と判定。all と receiver で使う。
type signalServer struct {
	srv  *receiver.Server
	gs   *grpc.Server
	hs   *health.Server
	addr string
}

func startSignalServer(cfg config, buf buffer.Buffer, blocklist action.Blocklist, lanes []receiver.Lane, observer func(receiver.Event), serveErr chan<- error, logger *slog.Logger) (*signalServer, error) {
	guard := guardrail.New(guardrail.Guardrail{
		BlockScore:      cfg.blockScore,
		BlockConfidence: cfg.blockConfidence,
		Level3Score:     cfg.level3Score,
		Level2Score:     cfg.level2Score,
	})
	srv := receiver.NewServer(buf, classifier.NewDefault(), nil, receiver.Options{Lanes: lanes, Logger: logger, Observer: observer, Guardrail: &guard})
	gs := grpc.NewServer()
	jevargosv1.RegisterSignalServiceServer(gs, srv)
	jevargosv1.RegisterControlServiceServer(gs, &action.ControlServer{Blocklist: blocklist})
	// 標準の gRPC Health Checking Protocol (Kubernetes の grpc プローブ・grpc_health_probe 用)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(gs, hs)
	hs.SetServingStatus(jevargosv1.SignalService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)

	lis, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		srv.Close()
		return nil, err
	}
	go func() { serveErr <- gs.Serve(lis) }()
	logger.Info("jev-argos-server listening", "addr", lis.Addr().String())
	return &signalServer{srv: srv, gs: gs, hs: hs, addr: lis.Addr().String()}, nil
}

// startConsumers は worker の後続処理ごとに consumer group で Redis Streams を読み始め、
// ダッシュボードへの配信用にすべての判定を受け取る。戻り値は停止して読んだ分を処理し終えるまで待つ関数。
func startConsumers(ctx context.Context, rdb *redis.Client, w *workers, logger *slog.Logger) (func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	host, _ := os.Hostname()
	consumerName := fmt.Sprintf("%s-%d", host, os.Getpid())
	for _, l := range w.lanes {
		opts := stream.ConsumerOptions{Group: l.Name, Emitter: l.Emitter, MinLevel: l.MinLevel, Logger: logger}
		if l.Name == "persist" {
			if f, ok := w.stores.decisions.(interface{ Flush(context.Context) }); ok {
				opts.Flush = f.Flush // 判定ログを書いてから処理済みにする
			}
		}
		// 遅い処理 (通知) は同じ group の Consumer を増やして並行に処理する (Consumer の名前は group 内で一意にする)
		for i := range max(1, l.Workers) {
			opts.Name = fmt.Sprintf("%s-%d", consumerName, i)
			c, err := stream.NewConsumer(rdb, opts)
			if err != nil {
				cancel()
				wg.Wait()
				return nil, err
			}
			wg.Add(1)
			go func() { defer wg.Done(); c.Run(ctx) }()
		}
		logger.Info("consuming judgments", "group", l.Name, "consumers", max(1, l.Workers))
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		stream.Tail(ctx, rdb, "", stream.Handlers{
			Event:   w.hub.PublishDecision,
			Summary: func(s stream.Summary) { w.hub.AddLevel1(s.Count, s.ScoreSum) },
		}, func(err error) { logger.Error("tail stream failed", "err", err) })
	}()
	return func() { cancel(); wg.Wait() }, nil
}

// adminHandler は管理 API (承認キュー・遮断リスト・ダッシュボードへの配信) を組み立てる。all と worker で使う。
func adminHandler(cfg config, w *workers, blocklist action.Blocklist, sig *signalServer, logger *slog.Logger) (http.Handler, error) {
	apiCfg := api.Config{
		Store:     w.actions,
		Executor:  newExecutor(cfg, blocklist),
		Blocklist: blocklist,
		Routes:    map[string]http.HandlerFunc{"GET /api/events/stream": w.hub.HandleStream},
		Logger:    logger,
	}
	if sig != nil && cfg.ingestToken != "" {
		apiCfg.PublicRoutes = ingestRoutes(cfg, sig)
	}
	apiCfg.AdminToken = adminToken(cfg, logger)
	return api.NewHandler(apiCfg)
}

// ingestOnlyHandler は receiver の HTTP: ヘルスチェックと、HTTP でのシグナル受信 (指定時) だけを提供する。
func ingestOnlyHandler(cfg config, sig *signalServer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	if cfg.ingestToken != "" {
		for pattern, h := range ingestRoutes(cfg, sig) {
			mux.Handle(pattern, h)
		}
	}
	return mux
}

// ingestRoutes は HTTP でのシグナル受信 (送信専用トークン。管理 API のトークンとは別)。
func ingestRoutes(cfg config, sig *signalServer) map[string]http.Handler {
	h := sig.srv.HTTPHandler(cfg.ingestToken)
	return map[string]http.Handler{"/api/signals": h, "/api/signals/": h}
}

func parseRole(role string) (string, error) {
	switch role {
	case roleAll, roleReceiver, roleWorker:
		return role, nil
	case "":
		return roleAll, nil
	}
	return "", fmt.Errorf("unknown JEV_ARGOS_ROLE %q (all | receiver | worker)", role)
}
