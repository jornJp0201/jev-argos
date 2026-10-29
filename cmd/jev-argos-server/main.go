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
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/jackc/pgx/v5/pgxpool"
	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
	"github.com/jev-argos/jev-argos/pkg/api"
	"github.com/jev-argos/jev-argos/pkg/approval"
	"github.com/jev-argos/jev-argos/pkg/buffer"
	"github.com/jev-argos/jev-argos/pkg/classifier"
	"github.com/jev-argos/jev-argos/pkg/db"
	"github.com/jev-argos/jev-argos/pkg/receiver"
	"github.com/redis/go-redis/v9"
)

const cleanupInterval = 30 * time.Second

type config struct {
	addr        string
	apiAddr     string
	adminToken  string
	redisURL    string
	postgresURL string
	demo        bool
}

// envOr は環境変数 key が設定されていればその値 (空文字を含む)、無ければ def を返す。
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func main() {
	var cfg config
	var healthcheck bool
	flag.StringVar(&cfg.addr, "addr", envOr("JEV_ARGOS_GRPC_ADDR", ":50051"), "gRPC listen address (or JEV_ARGOS_GRPC_ADDR)")
	flag.StringVar(&cfg.apiAddr, "api-addr", envOr("JEV_ARGOS_API_ADDR", "127.0.0.1:8080"), "admin HTTP API listen address; disabled if empty (or JEV_ARGOS_API_ADDR)")
	flag.BoolVar(&healthcheck, "healthcheck", false, "check the health of a running server and exit (0: healthy, 1: unhealthy)")
	flag.StringVar(&cfg.adminToken, "admin-token", os.Getenv("JEV_ARGOS_ADMIN_TOKEN"), "bearer token for the admin API; generated at startup if empty")
	flag.BoolVar(&cfg.demo, "demo", os.Getenv("JEV_ARGOS_DEMO") == "true", "run a demo with synthetic signals (or JEV_ARGOS_DEMO=true)")
	flag.StringVar(&cfg.redisURL, "redis-url", os.Getenv("JEV_ARGOS_REDIS_URL"), "Redis URL for the shared buffer (e.g. redis://localhost:6379/0); in-memory if empty")
	flag.StringVar(&cfg.postgresURL, "postgres-url", os.Getenv("JEV_ARGOS_POSTGRES_URL"), "PostgreSQL URL for decision logs (e.g. postgres://user@localhost:5432/jevargos); not persisted if empty")
	flag.Parse()

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

	// デモは既定で空きポートのローカルのみで受け付ける。アドレスを明示すればそのアドレスで待ち受ける (コンテナ用)
	_, addrSet := os.LookupEnv("JEV_ARGOS_GRPC_ADDR")
	flag.Visit(func(f *flag.Flag) { addrSet = addrSet || f.Name == "addr" })
	if cfg.demo && !addrSet {
		cfg.addr = "127.0.0.1:0"
	}
	if err := run(cfg, logger); err != nil {
		logger.Error("jev-argos-server failed", "err", err)
		os.Exit(1)
	}
}

func run(cfg config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	buf, closeBuf, err := newBuffer(ctx, cfg.redisURL, logger)
	if err != nil {
		return err
	}
	defer closeBuf()

	actions := approval.NewMemoryStore()
	emitter, closeEmitter, err := newEmitter(ctx, cfg.postgresURL, actions, logger)
	if err != nil {
		return err
	}
	defer closeEmitter()

	srv := receiver.NewServer(buf, classifier.NewDefault(), emitter, receiver.Options{Logger: logger})
	gs := grpc.NewServer()
	jevargosv1.RegisterSignalServiceServer(gs, srv)
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

	stopAPI := func() {}
	if cfg.apiAddr != "" {
		if stopAPI, err = startAPI(cfg, actions, serveErr, logger); err != nil {
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

// localAddr は待受アドレスを、同じホストから接続するためのアドレスに変換する (":8080" → "127.0.0.1:8080")。
func localAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

// checkHealth は同じ設定で起動中のサーバーの gRPC ヘルスと (有効なら) 管理 API の /api/healthz を確認する。
func checkHealth(cfg config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	grpcAddr, err := localAddr(cfg.addr)
	if err != nil {
		return fmt.Errorf("grpc addr: %w", err)
	}
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{
		Service: jevargosv1.SignalService_ServiceDesc.ServiceName,
	})
	if err != nil {
		return fmt.Errorf("grpc %s: %w", grpcAddr, err)
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("grpc %s: %s", grpcAddr, resp.GetStatus())
	}

	if cfg.apiAddr == "" {
		return nil
	}
	apiAddr, err := localAddr(cfg.apiAddr)
	if err != nil {
		return fmt.Errorf("api addr: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+apiAddr+"/api/healthz", nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("api %s: %w", apiAddr, err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("api %s: HTTP %d", apiAddr, res.StatusCode)
	}
	return nil
}

// startAPI は管理 HTTP API を起動し、停止用の関数を返す。
func startAPI(cfg config, actions approval.Store, serveErr chan<- error, logger *slog.Logger) (func(), error) {
	token := cfg.adminToken
	if token == "" {
		token = rand.Text()
		logger.Warn("admin token not configured; generated a one-time token (set JEV_ARGOS_ADMIN_TOKEN to fix it)", "admin_token", token)
	}
	handler, err := api.NewHandler(api.Config{Store: actions, AdminToken: token, Logger: logger})
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

// newBuffer は redisURL が空ならインメモリ、指定されていれば Redis のバッファを返す。
func newBuffer(ctx context.Context, redisURL string, logger *slog.Logger) (buffer.Buffer, func(), error) {
	if redisURL == "" {
		b := buffer.NewMemoryBuffer()
		b.StartCleanup(ctx, cleanupInterval)
		logger.Info("using in-memory buffer")
		return b, func() {}, nil
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := redis.NewClient(opts)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("connect redis %s: %w", opts.Addr, err)
	}
	b, err := buffer.NewRedisBuffer(client, buffer.RedisOptions{})
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	logger.Info("using redis buffer", "addr", opts.Addr)
	return b, func() { client.Close() }, nil
}

// newEmitter は Level 2 以上のイベントの後続処理を組み立てる。
// ログ出力と承認待ちアクションの提案は常に行い、postgresURL が指定されていれば判定ログを PostgreSQL にも保存する。
func newEmitter(ctx context.Context, postgresURL string, actions approval.Store, logger *slog.Logger) (receiver.Emitter, func(), error) {
	emitters := receiver.Emitters{
		receiver.LogEmitter{Logger: logger},
		approval.ProposeEmitter{Store: actions, Logger: logger},
	}
	if postgresURL == "" {
		return emitters, func() {}, nil
	}

	pool, err := pgxpool.New(ctx, postgresURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse postgres url: %w", err)
	}
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	store := db.NewPostgresStore(pool)
	if err := store.Migrate(connectCtx); err != nil {
		pool.Close()
		return nil, nil, err
	}
	logger.Info("persisting decisions to postgres", "host", pool.Config().ConnConfig.Host)
	return append(emitters, db.Emitter{Store: store, Logger: logger}), pool.Close, nil
}

// runDemo は代表的な通信パターンの疑似シグナルを送り、各シナリオの最終判定を表示する。
func runDemo(ctx context.Context, addr string) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := jevargosv1.NewSignalServiceClient(conn)

	type scenario struct {
		name    string
		signals []*jevargosv1.SecuritySignal
	}
	var (
		normal, burst, probing, slow []*jevargosv1.SecuritySignal
	)
	for range 20 {
		normal = append(normal, demoSignal("192.0.2.10", "/user.UserService/GetUser", 0, 20))
	}
	for range 30 {
		burst = append(burst, demoSignal("198.51.100.7", "/order.OrderService/Create", 13, 25))
	}
	for i := range 30 {
		probing = append(probing, demoSignal("203.0.113.9", fmt.Sprintf("/admin.AdminService/Op%d", i%5), 7, 15))
	}
	for range 10 {
		slow = append(slow, demoSignal("192.0.2.20", "/report.ReportService/Export", 0, 100))
	}
	slow = append(slow, demoSignal("192.0.2.20", "/report.ReportService/Export", 0, 600))

	scenarios := []scenario{
		{"正常トラフィック (20 件 OK)", normal},
		{"エラー集中 (INTERNAL x30, 単一メソッド)", burst},
		{"権限探索 (PERMISSION_DENIED x30, 5 メソッド)", probing},
		{"レイテンシ急上昇 (平常 100ms → 600ms)", slow},
	}

	fmt.Println("\n=== jev-argos demo: ReportSignal ===")
	for _, sc := range scenarios {
		var resp *jevargosv1.ReportResponse
		for _, s := range sc.signals {
			if resp, err = client.ReportSignal(ctx, s); err != nil {
				return fmt.Errorf("%s: %w", sc.name, err)
			}
		}
		fmt.Printf("  %-44s → level %d\n", sc.name, resp.ImmediateActionLevel)
	}

	fmt.Println("\n=== jev-argos demo: StreamSignals (Phase 2 バッチ送信) ===")
	stream, err := client.StreamSignals(ctx)
	if err != nil {
		return err
	}
	for i := range 30 {
		if err := stream.Send(demoSignal("233.252.0.1", fmt.Sprintf("/payment.PaymentService/Op%d", i%5), 7, 15)); err != nil {
			return err
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}
	fmt.Printf("  %-44s → accepted=%v, max level %d\n\n", "権限探索 30 件をバッチ送信", resp.Accepted, resp.ImmediateActionLevel)
	return nil
}

var demoSeq int

func demoSignal(ip, method string, statusCode int32, latencyMs int64) *jevargosv1.SecuritySignal {
	demoSeq++
	return &jevargosv1.SecuritySignal{
		SignalId:      rand.Text(),
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		SourceService: "demo-bff",
		TraceId:       fmt.Sprintf("trace-%04d", demoSeq),
		UserContext: &jevargosv1.UserContext{
			UserId:    "demo-user",
			UserRole:  "user",
			ClientIp:  ip,
			UserAgent: "jev-argos-demo/0.1",
		},
		RequestContext: &jevargosv1.RequestContext{
			Protocol: "grpc",
			Method:   method,
		},
		ResponseContext: &jevargosv1.ResponseContext{
			StatusCode: statusCode,
			LatencyMs:  latencyMs,
		},
	}
}
