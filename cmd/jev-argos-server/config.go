package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// config はサーバーの設定。すべてフラグか環境変数で指定できる (フラグが優先)。
// 一覧と説明は README.md の「設定」を参照。
type config struct {
	addr        string
	apiAddr     string
	adminToken  string
	redisURL    string
	postgresURL string
	demo        bool

	// 遮断 (pkg/action)
	blockTTL            time.Duration
	actionWebhookURL    string
	actionWebhookSecret string
}

// envOr は環境変数 key が設定されていればその値 (空文字を含む)、無ければ def を返す。
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s=%q (e.g. 15m): %v\n", key, v, err)
		os.Exit(2)
	}
	return d
}

// parseConfig はフラグと環境変数から設定を読む。healthcheck は -healthcheck が指定されたか。
func parseConfig() (cfg config, healthcheck bool) {
	flag.StringVar(&cfg.addr, "addr", envOr("JEV_ARGOS_GRPC_ADDR", ":50051"), "gRPC listen address (or JEV_ARGOS_GRPC_ADDR)")
	flag.StringVar(&cfg.apiAddr, "api-addr", envOr("JEV_ARGOS_API_ADDR", "127.0.0.1:8080"), "admin HTTP API listen address; disabled if empty (or JEV_ARGOS_API_ADDR)")
	flag.BoolVar(&healthcheck, "healthcheck", false, "check the health of a running server and exit (0: healthy, 1: unhealthy)")
	flag.StringVar(&cfg.adminToken, "admin-token", os.Getenv("JEV_ARGOS_ADMIN_TOKEN"), "bearer token for the admin API; generated at startup if empty")
	flag.BoolVar(&cfg.demo, "demo", os.Getenv("JEV_ARGOS_DEMO") == "true", "run a demo with synthetic signals (or JEV_ARGOS_DEMO=true)")
	flag.StringVar(&cfg.redisURL, "redis-url", os.Getenv("JEV_ARGOS_REDIS_URL"), "Redis URL for the shared buffer and blocklist (e.g. redis://localhost:6379/0); in-memory if empty")
	flag.StringVar(&cfg.postgresURL, "postgres-url", os.Getenv("JEV_ARGOS_POSTGRES_URL"), "PostgreSQL URL for decision logs and approval queue (e.g. postgres://user@localhost:5432/jevargos)")
	flag.DurationVar(&cfg.blockTTL, "block-ttl", envDuration("JEV_ARGOS_BLOCK_TTL", 15*time.Minute), "duration of automatic / approved IP blocks (or JEV_ARGOS_BLOCK_TTL)")
	flag.StringVar(&cfg.actionWebhookURL, "action-webhook-url", os.Getenv("JEV_ARGOS_ACTION_WEBHOOK_URL"), "URL that receives approved non-IP actions (session revoke, account suspend, ...)")
	flag.StringVar(&cfg.actionWebhookSecret, "action-webhook-secret", os.Getenv("JEV_ARGOS_ACTION_WEBHOOK_SECRET"), "HMAC secret for signing action webhooks")
	flag.Parse()

	// デモは既定で空きポートのローカルのみで受け付ける。アドレスを明示すればそのアドレスで待ち受ける (コンテナ用)
	_, addrSet := os.LookupEnv("JEV_ARGOS_GRPC_ADDR")
	flag.Visit(func(f *flag.Flag) { addrSet = addrSet || f.Name == "addr" })
	if cfg.demo && !addrSet && !healthcheck {
		cfg.addr = "127.0.0.1:0"
	}
	return cfg, healthcheck
}
