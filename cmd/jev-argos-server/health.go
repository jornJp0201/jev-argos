package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
)

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
