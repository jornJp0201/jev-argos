package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
)

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
