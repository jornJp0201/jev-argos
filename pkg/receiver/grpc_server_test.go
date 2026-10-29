package receiver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
)

type recorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *recorder) Emit(_ context.Context, e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) levels() []guardrail.Level {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []guardrail.Level
	for _, e := range r.events {
		out = append(out, e.Decision.Level)
	}
	return out
}

// startServer は bufconn 上で gRPC サーバーを起動し、クライアントを返す。
// 戻り値の stop はサーバーと Server を停止し、Emitter の処理完了を待つ。
func startServer(t *testing.T, emitter Emitter, opts Options) (jevargosv1.SignalServiceClient, *Server, func()) {
	t.Helper()
	return startServerWithBuffer(t, buffer.NewMemoryBuffer(), emitter, opts)
}

func startServerWithBuffer(t *testing.T, buf buffer.Buffer, emitter Emitter, opts Options) (jevargosv1.SignalServiceClient, *Server, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := NewServer(buf, classifier.NewDefault(), emitter, opts)
	gs := grpc.NewServer()
	jevargosv1.RegisterSignalServiceServer(gs, srv)
	go gs.Serve(lis)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	stop := func() {
		conn.Close()
		gs.GracefulStop()
		srv.Close()
	}
	t.Cleanup(stop)
	return jevargosv1.NewSignalServiceClient(conn), srv, stop
}

func sig(ip, method string, status int32, latencyMs int64) *jevargosv1.SecuritySignal {
	return &jevargosv1.SecuritySignal{
		SignalId:        fmt.Sprintf("%s-%s-%d", ip, method, status),
		UserContext:     &jevargosv1.UserContext{ClientIp: ip},
		RequestContext:  &jevargosv1.RequestContext{Protocol: "grpc", Method: method},
		ResponseContext: &jevargosv1.ResponseContext{StatusCode: status, LatencyMs: latencyMs},
	}
}

func report(t *testing.T, c jevargosv1.SignalServiceClient, s *jevargosv1.SecuritySignal) *jevargosv1.ReportResponse {
	t.Helper()
	resp, err := c.ReportSignal(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestReportSignal_NormalTrafficIsLevel1(t *testing.T) {
	rec := &recorder{}
	c, _, stop := startServer(t, rec, Options{})

	for range 10 {
		resp := report(t, c, sig("10.0.0.1", "/user.UserService/GetUser", 0, 20))
		if !resp.Accepted || resp.ImmediateActionLevel != 1 {
			t.Fatalf("resp = %+v, want accepted level 1", resp)
		}
	}
	stop()
	if got := rec.levels(); len(got) != 0 {
		t.Errorf("emitted %v, want nothing for level 1", got)
	}
}

func TestReportSignal_ProbingAttackIsBlocked(t *testing.T) {
	rec := &recorder{}
	c, _, stop := startServer(t, rec, Options{})

	// 5 つのメソッドに権限探索 → 合計 30 件の拒否
	var last *jevargosv1.ReportResponse
	for i := range 30 {
		last = report(t, c, sig("203.0.113.9", fmt.Sprintf("/admin.AdminService/M%d", i%5), 7, 15))
	}
	if last.ImmediateActionLevel != 4 {
		t.Errorf("final level = %d, want 4", last.ImmediateActionLevel)
	}
	stop()
	got := rec.levels()
	if len(got) == 0 || got[len(got)-1] != guardrail.Level4 {
		t.Errorf("emitted levels %v, want last to be 4", got)
	}
}

func TestReportSignal_ErrorBurstIsDowngraded(t *testing.T) {
	rec := &recorder{}
	c, _, stop := startServer(t, rec, Options{})

	var last *jevargosv1.ReportResponse
	for range 30 {
		last = report(t, c, sig("198.51.100.7", "/order.OrderService/Create", 13, 15))
	}
	if last.ImmediateActionLevel != 3 {
		t.Errorf("final level = %d, want 3", last.ImmediateActionLevel)
	}
	stop()

	rec.mu.Lock()
	defer rec.mu.Unlock()
	lastEvent := rec.events[len(rec.events)-1]
	if !lastEvent.Decision.Downgraded {
		t.Errorf("last event %+v, want downgraded", lastEvent.Decision)
	}
}

func TestReportSignal_RequiresClientIP(t *testing.T) {
	c, _, _ := startServer(t, &recorder{}, Options{})

	_, err := c.ReportSignal(context.Background(), &jevargosv1.SecuritySignal{SignalId: "no-ip"})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err = %v, want InvalidArgument", err)
	}
}

func TestStreamSignals_SkipsInvalidSignals(t *testing.T) {
	c, _, _ := startServer(t, &recorder{}, Options{})

	stream, err := c.StreamSignals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&jevargosv1.SecuritySignal{SignalId: "no-ip"}); err != nil {
		t.Fatal(err)
	}
	for i := range 30 {
		if err := stream.Send(sig("203.0.113.9", fmt.Sprintf("/m%d", i%5), 7, 15)); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatal(err)
	}
	if resp.Accepted || resp.ImmediateActionLevel != 4 {
		t.Errorf("resp = %+v, want accepted=false (one invalid) and level 4", resp)
	}
}

func TestDispatch_DropsWhenQueueFull(t *testing.T) {
	block := make(chan struct{})
	emitter := EmitterFunc(func(context.Context, Event) { <-block })
	srv := NewServer(buffer.NewMemoryBuffer(), classifier.NewDefault(), emitter, Options{QueueSize: 1, Workers: 1})

	// 1 件目はワーカーが保持、2 件目はキュー、3 件目以降は捨てられる
	for i := range 5 {
		srv.dispatch(Event{Signal: sig("10.0.0.1", fmt.Sprintf("/m%d", i), 7, 1)})
	}
	if got := srv.Dropped(); got < 3 {
		t.Errorf("Dropped = %d, want >= 3", got)
	}
	close(block)
	srv.Close()

	srv.dispatch(Event{Signal: sig("10.0.0.1", "/after-close", 7, 1)}) // Close 後も panic しない
}

func TestEmit_RecoversPanic(t *testing.T) {
	var calls int
	var mu sync.Mutex
	emitter := EmitterFunc(func(context.Context, Event) {
		mu.Lock()
		calls++
		mu.Unlock()
		panic("boom")
	})
	srv := NewServer(buffer.NewMemoryBuffer(), classifier.NewDefault(), emitter, Options{Workers: 1})
	srv.dispatch(Event{Signal: sig("10.0.0.1", "/a", 7, 1)})
	srv.dispatch(Event{Signal: sig("10.0.0.1", "/b", 7, 1)})
	srv.Close()

	if calls != 2 {
		t.Errorf("calls = %d, want 2 (worker must survive panic)", calls)
	}
}

// --- StreamSignals (Phase 2 バッチ受信) ---

// failingBuffer は常にエラーを返す Buffer (Redis 障害の模擬)。
type failingBuffer struct{}

var errBufferDown = errors.New("buffer down")

func (failingBuffer) RecordSignal(context.Context, *jevargosv1.SecuritySignal) error {
	return errBufferDown
}
func (failingBuffer) GetStats(context.Context, string, int) (buffer.WindowStats, error) {
	return buffer.WindowStats{}, errBufferDown
}
func (failingBuffer) GetLatencySpikeRatio(context.Context, string, int64) (float64, error) {
	return 0, errBufferDown
}

var quietLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func sendStream(t *testing.T, c jevargosv1.SignalServiceClient, signals []*jevargosv1.SecuritySignal) *jevargosv1.ReportResponse {
	t.Helper()
	stream, err := c.StreamSignals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range signals {
		if err := stream.Send(s); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func probing(ip string, n int) []*jevargosv1.SecuritySignal {
	var out []*jevargosv1.SecuritySignal
	for i := range n {
		out = append(out, sig(ip, fmt.Sprintf("/admin.AdminService/M%d", i%5), 7, 15))
	}
	return out
}

func TestStreamSignals_Empty(t *testing.T) {
	c, _, _ := startServer(t, &recorder{}, Options{})

	resp := sendStream(t, c, nil)
	if !resp.Accepted || resp.ImmediateActionLevel != 0 {
		t.Errorf("resp = %+v, want accepted with level 0", resp)
	}
}

func TestStreamSignals_ReportsMaxLevelAcrossIPs(t *testing.T) {
	rec := &recorder{}
	c, _, stop := startServer(t, rec, Options{})

	signals := append(probing("203.0.113.9", 30), sig("10.0.0.1", "/user.UserService/GetUser", 0, 20))
	resp := sendStream(t, c, signals)
	if !resp.Accepted || resp.ImmediateActionLevel != 4 {
		t.Errorf("resp = %+v, want accepted with max level 4", resp)
	}
	stop()
	if got := rec.levels(); len(got) == 0 {
		t.Error("want level 2+ events emitted from stream")
	}
}

func TestReportSignal_BufferFailureIsUnavailable(t *testing.T) {
	c, _, _ := startServerWithBuffer(t, failingBuffer{}, &recorder{}, Options{Logger: quietLogger})

	_, err := c.ReportSignal(context.Background(), sig("10.0.0.1", "/a", 0, 10))
	if status.Code(err) != codes.Unavailable {
		t.Errorf("err = %v, want Unavailable", err)
	}
}

func TestStreamSignals_BufferFailureDoesNotAbortStream(t *testing.T) {
	c, _, _ := startServerWithBuffer(t, failingBuffer{}, &recorder{}, Options{Logger: quietLogger})

	resp := sendStream(t, c, probing("203.0.113.9", 10))
	if resp.Accepted || resp.ImmediateActionLevel != 0 {
		t.Errorf("resp = %+v, want accepted=false with level 0", resp)
	}
}

// Redis を共有する 2 台のサーバー: A にバッチ送信した探索行為が、B での判定にも反映される。
func TestStreamSignals_RedisSharedAcrossServers(t *testing.T) {
	mr := miniredis.RunT(t)
	newRedisBuffer := func() buffer.Buffer {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { client.Close() })
		b, err := buffer.NewRedisBuffer(client, buffer.RedisOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	serverA, _, _ := startServerWithBuffer(t, newRedisBuffer(), &recorder{}, Options{})
	serverB, _, _ := startServerWithBuffer(t, newRedisBuffer(), &recorder{}, Options{})

	resp := sendStream(t, serverA, probing("203.0.113.9", 29))
	if !resp.Accepted {
		t.Fatalf("stream resp = %+v, want accepted", resp)
	}
	last := report(t, serverB, sig("203.0.113.9", "/admin.AdminService/M4", 7, 15))
	if last.ImmediateActionLevel != 4 {
		t.Errorf("server B level = %d, want 4 (stats shared via Redis)", last.ImmediateActionLevel)
	}
}
