package client

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
	"github.com/jev-argos/jev-argos/pkg/action"
	"github.com/jev-argos/jev-argos/pkg/buffer"
	"github.com/jev-argos/jev-argos/pkg/classifier"
	"github.com/jev-argos/jev-argos/pkg/receiver"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// controlPlane は本物の受信サーバーと遮断リスト配信を bufconn 上で動かす。
type controlPlane struct {
	conn      *grpc.ClientConn
	blocklist *action.MemoryBlocklist
	mu        sync.Mutex
	events    []receiver.Event
}

func (c *controlPlane) observed() []receiver.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]receiver.Event(nil), c.events...)
}

func startControlPlane(t *testing.T) *controlPlane {
	t.Helper()
	cp := &controlPlane{blocklist: action.NewMemoryBlocklist()}
	srv := receiver.NewServer(buffer.NewMemoryBuffer(), classifier.NewDefault(), receiver.Emitters{}, receiver.Options{
		Logger: quiet,
		Observer: func(e receiver.Event) {
			cp.mu.Lock()
			cp.events = append(cp.events, e)
			cp.mu.Unlock()
		},
	})
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	jevargosv1.RegisterSignalServiceServer(gs, srv)
	jevargosv1.RegisterControlServiceServer(gs, &action.ControlServer{Blocklist: cp.blocklist})
	go gs.Serve(lis)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(); gs.Stop(); srv.Close() })
	cp.conn = conn
	return cp
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUnaryServerInterceptor(t *testing.T) {
	cp := startControlPlane(t)
	r := NewReporter(cp.conn, ReporterOptions{})
	defer r.Close(context.Background())

	// アプリの gRPC サーバー (標準のヘルスチェックサービスを「アプリ」として使う)
	lis := bufconn.Listen(1 << 20)
	app := grpc.NewServer(grpc.ChainUnaryInterceptor(UnaryServerInterceptor(r, Options{
		SourceService: "go-bff",
		UserID:        func(context.Context) string { return "user-42" },
	})))
	healthpb.RegisterHealthServer(app, health.NewServer())
	go app.Serve(lis)
	defer app.Stop()
	conn, _ := grpc.NewClient("passthrough:///app",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUserAgent("go-test"))
	defer conn.Close()

	if _, err := healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{Service: "missing"}); status.Code(err) != codes.NotFound {
		t.Fatalf("app error must pass through unchanged: %v", err)
	}
	waitFor(t, func() bool { return len(cp.observed()) == 1 })
	s := cp.observed()[0].Signal
	if s.GetRequestContext().GetMethod() != "/grpc.health.v1.Health/Check" || s.GetResponseContext().GetStatusCode() != int32(codes.NotFound) ||
		s.GetUserContext().GetUserId() != "user-42" || s.GetSourceService() != "go-bff" || s.GetUserContext().GetUserAgent() == "" {
		t.Errorf("signal = %v", s)
	}
}

func TestMiddleware_RoutePatternAndStatus(t *testing.T) {
	cp := startControlPlane(t)
	r := NewReporter(cp.conn, ReporterOptions{})
	defer r.Close(context.Background())

	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{id}", func(w http.ResponseWriter, req *http.Request) { fmt.Fprint(w, req.PathValue("id")) })
	mux.HandleFunc("DELETE /admin/users/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	ts := httptest.NewServer(Middleware(r, Options{SourceService: "go-bff"})(mux))
	defer ts.Close()

	http.Get(ts.URL + "/users/42")
	req, _ := http.NewRequest("DELETE", ts.URL+"/admin/users/7", nil)
	http.DefaultClient.Do(req)
	http.Get(ts.URL + "/nope")

	waitFor(t, func() bool { return len(cp.observed()) == 3 })
	got := map[string]int32{}
	for _, e := range cp.observed() {
		got[e.Signal.GetRequestContext().GetMethod()] = e.Signal.GetResponseContext().GetStatusCode()
		if e.Signal.GetRequestContext().GetProtocol() != "http" || e.Signal.GetUserContext().GetClientIp() != "127.0.0.1" {
			t.Errorf("signal = %v", e.Signal)
		}
	}
	want := map[string]int32{"GET /users/{id}": 0, "DELETE /admin/users/{id}": 7, "GET (unmatched)": 5}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("methods = %v, want %v", got, want)
	}
}

func TestReporter_BatchModeUsesStreamSignals(t *testing.T) {
	cp := startControlPlane(t)
	var mu sync.Mutex
	var maxLevel int32
	r := NewReporter(cp.conn, ReporterOptions{
		Batch: true, BatchSize: 10, FlushInterval: 50 * time.Millisecond,
		OnResponse: func(resp *jevargosv1.ReportResponse, _ *jevargosv1.SecuritySignal) {
			mu.Lock()
			maxLevel = max(maxLevel, resp.GetImmediateActionLevel())
			mu.Unlock()
		},
	})
	for i := range 30 {
		r.Report(newSignal(Options{SourceService: "batch"}, context.Background(), "grpc", fmt.Sprintf("/admin.Admin/Op%d", i%5), "203.0.113.9", "", 7, time.Millisecond))
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := r.Stats(); st.Sent != 30 || st.Failed != 0 {
		t.Errorf("stats = %+v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	if maxLevel != 4 {
		t.Errorf("max level from batches = %d, want 4", maxLevel)
	}
	if n := len(cp.observed()); n != 30 {
		t.Errorf("observed = %d", n)
	}
}

func TestReporter_DropsWhenFullAndAfterClose(t *testing.T) {
	cp := startControlPlane(t)
	r := NewReporter(cp.conn, ReporterOptions{Batch: true, QueueSize: 1, FlushInterval: time.Hour, BatchSize: 1000})
	for range 5 {
		r.Report(&jevargosv1.SecuritySignal{})
	}
	r.Close(context.Background())
	r.Report(&jevargosv1.SecuritySignal{})
	if st := r.Stats(); st.Dropped < 4 {
		t.Errorf("stats = %+v, want drops", st)
	}
}

func TestBlocklistWatcher_EnforcedByMiddlewareAndInterceptor(t *testing.T) {
	cp := startControlPlane(t)
	r := NewReporter(cp.conn, ReporterOptions{})
	defer r.Close(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := NewBlocklistWatcher(ctx, cp.conn, quiet)
	waitFor(t, w.Ready)

	cp.blocklist.Block(context.Background(), action.Entry{TargetType: action.TargetIP, Target: "127.0.0.1", ExpiresAt: time.Now().Add(time.Minute)})
	waitFor(t, func() bool { return w.IsBlocked("::ffff:127.0.0.1") })

	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x", func(http.ResponseWriter, *http.Request) { called = true })
	ts := httptest.NewServer(Middleware(r, Options{SourceService: "go-bff", Blocklist: w})(mux))
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 || called {
		t.Errorf("status=%d handler called=%v", resp.StatusCode, called)
	}

	interceptor := UnaryServerInterceptor(r, Options{Blocklist: w})
	_, err = interceptor(peerCtx("127.0.0.1:5555"), nil, &grpc.UnaryServerInfo{FullMethod: "/a.A/B"}, func(context.Context, any) (any, error) {
		t.Error("handler must not run for blocked IP")
		return nil, nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("grpc err = %v", err)
	}

	cp.blocklist.Unblock(context.Background(), action.TargetIP, "127.0.0.1")
	waitFor(t, func() bool { return !w.IsBlocked("127.0.0.1") })
}
