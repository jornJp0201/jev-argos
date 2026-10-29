package client

import (
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
)

// BlockChecker は遮断中かを判定できるもの (通常は *BlocklistWatcher)。
type BlockChecker interface {
	IsBlocked(ip string) bool
}

// Options はインターセプター / ミドルウェアの設定。
type Options struct {
	// SourceService はシグナルの送信元サービス名 (例: "main-bff")。
	SourceService string
	// Blocklist を指定すると、遮断中の IP からのリクエストを拒否する (gRPC: PERMISSION_DENIED、HTTP: 403)。
	Blocklist BlockChecker
	// TrustProxyHeaders は x-forwarded-for / x-real-ip を信頼するか (既定 false)。
	// 信頼できるロードバランサーの背後でのみ true にする。直接公開されたサーバーで true にすると、
	// 攻撃者がヘッダーで IP を偽装し判定を回避できる。
	TrustProxyHeaders bool
	// UserID はリクエストからユーザー ID を取り出す。
	// [差し替えポイント] 認証方式はアプリごとに異なるため、認証ミドルウェアが ctx に入れた値などから返す。
	UserID func(ctx context.Context) string
	// Route は HTTP のルートのパターンを返す。既定は Go 1.22+ の ServeMux が設定する r.Pattern。
	// [差し替えポイント] chi / gorilla/mux などのルーターを使う場合は、そのルーターのパターンを返す関数を指定する。
	// 実際の URL ではなくパターン (例: "/users/{id}") を返すこと (URL 中の ID 等を送らないため)。
	Route func(r *http.Request) string
	// OnBlocked は遮断した HTTP リクエストへの応答。既定は 403 と {"error":"forbidden"}。
	// [差し替えポイント] 独自のエラー形式を返す場合に指定する。
	OnBlocked func(w http.ResponseWriter, r *http.Request)
}

func (o Options) userID(ctx context.Context) string {
	if o.UserID == nil {
		return ""
	}
	return o.UserID(ctx)
}

func newSignal(o Options, ctx context.Context, protocol, method, ip, ua string, code int32, latency time.Duration) *jevargosv1.SecuritySignal {
	return &jevargosv1.SecuritySignal{
		SignalId:      rand.Text(),
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		SourceService: o.SourceService,
		UserContext: &jevargosv1.UserContext{
			UserId:    o.userID(ctx),
			ClientIp:  normalizeIP(ip),
			UserAgent: ua,
		},
		RequestContext:  &jevargosv1.RequestContext{Protocol: protocol, Method: method},
		ResponseContext: &jevargosv1.ResponseContext{StatusCode: code, LatencyMs: latency.Milliseconds()},
	}
}

// normalizeIP は "::ffff:1.2.3.4" (IPv4-mapped IPv6) を "1.2.3.4" にする。
func normalizeIP(ip string) string {
	if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return v4.String()
		}
		return parsed.String()
	}
	return ip
}

func firstForwarded(xff string) string {
	first, _, _ := strings.Cut(xff, ",")
	return strings.TrimSpace(first)
}

// --- gRPC ---

func grpcClientIP(ctx context.Context, o Options) (ip, ua string) {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get("user-agent"); len(v) > 0 {
		ua = v[0]
	}
	if o.TrustProxyHeaders {
		if v := md.Get("x-forwarded-for"); len(v) > 0 && firstForwarded(v[0]) != "" {
			return firstForwarded(v[0]), ua
		}
		if v := md.Get("x-real-ip"); len(v) > 0 && v[0] != "" {
			return v[0], ua
		}
	}
	if p, ok := peer.FromContext(ctx); ok {
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err == nil {
			return host, ua
		}
		return p.Addr.String(), ua
	}
	return "", ua
}

var errBlocked = status.Error(codes.PermissionDenied, "blocked by jev-argos")

// UnaryServerInterceptor は単項 RPC のシグナルを送る gRPC サーバー用インターセプター。
func UnaryServerInterceptor(r *Reporter, o Options) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		ip, ua := grpcClientIP(ctx, o)
		var resp any
		var err error
		if o.Blocklist != nil && o.Blocklist.IsBlocked(normalizeIP(ip)) {
			err = errBlocked // 遮断中の送信元: ハンドラーへ進ませない (この RPC もシグナルとして送る)
		} else {
			resp, err = handler(ctx, req)
		}
		r.Report(newSignal(o, ctx, "grpc", info.FullMethod, ip, ua, int32(status.Code(err)), time.Since(start)))
		return resp, err
	}
}

// StreamServerInterceptor はストリーミング RPC のシグナルを送る gRPC サーバー用インターセプター。
func StreamServerInterceptor(r *Reporter, o Options) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		ip, ua := grpcClientIP(ss.Context(), o)
		var err error
		if o.Blocklist != nil && o.Blocklist.IsBlocked(normalizeIP(ip)) {
			err = errBlocked
		} else {
			err = handler(srv, ss)
		}
		r.Report(newSignal(o, ss.Context(), "grpc", info.FullMethod, ip, ua, int32(status.Code(err)), time.Since(start)))
		return err
	}
}

// --- net/http ---

// Middleware は net/http のミドルウェアを返す。ServeMux (ルーター) の外側に巻く:
//
//	http.ListenAndServe(":8080", client.Middleware(reporter, opts)(mux))
//
// HTTP ステータスは gRPC のステータスコードに変換して送る (403 → PERMISSION_DENIED など)。
func Middleware(r *Reporter, o Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			ip := httpClientIP(req, o)
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			if o.Blocklist != nil && o.Blocklist.IsBlocked(normalizeIP(ip)) {
				if o.OnBlocked != nil {
					o.OnBlocked(rec, req)
				} else {
					rec.Header().Set("Content-Type", "application/json")
					rec.WriteHeader(http.StatusForbidden)
					rec.Write([]byte(`{"error":"forbidden"}`))
				}
			} else {
				next.ServeHTTP(rec, req)
			}
			route := ""
			if o.Route != nil {
				route = o.Route(req)
			} else {
				route = req.Pattern // ServeMux がルーティング時に設定する (例: "GET /users/{id}")
			}
			if route == "" {
				route = "(unmatched)"
			}
			if !strings.Contains(route, " ") {
				route = req.Method + " " + route
			}
			r.Report(newSignal(o, req.Context(), "http", route, ip, req.UserAgent(), HTTPStatusToGRPC(rec.status), time.Since(start)))
		})
	}
}

func httpClientIP(r *http.Request, o Options) string {
	if o.TrustProxyHeaders {
		if ip := firstForwarded(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
		if ip := strings.TrimSpace(r.Header.Get("X-Real-Ip")); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Unwrap は http.ResponseController が元の ResponseWriter の機能 (Flush 等) を使えるようにする。
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// HTTPStatusToGRPC は HTTP ステータスを gRPC のステータスコードに変換する (Node.js アダプターと同じ対応表)。
func HTTPStatusToGRPC(code int) int32 {
	if code < 400 {
		return int32(codes.OK)
	}
	switch code {
	case 400:
		return int32(codes.InvalidArgument)
	case 401:
		return int32(codes.Unauthenticated)
	case 403:
		return int32(codes.PermissionDenied)
	case 404:
		return int32(codes.NotFound)
	case 408, 504:
		return int32(codes.DeadlineExceeded)
	case 409:
		return int32(codes.AlreadyExists)
	case 429:
		return int32(codes.ResourceExhausted)
	case 501:
		return int32(codes.Unimplemented)
	case 502, 503:
		return int32(codes.Unavailable)
	}
	if code < 500 {
		return int32(codes.FailedPrecondition)
	}
	return int32(codes.Internal)
}
