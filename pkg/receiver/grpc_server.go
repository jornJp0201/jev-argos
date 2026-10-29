// Package receiver は gRPC Signal Receiver (設計書 2 章 / 3 章) を提供する。
//
// 受信したシグナルは Sliding Window Buffer → Jev Classifier → Guardrail の順に
// 同期的に判定し (数マイクロ秒〜数ミリ秒)、結果のレベルを ReportResponse で即時に返す。
// Level 2 以上の後続処理 (LLM 分析・通知・遮断) は時間がかかるため、
// キュー経由でワーカーに渡し、RPC の応答を待たせない。
package receiver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
	"github.com/jev-argos/jev-argos/pkg/buffer"
	"github.com/jev-argos/jev-argos/pkg/classifier"
	"github.com/jev-argos/jev-argos/pkg/guardrail"
)

// Event は 1 シグナルの判定結果一式。
type Event struct {
	Signal     *jevargosv1.SecuritySignal
	Features   buffer.Features
	Assessment classifier.Assessment
	Decision   guardrail.Decision
}

// Emitter は Level 2 以上のイベントの後続処理 (LLM 非同期分析・Slack 通知・遮断コマンド発行) を行う。
// ワーカー goroutine から呼ばれる。
type Emitter interface {
	Emit(ctx context.Context, e Event)
}

// EmitterFunc は関数を Emitter として使うためのアダプター。
type EmitterFunc func(ctx context.Context, e Event)

func (f EmitterFunc) Emit(ctx context.Context, e Event) { f(ctx, e) }

// Emitters は複数の Emitter に順にイベントを渡す (例: ログ出力 + DB 保存)。
type Emitters []Emitter

func (es Emitters) Emit(ctx context.Context, e Event) {
	for _, em := range es {
		em.Emit(ctx, e)
	}
}

// Options は Server の設定。
type Options struct {
	QueueSize int // Emitter へのキュー長。満杯時はイベントを捨てる (既定 1024)
	Workers   int // Emitter を呼ぶワーカー数 (既定 4)
	Logger    *slog.Logger
}

// Server は SignalService の実装。
type Server struct {
	jevargosv1.UnimplementedSignalServiceServer

	buf     buffer.Buffer
	cls     *classifier.Classifier
	emitter Emitter
	logger  *slog.Logger

	mu      sync.RWMutex // closed と events の close を保護する
	closed  bool
	events  chan Event
	workers sync.WaitGroup
	dropped atomic.Uint64
}

var _ jevargosv1.SignalServiceServer = (*Server)(nil)

// NewServer は Server を作成し、Emitter のワーカーを起動する。
// 使い終わったら Close を呼ぶこと。
func NewServer(buf buffer.Buffer, cls *classifier.Classifier, emitter Emitter, opts Options) *Server {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 1024
	}
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Server{
		buf:     buf,
		cls:     cls,
		emitter: emitter,
		logger:  opts.Logger,
		events:  make(chan Event, opts.QueueSize),
	}
	for range opts.Workers {
		s.workers.Add(1)
		go s.work()
	}
	return s
}

// ReportSignal は単一シグナルを受信して判定し、対応レベルを返す。
func (s *Server) ReportSignal(ctx context.Context, signal *jevargosv1.SecuritySignal) (*jevargosv1.ReportResponse, error) {
	e, err := s.Evaluate(ctx, signal)
	if err != nil {
		return nil, err
	}
	return &jevargosv1.ReportResponse{
		Accepted:             true,
		ImmediateActionLevel: int32(e.Decision.Level),
	}, nil
}

// StreamSignals はシグナルのストリームを受信して判定する (Phase 2 のバッチ送信用)。
// 不正なシグナルや判定に失敗したシグナルは読み飛ばして残りの処理を続ける。
// 応答の accepted は全件を受け付けたかどうか、immediate_action_level は受け付けた中での最大レベル。
func (s *Server) StreamSignals(stream jevargosv1.SignalService_StreamSignalsServer) error {
	accepted := true
	var maxLevel guardrail.Level
	for {
		signal, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&jevargosv1.ReportResponse{
				Accepted:             accepted,
				ImmediateActionLevel: int32(maxLevel),
			})
		}
		if err != nil {
			return err
		}
		e, err := s.Evaluate(stream.Context(), signal)
		if err != nil {
			accepted = false
			continue
		}
		maxLevel = max(maxLevel, e.Decision.Level)
	}
}

// Evaluate はシグナルをバッファに記録して判定し、Level 2 以上なら Emitter に渡す。
func (s *Server) Evaluate(ctx context.Context, signal *jevargosv1.SecuritySignal) (Event, error) {
	if signal.GetUserContext().GetClientIp() == "" {
		// 送信元不明のシグナルを 1 つのバケットに集約すると、無関係な通信同士が合算されて誤判定を招く。
		return Event{}, status.Error(codes.InvalidArgument, "user_context.client_ip is required")
	}

	features, err := buffer.Observe(ctx, s.buf, signal)
	if err != nil {
		// バッファ (Redis 等) の障害。送信側は Fire-and-Forget のため、メイン処理には影響しない。
		s.logger.Error("buffer unavailable", "signal_id", signal.GetSignalId(), "err", err)
		return Event{}, status.Error(codes.Unavailable, "signal buffer unavailable")
	}
	assessment := s.cls.Classify(features)
	e := Event{
		Signal:     signal,
		Features:   features,
		Assessment: assessment,
		Decision:   guardrail.Decide(assessment),
	}
	if e.Decision.Level >= guardrail.Level2 {
		s.dispatch(e)
	}
	return e, nil
}

// Dropped はキュー満杯または Close 後のために Emitter に渡せなかったイベント数を返す。
func (s *Server) Dropped() uint64 {
	return s.dropped.Load()
}

// Close は新しいイベントの受付を止め、キューに残ったイベントを処理し終えるまで待つ。
// gRPC サーバーを停止した後に呼ぶこと。
func (s *Server) Close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.events)
	}
	s.mu.Unlock()
	s.workers.Wait()
}

func (s *Server) dispatch(e Event) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		s.dropped.Add(1)
		return
	}
	select {
	case s.events <- e:
	default:
		// 後続処理が詰まっても判定と応答は止めない。
		s.dropped.Add(1)
		s.logger.Warn("emitter queue full, event dropped", "signal_id", e.Signal.GetSignalId())
	}
}

func (s *Server) work() {
	defer s.workers.Done()
	for e := range s.events {
		s.emit(e)
	}
}

func (s *Server) emit(e Event) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("emitter panicked", "signal_id", e.Signal.GetSignalId(), "panic", r)
		}
	}()
	s.emitter.Emit(context.Background(), e)
}

// LogEmitter はイベントをログに出力するだけの Emitter。
// LLM 分析・Slack 通知・遮断コマンド発行の実装が揃うまでの暫定実装。
type LogEmitter struct {
	Logger *slog.Logger
}

func (l LogEmitter) Emit(_ context.Context, e Event) {
	logger := l.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("jev-argos action",
		"level", int(e.Decision.Level),
		"downgraded", e.Decision.Downgraded,
		"score", e.Assessment.Score,
		"confidence", e.Assessment.Confidence,
		"client_ip", e.Signal.GetUserContext().GetClientIp(),
		"method", e.Signal.GetRequestContext().GetMethod(),
		"ip_error_count_1m", e.Features.IPErrorCount1m,
		"unique_denied_methods_5m", e.Features.UniqueDeniedMethods5m,
		"latency_spike_ratio", e.Features.LatencySpikeRatio,
	)
}
