// Package events はダッシュボード向けに判定結果と LLM 分析をリアルタイム配信する。
//
//	GET /api/events/stream (Server-Sent Events)
//	  event: decision  … Level 2 以上の 1 件の判定
//	  event: summary   … Level 1 の判定の件数 (1 秒ごとに集計。0 件の秒は送らない)
//	  event: analysis  … LLM 分析の結果
//
// 接続直後に直近の判定と分析 (Backlog 件) と、直近 5 分の Level 1 の集計を送るため、
// ダッシュボードは開いた直後から概況と分析結果を表示できる。
// 受信が追いつかない購読者への配信は捨てる (判定の処理を遅らせないため)。
//
// PublishDecision は全シグナルの判定のたびに同期的に呼ばれるため、次の 3 点で判定を遅らせないようにしている。
//   - 大半を占める Level 1 は 1 件ずつ送らず、ロックを取らないカウンターで数えて 1 秒ごとにまとめる
//   - 購読者がいなければ JSON にせず、直近分として判定をそのまま保持する (接続されたときに JSON にする)
//   - 直近分はリングバッファで持ち、件数が上限に達してもコピーしない
package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/jornJp0201/jev-argos/pkg/api"
	"github.com/jornJp0201/jev-argos/pkg/approval"
	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
)

// Message は SSE の 1 イベント。
type Message struct {
	Name string
	Data json.RawMessage
}

// Decision はダッシュボードに送る判定 (フィールド名は proto と同じ snake_case)。
type Decision struct {
	Signal     json.RawMessage `json:"signal"`
	Features   Features        `json:"features"`
	Score      float64         `json:"score"`
	Confidence float64         `json:"confidence"`
	Level      int             `json:"level"`
	Downgraded bool            `json:"downgraded"`
}

type Features struct {
	IPErrorCount1m        int     `json:"ip_error_count_1m"`
	UniqueDeniedMethods5m int     `json:"unique_denied_methods_5m"`
	LatencySpikeRatio     float64 `json:"latency_spike_ratio"`
}

// Summary はダッシュボードに送る Level 1 の判定の集計 (Timestamp までの 1 区間分)。
type Summary struct {
	Timestamp string  `json:"timestamp"` // 区間の終わり (RFC 3339)
	Count     int64   `json:"count"`
	ScoreSum  float64 `json:"score_sum"` // 平均スコアの算出用
}

// AnalysisMessage はダッシュボードに送る LLM 分析。
type AnalysisMessage struct {
	SignalID string            `json:"signal_id"`
	ClientIP string            `json:"client_ip"`
	Analysis approval.Analysis `json:"analysis"`
}

const (
	// DefaultBacklog は接続直後に送る直近の判定 (Level 2 以上) と分析の件数。
	DefaultBacklog = 500
	// SummaryInterval は Level 1 の集計を送る間隔。
	SummaryInterval = time.Second
	// summaryBacklog は接続直後に送る Level 1 の集計の区間数 (ダッシュボードの概況の 5 分ぶん)。
	summaryBacklog = 300
	// scoreScale はスコアの合計をロックなしで足すための固定小数点の倍率 (S ∈ [0, 4])。
	scoreScale = 1e6
	// countScale は件数を固定小数点で数えるための倍率 (間引かれて届いたシグナルは 1/sample_rate 件ぶんと数えるため)。
	countScale = 1000
)

// entry は直近分の 1 件。購読者がいない間に届いた判定は data を持たず、接続されたときに JSON にする。
type entry struct {
	name  string
	data  json.RawMessage
	event receiver.Event
}

// Hub は判定と分析の配信元。Level 1 の集計を送るため、Start を呼ぶこと。
type Hub struct {
	mu        sync.Mutex
	subs      map[chan Message]struct{}
	nsubs     atomic.Int32 // len(subs)。ロックを取らずに購読者の有無を見るため
	backlog   ring[entry]  // 直近の判定と分析
	summaries ring[Message]
	logger    *slog.Logger

	level1Count atomic.Int64  // 件数 × countScale
	level1Score atomic.Uint64 // スコアの合計 × scoreScale
}

func NewHub(backlog int, logger *slog.Logger) *Hub {
	if backlog <= 0 {
		backlog = DefaultBacklog
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Hub{
		subs:      make(map[chan Message]struct{}),
		backlog:   newRing[entry](backlog),
		summaries: newRing[Message](summaryBacklog),
		logger:    logger,
	}
}

// Start は Level 1 の集計を SummaryInterval ごとに配信する goroutine を起動する。
// ctx がキャンセルされると停止する。
func (h *Hub) Start(ctx context.Context) {
	ticker := time.NewTicker(SummaryInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				h.flushSummary(now)
			}
		}
	}()
}

var marshalSignal = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}

// PublishDecision は判定を配信する。receiver.Options.Observer に渡す。
func (h *Hub) PublishDecision(e receiver.Event) {
	if e.Decision.Level < guardrail.Level2 {
		// アダプターが正常な応答を間引いて送った場合も、送られなかった分を含めた件数を配信する
		w := buffer.SampleWeight(e.Signal)
		h.level1Count.Add(int64(math.Round(w * countScale)))
		h.level1Score.Add(uint64(math.Round(e.Assessment.Score * w * scoreScale)))
		return
	}
	var data json.RawMessage
	if h.nsubs.Load() > 0 {
		var ok bool
		if data, ok = h.marshalDecision(e); !ok {
			return
		}
	}
	h.publish(entry{name: "decision", data: data, event: e})
}

// PublishAnalysis は LLM 分析を配信する (llm.SinkFunc として Emitter に渡す)。
func (h *Hub) PublishAnalysis(e receiver.Event, a approval.Analysis) {
	data, err := json.Marshal(AnalysisMessage{SignalID: e.Signal.GetSignalId(), ClientIP: e.Signal.GetUserContext().GetClientIp(), Analysis: a})
	if err != nil {
		return
	}
	h.publish(entry{name: "analysis", data: data})
}

func (h *Hub) marshalDecision(e receiver.Event) (json.RawMessage, bool) {
	sig, err := marshalSignal.Marshal(e.Signal)
	if err != nil {
		h.logger.Error("marshal signal", "err", err)
		return nil, false
	}
	data, err := json.Marshal(Decision{
		Signal: sig,
		Features: Features{
			IPErrorCount1m:        e.Features.IPErrorCount1m,
			UniqueDeniedMethods5m: e.Features.UniqueDeniedMethods5m,
			LatencySpikeRatio:     e.Features.LatencySpikeRatio,
		},
		Score:      e.Assessment.Score,
		Confidence: e.Assessment.Confidence,
		Level:      int(e.Decision.Level),
		Downgraded: e.Decision.Downgraded,
	})
	if err != nil {
		return nil, false
	}
	return data, true
}

func (h *Hub) publish(en entry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if en.data == nil && len(h.subs) > 0 {
		// 購読者の有無を確かめた直後に接続された場合
		data, ok := h.marshalDecision(en.event)
		if !ok {
			return
		}
		en.data = data
	}
	h.backlog.push(en)
	h.broadcast(Message{Name: en.name, Data: en.data})
}

// AddLevel1 は他のプロセスで数えた Level 1 の件数とスコアの合計を、次の集計に加える
// (判定サーバーを分けて動かす場合に、Redis Streams で届いた集計を足す)。
func (h *Hub) AddLevel1(count, scoreSum float64) {
	h.level1Count.Add(int64(math.Round(count * countScale)))
	h.level1Score.Add(uint64(math.Round(scoreSum * scoreScale)))
}

// flushSummary はこれまでに数えた Level 1 の件数を、now までの 1 区間の集計として配信する。
func (h *Hub) flushSummary(now time.Time) {
	count := h.level1Count.Swap(0)
	score := h.level1Score.Swap(0)
	if count == 0 {
		return
	}
	data, err := json.Marshal(Summary{
		Timestamp: now.UTC().Format(time.RFC3339Nano),
		Count:     int64(math.Round(float64(count) / countScale)),
		ScoreSum:  float64(score) / scoreScale,
	})
	if err != nil {
		return
	}
	m := Message{Name: "summary", Data: data}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.summaries.push(m)
	h.broadcast(m)
}

// broadcast は h.mu を保持した状態で呼ぶ。
func (h *Hub) broadcast(m Message) {
	for ch := range h.subs {
		select {
		case ch <- m:
		default:
		}
	}
}

// Subscribe は直近の集計・判定・分析と、以降の配信を受け取るチャネルを返す。
func (h *Hub) Subscribe() (backlog []Message, updates <-chan Message, cancel func()) {
	ch := make(chan Message, 1024)
	h.mu.Lock()
	summaries := h.summaries.items()
	entries := h.backlog.items()
	h.subs[ch] = struct{}{}
	h.nsubs.Store(int32(len(h.subs)))
	h.mu.Unlock()

	// JSON にしていない判定はロックの外で変換する (判定の処理を待たせないため)
	backlog = summaries
	for _, en := range entries {
		if en.data == nil {
			data, ok := h.marshalDecision(en.event)
			if !ok {
				continue
			}
			en.data = data
		}
		backlog = append(backlog, Message{Name: en.name, Data: en.data})
	}
	var once sync.Once
	return backlog, ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			h.nsubs.Store(int32(len(h.subs)))
			h.mu.Unlock()
			close(ch)
		})
	}
}

// HandleStream は GET /api/events/stream のハンドラー (管理 API の認証の内側に置く)。
func (h *Hub) HandleStream(w http.ResponseWriter, r *http.Request) {
	backlog, updates, cancel := h.Subscribe()
	defer cancel()
	api.ServeSSE(w, r, h.logger, func(m Message) (string, any) { return m.Name, m.Data }, backlog, updates)
}

// ring は直近 size 件を保持するリングバッファ。上限に達したら最も古い要素を上書きする。
type ring[T any] struct {
	buf  []T
	next int
	full bool
}

func newRing[T any](size int) ring[T] {
	return ring[T]{buf: make([]T, size)}
}

func (r *ring[T]) push(v T) {
	r.buf[r.next] = v
	r.next++
	if r.next == len(r.buf) {
		r.next, r.full = 0, true
	}
}

// items は保持している要素を古い順に返す (コピー)。
func (r *ring[T]) items() []T {
	if !r.full {
		return append([]T(nil), r.buf[:r.next]...)
	}
	out := make([]T, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	return append(out, r.buf[:r.next]...)
}
