// Package events はダッシュボード向けに判定結果と LLM 分析をリアルタイム配信する。
//
//	GET /api/events/stream (Server-Sent Events)
//	  event: decision  … 1 件の判定 (Level 1 を含む全件)
//	  event: analysis  … LLM 分析の結果
//
// 接続直後に直近の判定 (Backlog 件) を送るため、ダッシュボードは開いた直後から概況を表示できる。
// 受信が追いつかない購読者への配信は捨てる (判定の処理を遅らせないため)。
package events

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/jev-argos/jev-argos/pkg/api"
	"github.com/jev-argos/jev-argos/pkg/approval"
	"github.com/jev-argos/jev-argos/pkg/receiver"
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

// AnalysisMessage はダッシュボードに送る LLM 分析。
type AnalysisMessage struct {
	SignalID string            `json:"signal_id"`
	ClientIP string            `json:"client_ip"`
	Analysis approval.Analysis `json:"analysis"`
}

// DefaultBacklog は接続直後に送る直近の判定の件数。
const DefaultBacklog = 500

// Hub は判定と分析の配信元。
type Hub struct {
	mu      sync.Mutex
	subs    map[chan Message]struct{}
	backlog []Message // 直近の判定 (古い順)
	size    int
	logger  *slog.Logger
}

func NewHub(backlog int, logger *slog.Logger) *Hub {
	if backlog <= 0 {
		backlog = DefaultBacklog
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Hub{subs: make(map[chan Message]struct{}), size: backlog, logger: logger}
}

var marshalSignal = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}

// PublishDecision は判定を配信する。receiver.Options.Observer に渡す。
func (h *Hub) PublishDecision(e receiver.Event) {
	sig, err := marshalSignal.Marshal(e.Signal)
	if err != nil {
		h.logger.Error("marshal signal", "err", err)
		return
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
		return
	}
	h.publish(Message{Name: "decision", Data: data}, true)
}

// PublishAnalysis は LLM 分析を配信する (llm.SinkFunc として Emitter に渡す)。
func (h *Hub) PublishAnalysis(e receiver.Event, a approval.Analysis) {
	data, err := json.Marshal(AnalysisMessage{SignalID: e.Signal.GetSignalId(), ClientIP: e.Signal.GetUserContext().GetClientIp(), Analysis: a})
	if err != nil {
		return
	}
	h.publish(Message{Name: "analysis", Data: data}, false)
}

func (h *Hub) publish(m Message, keep bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if keep {
		if len(h.backlog) >= h.size {
			h.backlog = append(h.backlog[:0], h.backlog[len(h.backlog)-h.size+1:]...)
		}
		h.backlog = append(h.backlog, m)
	}
	for ch := range h.subs {
		select {
		case ch <- m:
		default:
		}
	}
}

// Subscribe は直近の判定と、以降の配信を受け取るチャネルを返す。
func (h *Hub) Subscribe() (backlog []Message, updates <-chan Message, cancel func()) {
	ch := make(chan Message, 1024)
	h.mu.Lock()
	backlog = append([]Message(nil), h.backlog...)
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return backlog, ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
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
