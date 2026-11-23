package main

// /metrics (Prometheus 形式) で出すメトリクスの集め方。

import (
	"context"

	"github.com/redis/go-redis/v9"

	"github.com/jornJp0201/jev-argos/pkg/metrics"
	"github.com/jornJp0201/jev-argos/pkg/stream"
)

// dropper は捨てた件数を数えている部品 (db.BatchWriter / llm.Emitter / stream.Publisher)。
type dropper interface{ Dropped() uint64 }

// metricsSources は /metrics で値を集める部品。役割によって nil のものがある。
type metricsSources struct {
	sig       *signalServer
	publisher *stream.Publisher
	workers   *workers
	rdb       *redis.Client // worker のストリームの遅れを見るため
}

func (m metricsSources) collect(ctx context.Context) []metrics.Family {
	var fams []metrics.Family
	if m.sig != nil {
		st := m.sig.srv.Stats()
		evaluated := metrics.Family{Name: "jevargos_signals_evaluated_total", Help: "Signals evaluated, by decided level.", Type: metrics.Counter}
		for level := 1; level < len(st.Evaluated); level++ {
			evaluated.Samples = append(evaluated.Samples, metrics.Sample{Labels: []string{"level", string(rune('0' + level))}, Value: float64(st.Evaluated[level])})
		}
		fams = append(fams, evaluated,
			metrics.Family{Name: "jevargos_signals_rejected_total", Help: "Signals rejected before evaluation to protect the server (OK responses are rejected first).", Type: metrics.Counter,
				Samples: []metrics.Sample{
					{Labels: []string{"reason", "rate_limited", "status", "ok"}, Value: float64(st.RateLimitedOK)},
					{Labels: []string{"reason", "rate_limited", "status", "error"}, Value: float64(st.RateLimitedError)},
					{Labels: []string{"reason", "overloaded", "status", "ok"}, Value: float64(st.OverloadedOK)},
					{Labels: []string{"reason", "overloaded", "status", "error"}, Value: float64(st.OverloadedError)},
				}},
			metrics.Family{Name: "jevargos_signals_in_flight", Help: "Signals being evaluated.", Type: metrics.Gauge, Samples: []metrics.Sample{{Value: float64(st.InFlight)}}},
			metrics.Map("jevargos_events_dropped_total", "Level 2+ events dropped because the follow-up queue was full.", metrics.Counter, "lane", st.DroppedByLane),
		)
	}
	if m.publisher != nil {
		fams = append(fams, single("jevargos_stream_publish_dropped_total", "Events that could not be added to the Redis stream.", m.publisher))
	}
	if w := m.workers; w != nil {
		if d, ok := w.stores.decisions.(dropper); ok {
			fams = append(fams, single("jevargos_decision_logs_dropped_total", "Decision logs dropped because the write queue was full.", d))
		}
		if w.llm != nil {
			fams = append(fams, single("jevargos_llm_analyses_dropped_total", "LLM analyses skipped because the analysis queue was full.", w.llm))
		}
	}
	if m.rdb != nil {
		fams = append(fams, m.streamGroups(ctx)...)
	}
	return fams
}

// streamGroups は worker の後続処理ごとの遅れ (まだ読んでいない件数) と、読んだが処理済みにしていない件数を返す。
func (m metricsSources) streamGroups(ctx context.Context) []metrics.Family {
	groups, err := m.rdb.XInfoGroups(ctx, stream.DefaultStream).Result()
	if err != nil {
		return nil // ストリームがまだ無い場合など
	}
	lag := metrics.Family{Name: "jevargos_stream_group_lag", Help: "Stream entries not yet read by each follow-up group.", Type: metrics.Gauge}
	pending := metrics.Family{Name: "jevargos_stream_group_pending", Help: "Stream entries read but not yet acknowledged by each follow-up group.", Type: metrics.Gauge}
	for _, g := range groups {
		lag.Samples = append(lag.Samples, metrics.Sample{Labels: []string{"group", g.Name}, Value: float64(g.Lag)})
		pending.Samples = append(pending.Samples, metrics.Sample{Labels: []string{"group", g.Name}, Value: float64(g.Pending)})
	}
	return []metrics.Family{lag, pending}
}

func single(name, help string, d dropper) metrics.Family {
	return metrics.Family{Name: name, Help: help, Type: metrics.Counter, Samples: []metrics.Sample{{Value: float64(d.Dropped())}}}
}
