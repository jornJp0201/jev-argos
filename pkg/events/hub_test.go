package events

import (
	"bufio"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
	"github.com/jornJp0201/jev-argos/pkg/approval"
	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
)

func event(id string, level guardrail.Level) receiver.Event {
	return receiver.Event{
		Signal: &jevargosv1.SecuritySignal{
			SignalId:        id,
			UserContext:     &jevargosv1.UserContext{ClientIp: "10.0.0.1"},
			RequestContext:  &jevargosv1.RequestContext{Method: "/a"},
			ResponseContext: &jevargosv1.ResponseContext{StatusCode: 0},
		},
		Features:   buffer.Features{LatencySpikeRatio: 1},
		Assessment: classifier.Assessment{Score: 0.1, Confidence: 0.97},
		Decision:   guardrail.Decision{Level: level},
	}
}

func TestHub_BacklogAndDecisionShape(t *testing.T) {
	h := NewHub(3, nil)
	// 購読者がいない間に届いた判定は、接続されたときに JSON にして送る
	for _, id := range []string{"s1", "s2", "s3", "s4"} {
		h.PublishDecision(event(id, guardrail.Level2))
	}
	h.PublishAnalysis(event("s4", guardrail.Level2), approval.Analysis{Status: "done"}) // 分析も backlog に残す
	backlog, _, cancel := h.Subscribe()
	defer cancel()
	if len(backlog) != 3 || backlog[2].Name != "analysis" {
		t.Fatalf("backlog = %d (last %q), want 3 capped with the analysis last", len(backlog), backlog[len(backlog)-1].Name)
	}
	var d struct {
		Signal struct {
			SignalID        string `json:"signal_id"`
			ResponseContext struct {
				StatusCode *int `json:"status_code"`
			} `json:"response_context"`
		} `json:"signal"`
		Level    int                `json:"level"`
		Features map[string]float64 `json:"features"`
	}
	json.Unmarshal(backlog[0].Data, &d)
	if backlog[0].Name != "decision" || d.Signal.SignalID != "s3" || d.Level != 2 {
		t.Errorf("oldest kept = %+v", d)
	}
	// ダッシュボードが参照する 0 値のフィールドも省略しない
	if d.Signal.ResponseContext.StatusCode == nil || d.Features["latency_spike_ratio"] != 1 {
		t.Errorf("zero values must be present: %s", backlog[0].Data)
	}
}

func TestHub_LiveDecision(t *testing.T) {
	h := NewHub(10, nil)
	_, updates, cancel := h.Subscribe()
	defer cancel()
	h.PublishDecision(event("live", guardrail.Level3))
	m := <-updates
	var d Decision
	if err := json.Unmarshal(m.Data, &d); m.Name != "decision" || err != nil || d.Level != 3 {
		t.Fatalf("live message = %q %s (%v)", m.Name, m.Data, err)
	}
	// 配信時に JSON にしたものを backlog でも使い回す
	backlog, _, cancel2 := h.Subscribe()
	defer cancel2()
	if len(backlog) != 1 || string(backlog[0].Data) != string(m.Data) {
		t.Errorf("backlog = %v, want the same message as the live one", backlog)
	}
}

func TestHub_Level1IsSummarized(t *testing.T) {
	h := NewHub(10, nil)
	_, updates, cancel := h.Subscribe()
	defer cancel()

	for _, score := range []float64{0.1, 0.2, 0.3} {
		e := event("l1", guardrail.Level1)
		e.Assessment.Score = score
		h.PublishDecision(e)
	}
	select {
	case m := <-updates:
		t.Fatalf("level 1 must not be sent one by one: %q %s", m.Name, m.Data)
	default:
	}

	at := time.Date(2026, 11, 19, 10, 0, 1, 0, time.UTC)
	h.flushSummary(at)
	h.flushSummary(at.Add(time.Second)) // 0 件の区間は送らない
	m := <-updates
	var s Summary
	if err := json.Unmarshal(m.Data, &s); m.Name != "summary" || err != nil {
		t.Fatalf("message = %q %s (%v)", m.Name, m.Data, err)
	}
	if s.Count != 3 || math.Abs(s.ScoreSum-0.6) > 1e-9 || s.Timestamp != "2026-11-19T10:00:01Z" {
		t.Errorf("summary = %+v", s)
	}
	select {
	case m := <-updates:
		t.Errorf("empty interval was sent: %s", m.Data)
	default:
	}

	// 後から接続したダッシュボードにも、判定より先に直近の集計を送る
	h.PublishDecision(event("l2", guardrail.Level2))
	backlog, _, cancel2 := h.Subscribe()
	defer cancel2()
	if len(backlog) != 2 || backlog[0].Name != "summary" || backlog[1].Name != "decision" {
		t.Errorf("backlog = %v, want summary then decision", backlog)
	}
}

// アダプターが間引いて送ったシグナルは、送られなかった分を含めて数える。
func TestHub_Level1CountsSampleWeight(t *testing.T) {
	h := NewHub(10, nil)
	_, updates, cancel := h.Subscribe()
	defer cancel()

	e := event("l1", guardrail.Level1)
	e.Assessment.Score = 0.1
	e.Signal.SampleRate = 0.1 // 10 件ぶん
	h.PublishDecision(e)
	plain := event("l1", guardrail.Level1) // 間引かれていない (1 件ぶん)
	plain.Assessment.Score = 0.2
	h.PublishDecision(plain)
	h.flushSummary(time.Now())

	var s Summary
	if err := json.Unmarshal((<-updates).Data, &s); err != nil {
		t.Fatal(err)
	}
	if s.Count != 11 || math.Abs(s.ScoreSum-1.2) > 1e-9 { // 0.1 × 10 + 0.2
		t.Errorf("summary = %+v, want count 11 and score_sum 1.2", s)
	}
}

func TestRing(t *testing.T) {
	r := newRing[int](3)
	if got := r.items(); len(got) != 0 {
		t.Fatalf("empty ring = %v", got)
	}
	for i := 1; i <= 5; i++ {
		r.push(i)
	}
	if got := r.items(); len(got) != 3 || got[0] != 3 || got[1] != 4 || got[2] != 5 {
		t.Errorf("items = %v, want [3 4 5]", got)
	}
}

func TestHub_Stream(t *testing.T) {
	h := NewHub(10, nil)
	h.PublishDecision(event("old", guardrail.Level2))
	srv := httptest.NewServer(http.HandlerFunc(h.HandleStream))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := bufio.NewReader(resp.Body)

	var events []string
	go func() {
		time.Sleep(100 * time.Millisecond)
		h.PublishAnalysis(event("old", guardrail.Level2), approval.Analysis{Status: "done", Summary: "s"})
	}()
	for len(events) < 2 {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "event: ") {
			events = append(events, strings.TrimSpace(strings.TrimPrefix(line, "event: ")))
		}
	}
	if events[0] != "decision" || events[1] != "analysis" {
		t.Errorf("events = %v, want backlog decision then live analysis", events)
	}
}
