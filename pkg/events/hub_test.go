package events

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
	"github.com/jev-argos/jev-argos/pkg/approval"
	"github.com/jev-argos/jev-argos/pkg/buffer"
	"github.com/jev-argos/jev-argos/pkg/classifier"
	"github.com/jev-argos/jev-argos/pkg/guardrail"
	"github.com/jev-argos/jev-argos/pkg/receiver"
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
	for _, id := range []string{"s1", "s2", "s3", "s4"} {
		h.PublishDecision(event(id, guardrail.Level1))
	}
	h.PublishAnalysis(event("s4", guardrail.Level2), approval.Analysis{Status: "done"}) // 分析は backlog に残さない
	backlog, _, cancel := h.Subscribe()
	defer cancel()
	if len(backlog) != 3 {
		t.Fatalf("backlog = %d, want 3 (capped)", len(backlog))
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
	if backlog[0].Name != "decision" || d.Signal.SignalID != "s2" || d.Level != 1 {
		t.Errorf("oldest kept = %+v", d)
	}
	// ダッシュボードが参照する 0 値のフィールドも省略しない
	if d.Signal.ResponseContext.StatusCode == nil || d.Features["latency_spike_ratio"] != 1 {
		t.Errorf("zero values must be present: %s", backlog[0].Data)
	}
}

func TestHub_Stream(t *testing.T) {
	h := NewHub(10, nil)
	h.PublishDecision(event("old", guardrail.Level1))
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
