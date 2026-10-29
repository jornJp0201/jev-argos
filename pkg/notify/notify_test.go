package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
	"github.com/jornJp0201/jev-argos/pkg/webhook"
)

type recorder struct {
	mu     sync.Mutex
	alerts []Alert
	err    error
}

func (r *recorder) Notify(_ context.Context, a Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, a)
	return r.err
}

func event(ip string, level guardrail.Level, downgraded bool) receiver.Event {
	return receiver.Event{
		Signal: &jevargosv1.SecuritySignal{
			SignalId:       "sig-" + ip,
			SourceService:  "main-bff",
			UserContext:    &jevargosv1.UserContext{ClientIp: ip, UserId: "user-42"},
			RequestContext: &jevargosv1.RequestContext{Method: "/admin.AdminService/ListUsers"},
		},
		Features:   buffer.Features{IPErrorCount1m: 7, UniqueDeniedMethods5m: 5, LatencySpikeRatio: 1},
		Assessment: classifier.Assessment{Score: 3.68, Confidence: 0.52},
		Decision:   guardrail.Decision{Level: level, Downgraded: downgraded},
	}
}

func TestEmitter_LevelThresholdAndCooldown(t *testing.T) {
	rec := &recorder{}
	now := time.Unix(1_700_000_000, 0)
	em := &Emitter{Notifiers: []Notifier{rec}, Cooldown: 10 * time.Minute, Now: func() time.Time { return now }}
	ctx := context.Background()

	em.Emit(ctx, event("10.0.0.1", guardrail.Level2, false)) // Level 2 は対象外
	em.Emit(ctx, event("10.0.0.1", guardrail.Level3, true))  // 通知
	em.Emit(ctx, event("10.0.0.1", guardrail.Level3, true))  // Cooldown 中 → 通知しない
	em.Emit(ctx, event("10.0.0.2", guardrail.Level3, false)) // 別 IP → 通知
	em.Emit(ctx, event("10.0.0.1", guardrail.Level4, false)) // Level が上がった → すぐ通知
	now = now.Add(11 * time.Minute)
	em.Emit(ctx, event("10.0.0.1", guardrail.Level3, false)) // Cooldown 後 → 通知

	var got []string
	for _, a := range rec.alerts {
		got = append(got, a.ClientIP+"/L"+string(rune('0'+a.Level)))
	}
	want := []string{"10.0.0.1/L3", "10.0.0.2/L3", "10.0.0.1/L4", "10.0.0.1/L3"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("notified %v, want %v", got, want)
	}
}

func TestEmitter_ContinuesAfterNotifierError(t *testing.T) {
	failing, ok := &recorder{err: errors.New("slack down")}, &recorder{}
	em := &Emitter{Notifiers: []Notifier{failing, ok}, Logger: nil}
	em.Emit(context.Background(), event("10.0.0.1", guardrail.Level4, false))
	if len(ok.alerts) != 1 {
		t.Error("second notifier must still be called")
	}
}

func TestSlackNotifier(t *testing.T) {
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
	}))
	defer srv.Close()

	a := AlertFromEvent(event("203.0.113.9", guardrail.Level3, true), time.Now())
	a.DashboardURL = "https://jev-argos.example.com"
	if err := (SlackNotifier{WebhookURL: srv.URL}).Notify(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	text := body["text"]
	for _, want := range []string{"Level 3", "承認待ち", "203.0.113.9", "user-42", "S=3.68", "C=0.52", "ダッシュボードで確認"} {
		if !strings.Contains(text, want) {
			t.Errorf("slack text missing %q:\n%s", want, text)
		}
	}
}

func TestWebhookNotifier_Signed(t *testing.T) {
	var got Alert
	var verified bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		body, verified = webhook.VerifyRequest(r, "secret", time.Minute)
		json.Unmarshal(body, &got)
	}))
	defer srv.Close()

	if err := (WebhookNotifier{URL: srv.URL, Secret: "secret"}).Notify(context.Background(), AlertFromEvent(event("10.0.0.1", guardrail.Level4, false), time.Now())); err != nil {
		t.Fatal(err)
	}
	if !verified || got.Type != "alert" || got.Level != 4 || got.ClientIP != "10.0.0.1" || got.UniqueDeniedMethods5m != 5 {
		t.Errorf("verified=%v alert=%+v", verified, got)
	}
}
