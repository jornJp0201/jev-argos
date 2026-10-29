package approval

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
	"github.com/jev-argos/jev-argos/pkg/buffer"
	"github.com/jev-argos/jev-argos/pkg/classifier"
	"github.com/jev-argos/jev-argos/pkg/guardrail"
	"github.com/jev-argos/jev-argos/pkg/receiver"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestStore(max int) (*MemoryStore, *clock) {
	c := &clock{t: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	return newMemoryStore(c.now, max), c
}

func proposal(ip, signalID string, score float64) Proposal {
	return Proposal{
		SignalID:       signalID,
		ProposedAction: ActionBlockIP,
		Target:         ip,
		Reason:         "test",
		Evidence:       Evidence{Score: score, ClientIP: ip},
	}
}

var ctx = context.Background()

func TestPropose_DedupesPendingPerTarget(t *testing.T) {
	s, clk := newTestStore(DefaultMaxActions)

	first, err := s.Propose(ctx, proposal("203.0.113.9", "sig-1", 3.6))
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Second)
	second, err := s.Propose(ctx, proposal("203.0.113.9", "sig-2", 3.8))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := s.Propose(ctx, proposal("198.51.100.7", "sig-3", 3.6))

	if second.ID != first.ID {
		t.Errorf("same target created a new action: %s != %s", second.ID, first.ID)
	}
	if second.EventCount != 2 || second.SignalID != "sig-2" || second.Evidence.Score != 3.8 || !second.UpdatedAt.After(first.CreatedAt) {
		t.Errorf("pending action not updated with latest evidence: %+v", second)
	}
	if other.ID == first.ID {
		t.Error("different target must create a separate action")
	}
	if all, _ := s.List(ctx, StatusPending); len(all) != 2 {
		t.Errorf("pending = %d, want 2", len(all))
	}
}

func TestDecide(t *testing.T) {
	s, _ := newTestStore(DefaultMaxActions)
	a, _ := s.Propose(ctx, proposal("203.0.113.9", "sig-1", 3.6))

	got, err := s.Decide(ctx, a.ID, true, "alice", "confirmed probing")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApproved || got.DecidedBy != "alice" || got.DecisionNote != "confirmed probing" || got.DecidedAt == nil {
		t.Errorf("decided action = %+v", got)
	}

	// 決定済みは変更できない (後から別の管理者が拒否しても上書きされない)
	again, err := s.Decide(ctx, a.ID, false, "bob", "")
	if !errors.Is(err, ErrAlreadyDecided) || again.Status != StatusApproved || again.DecidedBy != "alice" {
		t.Errorf("second decision: err=%v action=%+v", err, again)
	}

	if _, err := s.Decide(ctx, "act_missing", true, "alice", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: err = %v, want ErrNotFound", err)
	}
}

func TestDecide_NewProposalAfterDecisionCreatesNewAction(t *testing.T) {
	s, _ := newTestStore(DefaultMaxActions)
	a, _ := s.Propose(ctx, proposal("203.0.113.9", "sig-1", 3.6))
	if _, err := s.Decide(ctx, a.ID, false, "alice", "false positive"); err != nil {
		t.Fatal(err)
	}

	b, _ := s.Propose(ctx, proposal("203.0.113.9", "sig-2", 3.9))
	if b.ID == a.ID || b.Status != StatusPending {
		t.Errorf("after rejection, new evidence must open a new pending action: %+v", b)
	}
	if rejected, _ := s.Get(ctx, a.ID); rejected.Status != StatusRejected {
		t.Errorf("rejected action changed: %+v", rejected)
	}
}

func TestList_FiltersAndOrdersByUpdate(t *testing.T) {
	s, clk := newTestStore(DefaultMaxActions)
	a, _ := s.Propose(ctx, proposal("10.0.0.1", "s1", 3))
	clk.advance(time.Second)
	b, _ := s.Propose(ctx, proposal("10.0.0.2", "s2", 3))
	clk.advance(time.Second)
	s.Decide(ctx, a.ID, true, "alice", "")

	all, _ := s.List(ctx, "")
	if len(all) != 2 || all[0].ID != a.ID || all[1].ID != b.ID {
		t.Errorf("List(all) order = %v, want [a (updated last), b]", ids(all))
	}
	pending, _ := s.List(ctx, StatusPending)
	if len(pending) != 1 || pending[0].ID != b.ID {
		t.Errorf("List(pending) = %v", ids(pending))
	}
}

func TestPropose_EvictsDecidedWhenFull(t *testing.T) {
	s, _ := newTestStore(2)
	a, _ := s.Propose(ctx, proposal("10.0.0.1", "s1", 3))
	s.Propose(ctx, proposal("10.0.0.2", "s2", 3))

	if _, err := s.Propose(ctx, proposal("10.0.0.3", "s3", 3)); !errors.Is(err, ErrStoreFull) {
		t.Errorf("all pending and full: err = %v, want ErrStoreFull", err)
	}
	s.Decide(ctx, a.ID, false, "alice", "")
	if _, err := s.Propose(ctx, proposal("10.0.0.3", "s3", 3)); err != nil {
		t.Errorf("decided action should be evicted: %v", err)
	}
	if _, err := s.Get(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Error("oldest decided action should have been evicted")
	}
}

func TestSubscribe(t *testing.T) {
	s, _ := newTestStore(DefaultMaxActions)
	updates, cancel := s.Subscribe()

	a, _ := s.Propose(ctx, proposal("10.0.0.1", "s1", 3))
	s.Decide(ctx, a.ID, true, "alice", "")

	for _, want := range []Status{StatusPending, StatusApproved} {
		select {
		case got := <-updates:
			if got.ID != a.ID || got.Status != want {
				t.Errorf("update = %s/%s, want %s/%s", got.ID, got.Status, a.ID, want)
			}
		case <-time.After(time.Second):
			t.Fatal("no update received")
		}
	}

	cancel()
	cancel() // 二重解除しても panic しない
	if _, ok := <-updates; ok {
		t.Error("channel should be closed after cancel")
	}
	s.Propose(ctx, proposal("10.0.0.2", "s2", 3)) // 解除後の通知で panic しない
}

func event(level guardrail.Level, downgraded bool) receiver.Event {
	return receiver.Event{
		Signal: &jevargosv1.SecuritySignal{
			SignalId:        "sig-1",
			SourceService:   "main-bff",
			UserContext:     &jevargosv1.UserContext{ClientIp: "203.0.113.9", UserId: "user-42"},
			RequestContext:  &jevargosv1.RequestContext{Method: "/admin.AdminService/ListUsers"},
			ResponseContext: &jevargosv1.ResponseContext{StatusCode: 7},
		},
		Features:   buffer.Features{IPErrorCount1m: 7, UniqueDeniedMethods5m: 5, LatencySpikeRatio: 1},
		Assessment: classifier.Assessment{Score: 3.68, Confidence: 0.52},
		Decision:   guardrail.Decision{Level: level, Downgraded: downgraded},
	}
}

func TestProposeEmitter(t *testing.T) {
	s, _ := newTestStore(DefaultMaxActions)
	em := ProposeEmitter{Store: s}

	em.Emit(ctx, event(guardrail.Level2, false))
	em.Emit(ctx, event(guardrail.Level4, false))
	if all, _ := s.List(ctx, ""); len(all) != 0 {
		t.Fatalf("Level 2/4 must not create actions, got %d", len(all))
	}

	em.Emit(ctx, event(guardrail.Level3, true))
	all, _ := s.List(ctx, StatusPending)
	if len(all) != 1 {
		t.Fatalf("pending = %d, want 1", len(all))
	}
	a := all[0]
	if a.ProposedAction != ActionBlockIP || a.Target != "203.0.113.9" || a.SignalID != "sig-1" {
		t.Errorf("action = %+v", a)
	}
	want := Evidence{
		Score: 3.68, Confidence: 0.52, Level: 3, Downgraded: true,
		IPErrorCount1m: 7, UniqueDeniedMethods5m: 5, LatencySpikeRatio: 1,
		ClientIP: "203.0.113.9", UserID: "user-42", Method: "/admin.AdminService/ListUsers", SourceService: "main-bff",
	}
	if a.Evidence != want {
		t.Errorf("evidence = %+v, want %+v", a.Evidence, want)
	}
	if a.Reason == "" {
		t.Error("reason is empty")
	}
}

func ids(as []Action) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.ID)
	}
	return out
}
