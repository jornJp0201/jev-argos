package action

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
	"github.com/jev-argos/jev-argos/pkg/approval"
	"github.com/jev-argos/jev-argos/pkg/classifier"
	"github.com/jev-argos/jev-argos/pkg/guardrail"
	"github.com/jev-argos/jev-argos/pkg/receiver"
	"github.com/jev-argos/jev-argos/pkg/webhook"
)

var ctx = context.Background()

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func recv(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("no event received")
		return Event{}
	}
}

func ipEntry(ip string, expires time.Time) Entry {
	return Entry{TargetType: TargetIP, Target: ip, Reason: "test", Source: SourceAdmin, ExpiresAt: expires}
}

// --- MemoryBlocklist ---

func TestMemoryBlocklist(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	b := newMemoryBlocklist(clk.now)
	events, cancel := b.Subscribe()
	defer cancel()

	b.Block(ctx, ipEntry("10.0.0.1", clk.now().Add(time.Minute)))
	b.Block(ctx, ipEntry("10.0.0.2", time.Time{})) // 無期限
	if ev := recv(t, events); ev.Kind != EventAdded || ev.Entry.Target != "10.0.0.1" || ev.Entry.CreatedAt.IsZero() {
		t.Errorf("event = %+v", ev)
	}
	recv(t, events)

	if ok, _ := b.IsBlocked(ctx, TargetIP, "10.0.0.1"); !ok {
		t.Error("10.0.0.1 should be blocked")
	}
	if list, _ := b.List(ctx); len(list) != 2 {
		t.Errorf("list = %d, want 2", len(list))
	}

	clk.advance(time.Minute) // 10.0.0.1 は期限切れ
	if ok, _ := b.IsBlocked(ctx, TargetIP, "10.0.0.1"); ok {
		t.Error("expired entry must not block")
	}
	if list, _ := b.List(ctx); len(list) != 1 || list[0].Target != "10.0.0.2" {
		t.Errorf("list after expiry = %+v", list)
	}
	b.Sweep()
	if ev := recv(t, events); ev.Kind != EventRemoved || ev.Entry.Target != "10.0.0.1" {
		t.Errorf("sweep event = %+v", ev)
	}

	b.Unblock(ctx, TargetIP, "10.0.0.2")
	if ev := recv(t, events); ev.Kind != EventRemoved || ev.Entry.Target != "10.0.0.2" {
		t.Errorf("unblock event = %+v", ev)
	}
	b.Unblock(ctx, TargetIP, "10.0.0.9") // 存在しない対象は通知しない
	select {
	case ev := <-events:
		t.Errorf("unexpected event %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

// --- RedisBlocklist ---

func TestRedisBlocklist_SharedAcrossInstances(t *testing.T) {
	mr := miniredis.RunT(t)
	newClient := func() redis.UniversalClient {
		c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { c.Close() })
		return c
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a := NewRedisBlocklist(rctx, newClient(), "test:", nil)
	b := NewRedisBlocklist(rctx, newClient(), "test:", nil)
	eventsB, cancelB := b.Subscribe()
	defer cancelB()
	time.Sleep(100 * time.Millisecond) // Pub/Sub の購読開始を待つ

	if err := a.Block(ctx, ipEntry("203.0.113.9", time.Now().Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	if ev := recv(t, eventsB); ev.Kind != EventAdded || ev.Entry.Target != "203.0.113.9" {
		t.Errorf("instance b event = %+v", ev)
	}
	if ok, _ := b.IsBlocked(ctx, TargetIP, "203.0.113.9"); !ok {
		t.Error("instance b should see the block")
	}
	if list, _ := b.List(ctx); len(list) != 1 {
		t.Errorf("instance b list = %+v", list)
	}
	if ttl := mr.TTL("test:block:ip:203.0.113.9"); ttl <= 0 || ttl > time.Minute {
		t.Errorf("TTL = %v", ttl)
	}

	if err := b.Unblock(ctx, TargetIP, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if ev := recv(t, eventsB); ev.Kind != EventRemoved {
		t.Errorf("unblock event = %+v", ev)
	}
	if ok, _ := a.IsBlocked(ctx, TargetIP, "203.0.113.9"); ok {
		t.Error("instance a should see the unblock")
	}
}

func TestRedisBlocklist_ExpiresWithTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer c.Close()
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	b := NewRedisBlocklist(rctx, c, "", nil)

	b.Block(ctx, ipEntry("10.0.0.1", time.Now().Add(time.Minute)))
	b.Block(ctx, ipEntry("10.0.0.2", time.Now().Add(-time.Second))) // 既に期限切れ → 登録しない
	mr.FastForward(time.Minute)
	if list, _ := b.List(ctx); len(list) != 0 {
		t.Errorf("list after TTL = %+v", list)
	}
}

// --- Executors ---

func TestBlocklistExecutor(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	bl := newMemoryBlocklist(clk.now)
	x := BlocklistExecutor{Blocklist: bl, TTL: 10 * time.Minute, Now: clk.now}

	err := x.Execute(ctx, approval.Action{ProposedAction: approval.ActionBlockIP, Target: "10.0.0.1", DecidedBy: "alice", Reason: "probing"})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := bl.List(ctx)
	if len(list) != 1 || list[0].Source != SourceApproval || !list[0].ExpiresAt.Equal(clk.now().Add(10*time.Minute)) {
		t.Errorf("entry = %+v", list)
	}
	if err := x.Execute(ctx, approval.Action{ProposedAction: approval.ActionDeleteAccount}); err == nil {
		t.Error("non block_ip action must fail")
	}
}

func TestWebhookExecutor_SignsAndVerifies(t *testing.T) {
	const secret = "s3cr3t"
	var got WebhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts, sig := r.Header.Get("X-Jev-Argos-Timestamp"), r.Header.Get("X-Jev-Argos-Signature")
		if !webhook.Verify(secret, ts, sig, body, time.Now(), 5*time.Minute) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	a := approval.Action{ID: "act_1", ProposedAction: approval.ActionSuspendAccount, Target: "user-42", Status: approval.StatusApproved}
	if err := (WebhookExecutor{URL: srv.URL, Secret: secret}).Execute(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got.Type != "action.approved" || got.Action.ID != "act_1" || got.Action.Target != "user-42" {
		t.Errorf("payload = %+v", got)
	}

	// 鍵が違えば受信側が拒否し、実行失敗になる
	if err := (WebhookExecutor{URL: srv.URL, Secret: "wrong"}).Execute(ctx, a); err == nil {
		t.Error("wrong secret: want error")
	}
	if err := (WebhookExecutor{}).Execute(ctx, a); err == nil {
		t.Error("missing URL: want error")
	}
}

type recordingExecutor struct{ actions []approval.Action }

func (r *recordingExecutor) Execute(_ context.Context, a approval.Action) error {
	r.actions = append(r.actions, a)
	return nil
}

func TestRouter(t *testing.T) {
	block, fallback := &recordingExecutor{}, &recordingExecutor{}
	r := Router{Routes: map[approval.ActionType]approval.Executor{approval.ActionBlockIP: block}, Fallback: fallback}
	r.Execute(ctx, approval.Action{ProposedAction: approval.ActionBlockIP})
	r.Execute(ctx, approval.Action{ProposedAction: approval.ActionDeleteData})
	if len(block.actions) != 1 || len(fallback.actions) != 1 {
		t.Errorf("block=%d fallback=%d", len(block.actions), len(fallback.actions))
	}
	if err := (Router{}).Execute(ctx, approval.Action{ProposedAction: approval.ActionStopService}); err == nil {
		t.Error("no route: want error")
	}
}

func event(level guardrail.Level) receiver.Event {
	return receiver.Event{
		Signal:     &jevargosv1.SecuritySignal{UserContext: &jevargosv1.UserContext{ClientIp: "203.0.113.9"}},
		Assessment: classifier.Assessment{Score: 3.9, Confidence: 0.9},
		Decision:   guardrail.Decision{Level: level},
	}
}

func TestAutoBlockEmitter(t *testing.T) {
	bl := NewMemoryBlocklist()
	em := AutoBlockEmitter{Blocklist: bl, TTL: time.Minute}
	em.Emit(ctx, event(guardrail.Level3))
	if list, _ := bl.List(ctx); len(list) != 0 {
		t.Fatal("Level 3 must not auto block")
	}
	em.Emit(ctx, event(guardrail.Level4))
	list, _ := bl.List(ctx)
	if len(list) != 1 || list[0].Target != "203.0.113.9" || list[0].Source != SourceLevel4 || list[0].ExpiresAt.IsZero() {
		t.Errorf("auto block = %+v", list)
	}
}

type failingBlocklist struct{ Blocklist }

func (failingBlocklist) Block(context.Context, Entry) error { return errors.New("down") }

func TestAutoBlockEmitter_LogsErrors(t *testing.T) {
	// 失敗しても panic せずログに残すだけ
	AutoBlockEmitter{Blocklist: failingBlocklist{}}.Emit(ctx, event(guardrail.Level4))
}

// --- ControlServer (gRPC) ---

func TestControlServer_WatchBlocklist(t *testing.T) {
	bl := NewMemoryBlocklist()
	bl.Block(ctx, ipEntry("10.0.0.1", time.Now().Add(time.Hour)))

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	jevargosv1.RegisterControlServiceServer(gs, &ControlServer{Blocklist: bl})
	go gs.Serve(lis)
	defer gs.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(c context.Context, _ string) (net.Conn, error) { return lis.DialContext(c) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stream, err := jevargosv1.NewControlServiceClient(conn).WatchBlocklist(sctx, &jevargosv1.WatchBlocklistRequest{})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := stream.Recv()
	if err != nil || snap.GetKind() != jevargosv1.BlocklistEvent_SNAPSHOT || len(snap.GetEntries()) != 1 || snap.GetEntries()[0].GetTarget() != "10.0.0.1" {
		t.Fatalf("snapshot = %v, err %v", snap, err)
	}
	if e := FromProto(snap.GetEntries()[0]); e.ExpiresAt.IsZero() {
		t.Error("expires_at lost")
	}

	bl.Block(ctx, ipEntry("10.0.0.2", time.Time{}))
	if ev, _ := stream.Recv(); ev.GetKind() != jevargosv1.BlocklistEvent_ADDED || ev.GetEntries()[0].GetTarget() != "10.0.0.2" || ev.GetEntries()[0].GetExpiresAtUnixMs() != 0 {
		t.Errorf("added = %v", ev)
	}
	bl.Unblock(ctx, TargetIP, "10.0.0.1")
	if ev, _ := stream.Recv(); ev.GetKind() != jevargosv1.BlocklistEvent_REMOVED || ev.GetEntries()[0].GetTarget() != "10.0.0.1" {
		t.Errorf("removed = %v", ev)
	}
}
