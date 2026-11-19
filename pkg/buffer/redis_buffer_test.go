package buffer

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestRedis は miniredis (インプロセスの Redis 互換サーバー) とそのクライアントを返す。
func newTestRedis(t *testing.T) (*miniredis.Miniredis, redis.UniversalClient) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })
	return mr, client
}

func newTestRedisBuffer(t *testing.T, client redis.UniversalClient, opts RedisOptions) *RedisBuffer {
	t.Helper()
	b, err := NewRedisBuffer(client, opts)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRedisBuffer(t *testing.T) {
	runContractTests(t, func(t *testing.T, now func() time.Time, maxEvents int) Buffer {
		_, client := newTestRedis(t)
		return newTestRedisBuffer(t, client, RedisOptions{Now: now, MaxEventsPerIP: maxEvents})
	})
}

// 複数のサーバーインスタンスが同じ Redis を使うと、統計を共有する。レイテンシ基準値はすり合わせで共有する。
func TestRedisBuffer_SharedAcrossInstances(t *testing.T) {
	_, client := newTestRedis(t)
	clk := newFakeClock()
	a := newTestRedisBuffer(t, client, RedisOptions{Now: clk.now})
	b := newTestRedisBuffer(t, client, RedisOptions{Now: clk.now})

	// 同じミリ秒に別インスタンスから記録しても、イベントは潰れない
	record(t, a, signal("1.1.1.1", "/x", codeDenied, 10))
	record(t, b, signal("1.1.1.1", "/y", codeDenied, 10))
	record(t, a, signal("1.1.1.1", "/z", codeOK, 100))

	for name, buf := range map[string]Buffer{"a": a, "b": b} {
		got := stats(t, buf, "1.1.1.1", 60)
		if got.ErrorCount != 2 || got.UniqueDeniedMethods != 2 {
			t.Errorf("instance %s: %+v, want 2 errors / 2 denied methods", name, got)
		}
	}
	if got := ratio(t, b, "/z", 300); got != 1 {
		t.Errorf("instance b ratio before sync = %v, want 1 (no baseline yet)", got)
	}
	syncLatency(t, a)
	syncLatency(t, b)
	if got := ratio(t, b, "/z", 300); got != 3 {
		t.Errorf("instance b ratio = %v, want 3 (baseline written by a)", got)
	}
}

func syncLatency(t *testing.T, b *RedisBuffer) {
	t.Helper()
	if err := b.SyncLatency(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// 判定 1 回で Redis に問い合わせるのは 1 回だけで、正常応答でレイテンシのキーには書き込まない。
func TestRedisBuffer_ObserveIsOneRoundTrip(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })
	rt := &roundTrips{}
	client.AddHook(rt)
	b := newTestRedisBuffer(t, client, RedisOptions{KeyPrefix: "test:"})

	ctx := context.Background()
	for _, code := range []int32{codeOK, codeInternal, codeDenied} {
		rt.n.Store(0)
		if _, err := Observe(ctx, b, signal("1.1.1.1", "/a", code, 10)); err != nil {
			t.Fatal(err)
		}
		if got := rt.n.Load(); got != 1 {
			t.Errorf("status %d: round trips = %d, want 1", code, got)
		}
	}
	if mr.Exists("test:latency") {
		t.Error("latency key must not be written per request")
	}
	syncLatency(t, b)
	if got := mr.HGet("test:latency", "/a"); got != "10" {
		t.Errorf("latency after sync = %q, want 10", got)
	}
}

// すり合わせでは、各インスタンスが観測した平均を件数に応じた重みで全体の基準値に混ぜる。
func TestRedisBuffer_LatencySyncMerges(t *testing.T) {
	_, client := newTestRedis(t)
	a := newTestRedisBuffer(t, client, RedisOptions{})
	b := newTestRedisBuffer(t, client, RedisOptions{})

	record(t, a, signal("1.1.1.1", "/a", codeOK, 100))
	syncLatency(t, a) // 全体の基準値が無いので 100 になる
	record(t, b, signal("2.2.2.2", "/a", codeOK, 300))
	record(t, b, signal("2.2.2.2", "/a", codeOK, 300))
	syncLatency(t, b) // 平均 300 の 2 件: 100 + (1 - 0.9^2) × (300 - 100) = 138
	syncLatency(t, a) // a も全体の基準値を受け取る

	for name, buf := range map[string]*RedisBuffer{"a": a, "b": b} {
		if got := ratio(t, buf, "/a", 276); math.Abs(got-2) > 1e-9 {
			t.Errorf("instance %s ratio = %v, want 2 (baseline 138)", name, got)
		}
	}
	// 各インスタンスは手元の観測をすぐに基準値へ反映する
	record(t, a, signal("1.1.1.1", "/a", codeOK, 238)) // 138 + 0.1 × (238 - 138) = 148
	if got := ratio(t, a, "/a", 296); math.Abs(got-2) > 1e-9 {
		t.Errorf("local ratio = %v, want 2 (baseline 148)", got)
	}
}

// すり合わせに失敗した観測は捨てず、次回に送る。
func TestRedisBuffer_LatencySyncRetries(t *testing.T) {
	mr, client := newTestRedis(t)
	b := newTestRedisBuffer(t, client, RedisOptions{KeyPrefix: "test:"})

	record(t, b, signal("1.1.1.1", "/a", codeOK, 100))
	mr.Close()
	if err := b.SyncLatency(context.Background()); err == nil {
		t.Fatal("SyncLatency: want error while redis is down")
	}
	if err := mr.Restart(); err != nil {
		t.Fatal(err)
	}
	syncLatency(t, b)
	if got := mr.HGet("test:latency", "/a"); got != "100" {
		t.Errorf("latency after retry = %q, want 100", got)
	}
}

func TestRedisBuffer_KeysExpire(t *testing.T) {
	mr, client := newTestRedis(t)
	b := newTestRedisBuffer(t, client, RedisOptions{KeyPrefix: "test:"})

	record(t, b, signal("1.1.1.1", "/a", codeDenied, 10))
	for _, key := range []string{"test:{1.1.1.1}:err", "test:{1.1.1.1}:denied"} {
		if ttl := mr.TTL(key); ttl != RetentionSeconds*time.Second {
			t.Errorf("TTL(%s) = %v, want %v", key, ttl, RetentionSeconds*time.Second)
		}
	}

	mr.FastForward(RetentionSeconds * time.Second)
	if keys := mr.Keys(); len(keys) != 0 {
		t.Errorf("keys after retention = %v, want none", keys)
	}
}

func TestRedisBuffer_PrunesExpiredOnWrite(t *testing.T) {
	mr, client := newTestRedis(t)
	clk := newFakeClock()
	b := newTestRedisBuffer(t, client, RedisOptions{Now: clk.now, KeyPrefix: "test:"})

	record(t, b, signal("1.1.1.1", "/a", codeDenied, 10))
	clk.advance(RetentionSeconds * time.Second)
	record(t, b, signal("1.1.1.1", "/b", codeDenied, 10))

	for _, key := range []string{"test:{1.1.1.1}:err", "test:{1.1.1.1}:denied"} {
		members, err := mr.ZMembers(key)
		if err != nil {
			t.Fatal(err)
		}
		if len(members) != 1 {
			t.Errorf("%s members = %v, want only the new one", key, members)
		}
	}
}

func TestRedisBuffer_ReturnsErrorWhenRedisDown(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { client.Close() })
	b := newTestRedisBuffer(t, client, RedisOptions{})
	mr.Close()

	ctx := context.Background()
	if err := b.RecordSignal(ctx, signal("1.1.1.1", "/a", codeDenied, 10)); err == nil {
		t.Error("RecordSignal: want error")
	}
	if _, err := b.GetStats(ctx, "1.1.1.1", 60); err == nil {
		t.Error("GetStats: want error")
	}
	if _, err := Observe(ctx, b, signal("1.1.1.1", "/a", codeDenied, 10)); err == nil {
		t.Error("Observe: want error")
	}
	if _, err := Observe(ctx, b, signal("1.1.1.1", "/a", codeOK, 10)); err == nil {
		t.Error("Observe (ok): want error")
	}
	// レイテンシの基準値はメモリ上で扱うため、Redis が止まっていても更新・参照できる
	if err := b.RecordSignal(ctx, signal("1.1.1.1", "/a", codeOK, 10)); err != nil {
		t.Errorf("RecordSignal (latency): %v", err)
	}
	if _, err := b.GetLatencySpikeRatio(ctx, "/a", 10); err != nil {
		t.Errorf("GetLatencySpikeRatio: %v", err)
	}
}
