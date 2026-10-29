package buffer

import (
	"context"
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

// 複数のサーバーインスタンスが同じ Redis を使うと、統計とレイテンシ基準値を共有する。
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
	if got := ratio(t, b, "/z", 300); got != 3 {
		t.Errorf("instance b ratio = %v, want 3 (baseline written by a)", got)
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
	if err := b.RecordSignal(ctx, signal("1.1.1.1", "/a", codeOK, 10)); err == nil {
		t.Error("RecordSignal (latency): want error")
	}
	if _, err := b.GetStats(ctx, "1.1.1.1", 60); err == nil {
		t.Error("GetStats: want error")
	}
	if _, err := b.GetLatencySpikeRatio(ctx, "/a", 10); err == nil {
		t.Error("GetLatencySpikeRatio: want error")
	}
	if _, err := Observe(ctx, b, signal("1.1.1.1", "/a", codeDenied, 10)); err == nil {
		t.Error("Observe: want error")
	}
}
