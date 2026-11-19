package buffer

import (
	"context"
	"os"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// Observe 1 回あたりの時間と Redis への往復回数を測る。
// JEV_ARGOS_TEST_REDIS_URL を指定すると実際の Redis で測る (未指定なら miniredis)。
//
//	JEV_ARGOS_TEST_REDIS_URL=redis://localhost:6379/15 go test -run '^$' -bench Redis -benchmem ./pkg/buffer/

// roundTrips は Redis へのコマンド送信 (パイプラインは 1 回) を数える go-redis のフック。
type roundTrips struct{ n atomic.Int64 }

func (r *roundTrips) DialHook(next redis.DialHook) redis.DialHook { return next }

func (r *roundTrips) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		r.n.Add(1)
		return next(ctx, cmd)
	}
}

func (r *roundTrips) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		r.n.Add(1)
		return next(ctx, cmds)
	}
}

func newBenchRedis(b *testing.B) (*redis.Client, *roundTrips) {
	b.Helper()
	var opts *redis.Options
	if url := os.Getenv("JEV_ARGOS_TEST_REDIS_URL"); url != "" {
		var err error
		if opts, err = redis.ParseURL(url); err != nil {
			b.Fatal(err)
		}
	} else {
		opts = &redis.Options{Addr: miniredis.RunT(b).Addr()}
	}
	client := redis.NewClient(opts)
	b.Cleanup(func() { client.Close() })
	if err := client.FlushDB(context.Background()).Err(); err != nil {
		b.Fatal(err)
	}
	rt := &roundTrips{}
	client.AddHook(rt)
	return client, rt
}

func benchRedisObserve(b *testing.B, status int32) {
	client, rt := newBenchRedis(b)
	buf, err := NewRedisBuffer(client, RedisOptions{KeyPrefix: "bench:"})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	s := signal("192.0.2.1", "/user.UserService/GetUser", status, 20)
	if _, err := Observe(ctx, buf, s); err != nil { // スクリプトの読み込みなど初回だけの往復を除く
		b.Fatal(err)
	}
	rt.n.Store(0)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := Observe(ctx, buf, s); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(rt.n.Load())/float64(b.N), "roundtrips/op")
}

// 正常な応答 (大半のリクエスト)。
func BenchmarkRedisObserve_OK(b *testing.B) { benchRedisObserve(b, codeOK) }

// 権限エラー (攻撃の兆候)。
func BenchmarkRedisObserve_Denied(b *testing.B) { benchRedisObserve(b, codeDenied) }

// 並列の gRPC リクエストから同時に呼ばれる場合のスループット (送信元 IP は 256 種類)。
func BenchmarkRedisObserve_Parallel(b *testing.B) {
	client, rt := newBenchRedis(b)
	buf, err := NewRedisBuffer(client, RedisOptions{KeyPrefix: "bench:"})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	var seq atomic.Int64
	b.SetParallelism(8) // GOMAXPROCS × 8 並列 (I/O 待ちが主のため多めにする)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := seq.Add(1)
			status := int32(codeOK)
			if i%10 == 0 {
				status = codeDenied
			}
			s := signal("192.0.2."+strconv.Itoa(int(i%256)), "/user.UserService/GetUser", status, 20)
			if _, err := Observe(ctx, buf, s); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.ReportMetric(float64(rt.n.Load())/float64(b.N), "roundtrips/op")
}
