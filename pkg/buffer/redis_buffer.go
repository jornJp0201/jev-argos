package buffer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
)

// RedisOptions は RedisBuffer の設定。
type RedisOptions struct {
	// KeyPrefix は全キーの接頭辞 (既定 "jevargos:")。
	KeyPrefix string
	// MaxEventsPerIP は 1 IP あたりに保持する件数の上限 (既定 DefaultMaxEventsPerIP)。
	MaxEventsPerIP int
	// Now は現在時刻を返す関数 (既定 time.Now)。
	// 複数インスタンスで集計を共有するため、各サーバーの時計は NTP 等で同期しておくこと。
	Now func() time.Time
}

// RedisBuffer は Redis 上で集計する Buffer 実装。複数のサーバーインスタンスで統計を共有できる。
//
// キー構成 ({ip} は Redis Cluster のハッシュタグ。同じ IP のキーを同じスロットに置く):
//
//	<prefix>{<ip>}:err     Sorted Set  member=イベント ID, score=受信時刻 (ms)   … 異常応答
//	<prefix>{<ip>}:denied  Sorted Set  member=メソッド,   score=最後の拒否時刻 (ms) … PERMISSION_DENIED
//	<prefix>latency        Hash        field=メソッド,    value=平常時レイテンシの EWMA (ms)
//
// IP ごとのキーは書き込みのたびに保持期間外のメンバーを削除し、TTL も付けるため、
// アクセスが途絶えた IP のキーは Redis が自動で削除する (定期クリーンアップは不要)。
type RedisBuffer struct {
	client    redis.UniversalClient
	prefix    string
	maxEvents int
	now       func() time.Time

	instanceID string        // イベント ID をインスタンス間で一意にするための乱数
	seq        atomic.Uint64 // 同一インスタンス・同一ミリ秒内での一意化
}

var _ Buffer = (*RedisBuffer)(nil)

// updateLatencyScript は平常時レイテンシの EWMA を原子的に更新する。
// 複数インスタンスが同じメソッドを同時に更新しても値が失われないよう、読み書きを 1 スクリプトで行う。
var updateLatencyScript = redis.NewScript(`
local latency = tonumber(ARGV[2])
local baseline = redis.call('HGET', KEYS[1], ARGV[1])
if baseline then
  baseline = tonumber(baseline)
  latency = baseline + tonumber(ARGV[3]) * (latency - baseline)
end
redis.call('HSET', KEYS[1], ARGV[1], string.format('%.17g', latency))
return 1
`)

// NewRedisBuffer は client を使う RedisBuffer を返す。client の Close は呼び出し側が行う。
func NewRedisBuffer(client redis.UniversalClient, opts RedisOptions) (*RedisBuffer, error) {
	if opts.KeyPrefix == "" {
		opts.KeyPrefix = "jevargos:"
	}
	if opts.MaxEventsPerIP <= 0 {
		opts.MaxEventsPerIP = DefaultMaxEventsPerIP
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("redis buffer: generate instance id: %w", err)
	}
	return &RedisBuffer{
		client:     client,
		prefix:     opts.KeyPrefix,
		maxEvents:  opts.MaxEventsPerIP,
		now:        opts.Now,
		instanceID: hex.EncodeToString(id),
	}, nil
}

// RecordSignal はシグナルを記録する。
// 異常応答はウィンドウ集計用に保持し、正常応答はレイテンシの基準値の更新にだけ使う。
func (b *RedisBuffer) RecordSignal(ctx context.Context, signal *jevargosv1.SecuritySignal) error {
	ip := signal.GetUserContext().GetClientIp()
	method := signal.GetRequestContext().GetMethod()
	resp := signal.GetResponseContext()

	if resp.GetStatusCode() == 0 {
		err := updateLatencyScript.Run(ctx, b.client,
			[]string{b.latencyKey()},
			method, resp.GetLatencyMs(), latencyAlpha,
		).Err()
		if err != nil {
			return fmt.Errorf("redis buffer: update latency: %w", err)
		}
		return nil
	}

	nowMs := b.now().UnixMilli()
	expired := strconv.FormatInt(nowMs-RetentionSeconds*1000, 10)
	ttl := RetentionSeconds * time.Second
	errKey, deniedKey := b.errKey(ip), b.deniedKey(ip)
	member := fmt.Sprintf("%d:%s:%d", nowMs, b.instanceID, b.seq.Add(1))

	_, err := b.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.ZAdd(ctx, errKey, redis.Z{Score: float64(nowMs), Member: member})
		p.ZRemRangeByScore(ctx, errKey, "-inf", expired)
		p.ZRemRangeByRank(ctx, errKey, 0, int64(-b.maxEvents-1)) // 新しい maxEvents 件だけ残す
		p.Expire(ctx, errKey, ttl)
		if resp.GetStatusCode() == codePermissionDenied {
			p.ZAdd(ctx, deniedKey, redis.Z{Score: float64(nowMs), Member: method})
			p.ZRemRangeByScore(ctx, deniedKey, "-inf", expired)
			p.ZRemRangeByRank(ctx, deniedKey, 0, int64(-b.maxEvents-1))
			p.Expire(ctx, deniedKey, ttl)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("redis buffer: record error event: %w", err)
	}
	return nil
}

// GetStats は clientIP について直近 windowSeconds 秒の統計を返す。
func (b *RedisBuffer) GetStats(ctx context.Context, clientIP string, windowSeconds int) (WindowStats, error) {
	windowSeconds = clampWindow(windowSeconds)
	if windowSeconds == 0 {
		return WindowStats{}, nil
	}

	// "(" は排他境界。ちょうど windowSeconds 秒前のイベントは窓の外とする (MemoryBuffer と同じ)。
	minScore := "(" + strconv.FormatInt(b.now().UnixMilli()-int64(windowSeconds)*1000, 10)
	var errCount, deniedCount *redis.IntCmd
	_, err := b.client.Pipelined(ctx, func(p redis.Pipeliner) error {
		errCount = p.ZCount(ctx, b.errKey(clientIP), minScore, "+inf")
		deniedCount = p.ZCount(ctx, b.deniedKey(clientIP), minScore, "+inf")
		return nil
	})
	if err != nil {
		return WindowStats{}, fmt.Errorf("redis buffer: get stats: %w", err)
	}
	return WindowStats{
		WindowSeconds:       windowSeconds,
		ErrorCount:          int(errCount.Val()),
		UniqueDeniedMethods: int(deniedCount.Val()),
	}, nil
}

// GetLatencySpikeRatio は method の平常時平均レイテンシに対する latencyMs の比率を返す。
func (b *RedisBuffer) GetLatencySpikeRatio(ctx context.Context, method string, latencyMs int64) (float64, error) {
	baseline, err := b.client.HGet(ctx, b.latencyKey(), method).Float64()
	if errors.Is(err, redis.Nil) {
		return 1.0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("redis buffer: get latency baseline: %w", err)
	}
	return spikeRatio(baseline, true, latencyMs), nil
}

func (b *RedisBuffer) errKey(ip string) string    { return b.prefix + "{" + ip + "}:err" }
func (b *RedisBuffer) deniedKey(ip string) string { return b.prefix + "{" + ip + "}:denied" }
func (b *RedisBuffer) latencyKey() string         { return b.prefix + "latency" }
