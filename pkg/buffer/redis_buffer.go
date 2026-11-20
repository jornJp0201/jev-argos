package buffer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
)

// DefaultLatencySyncInterval は平常時レイテンシの基準値を Redis とすり合わせる既定の間隔。
const DefaultLatencySyncInterval = 5 * time.Second

// RedisOptions は RedisBuffer の設定。
type RedisOptions struct {
	// KeyPrefix は全キーの接頭辞 (既定 "jevargos:")。
	KeyPrefix string
	// MaxEventsPerIP は 1 IP あたりに保持する件数の上限 (既定 DefaultMaxEventsPerIP)。
	MaxEventsPerIP int
	// Now は現在時刻を返す関数 (既定 time.Now)。
	// 複数インスタンスで集計を共有するため、各サーバーの時計は NTP 等で同期しておくこと。
	Now func() time.Time
	// LatencySyncInterval は平常時レイテンシの基準値を Redis とすり合わせる間隔 (既定 DefaultLatencySyncInterval)。
	// 短いほどインスタンス間の基準値の差が小さくなり、長いほど Redis への書き込みが減る。
	LatencySyncInterval time.Duration
	// Logger はすり合わせの失敗を出力する (既定 slog.Default())。
	Logger *slog.Logger
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
//
// 1 シグナルの判定 (Observe) で Redis へ問い合わせるのは 1 回だけ。記録と 2 つの窓の集計を 1 つのパイプラインで送る。
// 平常時レイテンシの基準値は全メソッドで 1 つのキーに入るため、リクエストのたびに更新すると
// そのキー (Redis Cluster では 1 つのノード) に書き込みが集中する。そこで基準値は各インスタンスのメモリで計算し、
// LatencySyncInterval ごとに「その間に観測した平均と件数」を送って全体の基準値を受け取る (SyncLatency)。
// インスタンス間の基準値の差は、最大で 1 回のすり合わせの間隔ぶんになる。
type RedisBuffer struct {
	client    redis.UniversalClient
	prefix    string
	maxEvents int
	now       func() time.Time
	syncEvery time.Duration
	logger    *slog.Logger

	instanceID string        // イベント ID をインスタンス間で一意にするための乱数
	seq        atomic.Uint64 // 同一インスタンス・同一ミリ秒内での一意化

	latencyMu sync.Mutex
	baseline  map[string]float64       // メソッド -> 平常時レイテンシの EWMA (ms)。判定にはこれを使う
	pending   map[string]latencySample // 前回のすり合わせ以降に観測した正常応答
}

// latencySample は 1 つのメソッドについて、すり合わせの間隔内に観測した正常応答のレイテンシの合計と件数。
// 間引かれて届いた正常応答は 1/sample_rate 件ぶんとして数えるため、件数は小数になりうる。
type latencySample struct {
	sum float64
	n   float64
}

var (
	_ Buffer         = (*RedisBuffer)(nil)
	_ SignalObserver = (*RedisBuffer)(nil)
)

// syncLatencyScript は各インスタンスが観測した平均を全体の基準値 (EWMA) に反映し、反映後の全メソッドの値を返す。
// n 件の観測を平均 m の 1 件として扱い、EWMA を n 回適用したときと同じ重み 1-(1-α)^n で混ぜる。
// 複数インスタンスが同時にすり合わせても値が失われないよう、読み書きを 1 スクリプトで行う。
//
//	KEYS[1] = <prefix>latency
//	ARGV    = α, メソッド 1, 平均 1, 件数 1, メソッド 2, ...
var syncLatencyScript = redis.NewScript(`
local alpha = tonumber(ARGV[1])
for i = 2, #ARGV, 3 do
  local mean = tonumber(ARGV[i + 1])
  local n = tonumber(ARGV[i + 2])
  local baseline = redis.call('HGET', KEYS[1], ARGV[i])
  if baseline then
    baseline = tonumber(baseline)
    mean = baseline + (1 - (1 - alpha) ^ n) * (mean - baseline)
  end
  redis.call('HSET', KEYS[1], ARGV[i], string.format('%.17g', mean))
end
return redis.call('HGETALL', KEYS[1])
`)

// NewRedisBuffer は client を使う RedisBuffer を返す。client の Close は呼び出し側が行う。
// 平常時レイテンシの基準値をインスタンス間で共有するため、Start を呼ぶこと。
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
	if opts.LatencySyncInterval <= 0 {
		opts.LatencySyncInterval = DefaultLatencySyncInterval
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
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
		syncEvery:  opts.LatencySyncInterval,
		logger:     opts.Logger,
		instanceID: hex.EncodeToString(id),
		baseline:   make(map[string]float64),
		pending:    make(map[string]latencySample),
	}, nil
}

// Start は起動時に全体の基準値を読み込み、LatencySyncInterval ごとに SyncLatency を実行する goroutine を起動する。
// ctx がキャンセルされると、まだ送っていない観測を送ってから停止する。
func (b *RedisBuffer) Start(ctx context.Context) {
	if err := b.SyncLatency(ctx); err != nil {
		b.logger.Warn("redis buffer: initial latency sync failed", "err", err)
	}
	ticker := time.NewTicker(b.syncEvery)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				flushCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := b.SyncLatency(flushCtx); err != nil {
					b.logger.Warn("redis buffer: final latency sync failed", "err", err)
				}
				return
			case <-ticker.C:
				if err := b.SyncLatency(ctx); err != nil {
					b.logger.Warn("redis buffer: latency sync failed", "err", err)
				}
			}
		}
	}()
}

// SyncLatency は前回以降に観測した正常応答を全体の基準値に反映し、全体の基準値を受け取る (往復 1 回)。
// 失敗した場合、観測は次回のすり合わせで送る。
func (b *RedisBuffer) SyncLatency(ctx context.Context) error {
	b.latencyMu.Lock()
	pending := b.pending
	b.pending = make(map[string]latencySample, len(pending))
	b.latencyMu.Unlock()

	args := make([]any, 0, 1+3*len(pending))
	args = append(args, latencyAlpha)
	for method, s := range pending {
		args = append(args, method, s.sum/s.n, s.n)
	}
	res, err := syncLatencyScript.Run(ctx, b.client, []string{b.latencyKey()}, args...).StringSlice()
	if err != nil {
		b.latencyMu.Lock()
		for method, s := range pending {
			p := b.pending[method]
			b.pending[method] = latencySample{sum: p.sum + s.sum, n: p.n + s.n}
		}
		b.latencyMu.Unlock()
		return fmt.Errorf("redis buffer: sync latency: %w", err)
	}

	global := make(map[string]float64, len(res)/2)
	for i := 0; i+1 < len(res); i += 2 {
		v, err := strconv.ParseFloat(res[i+1], 64)
		if err != nil {
			continue
		}
		global[res[i]] = v
	}
	b.latencyMu.Lock()
	for method, v := range global {
		b.baseline[method] = v
	}
	b.latencyMu.Unlock()
	return nil
}

// ObserveSignal はレイテンシの比率を算出してシグナルを記録し、記録後の 1 分と 5 分の窓の集計を返す。
// Redis への往復は 1 回。
func (b *RedisBuffer) ObserveSignal(ctx context.Context, signal *jevargosv1.SecuritySignal) (Features, error) {
	ip := signal.GetUserContext().GetClientIp()
	method := signal.GetRequestContext().GetMethod()
	resp := signal.GetResponseContext()

	ratio := b.spikeRatio(method, resp.GetLatencyMs())
	ok := resp.GetStatusCode() == 0
	if ok {
		b.observeLatency(method, resp.GetLatencyMs(), SampleWeight(signal))
	}

	nowMs := b.now().UnixMilli()
	var errCount, deniedCount *redis.IntCmd
	queue := func(p redis.Pipeliner) error {
		if !ok {
			b.queueRecord(ctx, p, ip, method, resp.GetStatusCode(), nowMs)
		}
		errCount = p.ZCount(ctx, b.errKey(ip), windowMin(nowMs, 60), "+inf")
		deniedCount = p.ZCount(ctx, b.deniedKey(ip), windowMin(nowMs, RetentionSeconds), "+inf")
		return nil
	}
	var err error
	if ok {
		_, err = b.client.Pipelined(ctx, queue) // 読むだけなのでトランザクションにしない
	} else {
		_, err = b.client.TxPipelined(ctx, queue) // 自分の記録を含めて集計する
	}
	if err != nil {
		return Features{}, fmt.Errorf("redis buffer: observe: %w", err)
	}
	return Features{
		IPErrorCount1m:        int(errCount.Val()),
		UniqueDeniedMethods5m: int(deniedCount.Val()),
		LatencySpikeRatio:     ratio,
	}, nil
}

// RecordSignal はシグナルを記録する。
// 異常応答はウィンドウ集計用に Redis に保持し、正常応答はレイテンシの基準値の更新 (メモリ上) にだけ使う。
func (b *RedisBuffer) RecordSignal(ctx context.Context, signal *jevargosv1.SecuritySignal) error {
	method := signal.GetRequestContext().GetMethod()
	resp := signal.GetResponseContext()
	if resp.GetStatusCode() == 0 {
		b.observeLatency(method, resp.GetLatencyMs(), SampleWeight(signal))
		return nil
	}
	_, err := b.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		b.queueRecord(ctx, p, signal.GetUserContext().GetClientIp(), method, resp.GetStatusCode(), b.now().UnixMilli())
		return nil
	})
	if err != nil {
		return fmt.Errorf("redis buffer: record error event: %w", err)
	}
	return nil
}

// queueRecord は異常応答の記録を p に積む。
func (b *RedisBuffer) queueRecord(ctx context.Context, p redis.Pipeliner, ip, method string, status int32, nowMs int64) {
	expired := strconv.FormatInt(nowMs-RetentionSeconds*1000, 10)
	ttl := RetentionSeconds * time.Second
	errKey := b.errKey(ip)
	member := fmt.Sprintf("%d:%s:%d", nowMs, b.instanceID, b.seq.Add(1))

	p.ZAdd(ctx, errKey, redis.Z{Score: float64(nowMs), Member: member})
	p.ZRemRangeByScore(ctx, errKey, "-inf", expired)
	p.ZRemRangeByRank(ctx, errKey, 0, int64(-b.maxEvents-1)) // 新しい maxEvents 件だけ残す
	p.Expire(ctx, errKey, ttl)
	if status == codePermissionDenied {
		deniedKey := b.deniedKey(ip)
		p.ZAdd(ctx, deniedKey, redis.Z{Score: float64(nowMs), Member: method})
		p.ZRemRangeByScore(ctx, deniedKey, "-inf", expired)
		p.ZRemRangeByRank(ctx, deniedKey, 0, int64(-b.maxEvents-1))
		p.Expire(ctx, deniedKey, ttl)
	}
}

// GetStats は clientIP について直近 windowSeconds 秒の統計を返す。
func (b *RedisBuffer) GetStats(ctx context.Context, clientIP string, windowSeconds int) (WindowStats, error) {
	windowSeconds = clampWindow(windowSeconds)
	if windowSeconds == 0 {
		return WindowStats{}, nil
	}

	minScore := windowMin(b.now().UnixMilli(), windowSeconds)
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

// GetLatencySpikeRatio は method の平常時平均レイテンシに対する latencyMs の比率を返す (Redis には問い合わせない)。
func (b *RedisBuffer) GetLatencySpikeRatio(_ context.Context, method string, latencyMs int64) (float64, error) {
	return b.spikeRatio(method, latencyMs), nil
}

func (b *RedisBuffer) spikeRatio(method string, latencyMs int64) float64 {
	b.latencyMu.Lock()
	baseline, ok := b.baseline[method]
	b.latencyMu.Unlock()
	return spikeRatio(baseline, ok, latencyMs)
}

// observeLatency は正常応答のレイテンシ weight 件ぶんを手元の基準値に反映し、次回のすり合わせで送る観測に加える。
func (b *RedisBuffer) observeLatency(method string, latencyMs int64, weight float64) {
	latency := float64(latencyMs)
	b.latencyMu.Lock()
	defer b.latencyMu.Unlock()
	if baseline, ok := b.baseline[method]; ok {
		b.baseline[method] = mergeLatency(baseline, latency, weight)
	} else {
		b.baseline[method] = latency
	}
	s := b.pending[method]
	b.pending[method] = latencySample{sum: s.sum + weight*latency, n: s.n + weight}
}

// windowMin は直近 windowSeconds 秒の窓の下限を返す。
// "(" は排他境界。ちょうど windowSeconds 秒前のイベントは窓の外とする (MemoryBuffer と同じ)。
func windowMin(nowMs int64, windowSeconds int) string {
	return "(" + strconv.FormatInt(nowMs-int64(windowSeconds)*1000, 10)
}

func (b *RedisBuffer) errKey(ip string) string    { return b.prefix + "{" + ip + "}:err" }
func (b *RedisBuffer) deniedKey(ip string) string { return b.prefix + "{" + ip + "}:denied" }
func (b *RedisBuffer) latencyKey() string         { return b.prefix + "latency" }
