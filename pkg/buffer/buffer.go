// Package buffer は Sliding Window Buffer (設計書 5.1.1 Step 1) を提供する。
// シグナルを記録し、Jev 判定に渡す時系列特徴量の元になる直近統計を算出する。
//
// 実装は 2 種類あり、設定で切り替える (設計書 7.2):
//   - MemoryBuffer: 単一プロセス内で集計する (開発用・Zero Config)
//   - RedisBuffer: Redis 上で集計し、複数のサーバーインスタンスで統計を共有する (本番用)。
//     平常時レイテンシの基準値だけは各インスタンスのメモリで計算し、定期的に Redis とすり合わせる
package buffer

import (
	"context"
	"math"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
)

// RetentionSeconds はバッファがシグナルを保持する期間 (秒)。
// これより長いウィンドウを指定した場合も、この期間分だけが集計対象になる。
const RetentionSeconds = 300

// DefaultMaxEventsPerIP は 1 IP あたりに保持する異常応答の上限。
// 大量エラーを送り付ける攻撃でメモリが枯渇しないよう、超えた分は古い順に捨てる。
// 分類器の特徴量はこれよりずっと少ない件数で飽和するため、判定への影響はない。
const DefaultMaxEventsPerIP = 10000

// gRPC status code: PERMISSION_DENIED
const codePermissionDenied = 7

// latencyAlpha は平常時レイテンシ (EWMA) の平滑化係数。
const latencyAlpha = 0.1

// maxSampleWeight は 1 件のシグナルが表せる件数の上限 (sample_rate 0.01 に相当)。
// 極端に小さい sample_rate で、1 件が基準値や件数を大きく動かさないようにする。
const maxSampleWeight = 100

// SampleWeight はシグナルが何件ぶんの応答を表すかを返す。
// アダプターが正常な応答を間引いて送った場合は 1/sample_rate、間引いていなければ 1。
func SampleWeight(signal *jevargosv1.SecuritySignal) float64 {
	r := signal.GetSampleRate()
	if r <= 0 || r >= 1 {
		return 1
	}
	return min(1/r, maxSampleWeight)
}

// mergeLatency は基準値 (EWMA) に、平均 mean の観測 weight 件ぶんを反映した値を返す。
// EWMA を weight 回適用したときと同じ重み 1-(1-α)^weight で混ぜる。
func mergeLatency(baseline, mean, weight float64) float64 {
	return baseline + (1-math.Pow(1-latencyAlpha, weight))*(mean-baseline)
}

// WindowStats は 1 つの IP について、指定ウィンドウ内で集計した統計。
type WindowStats struct {
	// WindowSeconds は集計に使ったウィンドウ幅 (秒)。RetentionSeconds で頭打ちになる。
	WindowSeconds int
	// ErrorCount はウィンドウ内の異常応答数 (status_code != 0)。
	// windowSeconds = 60 のとき ip_error_count_1m に相当する。
	ErrorCount int
	// UniqueDeniedMethods はウィンドウ内に PERMISSION_DENIED を起こしたユニークな API メソッド数。
	// windowSeconds = 300 のとき unique_denied_methods_5m に相当する。
	UniqueDeniedMethods int
}

// Buffer は Sliding Window Buffer の共通インターフェース。
//
// [差し替えポイント] Redis 以外の共有ストア (Memcached・DynamoDB 等) を使う場合はこれを実装する。
// 振る舞いの要件は buffer_contract_test.go の共通テスト (runContractTests) で確認できる。
type Buffer interface {
	// RecordSignal はシグナルを記録する。
	RecordSignal(ctx context.Context, signal *jevargosv1.SecuritySignal) error
	// GetStats は clientIP について直近 windowSeconds 秒の統計を返す。
	// windowSeconds は RetentionSeconds で頭打ちになり、0 以下なら空の統計を返す。
	GetStats(ctx context.Context, clientIP string, windowSeconds int) (WindowStats, error)
	// GetLatencySpikeRatio は method の平常時平均レイテンシに対する latencyMs の比率
	// (latency_spike_ratio) を返す。基準値がまだ無い場合は 1.0。
	// 今回のシグナル自身を基準に含めないよう、RecordSignal より前に呼ぶこと。
	GetLatencySpikeRatio(ctx context.Context, method string, latencyMs int64) (float64, error)
}

// Features は Jev 判定に渡す判定コンテキストベクトル (設計書 5.1.1 Step 1 の出力)。
type Features struct {
	IPErrorCount1m        int     // 直近 60 秒間の同一 IP からの異常応答数
	UniqueDeniedMethods5m int     // 直近 300 秒間に同一 IP が PERMISSION_DENIED を起こしたユニークメソッド数
	LatencySpikeRatio     float64 // 当該メソッドの平常時平均レイテンシに対する比率
}

// SignalObserver は Observe の処理 (比率の算出 → 記録 → 2 つの窓の集計) をまとめて行える Buffer が実装する (任意)。
// Buffer のメソッドを順に呼ぶと外部ストアへの往復が 4 回になるため、RedisBuffer はこれを実装して 1 回にしている。
type SignalObserver interface {
	ObserveSignal(ctx context.Context, signal *jevargosv1.SecuritySignal) (Features, error)
}

// Observe はシグナルを b に記録し、記録後の統計から Features を組み立てる。
// b が SignalObserver を実装していればそちらを使う。
func Observe(ctx context.Context, b Buffer, signal *jevargosv1.SecuritySignal) (Features, error) {
	if o, ok := b.(SignalObserver); ok {
		return o.ObserveSignal(ctx, signal)
	}
	ip := signal.GetUserContext().GetClientIp()
	ratio, err := b.GetLatencySpikeRatio(ctx,
		signal.GetRequestContext().GetMethod(),
		signal.GetResponseContext().GetLatencyMs(),
	)
	if err != nil {
		return Features{}, err
	}
	if err := b.RecordSignal(ctx, signal); err != nil {
		return Features{}, err
	}
	errStats, err := b.GetStats(ctx, ip, 60)
	if err != nil {
		return Features{}, err
	}
	deniedStats, err := b.GetStats(ctx, ip, 300)
	if err != nil {
		return Features{}, err
	}
	return Features{
		IPErrorCount1m:        errStats.ErrorCount,
		UniqueDeniedMethods5m: deniedStats.UniqueDeniedMethods,
		LatencySpikeRatio:     ratio,
	}, nil
}

// clampWindow は windowSeconds を [0, RetentionSeconds] に収める。
func clampWindow(windowSeconds int) int {
	return max(0, min(windowSeconds, RetentionSeconds))
}
