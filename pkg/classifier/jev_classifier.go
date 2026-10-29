// Package classifier は Jev 確率分類エンジン (設計書 5.1.1 Step 2) を提供する。
// 特徴量ベクトルからリスクスコア S と確信度 C を算出する。
// S と C から対応レベルを決める安全境界ルール (Step 3) は guardrail パッケージが担う。
package classifier

import (
	"math"

	"github.com/jornJp0201/jev-argos/pkg/buffer"
)

const (
	MinScore = 0.0
	MaxScore = 4.0
)

// Model は特徴量ベクトルからリスクスコア S と確信度 C を算出する分類モデル。
//
// [差し替えポイント] 学習済みの Jev モデルを使う場合は Model を実装し、classifier.New(model) に渡す
// (cmd/jev-argos-server/main.go の classifier.NewDefault() を置き換える)。既定の HeuristicModel は
// 学習データが無い段階の暫定のルールベースモデル。
// 返り値は Classifier 側で範囲外・NaN を補正するため、厳密に範囲内である必要はない。
type Model interface {
	Evaluate(features buffer.Features) (score, confidence float64)
}

// Assessment は 1 シグナルの評価結果。
type Assessment struct {
	Score      float64 // S ∈ [0.0, 4.0]
	Confidence float64 // C ∈ [0.0, 1.0]
}

// Classifier は Model の出力を正規化して Assessment を返す。
type Classifier struct {
	model Model
}

// New は指定した Model を使う Classifier を返す。
func New(model Model) *Classifier {
	return &Classifier{model: model}
}

// NewDefault は HeuristicModel を使う Classifier を返す。
func NewDefault() *Classifier {
	return New(HeuristicModel{})
}

// Classify は特徴量ベクトルを評価する。
func (c *Classifier) Classify(features buffer.Features) Assessment {
	score, confidence := c.model.Evaluate(features)
	// NaN はスコアを最小、確信度を 0 として扱い、遮断に倒れないようにする。
	return Assessment{
		Score:      clamp(score, MinScore, MaxScore, MinScore),
		Confidence: clamp(confidence, 0, 1, 0),
	}
}

func clamp(v, lo, hi, nan float64) float64 {
	if math.IsNaN(v) {
		return nan
	}
	return math.Max(lo, math.Min(hi, v))
}

// HeuristicModel は学習済み Jev モデルが用意されるまでの暫定ルールベースモデル。
//
// 各特徴量を [0, 1] に正規化し、noisy-OR で危険確率 p を合成して S = 4p とする。
// 確信度は、危険側 (p >= 0.5) では「証拠量」と「複数特徴量の裏付け」から、
// 安全側では 1 - p から算出する。単一の特徴量だけが突出している場合は
// 確信度が 0.8 に届かず、Level 4 にはならない。
type HeuristicModel struct{}

const (
	errorCountSaturation   = 30.0 // この件数で ip_error_count_1m の寄与が最大
	deniedMethodSaturation = 5.0  // この件数で unique_denied_methods_5m の寄与が最大
	latencyRatioSaturation = 5.0  // この倍率で latency_spike_ratio の寄与が最大

	errorWeight   = 0.9
	deniedWeight  = 0.9
	latencyWeight = 0.6

	activeFeatureThreshold = 0.5  // この値以上の正規化特徴量を「反応あり」とみなす
	evidenceHalfPoint      = 10.0 // 証拠量がこの件数で volume = 0.5
)

func (HeuristicModel) Evaluate(f buffer.Features) (score, confidence float64) {
	features := [3]float64{
		clamp(float64(f.IPErrorCount1m)/errorCountSaturation, 0, 1, 0),
		clamp(float64(f.UniqueDeniedMethods5m)/deniedMethodSaturation, 0, 1, 0),
		clamp((f.LatencySpikeRatio-1)/(latencyRatioSaturation-1), 0, 1, 0),
	}
	weights := [3]float64{errorWeight, deniedWeight, latencyWeight}

	benign := 1.0
	active := 0
	for i, v := range features {
		benign *= 1 - weights[i]*v
		if v >= activeFeatureThreshold {
			active++
		}
	}
	p := 1 - benign

	if p < 0.5 {
		return MaxScore * p, 1 - p
	}
	n := float64(f.IPErrorCount1m + f.UniqueDeniedMethods5m)
	volume := n / (n + evidenceHalfPoint)
	corroboration := math.Min(float64(active), 2) / 2
	return MaxScore * p, 0.5*volume + 0.5*corroboration
}
