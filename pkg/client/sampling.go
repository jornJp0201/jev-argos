package client

import (
	"math/rand/v2"
	"sync"
	"time"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
)

// Sampling は正常な応答を間引いて送る設定 (ReporterOptions.Sampling)。
//
// サーバーは正常な応答を、API ごとの普段の処理時間 (レイテンシの基準値) の計算にしか使わない。
// 攻撃の判定に使う統計 (エラー数・権限エラーを起こした API の数) はエラーだけから数えるため、
// エラーをすべて送れば、正常な応答を間引いても判定は変わらない。リクエストの大半は正常な応答なので、送る量が大きく減る。
//
//   - エラー (status_code != 0) はすべて送る
//   - 遅い応答は必ず送る (処理時間の急増を見逃さないため)。遅いかどうかは、アダプターの手元で API ごとに求めた平均と比べる
//   - それ以外の正常な応答は Rate の割合だけ送る。送ったシグナルには sample_rate を付け、
//     サーバーは 1/sample_rate 件ぶんとして基準値やダッシュボードの件数に反映する
type Sampling struct {
	// Rate は正常な応答を送る割合 (例: 0.1 なら 10 件に 1 件)。0 以下または 1 以上なら間引かない。
	// サーバーは 0.01 未満を 0.01 として扱う。
	Rate float64
	// SlowFactor は、API ごとの手元の平均の何倍を超えたら必ず送るか (0 なら 2)。
	SlowFactor float64
	// SlowThreshold は、これを超えたら必ず送る処理時間 (0 なら使わない)。
	SlowThreshold time.Duration
	// Random は 0 以上 1 未満の乱数 (テスト用。nil なら math/rand/v2)。
	Random func() float64
}

// maxSampledMethods は手元で平均を持つ API の数の上限 (メモリを使い切らないように)。
// 超えた API は平均を持たず、SlowThreshold だけで遅いかを判断する。
const maxSampledMethods = 10000

// sampler は Sampling に従って、シグナルを送るかを決める。複数 goroutine から使える。
type sampler struct {
	cfg  Sampling
	mu   sync.Mutex
	mean map[string]float64 // API -> 正常な応答の処理時間の平均 (EWMA、ms)
}

func newSampler(cfg Sampling) *sampler {
	if cfg.Rate <= 0 || cfg.Rate >= 1 {
		return nil
	}
	if cfg.SlowFactor <= 0 {
		cfg.SlowFactor = 2
	}
	if cfg.Random == nil {
		cfg.Random = rand.Float64
	}
	return &sampler{cfg: cfg, mean: make(map[string]float64)}
}

// samplerAlpha は手元の平均 (EWMA) の平滑化係数 (サーバーの基準値と同じ)。
const samplerAlpha = 0.1

// keep はシグナルを送るかを返す。送る場合は、間引いたときだけ s.SampleRate を設定する。
func (sp *sampler) keep(s *jevargosv1.SecuritySignal) bool {
	resp := s.GetResponseContext()
	if resp.GetStatusCode() != 0 {
		return true
	}
	latency := float64(resp.GetLatencyMs())
	if sp.cfg.SlowThreshold > 0 && latency > float64(sp.cfg.SlowThreshold.Milliseconds()) {
		return true
	}
	method := s.GetRequestContext().GetMethod()

	sp.mu.Lock()
	mean, known := sp.mean[method]
	first := !known && len(sp.mean) < maxSampledMethods
	switch {
	case known:
		sp.mean[method] = mean + samplerAlpha*(latency-mean)
	case first:
		sp.mean[method] = latency
	}
	sp.mu.Unlock()

	if first {
		return true // 初めて見る API は、サーバーの基準値の初期値になるので送る
	}
	if known && latency > mean*sp.cfg.SlowFactor {
		return true
	}
	if sp.cfg.Random() >= sp.cfg.Rate {
		return false
	}
	s.SampleRate = sp.cfg.Rate
	return true
}
