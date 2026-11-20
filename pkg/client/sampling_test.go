package client

import (
	"context"
	"math"
	"math/rand/v2"
	"testing"
	"time"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
)

func okSignal(method string, latencyMs int64) *jevargosv1.SecuritySignal {
	return &jevargosv1.SecuritySignal{
		UserContext:     &jevargosv1.UserContext{ClientIp: "192.0.2.1"},
		RequestContext:  &jevargosv1.RequestContext{Method: method},
		ResponseContext: &jevargosv1.ResponseContext{LatencyMs: latencyMs},
	}
}

// 乱数が r を返す sampler (Rate 0.1)。
func fixedSampler(r float64) *sampler {
	return newSampler(Sampling{Rate: 0.1, Random: func() float64 { return r }})
}

func TestSampler_Disabled(t *testing.T) {
	for _, rate := range []float64{0, 1, -1, 2} {
		if newSampler(Sampling{Rate: rate}) != nil {
			t.Errorf("Rate %v: sampling should be disabled", rate)
		}
	}
}

func TestSampler_AlwaysKeepsErrors(t *testing.T) {
	sp := fixedSampler(0.99) // 乱数では必ず間引かれる
	s := okSignal("/m", 10)
	s.ResponseContext.StatusCode = 7
	if !sp.keep(s) || s.SampleRate != 0 {
		t.Errorf("error response must be sent without sample_rate (got %v)", s.SampleRate)
	}
}

func TestSampler_KeepsFirstAndSlowResponses(t *testing.T) {
	sp := fixedSampler(0.99)
	if !sp.keep(okSignal("/m", 50)) {
		t.Error("first response of a method must be sent (it seeds the server's baseline)")
	}
	if sp.keep(okSignal("/m", 60)) {
		t.Error("normal response should be skipped")
	}
	s := okSignal("/m", 200) // 平均 (約 51ms) の 2 倍を超える
	if !sp.keep(s) || s.SampleRate != 0 {
		t.Errorf("slow response must be sent without sample_rate (got %v)", s.SampleRate)
	}

	abs := newSampler(Sampling{Rate: 0.1, SlowThreshold: 30 * time.Millisecond, Random: func() float64 { return 0.99 }})
	abs.keep(okSignal("/m", 50))
	if !abs.keep(okSignal("/m", 40)) {
		t.Error("response slower than SlowThreshold must be sent")
	}
}

func TestSampler_SetsSampleRate(t *testing.T) {
	sp := fixedSampler(0.05)
	sp.keep(okSignal("/m", 50))
	s := okSignal("/m", 50)
	if !sp.keep(s) || s.SampleRate != 0.1 {
		t.Errorf("sampled response: kept=%v sample_rate=%v, want kept with 0.1", s.SampleRate != 0, s.SampleRate)
	}
}

// 間引かれた応答は送られず、送られた応答は sample_rate を付けてサーバーに届く。
func TestReporter_Sampling(t *testing.T) {
	cp := startControlPlane(t)
	randoms := []float64{0.99, 0.05} // 2 件目は間引き、3 件目は送る
	r := NewReporter(cp.conn, ReporterOptions{Sampling: Sampling{Rate: 0.1, Random: func() float64 {
		v := randoms[0]
		randoms = randoms[1:]
		return v
	}}})
	for range 3 {
		r.Report(okSignal("/m", 50))
	}
	r.Close(context.Background())

	got := cp.observed()
	rates := map[float64]int{}
	for _, e := range got {
		rates[e.Signal.GetSampleRate()]++
	}
	if len(got) != 2 || rates[0] != 1 || rates[0.1] != 1 { // 送信は並列のため、届く順序は決まっていない
		t.Fatalf("observed sample_rates %v, want one without sample_rate and one with 0.1", rates)
	}
	if st := r.Stats(); st.Skipped != 1 || st.Sent != 2 {
		t.Errorf("stats = %+v, want Sent=2 Skipped=1", st)
	}
}

// traffic は 1 つの API の正常な応答の処理時間を返す。
// 普段は平均 50ms でばらつき、3% は処理時間の急増 (150〜250ms) とする。spike は急増かどうか。
func traffic(rng *rand.Rand) (latencyMs int64, spike bool) {
	if rng.Float64() < 0.03 {
		return int64(150 + rng.IntN(100)), true
	}
	return max(1, int64(50+rng.NormFloat64()*15)), false
}

// trueMean は traffic の処理時間の平均 (0.97 × 50 + 0.03 × 199.5)。
const trueMean = 0.97*50 + 0.03*199.5

// 正常な応答だけの流れを、全件送った場合と間引いた場合でサーバーに渡し、
// 送る量・レイテンシの基準値の誤差・処理時間の急増を検知できた数 (Level 2 以上) を比べる。
// 「重みなし」は sample_rate を付けずに送った場合 (サーバーが 1 件を 1 件として数える)。
//
//	go test -run SamplingAccuracy -v ./pkg/client/
func TestSamplingAccuracy(t *testing.T) {
	const n = 200000
	ctx := context.Background()
	cls, guard := classifier.NewDefault(), guardrail.Default()

	type result struct {
		sent, detected, falseAlerts int
		baselineErr                 float64 // 基準値と真の平均との差の平均 (ms)
	}
	run := func(rate float64, weighted bool) result {
		rng := rand.New(rand.NewPCG(1, 2))
		var sp *sampler
		if rate > 0 {
			sp = newSampler(Sampling{Rate: rate, Random: rng.Float64})
		}
		buf := buffer.NewMemoryBuffer()
		var res result
		var errSum float64
		for range n {
			latency, spike := traffic(rng)
			s := okSignal("/user.UserService/GetUser", latency)
			if sp != nil && !sp.keep(s) {
				continue
			}
			if !weighted {
				s.SampleRate = 0
			}
			res.sent++
			f, _ := buffer.Observe(ctx, buf, s)
			if guard.Decide(cls.Classify(f)).Level >= guardrail.Level2 {
				if spike {
					res.detected++
				} else {
					res.falseAlerts++
				}
			}
			ratio, _ := buf.GetLatencySpikeRatio(ctx, "/user.UserService/GetUser", 100)
			errSum += math.Abs(100/ratio - trueMean)
		}
		res.baselineErr = errSum / float64(res.sent)
		return res
	}

	full, sampled, unweighted := run(0, true), run(0.1, true), run(0.1, false)
	for _, r := range []struct {
		name string
		result
	}{{"全件           ", full}, {"25% (重み付き) ", run(0.25, true)}, {"10% (重み付き) ", sampled}, {"10% (重みなし) ", unweighted}} {
		t.Logf("%s: 送信 %6d 件 (%5.1f%%), 基準値の誤差 %4.1fms, 急増の検知 %4d 件 (%5.1f%%), 誤検知 %d 件",
			r.name, r.sent, 100*float64(r.sent)/n, r.baselineErr, r.detected, 100*float64(r.detected)/float64(full.detected), r.falseAlerts)
	}

	if sampled.sent > n/7 {
		t.Errorf("sent %d of %d, want about 13%% (10%% + slow responses)", sampled.sent, n)
	}
	if sampled.detected < full.detected*8/10 {
		t.Errorf("detected %d spikes, want at least 80%% of %d", sampled.detected, full.detected)
	}
	if sampled.falseAlerts > n/10000 { // 基準値のばらつきが増えるため、わずかに起きる
		t.Errorf("false alerts %d, want at most 0.01%% of %d", sampled.falseAlerts, n)
	}
}
