package classifier_test

import (
	"math"
	"testing"

	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
)

type fixedModel struct{ score, confidence float64 }

func (m fixedModel) Evaluate(buffer.Features) (float64, float64) { return m.score, m.confidence }

func TestClassify_ClampsModelOutput(t *testing.T) {
	tests := []struct {
		name                string
		score, conf         float64
		wantScore, wantConf float64
	}{
		{"in range", 2.5, 0.7, 2.5, 0.7},
		{"above range", 9, 1.5, classifier.MaxScore, 1},
		{"below range", -1, -0.5, classifier.MinScore, 0},
		{"NaN confidence becomes 0", 4, math.NaN(), classifier.MaxScore, 0},
		{"NaN score becomes minimum", math.NaN(), 1, classifier.MinScore, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifier.New(fixedModel{tt.score, tt.conf}).Classify(buffer.Features{})
			if got.Score != tt.wantScore || got.Confidence != tt.wantConf {
				t.Errorf("got %+v; want S=%v C=%v", got, tt.wantScore, tt.wantConf)
			}
		})
	}
}

// NaN の確信度は 0 に補正されるため、スコアが最大でも遮断されない。
func TestClassify_NaNConfidenceNeverBlocks(t *testing.T) {
	a := classifier.New(fixedModel{4, math.NaN()}).Classify(buffer.Features{})
	if d := guardrail.Decide(a); d.Level == guardrail.Level4 {
		t.Errorf("Decide(%+v) = %+v; must not block", a, d)
	}
}

func TestHeuristicModel(t *testing.T) {
	tests := []struct {
		name           string
		features       buffer.Features
		wantLevel      guardrail.Level
		wantDowngraded bool
	}{
		{"normal traffic", buffer.Features{LatencySpikeRatio: 1}, guardrail.Level1, false},
		{"few errors", buffer.Features{IPErrorCount1m: 3, LatencySpikeRatio: 1}, guardrail.Level1, false},
		// エラー大量だが他の特徴量の裏付けが無い: 危険スコアでも遮断せず人間に回す
		{"error burst only", buffer.Features{IPErrorCount1m: 30, LatencySpikeRatio: 1}, guardrail.Level3, true},
		// エラー大量 + 権限探索 (フットプリンティング): 即時遮断
		{"error burst with method probing", buffer.Features{IPErrorCount1m: 30, UniqueDeniedMethods5m: 5, LatencySpikeRatio: 1}, guardrail.Level4, false},
		{"latency spike only", buffer.Features{LatencySpikeRatio: 5}, guardrail.Level2, false},
	}
	c := classifier.NewDefault()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := c.Classify(tt.features)
			if a.Score < classifier.MinScore || a.Score > classifier.MaxScore || a.Confidence < 0 || a.Confidence > 1 {
				t.Fatalf("Classify(%+v) out of range: %+v", tt.features, a)
			}
			d := guardrail.Decide(a)
			if d.Level != tt.wantLevel || d.Downgraded != tt.wantDowngraded {
				t.Errorf("Classify(%+v) = %+v -> %+v; want level %d, downgraded %v",
					tt.features, a, d, tt.wantLevel, tt.wantDowngraded)
			}
		})
	}
}
