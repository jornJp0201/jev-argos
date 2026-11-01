package guardrail

import (
	"math"
	"testing"

	"github.com/jornJp0201/jev-argos/pkg/classifier"
)

func TestNew_FillsDefaults(t *testing.T) {
	g := New(Guardrail{BlockConfidence: 0.6}) // 一部だけ指定
	if g.BlockConfidence != 0.6 {
		t.Errorf("BlockConfidence = %v, want 0.6", g.BlockConfidence)
	}
	if g.BlockScore != DefaultBlockScore || g.Level3Score != DefaultLevel3Score || g.Level2Score != DefaultLevel2Score {
		t.Errorf("unset fields not defaulted: %+v", g)
	}
}

func TestGuardrail_CustomThresholds(t *testing.T) {
	// 確信度の閾値を下げると、既定では格下げされる (S=3.6, C=0.6) が自動遮断 (Level 4) になる。
	lenient := New(Guardrail{BlockConfidence: 0.5})
	a := classifier.Assessment{Score: 3.6, Confidence: 0.6}
	if got := Decide(a); got.Level != Level3 || !got.Downgraded { // 既定
		t.Errorf("default Decide = %+v; want downgraded Level 3", got)
	}
	if got := lenient.Decide(a); got.Level != Level4 || got.Downgraded {
		t.Errorf("lenient Decide = %+v; want Level 4", got)
	}
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name           string
		score, conf    float64
		wantLevel      Level
		wantDowngraded bool
	}{
		{"block at exact thresholds", 3.5, 0.8, Level4, false},
		{"block at max", 4.0, 1.0, Level4, false},
		{"downgrade just below confidence threshold", 3.5, 0.79, Level3, true},
		{"downgrade at max score with low confidence", 4.0, 0.1, Level3, true},
		{"just below block score is plain level 3", 3.49, 1.0, Level3, false},
		{"level 3 lower bound", 2.5, 0.5, Level3, false},
		{"level 2", 1.5, 0.9, Level2, false},
		{"level 1", 1.49, 0.9, Level1, false},
		{"zero", 0, 1, Level1, false},
		{"NaN never blocks", math.NaN(), math.NaN(), Level1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(classifier.Assessment{Score: tt.score, Confidence: tt.conf})
			if got.Level != tt.wantLevel || got.Downgraded != tt.wantDowngraded {
				t.Errorf("Decide(S=%v, C=%v) = %+v; want level %d, downgraded %v",
					tt.score, tt.conf, got, tt.wantLevel, tt.wantDowngraded)
			}
		})
	}
}
