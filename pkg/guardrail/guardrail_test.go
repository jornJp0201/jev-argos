package guardrail

import (
	"math"
	"testing"

	"github.com/jornJp0201/jev-argos/pkg/classifier"
)

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
