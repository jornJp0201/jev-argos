// Package guardrail は確信度ガードレールと安全境界ルール (設計書 5.1.1 Step 3) を提供する。
// Jev の評価結果 (S, C) から対応レベルを決定する。
package guardrail

import "github.com/jev-argos/jev-argos/pkg/classifier"

// Level は判定結果の対応レベル (設計書 5 章)。
type Level int

const (
	Level1 Level = 1 // 静観 / 記録のみ
	Level2 Level = 2 // LLM 非同期分析
	Level3 Level = 3 // LLM 深層解析 + 人間への通知 (Human-in-the-Loop)
	Level4 Level = 4 // 即時遮断
)

const (
	// BlockScoreThreshold 以上かつ BlockConfidenceThreshold 以上で Level 4。
	BlockScoreThreshold = 3.5
	// BlockConfidenceThreshold 未満での自動遮断は誤遮断率が許容範囲 (FPR <= 10%) を超えるため、
	// Level 3 にダウングレードして人間の判断に回す。
	BlockConfidenceThreshold = 0.8

	// Level 2 / 3 の下限スコア。設計書に数値の定めが無いため暫定値。
	// [差し替えポイント] 運用データを見て調整する (S ≥ 3.5 / C ≥ 0.8 の遮断条件は設計書 5.1.1 の値)。
	Level2ScoreThreshold = 1.5
	Level3ScoreThreshold = 2.5
)

// Decision は安全境界ルールを適用した結果。
type Decision struct {
	Level Level
	// Downgraded は S >= 3.5 だが C < 0.8 のため Level 4 から Level 3 に下げたことを示す。
	Downgraded bool
}

// Decide は評価結果に安全境界ルールを適用して対応レベルを決める。
func Decide(a classifier.Assessment) Decision {
	switch {
	case a.Score >= BlockScoreThreshold && a.Confidence >= BlockConfidenceThreshold:
		return Decision{Level: Level4}
	case a.Score >= BlockScoreThreshold:
		return Decision{Level: Level3, Downgraded: true}
	case a.Score >= Level3ScoreThreshold:
		return Decision{Level: Level3}
	case a.Score >= Level2ScoreThreshold:
		return Decision{Level: Level2}
	default:
		return Decision{Level: Level1}
	}
}
