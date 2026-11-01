// Package guardrail は確信度ガードレールと安全境界ルール (設計書 5.1.1 Step 3) を提供する。
// Jev の評価結果 (S, C) から対応レベルを決定する。
package guardrail

import "github.com/jornJp0201/jev-argos/pkg/classifier"

// Level は判定結果の対応レベル (設計書 5 章)。
type Level int

const (
	Level1 Level = 1 // 静観 / 記録のみ
	Level2 Level = 2 // LLM 非同期分析
	Level3 Level = 3 // LLM 深層解析 + 人間への通知 (Human-in-the-Loop)
	Level4 Level = 4 // 即時遮断
)

// 既定の閾値。実測から導いた値ではなく、安全側に倒した初期値で、運用データを見て調整する前提 (設計書 5.1.1)。
const (
	// DefaultBlockScore 以上かつ DefaultBlockConfidence 以上で Level 4 (自動遮断)。
	DefaultBlockScore = 3.5
	// DefaultBlockConfidence 未満での自動遮断は、ネットワーク瞬断やアプリのバグで正常ユーザーを
	// 締め出すリスクが高い。誤遮断を避けるため確信度の閾値を高めに置き、未満なら Level 3 に下げて人間の判断に回す。
	DefaultBlockConfidence = 0.8
	// Level 2 / 3 の下限スコア (設計書に定めが無いため暫定の初期値)。
	DefaultLevel3Score = 2.5
	DefaultLevel2Score = 1.5
)

// Guardrail はレベルを分ける閾値。ゼロ値のフィールドは既定値として扱われる (New を使うと明示的)。
//
// [差し替えポイント] 判定を厳しく / 緩くしたい場合はここを変える。ライブラリとして使う場合は
// guardrail.New(...) で構造体を作って receiver.Options.Guardrail に渡す。付属サーバーでは
// 環境変数 (JEV_ARGOS_BLOCK_SCORE / _BLOCK_CONFIDENCE / _LEVEL3_SCORE / _LEVEL2_SCORE) で指定できる。
type Guardrail struct {
	BlockScore      float64 // この S 以上かつ BlockConfidence 以上で Level 4
	BlockConfidence float64 // この C 未満なら、S が遮断域でも Level 3 に格下げ
	Level3Score     float64 // この S 以上で Level 3
	Level2Score     float64 // この S 以上で Level 2
}

// New は閾値を指定した Guardrail を返す。0 以下のフィールドは既定値で補う。
func New(g Guardrail) Guardrail {
	if g.BlockScore <= 0 {
		g.BlockScore = DefaultBlockScore
	}
	if g.BlockConfidence <= 0 {
		g.BlockConfidence = DefaultBlockConfidence
	}
	if g.Level3Score <= 0 {
		g.Level3Score = DefaultLevel3Score
	}
	if g.Level2Score <= 0 {
		g.Level2Score = DefaultLevel2Score
	}
	return g
}

// Default は既定の閾値を使う Guardrail を返す。
func Default() Guardrail { return New(Guardrail{}) }

// Decision は安全境界ルールを適用した結果。
type Decision struct {
	Level Level
	// Downgraded は S が遮断域だが確信度が足りず Level 4 から Level 3 に下げたことを示す。
	Downgraded bool
}

// Decide は評価結果に安全境界ルールを適用して対応レベルを決める。
func (g Guardrail) Decide(a classifier.Assessment) Decision {
	switch {
	case a.Score >= g.BlockScore && a.Confidence >= g.BlockConfidence:
		return Decision{Level: Level4}
	case a.Score >= g.BlockScore:
		return Decision{Level: Level3, Downgraded: true}
	case a.Score >= g.Level3Score:
		return Decision{Level: Level3}
	case a.Score >= g.Level2Score:
		return Decision{Level: Level2}
	default:
		return Decision{Level: Level1}
	}
}

// Decide は既定の閾値で判定する (Default().Decide と同じ)。閾値を変える場合は Guardrail を作って Decide メソッドを使う。
func Decide(a classifier.Assessment) Decision { return Default().Decide(a) }
