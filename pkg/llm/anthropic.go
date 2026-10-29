package llm

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// DefaultAnthropicModel は Claude を使う場合の既定のモデル。
// [差し替えポイント] JEV_ARGOS_LLM_MODEL で変更できる (例: コストを抑えるなら "claude-haiku-5-5")。
const DefaultAnthropicModel = "claude-opus-5-5"

// AnthropicProvider は Claude (Anthropic Messages API) を公式 Go SDK で呼ぶ Provider。
//
// API キーは SDK の既定の方法で解決する (環境変数 ANTHROPIC_API_KEY など)。
// データは Anthropic に送られるため Local() は false (既定では IP・ユーザー ID を伏せて送る)。
//
// 安全性の分類器が要求を断った場合 (stop_reason: refusal) に備え、サーバー側のフォールバック
// (fallbacks: "default") を有効にしている。断られた要求は、拒否の種類に応じて別のモデルが引き継ぐ。
type AnthropicProvider struct {
	Model  string // 既定 DefaultAnthropicModel
	client anthropic.Client
}

var _ Provider = (*AnthropicProvider)(nil)

// NewAnthropicProvider は AnthropicProvider を作る。opts で API キーや接続先を上書きできる
// (例: option.WithAPIKey, テスト用の option.WithBaseURL)。
func NewAnthropicProvider(model string, opts ...option.RequestOption) *AnthropicProvider {
	if model == "" {
		model = DefaultAnthropicModel
	}
	return &AnthropicProvider{Model: model, client: anthropic.NewClient(opts...)}
}

func (p *AnthropicProvider) Name() string { return "anthropic/" + p.Model }
func (p *AnthropicProvider) Local() bool  { return false }

func (p *AnthropicProvider) Complete(ctx context.Context, req CompletionRequest) (string, error) {
	msg, err := p.client.Beta.Messages.New(ctx, anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(p.Model),
		MaxTokens: 16000,
		System:    []anthropic.BetaTextBlockParam{{Text: req.System}},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(req.User)),
		},
		// 応答を JSON Schema に従う JSON に制約する (構造化出力)
		OutputConfig: anthropic.BetaOutputConfigParam{
			Format: anthropic.BetaJSONOutputFormatParam{Schema: req.Schema},
		},
		Fallbacks: anthropic.BetaFallbacksParamOfDefault(),
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
	})
	if err != nil {
		var apiErr *anthropic.Error
		if errors.As(err, &apiErr) {
			return "", fmt.Errorf("anthropic: HTTP %d: %w", apiErr.StatusCode, err)
		}
		return "", fmt.Errorf("anthropic: %w", err)
	}
	if msg.StopReason == anthropic.BetaStopReasonRefusal {
		return "", fmt.Errorf("anthropic: request declined (category %q)", msg.StopDetails.Category)
	}
	var b strings.Builder
	for _, block := range msg.Content {
		if t, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			b.WriteString(t.Text)
		}
	}
	if b.Len() == 0 {
		return "", fmt.Errorf("anthropic: empty response (stop_reason %q)", msg.StopReason)
	}
	return b.String(), nil
}
