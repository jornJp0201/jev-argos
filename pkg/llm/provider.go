// Package llm は LLM による深層分析 (設計書 2 章 "AI Adapter (LLM Async Analyzer)") を提供する。
//
// Level 2 以上の判定を非同期に LLM へ渡し、要因の要約・推奨対応を得て、判定ログ・承認キュー・
// ダッシュボードに反映する。RPC の応答は待たせない。
//
// 構成と差し替えポイント:
//
//	Provider  … LLM の呼び出し先。既定は Ollama (ローカル、API キー不要)。Claude (Anthropic) も同梱。
//	            [差し替えポイント] 他の LLM を使う場合は Provider を実装する (provider.go の例を参照)。
//	Masker    … LLM に送る前に IP・ユーザー ID を伏せる。[差し替えポイント] 伏せる範囲を変える場合に実装する。
//	Analyzer  … プロンプトの組み立てと結果の解釈。[差し替えポイント] SystemPrompt を変えて分析の観点を調整できる。
//	Emitter   … receiver から判定を受け取り、キュー・間引き (コスト制御)・結果の配信 (Sink) を行う。
//	Sink      … 分析結果の配信先。[差し替えポイント] 独自の保存先・通知先を足す場合に実装する。
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CompletionRequest は LLM への 1 回の問い合わせ。
type CompletionRequest struct {
	System string
	User   string
	// Schema は応答の JSON Schema。Provider は応答をこの形の JSON に制約すること (構造化出力)。
	Schema map[string]any
}

// Provider は LLM の呼び出し先。
//
// [差し替えポイント] OpenAI・Azure OpenAI・Gemini・社内の LLM ゲートウェイなどを使う場合は、
// このインターフェースを実装し、cmd/jev-argos-server の newLLMProvider で選べるようにする。
// 実装の要点:
//   - Complete は req.Schema に従う JSON の文字列だけを返す (前後に説明文を付けない)。
//     構造化出力 (JSON Schema 指定) に対応した API を使うと確実。
//   - ctx のキャンセル・期限を守る。
//   - Local は、データが組織の外に出ない (ローカルで動く) 場合に true を返す。
//     false の場合、既定では IP・ユーザー ID を伏せてから送る (Masker)。
//
// 例 (OpenAI 互換の Chat Completions API の場合):
//
//	type OpenAIProvider struct{ BaseURL, APIKey, Model string }
//	func (p OpenAIProvider) Name() string { return "openai/" + p.Model }
//	func (p OpenAIProvider) Local() bool  { return false }
//	func (p OpenAIProvider) Complete(ctx context.Context, r llm.CompletionRequest) (string, error) {
//		// POST {BaseURL}/chat/completions に messages (system / user) と
//		// response_format: {"type": "json_schema", "json_schema": {"name": "analysis", "schema": r.Schema, "strict": true}}
//		// を送り、choices[0].message.content を返す
//	}
type Provider interface {
	// Name は分析結果に記録する識別子 (例: "ollama/qwen2.5:3b")。
	Name() string
	// Local はデータが外部に送られないか。
	Local() bool
	Complete(ctx context.Context, req CompletionRequest) (string, error)
}

// DefaultOllamaURL / DefaultOllamaModel は何も設定しない場合の既定値。
const (
	DefaultOllamaURL = "http://localhost:11434"
	// DefaultOllamaModel は日本語と JSON 出力が比較的安定した軽量モデル。
	// [差し替えポイント] JEV_ARGOS_LLM_MODEL で変更できる。精度が必要なら大きいモデルを使う。
	DefaultOllamaModel = "qwen2.5:3b"
)

// OllamaProvider は Ollama (https://ollama.com) の /api/chat を呼ぶ Provider。
// ローカルで動くため API キーは不要で、データは外部に出ない。
//
// 使う前に Ollama を起動し、モデルを取得しておく: `ollama pull qwen2.5:3b`
type OllamaProvider struct {
	BaseURL string // 既定 DefaultOllamaURL
	Model   string // 既定 DefaultOllamaModel
	Client  *http.Client
}

var _ Provider = OllamaProvider{}

func (p OllamaProvider) model() string {
	if p.Model == "" {
		return DefaultOllamaModel
	}
	return p.Model
}

func (p OllamaProvider) Name() string { return "ollama/" + p.model() }
func (p OllamaProvider) Local() bool  { return true }

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Format   map[string]any  `json:"format,omitempty"` // JSON Schema による構造化出力
	Options  map[string]any  `json:"options,omitempty"`
}

type ollamaChatResponse struct {
	Message ollamaMessage `json:"message"`
	Error   string        `json:"error"`
}

func (p OllamaProvider) Complete(ctx context.Context, req CompletionRequest) (string, error) {
	base := p.BaseURL
	if base == "" {
		base = DefaultOllamaURL
	}
	body, err := json.Marshal(ollamaChatRequest{
		Model: p.model(),
		Messages: []ollamaMessage{
			{Role: "system", Content: req.System},
			{Role: "user", Content: req.User},
		},
		Format:  req.Schema,
		Options: map[string]any{"temperature": 0},
	})
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute} // ローカル LLM は初回のモデル読み込みに時間がかかる
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("ollama %s: %w (Ollama が起動しているか確認してください)", base, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var out ollamaChatResponse
	_ = json.Unmarshal(data, &out)
	if resp.StatusCode != http.StatusOK {
		msg := out.Error
		if msg == "" {
			msg = strings.TrimSpace(string(data))
		}
		if resp.StatusCode == http.StatusNotFound {
			msg += fmt.Sprintf(" (モデルを取得してください: ollama pull %s)", p.model())
		}
		return "", fmt.Errorf("ollama: HTTP %d: %s", resp.StatusCode, msg)
	}
	return out.Message.Content, nil
}
