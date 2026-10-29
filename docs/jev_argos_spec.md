# Jev-Argos コントロールサーバー アーキテクチャ・実装詳細設計書

> 本書は設計時点の文書である。本書に記載した性能・コストの数値は設計上の目標または見込みであり、まだ測定していない (検証計画は 9 章)。
> 実装との差分は [10 章](#10-実装との差分) にまとめている。

## 1. 概要 (Overview)

本設計書は、BFF（Backend For Frontend）およびバックエンド（gRPC/REST）環境におけるセキュリティ監視・障害回避・自動ハンドリングを目的としたセキュリティ・コントロールプレーン・ライブラリ **`jev-argos`** (ジェブ・アルゴス) の実装仕様を定めるものである。

**`jev-argos`** は、メインの通信ライン（データプレーン）から独立した制御層として動作する。「Jev（即時判定用の分類エンジン）」によるミリ秒単位を目標とした1次判定と「LLM（大規模言語モデル）」による深層コンテキスト分析を組み合わせ、自律的な防衛・監視を実現する。

## 2. システム全体のアーキテクチャ構成

システム全体における**今回開発・提供する `jev-argos` ライブラリのスコープ**と、ユーザー側で保持・運用される外部システム（メインアプリ／コントロール用フロントエンド）との境界線を明確に定義する。

```
【 ユーザー既存システム (データプレーン) 】 ── (開発対象外) ────────────────┐
│                                                                        │
│  [ メイン フロントエンド (RUM / CSP) ]                                 │
│             │                                                          │
│             │ (ユーザー通信)                                            │
│             ▼                                                          │
│  [ メイン BFF (Node.js/Go等) ] ───(gRPC Interceptor)──┐               │
│             │                                           │                │
│             ▼ (gRPC + Metadata)                         │                │
│  [ バックエンド群 (gRPC) ] ──(gRPC Interceptor)──────┤                │
│     ├─ サービス A                                    │                │
│     ├─ サービス B                                    │                │
│     └─ サービス C                                    │                │
└─────────────────────────────────────────────────────┼────────────────┘
                                                      │ (非同期シグナル送信)
┌─────────────────────────────────────────────────────▼────────────────┐
│ 【 ★ 本ライブラリの開発範囲: jev-argos 】                               │
│                                                                      │
│   [ jev-argos Control Engine (Go言語) ]                              │
│      ├── 1. Signal Receiver (gRPC Server / HTTP)                     │
│      ├── 2. Sliding Window Buffer (インメモリ / Redis Adapter)          │
│      ├── 3. Jev Classifier Engine (Score 0.0-4.0 + Confidence)        │
│      ├── 4. AI Adapter (LLM Async Analyzer: OpenAI/Claude/Ollama)    │
│      └── 5. Guardrails & Action Emitter (遮断・制限コマンド発行)        │
│                                                                      │
│   [ jev-argos Client Adapters (TypeScript / Go) ]                    │
│      └── Node.js / Go 用 gRPC Interceptor ライブラリ                   │
│                                                                      │
└──────┬──────────────────────────────────────────────┬────────────────┘
       │                                              │
       │ (Level 3 以上: アラート通知)                  │ (分析ログ・ステータス参照)
       ▼                                              ▼
 【 外部通知 】 (外部サービス)                 【 運用管理 UI 】 (別システム)
  [ Slack / Webhook ]                          [ コントロール用 フロントエンド (React/TS) ]
```

## 3. インターフェース設計 (Signal Receiver API)

メインBFFやバックエンドのInterceptorから、メイン処理のレイテンシに影響を与えずに通信メタデータを収集するためのgRPCインターフェースを定義する。

### 3.1 Protobuf 定義 (`signal.proto`)

```protobuf
syntax = "proto3";

package jevargos.v1;

option go_package = "github.com/jornJp0201/jev-argos/gen/v1;jevargosv1";

// 監視シグナル収集サービス
service SignalService {
  // 単一シグナルの送信 (Fire-and-Forget用)
  rpc ReportSignal (SecuritySignal) returns (ReportResponse);
  
  // 大量ログ・バッチ用のストリーミング送信 (将来の拡張用)
  rpc StreamSignals (stream SecuritySignal) returns (ReportResponse);
}

// メインのシグナル構造体
message SecuritySignal {
  string signal_id = 1;        // UUID
  string timestamp = 2;        // ISO8601 フォーマット
  string source_service = 3;   // 例: "main-bff", "payment-backend"

  UserContext user_context = 4;
  RequestContext request_context = 5;
  ResponseContext response_context = 6;
  
  string trace_id = 7;         // フロントエンド・他サービスとの追跡用キー
}

// ユーザー・クライアント情報
message UserContext {
  string user_id = 1;          // メタデータから抽出した識別子
  string user_role = 2;        // 例: "admin", "user", "guest"
  string client_ip = 3;        // IPアドレス
  string user_agent = 4;       // User-Agent 文字列
  string session_hash = 5;     // セッション/トークンの難読化ハッシュ
}

// リクエスト詳細
message RequestContext {
  string protocol = 1;         // "grpc" または "http"
  string method = 2;           // 例: "/user.UserService/GetUser"
  map<string, string> metadata_masked = 3; // 重要なヘッダー (マスク済み)
  string payload_summary = 4;  // パラメータ概要 (個人情報マスク済み)
}

// レスポンス詳細・エラー情報
message ResponseContext {
  int32 status_code = 1;       // gRPC Status Code (0: OK, 7: PERMISSION_DENIED 等)
  string error_code = 2;       // アプリケーション固有エラーコード
  string error_message = 3;    // PIIマスク済みエラーメッセージ
  int64 latency_ms = 4;        // 処理時間 (ミリ秒)
}

// レスポンス
message ReportResponse {
  bool accepted = 1;
  int32 immediate_action_level = 2; // レベル4等の即時ブロック通知用
}
```

## 4. シグナル送信・パフォーマンス戦略

メインアプリケーションの応答速度に影響を与えないよう、送信処理は応答の返却後に非同期で行い、以下のフェーズ構成をとる。

* **Phase 1 (初期実装・完全非同期):**
  * メインレスポンス返却後に、言語機能（Goの `goroutine` や Node.js の `setImmediate` / Worker）を利用して `ReportSignal` をバックグラウンドで発行する (Fire-and-Forget 方式)。

* **Phase 2 (高トラフィック期・バッチストリーミング):**
  * Interceptor 側でインメモリのリングバッファ（キュー）へ即座に書き込み、バックグラウンド Worker が一定間隔（例: 100ms）または一定件数（例: 50件）ごとに `StreamSignals` を用いて一括送信する。

## 5. コントロールサーバー内部モジュール設計

コントロールサーバー内部は、以下の4つの処理パイプラインで構成される。

```
[ Signal Receiver ] ──► [ Sliding Window Buffer ] ──► [ Jev Classifier Engine ]
                              (直近統計の結合)                       │
          ┌──────────────────────────────────────────────────────────┤
          ▼                                                          ▼
     【Level 1】                                            【Level 2 / 3 / 4】
   (静観 / 記録のみ)                                   (LLM 非同期分析 / Slack / 遮断)
```

### 5.1 Jev 判定エンジン (Time Window Data + Score プリミティブ)

単一イベントデータ（点）に、インメモリで集計した「直近の履歴統計（面）」を結合してJevに渡すことで、ミリ秒単位を目標としたリスクスコアリング（Score 0.0〜4.0）を行う。

#### 5.1.1 Jev 判定アルゴリズムの詳細と動作メカニズム

Jevの判定プロセスは、単なるAIプロンプトの丸投げではなく、**「時系列特徴量のリアルタイム抽出」→「確率的スコアリング（Score 0.0-4.0）」→「確信度（Confidence）による安全補正」** の3つの数学的・論理的ステップで構成される。

```
[ 入力シグナル (SecuritySignal) ]
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│ Step 1: 時系列特徴量抽出 (Sliding Window Aggregator)    │
│  - ip_error_count_1m (1分間のIP累積エラー数)             │
│  - unique_denied_methods_5m (5分間の拒否メソッド分散度)  │
│  - latency_spike_ratio (通常比レイテンシ異常率)         │
└──────────────────────────────┬──────────────────────────┘
                               │ (合成されたベクトル構造体)
                               ▼
┌─────────────────────────────────────────────────────────┐
│ Step 2: Jev 確率分類エンジン (Score Evaluation)          │
│  - 入力文脈をもとに多次元分類マッピングを実行           │
│  - 出力: リスクスコア S ∈ [0.0, 4.0], 確信度 C ∈ [0.0, 1.0] │
└──────────────────────────────┬──────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────┐
│ Step 3: 安全境界ルールガード (Safety Threshold Guard)    │
│  - IF S >= 3.5 AND C >= 0.8  ⇒  Level 4 (即時遮断)       │
│  - IF S >= 3.5 AND C < 0.8   ⇒  Level 3 (ダウングレード) │
└──────────────────────────────┬──────────────────────────┘
                               │ (C < 0.8 は自動遮断せず、人間の判断に回す)
```

1. **Step 1: 時系列特徴量の動的算出 (Sliding Window Aggregator)**
   シグナル到着時、単体データに加えて以下の動的指標をメモリ上の集計から算出し、判定コンテキストベクトルを作成する。
   * `ip_error_count_1m`: 直近60秒間の同一IPからの異常応答数。
   * `unique_denied_methods_5m`: 直近300秒間に同一送信元から `PERMISSION_DENIED` を起こしたユニークなAPIメソッド数（＝攻撃者の探索的フットプリンティング行為を定量化）。
   * `latency_spike_ratio`: 当該APIの通常時平均レイテンシに対する異常上昇比率（＝DoSやリソース枯渇攻撃の検出指標）。

2. **Step 2: Jev 確率分類モデルによる評価**
   特徴量ベクトルを入力とし、リスクの大きさ (スコア) と、その判定の確からしさ (確信度) を出力する分類モデルで評価する。
   学習済みの確率分類モデル (事後確率に基づく分類) を想定するが、学習データが揃うまでは同じ入出力のルールベースのモデルで代替する (10 章)。
   * リスクスコア $S \in [0.0, 4.0]$
   * 確信度 $C \in [0.0, 1.0]$ (Confidence)

3. **Step 3: 確信度 $C \ge 0.8$ の閾値とセーフティ・ガードレール**
   * **閾値の考え方:** 自動遮断は正常なユーザーを締め出すと業務に直接影響するため、誤遮断を避けることを優先し、確信度の閾値を高め ($C = 0.8$) に置く。
     確信度と実際の誤遮断率の関係はモデルとデータに依存するため、この値は初期値であり、運用で記録した誤遮断の件数をもとに調整する。
   * 確信度が低い状態で自動遮断（Level 4）を実行すると、単なるネットワーク瞬断やアプリのバグで正常ユーザーを締め出すリスク（障害発生リスク）が高まる。
   * したがって、$S \ge 3.5$（危険判定）であっても $C < 0.8$ の場合は強制的に Level 3 へダウングレードし、LLMによる深層解析と人間への通知（Human-in-the-Loop）へ迂回させる。

#### 5.1.2 Jev を 1 次判定に採用する理由 (技術選定)

1. **なぜ従来の WAF (If-Else / 固定閾値) では不十分なのか？**
   * 固定ルール（例: 1分間に100回エラーで遮断）は、低速スキャン（11分に1回アクセス）や分散IP攻撃を通過させてしまう。一方、閾値を下げすぎると正常なスパイクアクセスを誤遮断する。
   * Jev はエラーの「頻度・分散度・レイテンシ変化」の複合ベクトルを判定するため、動的な閾値制御が可能。

2. **なぜ直接 LLM (GPT-4o/Claude) を呼ぶのではなく Jev を1次判定にするのか？**
   * **レイテンシ:** LLM の呼び出しは一般に 1 回あたり秒単位の時間がかかるため、リクエストの処理中に判定するには遅すぎる。Jev は 50ms 未満 (目標 15ms) での判定を目標とする。
   * **コスト:** 全アクセスを LLM に通すとトークンコストが大きくなる。通常のトラフィックの大半は Level 1 (正常 / 軽微) と見込まれるため、Jev で振るい落とすことで LLM に渡す件数を大きく減らせる見込みである。
   * いずれの数値も目標・見込みであり、9 章の実験で検証する。

## 6. 安全制御とガードレール機構 (Guardrails & Governance)

AIの過剰制御や暴走（誤判定・プロンプトインジェクション等）を防止するため、以下の防護策をサーバー設計に組み込む。

### 6.1 データベースアクセスの制限
* **リードレプリカ（分析専用DB）接続:** LLMの分析用接続は、本番DBではなくリアルタイム同期されたリードレプリカに限定し、本番のWeb処理への負荷影響を遮断する。
* **個人情報マスク済みビュー (Safe View):** PII（個人情報・決済情報等）を除外・ハッシュ化したデータベースビューのみをLLMに参照許可する。
* **タイムアウト設定:** クエリの実行時間を DB レベルで上限設定（例: 最大2秒）し、AIの誤処理によるDBリソース枯渇を防ぐ。

### 6.2 制御権限の境界線 (Blast Radius Control)
* **自動化許可:** 一時的なアクセス遮断（IPブロック、トークン無効化）、縮小運転（フォールバック）への切り替え。
* **人間承認の必須化 (Human-in-the-Loop):** ユーザーアカウントの永久削除、DBデータの削除・改ざん、サービス全体の完全停止などの不可逆な操作は、コントロール用フロント画面にて管理者が「承認」ボタンを押下して実行する仕様とする。

## 7. ディレクトリ構成と本番DB切り替え設計

### 7.1 プロジェクト・ファイル構成 (モノレポ)

```text
jev-argos/
├── go.mod / go.sum
├── pnpm-workspace.yaml / package.json   # TypeScript パッケージのワークスペース
├── cmd/jev-argos-server/                 # コントロールサーバーのエントリポイント
├── pkg/                                  # Go のライブラリ
│   ├── receiver/                         # Signal Receiver (gRPC / HTTP)
│   ├── buffer/                           # Sliding Window Buffer (インメモリ / Redis)
│   ├── classifier/                       # Jev 判定エンジン
│   ├── guardrail/                        # 確信度ガードレール・安全境界ルール
│   ├── action/                           # Action Emitter (遮断リスト・承認されたアクションの実行)
│   ├── approval/                         # 承認キュー (Human-in-the-Loop)
│   ├── llm/                              # AI Adapter (LLM 非同期分析)
│   ├── notify/                           # Slack / Webhook 通知
│   ├── db/                               # 判定ログ (PostgreSQL / SQLite)・Safe View
│   ├── events/ api/ webhook/             # 管理 API・リアルタイム配信・署名付き Webhook
│   └── client/                           # Go 用アダプター
├── gen/v1/                               # Protobuf 生成コード (Go)
├── packages/
│   ├── adapter-node/                     # Node.js 用アダプター
│   └── dashboard/                        # コントロール用 UI
└── proto/signal.proto                    # Protobuf スキーマ定義
```

Redis / PostgreSQL への対応は Go 側 (`pkg/buffer`・`pkg/db`・`pkg/approval`) に実装したため、当初案の TypeScript 用アダプター (`packages/adapter-pg`・`packages/adapter-redis`) は設けていない。

### 7.2 DB・バッファのアダプター切替設計 (Zero-Config to Production)

開発時はデフォルトで「インメモリ＋SQLite」、本番環境では設定変更のみで「Redis＋PostgreSQL」に切り替え可能なインターフェース設計を採用する。

```go
// Go 側のアダプター・インターフェース例
type StorageAdapter interface {
    SaveSignal(ctx context.Context, signal *v1.SecuritySignal) error
    GetWindowStats(ctx context.Context, ip string) (*WindowStats, error)
}

// 環境変数等による簡単な注入・切り替え
func NewStorage(cfg Config) StorageAdapter {
    if cfg.Env == "production" {
        return redis.NewRedisAdapter(cfg.RedisURL)
    }
    return memory.NewInMemoryAdapter() // デフォルト: Zero Config
}
```

## 8. 技術スタックおよび言語構成 (Tech Stack & Languages)

本プロジェクトにおける開発言語と役割分担を明確に定義する。

| コンポーネント | 主な役割 | 使用言語 / フレームワーク |
| :--- | :--- | :--- |
| **`jev-argos` コアエンジン** | gRPCサーバー、Sliding Window、Jev判定、ガードレール | **Go (Golang)** <br>*(理由: 超軽量・低レイテンシ・並行処理 `goroutine` の強み)* |
| **BFFアダプター (`adapter-node`)** | メインBFF (Node.js) へ組み込むシグナル送信ライブラリ | **TypeScript / Node.js** |
| **コントロール用 UI** | 管理者がアラート確認や人間承認 (Human-in-the-Loop) を行う画面 | **TypeScript (React / Vite)** |
| **データ通信 Protocol** | メインBFF / バックエンド ↔ コントロールサーバー間通信 | **gRPC (Protocol Buffers)** |

## 9. 実証実験・パフォーマンス検証計画 (Benchmarking Plan)

実装完了後、設計上の目標を満たしているかを定量的に確認するため、以下の検証実験を行う (未実施)。

### 9.1 実験1: 合成データ負荷実験 (DoS / ブルートフォース シミュレーション)
* **目的:** スパイク時の検知スピードと、BFF側での即時遮断レスポンス時間を測定。
* **指標 (KPI):**
  * 大量エラー発生から Jev が Level 4（要遮断）と判定するまでのレイテンシ ($\le 15\text{ms}$ 目標)。
  * Level 4 発動後、バックエンドへの無駄なリクエストが 0% になるまでの時間。

### 9.2 実験2: LLM単体 vs Jev-Argos 2段階構成の定量的比較
* **目的:** 全アクセスを直接 LLM に投げる従来方式と、Jev 経由の 2段階構成の速度・コスト比較。
* 次の表は検証する仮説 (設計時の見込み) であり、測定結果ではない。

| 比較項目 | 従来方式 (直接 LLM) | Jev-Argos (Jev + LLM 2段階) | 見込み |
| :--- | :--- | :--- | :--- |
| **1次判定レイテンシ** | 秒単位 (LLM の応答時間) | 15ms 〜 40ms (目標) | 大幅に短縮 |
| **10万件処理コスト** | 全件分のトークン料金 | LLM に渡す件数分のみ | 大幅に削減 |
| **メインアプリ遅延** | 判定を待つ場合は応答が遅れる | 応答後に非同期で送信するため、判定による遅延は生じない設計 | 遅延なし (設計上) |

* 測定方法: 同じ合成データを両方式で処理し、判定までの時間・LLM の呼び出し件数を記録する。コストは呼び出し件数とトークン数から算出する。

## 10. 実装との差分

設計から実装の段階で変えた点・未実装の点を記す (2026-10 時点)。

| 項目 | 設計 | 実装 |
| :--- | :--- | :--- |
| Jev の分類モデル | 学習済みの確率分類モデル | 学習データが無いため、同じ入出力のルールベースの暫定モデル (`HeuristicModel`)。`classifier.Model` を実装すれば差し替えられる |
| Level 2 / 3 の境界 | 定めなし | S ≥ 1.5 / 2.5 の暫定値 |
| 自動化を許可する操作 (6.2) | IP ブロック・トークン無効化・縮小運転 | 自動で実行するのは Level 4 の IP 一時遮断のみ。トークン無効化と縮小運転も承認を経て実行する (より保守的にした) |
| 不可逆な操作の実行 (6.2) | 管理画面の承認ボタンで実行 | 承認後、アプリの受信エンドポイントへ署名付き Webhook で実行を依頼する (実行方法はアプリごとに異なるため) |
| AI Adapter の LLM | OpenAI / Claude / Ollama | Ollama (既定) と Claude を実装。他の LLM は `llm.Provider` を実装して追加する |
| ストレージの切り替え (7.2) | 単一の `StorageAdapter` | 統計 (`buffer.Buffer`)・判定ログ (`db.DecisionStore`)・承認キュー (`approval.Store`)・遮断リスト (`action.Blocklist`) に分け、それぞれメモリ / Redis / PostgreSQL を環境変数で切り替える。SQLite は指定時のみ使う |
| 遮断の配信 | 定めなし | proto に `ControlService.WatchBlocklist` を追加し、アダプターが遮断リストを購読して拒否する |
| シグナル受信 | gRPC / HTTP | gRPC に加え、HTTP (`POST /api/signals`) を実装 |
| コントロール用 UI | React / Next.js | React / Vite |
| 性能検証 (9 章) | 実施する | 未実施 |
