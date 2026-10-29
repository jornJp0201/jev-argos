# jev-argos

BFF / gRPC バックエンド向けの**セキュリティ・コントロールプレーン**。
メインの通信 (データプレーン) から独立した制御層として、通信メタデータを非同期に集めて攻撃や異常を判定し、
遮断・通知・人間による承認までをつなぐ。

## 目的: 3 段構えの判定

| 段 | 担当 | 速度 | 役割 |
| --- | --- | --- | --- |
| 1 次判定 | **Jev** (分類特化モデル) | ミリ秒 | 全シグナルを Sliding Window の時系列特徴量で採点し、リスクスコア S (0.0〜4.0) と確信度 C (0.0〜1.0) を出す |
| 深層分析 | **LLM** | 秒 | Jev が振るい落とした後の Level 2 以上だけを文脈込みで分析する (LLM の呼び出しコストを大幅に削減) |
| 最終判断 | **人間 (Human-in-the-Loop)** | — | 確信度が足りない遮断や不可逆な操作を、管理者がダッシュボードで承認 / 拒否する |

アプリ側は応答を返した後にシグナルを送るだけ (Fire-and-Forget) なので、メイン処理のレイテンシは増えない。

### 判定レベルと安全境界ルール

| Level | 条件 | 対応 |
| --- | --- | --- |
| 1 | S < 1.5 | 静観 / 記録のみ |
| 2 | 1.5 ≤ S < 2.5 | LLM 非同期分析・判定ログ保存 |
| 3 | 2.5 ≤ S < 3.5、**または S ≥ 3.5 かつ C < 0.8** | 深層解析 + 管理者の承認待ち (IP 一時遮断を提案) |
| 4 | S ≥ 3.5 かつ C ≥ 0.8 | 即時遮断 (`immediate_action_level = 4` を返す) |

S ≥ 3.5 でも確信度 C < 0.8 なら自動遮断せず Level 3 に格下げする。誤遮断で正常なユーザーを締め出さないための安全装置。

Jev が使う特徴量 (Sliding Window):

- `ip_error_count_1m`: 同一 IP の直近 60 秒の異常応答数
- `unique_denied_methods_5m`: 同一 IP が直近 300 秒に PERMISSION_DENIED を受けた API の種類数 (権限探索の検知)
- `latency_spike_ratio`: そのメソッドの平常時平均レイテンシに対する比 (リソース枯渇系の検知)

## 構成

```
BFF / バックエンド ──(gRPC インターセプター, 非同期)──► jev-argos コアサーバー (Go)
                                                        ├─ Signal Receiver (gRPC :50051)
                                                        ├─ Sliding Window Buffer (メモリ / Redis)
                                                        ├─ Jev Classifier + Guardrail
                                                        ├─ 判定ログ保存 (PostgreSQL)
                                                        └─ 管理 API (HTTP :8080) ◄── ダッシュボード (React)
```

```
.
├── cmd/jev-argos-server/   コアサーバーのエントリポイント
├── pkg/
│   ├── buffer/             Sliding Window Buffer (MemoryBuffer / RedisBuffer)
│   ├── classifier/         Jev 分類エンジン (S, C の算出)
│   ├── guardrail/          安全境界ルール (レベル決定・格下げ)
│   ├── receiver/           gRPC Signal Receiver (ReportSignal / StreamSignals)
│   ├── db/                 判定ログの PostgreSQL 保存
│   ├── approval/           承認待ちアクション (Human-in-the-Loop)
│   └── api/                管理 HTTP API (+ SSE)
├── proto/signal.proto      シグナルのスキーマ (Go / TS 共通)
├── gen/v1/                 proto から生成した Go コード
├── packages/
│   ├── adapter-node/       @jev-argos/adapter-node — Node.js 用 gRPC インターセプター
│   └── dashboard/          コントロール用ダッシュボード (Vite + React + Tailwind)
├── docs/jev_argos_spec.md  設計書
└── docker-compose.yml      ローカル検証環境
```

## クイックスタート (Docker Compose)

コアサーバー・Redis・PostgreSQL・ダッシュボードを一括で起動する。

```sh
export JEV_ARGOS_ADMIN_TOKEN=$(openssl rand -hex 16)   # 管理 API のトークン (必須)
docker compose up --build
```

| サービス | URL | 備考 |
| --- | --- | --- |
| ダッシュボード | http://localhost:3000 | 管理 API へのトークン付与は nginx が行う |
| gRPC (シグナル受信) | localhost:50051 | BFF のインターセプターの送信先 |
| 管理 API | http://localhost:8080 | `Authorization: Bearer $JEV_ARGOS_ADMIN_TOKEN` が必須 |
| PostgreSQL | localhost:55432 | `jevargos` / `jevargos` (判定ログは `jev_decision_logs`) |

- 起動時に疑似シグナルが流れ (`JEV_ARGOS_DEMO=true`)、ダッシュボードに承認待ちアラートが表示される。不要なら `JEV_ARGOS_DEMO=false docker compose up`。
- 公開ポートはすべて `127.0.0.1` に限定している。ダッシュボードに到達できる人は承認操作ができるため、外部に公開する場合は前段で管理者を認証すること。
- 停止は `docker compose down` (判定ログも消すなら `docker compose down -v`)。

## コアサーバーをローカルで起動する

Go 1.24 以上が必要。外部依存なし (インメモリ) で起動できる。

```sh
go run ./cmd/jev-argos-server                # gRPC :50051 + 管理 API 127.0.0.1:8080
go run ./cmd/jev-argos-server -demo          # 疑似シグナルを流して動作確認 (デモ後も API は起動し続ける)
go run ./cmd/jev-argos-server -demo -api-addr=""   # デモだけ実行して終了
```

| フラグ | 環境変数 | 既定 | 内容 |
| --- | --- | --- | --- |
| `-addr` | — | `:50051` | gRPC の待受アドレス |
| `-api-addr` | — | `127.0.0.1:8080` | 管理 API の待受アドレス (空で無効) |
| `-admin-token` | `JEV_ARGOS_ADMIN_TOKEN` | (起動ごとに生成してログに出力) | 管理 API の Bearer トークン |
| `-redis-url` | `JEV_ARGOS_REDIS_URL` | (インメモリ) | Redis で統計を共有する (複数インスタンス構成) |
| `-postgres-url` | `JEV_ARGOS_POSTGRES_URL` | (保存しない) | Level 2〜4 の判定ログを PostgreSQL に保存する |
| `-demo` | `JEV_ARGOS_DEMO=true` | false | 疑似シグナルを流す |

## BFF への導入

### Node.js (`@jev-argos/adapter-node`)

```ts
import * as grpc from "@grpc/grpc-js";
import { SignalReporter, createServerInterceptor, createClientInterceptor } from "@jev-argos/adapter-node";

// コアサーバーへの非同期送信クライアント (失敗・タイムアウトはアプリに影響しない)
const reporter = new SignalReporter({
  target: "localhost:50051",
  onResponse: (res, signal) => {
    if (res.immediate_action_level >= 4) {
      // 例: signal.user_context.client_ip を一時遮断リストに追加する
    }
  },
});

// gRPC サーバーとして RPC を受ける場合: 接続元 IP・User-Agent・ステータス・レイテンシを自動取得
const server = new grpc.Server({
  interceptors: [createServerInterceptor(reporter, { sourceService: "main-bff" })],
});

// BFF からバックエンドを呼び出す場合: エンドユーザーの IP は送信メタデータの x-forwarded-for から取得
const userClient = new UserServiceClient("user-service:50051", grpc.credentials.createInsecure(), {
  interceptors: [
    createClientInterceptor(reporter, {
      sourceService: "main-bff",
      extractUser: (md) => ({ userId: md.get("x-user-id")[0] as string | undefined }),
    }),
  ],
});

// 終了時: 送信中のシグナルを待ってから閉じる
process.on("SIGTERM", () => void reporter.close());
```

オプションの詳細 (IP 偽装対策の `trustProxyHeaders`、PII を送らない既定値など) は
[packages/adapter-node/README.md](packages/adapter-node/README.md) を参照。

### Go

Go 用のアダプターパッケージはまだ無いため、生成済みクライアント (`gen/v1`) を使ったインターセプターの例を示す。

```go
import (
	"context"
	"crypto/rand"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
)

// JevArgosInterceptor は RPC ごとのシグナルを jev-argos へ非同期送信する UnaryServerInterceptor。
func JevArgosInterceptor(client jevargosv1.SignalServiceClient, source string) grpc.UnaryServerInterceptor {
	inFlight := make(chan struct{}, 1000) // 同時送信数の上限 (超えた分は捨てる)

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req) // メインの処理

		var ip, ua string
		if p, ok := peer.FromContext(ctx); ok {
			ip, _, _ = net.SplitHostPort(p.Addr.String())
		}
		if md, ok := metadata.FromIncomingContext(ctx); ok && len(md.Get("user-agent")) > 0 {
			ua = md.Get("user-agent")[0]
		}
		signal := &jevargosv1.SecuritySignal{
			SignalId:        rand.Text(),
			Timestamp:       start.UTC().Format(time.RFC3339Nano),
			SourceService:   source,
			UserContext:     &jevargosv1.UserContext{ClientIp: ip, UserAgent: ua},
			RequestContext:  &jevargosv1.RequestContext{Protocol: "grpc", Method: info.FullMethod},
			ResponseContext: &jevargosv1.ResponseContext{StatusCode: int32(status.Code(err)), LatencyMs: time.Since(start).Milliseconds()},
		}

		// Fire-and-Forget: 応答を返した後にバックグラウンドで送る
		select {
		case inFlight <- struct{}{}:
			go func() {
				defer func() { <-inFlight }()
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				_, _ = client.ReportSignal(ctx, signal)
			}()
		default:
		}
		return resp, err
	}
}
```

```go
conn, _ := grpc.NewClient("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
server := grpc.NewServer(grpc.ChainUnaryInterceptor(
	JevArgosInterceptor(jevargosv1.NewSignalServiceClient(conn), "main-bff"),
))
```

## ダッシュボード

- **Overview**: 直近 5 分のリクエスト数・Level 3 アラート数・Level 4 遮断数・平均 Jev スコア
- **承認待ちアラート**: 管理 API の実データ。モーダルで AI の判定根拠を確認し、承認 / 拒否する (SSE でリアルタイム反映)
- **Signal Stream / 詳細分析**: レベル別バッジ・確信度・特徴量・LLM 要因解析

ローカル開発の手順は [packages/dashboard/README.md](packages/dashboard/README.md) を参照。

## 開発

```sh
corepack enable && pnpm install   # TypeScript パッケージの依存

go test ./...                     # Go の全テスト (-race 推奨)
pnpm build                        # TypeScript パッケージ群のビルド
pnpm test                         # TypeScript パッケージ群のテスト

./scripts/gen-proto.sh            # proto/signal.proto を変更したら Go コードを再生成 (protoc が必要)
```

PostgreSQL の結合テストは `JEV_ARGOS_TEST_POSTGRES_URL` を設定したときだけ実行される。
Redis のテストはインプロセスの互換サーバー (miniredis) で動くため、Redis は不要。

## 実装状況と既知の制約

- **Jev モデル**: 学習済みモデルの代わりに、同じインターフェースのルールベース暫定モデル (`HeuristicModel`) で動いている。Level 2/3 の境界値 (1.5 / 2.5) も暫定値。
- **LLM 深層分析**: 未接続。ダッシュボードの解析結果は「モック」と明示した文面。
- **遮断の実行**: 承認されたアクションは記録・ログ出力のみ (`LogExecutor`)。BFF・ゲートウェイへの遮断コマンド発行は未実装。
- **承認待ちアクション**: メモリ上に保持するため、コアサーバーの再起動で消える。
- **ダッシュボードの Signal Stream**: コアサーバーに配信 API が無いため、ブラウザ内のシミュレーターのデータ (画面に「デモデータ」と表示)。承認待ちアラートは実データ。
- **管理者の認証**: 管理 API は共有トークン方式。承認者名は自己申告のため、本番ではダッシュボードの前段で管理者を認証すること。
- `packages/core`・`packages/adapter-pg`・`packages/adapter-redis` は初期セットアップ時のプレースホルダーで未使用 (Redis / PostgreSQL 対応は Go 側 `pkg/buffer`・`pkg/db` に実装)。

詳細な設計は [docs/jev_argos_spec.md](docs/jev_argos_spec.md) を参照。
