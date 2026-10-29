# jev-argos

**Web サービスの BFF / バックエンドに組み込む、攻撃の検知と遮断のためのライブラリ。**

あなたのアプリにミドルウェアを 1 行追加すると、リクエストごとの情報 (送信元 IP・API・ステータス・処理時間) が
判定サーバーに送られます。判定サーバーは送信元の直近の振る舞いから攻撃らしさを採点し、危険な送信元は自動で遮断し、
判断に迷うものは管理者の承認に回します。

```ts
app.use(createExpressMiddleware(reporter, { sourceService: "main-bff", blocklist })); // Express ならこれだけ
```

## できること

- **攻撃の検知**: 権限の探索 (いろいろな管理 API を試す)、エラーの集中、処理時間の急増などを、送信元ごとの直近の統計から見つける。
- **自動遮断**: 危険と確信できる送信元は、その場で一定時間 (既定 15 分) 遮断する。アプリ側のミドルウェアが以降のリクエストを 403 で拒否する。
- **人間の判断を挟む**: 危険そうでも確信が持てないものは自動で遮断せず、承認キューに入れて管理者の判断を待つ。誤って正常なユーザーを締め出さないため。
- **LLM による分析**: 怪しい送信元について、LLM が「何が起きているか」「どう対応すべきか」をまとめる。既定はローカルの Ollama (API キー不要)。
- **通知**: 要注意の送信元を Slack や Webhook に知らせる。

**アプリを遅くしない**のが前提です。ミドルウェアは応答を返した後に情報を送るだけで、判定サーバーが止まっていてもアプリは影響を受けません。

## 構成

jev-argos は 2 つの部品からできています。

| 部品 | 置き場所 | 役割 |
| --- | --- | --- |
| **アダプター** (ライブラリ) | あなたの BFF の中 | リクエストの情報を送り、遮断中の送信元を拒否する。Node.js 版 `@jornjp/adapter-node`、Go 版 `pkg/client` |
| **判定サーバー** `jev-argos-server` | 別プロセス (Docker / `go run`) | 採点・遮断・承認キュー・LLM 分析・通知を行う。Go のライブラリ (`pkg/`) として自分のサーバーに組み込むこともできる |

```
  あなたのアプリ                               jev-argos-server
  ==============                               ================

  [ BFF (Node.js / Go) ]
    + adapter  --- request info (async) --->   score each request (Jev)  ->  Level 1-4
               <-- blocked IPs -------------     Level 4    : block automatically
                                                 Level 3    : approval queue + Slack / Webhook
                                                 Level 2-4  : LLM analysis, decision log
```

Redis・PostgreSQL・LLM・Slack はすべて任意です。何も用意しなくても判定と遮断は動き、必要に応じて足していけます。

## はじめかた

### ステップ 1: 判定サーバーを起動する

```bash
# リポジトリのルートでイメージをビルドして起動
docker build -t jev-argos/server .
docker run -d --name jev-argos -p 127.0.0.1:50051:50051 jev-argos/server

# または Go 1.26 以上で直接起動
go run ./cmd/jev-argos-server
```

ポート 50051 (gRPC) でリクエストの情報を受け付けます。

### ステップ 2: アダプターをインストールする

```bash
pnpm add @jornjp/adapter-node    # または npm i @jornjp/adapter-node
```

> npm に公開する前は、リポジトリからパッケージを作って入れる:
>
> ```bash
> corepack enable && pnpm install && pnpm --filter @jornjp/adapter-node build
> (cd packages/adapter-node && npm pack)     # jornjp-adapter-node-0.1.0.tgz ができる
> pnpm add /path/to/jev-argos/packages/adapter-node/jornjp-adapter-node-0.1.0.tgz   # あなたのアプリで
> ```

### ステップ 3: BFF に組み込む

**Express** — ルートより前に追加する。

```ts
import express from "express";
import { BlocklistWatcher, SignalReporter, createExpressMiddleware } from "@jornjp/adapter-node";

const reporter = new SignalReporter({ target: "localhost:50051" });   // 情報を送る
const blocklist = new BlocklistWatcher({ target: "localhost:50051" }); // 遮断中の IP を受け取る

const app = express();
app.use(createExpressMiddleware(reporter, { sourceService: "main-bff", blocklist }));

app.get("/users/:id", (req, res) => res.json({ id: req.params.id })); // 既存のルートはそのまま
```

**Next.js (App Router)** — Route Handler を `withJevArgos` で包む。

```ts
// app/api/users/[id]/route.ts
import { SignalReporter, withJevArgos } from "@jornjp/adapter-node";

const reporter = new SignalReporter({ target: "localhost:50051" });
export const runtime = "nodejs"; // gRPC は Edge Runtime では動かない

export const GET = withJevArgos(reporter, { route: "/api/users/[id]", sourceService: "main-bff" },
  async (_req: Request, { params }: { params: Promise<{ id: string }> }) => {
    return Response.json({ id: (await params).id });
  },
);
```

**Go の BFF**

```go
import "github.com/jev-argos/jev-argos/pkg/client"

conn, _ := grpc.NewClient("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
reporter := client.NewReporter(conn, client.ReporterOptions{})
blocklist := client.NewBlocklistWatcher(ctx, conn, nil)
opts := client.Options{SourceService: "main-bff", Blocklist: blocklist}

http.ListenAndServe(":8080", client.Middleware(reporter, opts)(mux))                      // net/http
grpc.NewServer(grpc.ChainUnaryInterceptor(client.UnaryServerInterceptor(reporter, opts))) // gRPC
```

Fastify・gRPC (Node.js)・ロードバランサー配下での IP の扱いは [アダプターの README](packages/adapter-node/README.md) を参照。
gRPC を使えない環境からは、HTTP の `POST /api/signals` (JSON) でも送れる ([判定サーバーの README](cmd/jev-argos-server/README.md#api))。

### ステップ 4: 動作を確認する

存在しないページに 1 分間で 30 回アクセスすると、エラーの集中として検知されます。

```bash
for i in $(seq 30); do curl -s -o /dev/null http://localhost:3000/no-such-page-$i; done
docker logs jev-argos 2>&1 | grep "jev-argos action"
```

```
msg="jev-argos action" level=3 downgraded=true score=3.6 confidence=0.625 client_ip=127.0.0.1 method="GET (unmatched)" ip_error_count_1m=30 ...
```

この例は「危険そうだが確信が足りない」ので、自動遮断ではなく承認キューに入っています (`level=3 downgraded=true`)。
正常なリクエストはログに出ません。

### 次にやること

| やりたいこと | 方法 |
| --- | --- |
| 判定の記録を残す | `JEV_ARGOS_POSTGRES_URL` (本番) か `JEV_ARGOS_SQLITE_PATH` (開発) を指定 |
| 判定サーバーを複数台にする | `JEV_ARGOS_REDIS_URL` と `JEV_ARGOS_POSTGRES_URL` を指定 |
| LLM 分析を使う | Ollama を入れて `ollama pull qwen2.5:3b` (Claude なら `JEV_ARGOS_LLM_PROVIDER=anthropic`) |
| Slack に通知する | `JEV_ARGOS_SLACK_WEBHOOK_URL` を指定 |
| 承認待ちを確認・承認する | 管理 API、または [Web ダッシュボード](#付属-web-ダッシュボード) |
| 自社の環境に合わせる | [差し替えポイント](#差し替えポイント) |

設定の一覧は [判定サーバーの README](cmd/jev-argos-server/README.md#設定) にあります。

## 判定の仕組み

判定エンジン **Jev** は、1 件のリクエストだけでなく、同じ送信元の直近の振る舞いを合わせて採点します。

- 同じ IP の 1 分間のエラー数
- 5 分間に権限エラーを受けた API の種類数 (多いほど、権限の探索が疑われる)
- その API の普段の処理時間に対する比 (大きいほど、負荷をかける攻撃が疑われる)

固定の閾値 (例: 1 分間に 100 回エラーで遮断) では見逃す低速な攻撃や、逆に誤って遮断してしまう正常なアクセスの急増も、
複数の兆候を組み合わせることで見分けやすくなります。採点結果は**リスクスコア S** (0.0〜4.0) と**確信度 C** (0.0〜1.0) で表し、4 段階で扱います。

| Level | 条件 | 対応 |
| --- | --- | --- |
| **1** 正常 | S < 1.5 | 何もしない (記録のみ)。大半のリクエストはここ |
| **2** 不審 | 1.5 ≤ S < 2.5 | 判定ログに残し、LLM が分析する |
| **3** 攻撃の疑い | 2.5 ≤ S < 3.5 | 承認キューに「IP の一時遮断」を提案し、Slack 等に通知する。管理者が承認すると遮断する |
| **4** 危険 | S ≥ 3.5 かつ C ≥ 0.8 | その場で自動遮断する (既定 15 分) |

**安全装置**: スコアが危険域 (S ≥ 3.5) でも、確信度が 0.8 未満なら自動遮断せず Level 3 (人間の判断) に回します。
LLM が提案した対処や、アカウント削除のような取り消せない操作も、管理者が承認するまで実行されません。

**なぜ LLM だけで判定しないのか**: LLM は 1 件の判定に秒単位の時間がかかることが多く、全リクエストに使うとコストも大きくなります。
jev-argos では Jev がすべてのリクエストを軽い計算で採点し (ミリ秒単位が目標。性能は未検証)、LLM は怪しいものだけを分析します。

## 差し替えポイント

jev-argos はライブラリとして、自社の環境に合わせて部品を差し替えられるように作っています。
差し替えが必要な箇所にはコードに `[差し替えポイント]` のコメントを付けているので、次のコマンドで一覧できます。

```bash
grep -rn "差し替えポイント" cmd pkg packages/*/src packages/dashboard/*.ts packages/dashboard/*.template
```

**アプリ側 (アダプター)**

| 何を変えるか | 場所 | 既定 |
| --- | --- | --- |
| ユーザー ID の取り出し方 (認証方式に合わせる) | Node.js の `extractUser` / `userId`、Go の `client.Options.UserID` | 送らない |
| ルートのパターンの取り出し方 (chi 等) | Go の `client.Options.Route` | ServeMux の `r.Pattern` |
| 遮断したリクエストへの応答 | `onBlocked` / `OnBlocked` | 403 `{"error":"forbidden"}` |

**判定サーバー**

| 何を変えるか | 場所 | 既定 |
| --- | --- | --- |
| **Jev モデル** (学習済みモデルへの置き換え) | `pkg/classifier` の `Model` | ルールベースの暫定モデル `HeuristicModel` |
| **Level 2/3 の境界値** | `pkg/guardrail` | S ≥ 1.5 / 2.5 (暫定値) |
| **LLM** (OpenAI・社内ゲートウェイ等) | `pkg/llm` の `Provider`、`cmd/jev-argos-server/components.go` の `newLLMProvider` | Ollama `qwen2.5:3b` (Claude も同梱) |
| **LLM に送る情報の伏せ方** | `pkg/llm` の `Masker` | 外部の LLM のときだけ IP・ユーザー ID を仮名化 |
| **分析の観点 (プロンプト)** | `pkg/llm` の `DefaultSystemPrompt` / `Analyzer.SystemPrompt` | 汎用のセキュリティ分析 |
| **LLM 分析の頻度・並列数** | `pkg/llm` の `Emitter` (`Cooldown` / `Workers`) | 同じ IP は 5 分に 1 回、並列 2 |
| **分析結果の配信先** (チケット起票・SIEM 等) | `pkg/llm` の `Sink` | 判定ログ・承認キュー・ダッシュボード |
| **通知先** (PagerDuty・Teams 等) | `pkg/notify` の `Notifier`、`components.go` の `newNotifiers` | Slack / 汎用 Webhook |
| **通知の文面** | `pkg/notify` の `SlackText` | 日本語の要約 |
| **承認された対処の実行方法** | `pkg/action` の `Router` / `WebhookExecutor`、`components.go` の `newExecutor` | IP 遮断 → 遮断リスト、それ以外 → アプリの Webhook |
| **アプリ固有の対処** | `pkg/approval` の `ActionType` | 7 種類 (IP 遮断・セッション無効化・縮小運転・アカウント停止 / 削除・データ削除・サービス停止) |
| **判定後の処理の追加・削除** | `components.go` の `newEmitters` | ログ・自動遮断・承認キュー・判定ログ・通知・LLM |
| **統計の保存先** | `pkg/buffer` の `Buffer` | メモリ / Redis |
| **LLM 用 DB ユーザーの権限** | `pkg/db` の Safe View の定義 (SQL コメント) | — (本番で設定する) |

Web ダッシュボードの差し替えポイントは [付属: Web ダッシュボード](#付属-web-ダッシュボード) を参照。

## リポジトリの構成

| パッケージ | 言語 | 役割 | ドキュメント |
| --- | --- | --- | --- |
| `packages/adapter-node` | TypeScript | `@jornjp/adapter-node` — Node.js の BFF 用アダプター | [README](packages/adapter-node/README.md) |
| `pkg/client` | Go | Go の BFF 用アダプター | 上記「Go の BFF」 |
| `cmd/jev-argos-server` + `pkg/` | Go | 判定サーバー (受信・採点・遮断・承認キュー・LLM 分析・通知・管理 API) | [README](cmd/jev-argos-server/README.md) |
| `packages/dashboard` | TypeScript / React | 付属の Web ダッシュボード (任意) | [README](packages/dashboard/README.md) |

```
.
├── packages/adapter-node/  Node.js 用アダプター (@jornjp/adapter-node)
├── pkg/
│   ├── client/             Go 用アダプター
│   ├── receiver/           受信 (gRPC / HTTP)
│   ├── buffer/             送信元ごとの直近の統計 (メモリ / Redis)
│   ├── classifier/         Jev (スコア S と確信度 C の算出)
│   ├── guardrail/          Level の決定 (確信度不足なら格下げ)
│   ├── action/             遮断リスト・自動遮断・承認された対処の実行
│   ├── approval/           承認キュー (メモリ / PostgreSQL)
│   ├── llm/                LLM 分析 (Ollama / Claude)
│   ├── notify/             Slack / Webhook 通知
│   ├── db/                 判定ログ (PostgreSQL / SQLite)
│   ├── events/             判定のリアルタイム配信 (ダッシュボード用)
│   ├── api/                管理 HTTP API
│   └── webhook/            署名付き Webhook の送信・検証
├── cmd/jev-argos-server/   判定サーバーのエントリポイント (部品の組み立てと設定)
├── proto/signal.proto      アダプターとサーバーの通信の定義
├── gen/v1/                 proto から生成した Go コード
├── packages/dashboard/     付属の Web ダッシュボード (任意)
├── docs/jev_argos_spec.md  設計書
├── Dockerfile              判定サーバーのイメージ
└── docker-compose.yml      一式を起動するローカル検証環境
```

## 開発

```bash
corepack enable && pnpm install   # TypeScript パッケージの依存

go test ./...                     # Go の全テスト (-race 推奨)
pnpm build                        # TypeScript パッケージ群のビルド
pnpm test                         # TypeScript パッケージ群のテスト

go run ./cmd/jev-argos-server -demo   # 疑似的なリクエストを流して判定を確認
./scripts/gen-proto.sh                # proto/signal.proto を変更したら Go コードを再生成 (protoc が必要)
```

PostgreSQL の結合テストは `JEV_ARGOS_TEST_POSTGRES_URL` を設定したときだけ実行されます。
Redis・LLM (Ollama / Claude)・Slack のテストは擬似サーバーで動くため、外部サービスは不要です。

## 実装状況と既知の制約

- **Jev モデル**: 学習済みモデルの代わりに、ルールベースの暫定モデルで動いている (学習データが無いため)。`classifier.Model` を実装すれば差し替えられる。
- **LLM 分析の精度**: 使う LLM に依存する。既定の `qwen2.5:3b` は軽さを優先したモデルなので、精度が必要なら大きいモデルや Claude を使う。LLM が提案できる対処は取り消せるもの (IP 遮断・セッション無効化・アカウント一時停止・縮小運転) に限り、すべて承認キューを通る。
- **遮断以外の対処の実行**: セッション無効化・アカウント操作・データ削除・縮小運転・サービス停止は、アプリが受信エンドポイント (`JEV_ARGOS_ACTION_WEBHOOK_URL`) を用意して実行する。jev-argos は署名付きで依頼するだけ。
- **複数台構成**: Redis (統計・遮断リスト) と PostgreSQL (承認キュー) を使うと複数台で共有される。指定しない場合はメモリ上にあり、再起動で消える。
- **通信の暗号化と認証**: gRPC・管理 API とも TLS は内蔵していない。管理 API は共有トークン方式で、承認者名は自己申告。本番ではサービスメッシュやリバースプロキシで TLS と管理者の認証を行う。
- **パッケージの公開**: Docker イメージ・npm パッケージとも未公開 (ローカルでビルドして使う)。
- **性能検証**: 設計書 9 章の性能検証 (判定までのレイテンシ、LLM 単体との比較) は未実施。

詳細な設計は [docs/jev_argos_spec.md](docs/jev_argos_spec.md) を参照。

## 付属: Web ダッシュボード

ライブラリの動作を目で確かめたり、承認待ちを画面で操作したりするための Web アプリ (React) を同梱しています。
jev-argos の利用に必須ではなく、管理 API を自社の管理画面から呼んでもかまいません。

- **概況**: 直近 5 分のリクエスト数・Level 3 / 4 の件数・平均スコア
- **承認待ち**: 判定の根拠と LLM の分析を見て、承認 / 拒否する。取り消せない操作は対象の再入力が必要
- **遮断中の一覧**: 自動遮断・承認・手動の遮断を確認し、解除する
- **シグナル一覧と詳細**: リクエストごとの Level・スコア・確信度・特徴量・LLM 分析

詳しくは [ダッシュボードの README](packages/dashboard/README.md) を参照。

| 何を変えるか | 場所 | 既定 |
| --- | --- | --- |
| データの取得元 | `packages/dashboard/src/types.ts` の `DataSource`、`App.tsx` | 判定サーバーの SSE |
| 管理者の認証 | `packages/dashboard/nginx.conf.template` / `vite.config.ts` | 共有トークン (本番では前段に SSO を置く) |

### Docker Compose で一式を起動する

判定サーバー・Redis・PostgreSQL・ダッシュボードをまとめて起動します (ローカルでの検証用)。

```bash
export JEV_ARGOS_ADMIN_TOKEN=$(openssl rand -hex 16)   # 管理 API のトークン (必須)
docker compose up --build
```

| サービス | URL | 備考 |
| --- | --- | --- |
| ダッシュボード | http://localhost:3000 | 管理 API へのトークン付与はダッシュボードの nginx が行う |
| gRPC (受信) | localhost:50051 | アダプターの `target` に指定する |
| 管理 API | http://localhost:8080 | `Authorization: Bearer $JEV_ARGOS_ADMIN_TOKEN` が必須 |
| PostgreSQL | localhost:55432 | `jevargos` / `jevargos`。判定ログ `jev_decision_logs`、承認キュー `jev_actions` |

- 起動時に疑似的なリクエストが流れ (`JEV_ARGOS_DEMO=true`)、承認待ちと遮断中の IP が表示される。不要なら `JEV_ARGOS_DEMO=false docker compose up`。
- LLM 分析はホストの Ollama (`http://localhost:11434`) を使う。Ollama もコンテナで動かす場合:
  ```bash
  JEV_ARGOS_OLLAMA_URL=http://ollama:11434 docker compose --profile llm up --build
  docker compose exec ollama ollama pull qwen2.5:3b   # 初回のみ
  ```
- Slack 通知は `JEV_ARGOS_SLACK_WEBHOOK_URL`、承認された対処の実行先は `JEV_ARGOS_ACTION_WEBHOOK_URL` を指定して起動する。
- 公開ポートはすべて `127.0.0.1` に限定している。ダッシュボードに到達できる人は承認操作ができるため、外部に公開する場合は前段で管理者を認証すること。
- 停止は `docker compose down` (データも消す場合は `docker compose down -v`)。
