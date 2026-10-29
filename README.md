# jev-argos

**BFF / バックエンド向けのセキュリティ・コントロールプレーン (制御基盤)。**
ミリ秒単位の 1 次リスク判定エンジン「Jev」、LLM による深層分析、誤判定を防ぐ Human-in-the-Loop 承認機能を組み合わせ、
アプリ本体の通信経路の外側から、攻撃の検知・遮断・人間による判断までを担う。

- **アプリを遅くしない**: アプリは応答を返した後に通信のメタデータを送るだけ。判定は別プロセスで行う。
- **誤遮断しない**: 確信度が足りない遮断は自動で実行せず、管理者の承認に回す。
- **導入は 2 つだけ**: 判定サーバー (`jev-argos-server`) を起動し、BFF にミドルウェア (`@jev-argos/adapter-node` / Go の `pkg/client`) を 1 行挟む。
- **ライブラリとして差し替えられる**: LLM・保存先・通知先・遮断の実行方法などはインターフェースで分かれている ([差し替えポイント](#差し替えポイント))。

## 解決する課題 (Why jev-argos?)

| 従来の方法 | 問題 |
| --- | --- |
| **WAF / 固定ルール** (例: 1 分間に 100 回エラーで遮断) | 閾値が固定。低速スキャン (数分に 1 回) や分散した攻撃、未知のパターンを見逃す。閾値を下げると、正常なアクセスの急増を誤遮断する |
| **LLM の直接利用** | 1 件の判定に 1〜3 秒かかり、リクエストの処理中には使えない。全リクエストに使うとトークンコストが莫大になる |

**jev-argos のアプローチ**: すべてのリクエストを Jev がミリ秒で採点し、LLM と人間は本当に必要なものだけを見る。

Jev は単発のリクエスト (点) に、送信元の直近の振る舞い (面) を合わせて評価する。
同じ IP の 1 分間のエラー数、5 分間に権限エラーを受けた API の種類数 (権限の探索行為)、平常時に対するレイテンシの比 (リソース枯渇系の攻撃) を組み合わせるため、固定の閾値では捉えにくいパターンも検知できる。
結果はリスクスコア S (0.0〜4.0) と確信度 C (0.0〜1.0) で表し、次の 4 段階で扱う。

| Level | 判定 | jev-argos の対応 |
| --- | --- | --- |
| **1** 正常 / 軽微 | S < 1.5 | 記録のみ。大半の通信はここで終わり、LLM を呼ばない (コストも追加の遅延もかからない) |
| **2** 不審 | 1.5 ≤ S < 2.5 | 判定ログを保存し、LLM で非同期に深層分析 (要約・根拠・推奨対応) |
| **3** 攻撃の疑い | 2.5 ≤ S < 3.5 | 承認キューに「IP の一時遮断」を提案し、Slack / Webhook とダッシュボードに通知。管理者が承認すると遮断する |
| **4** 危険 | S ≥ 3.5 かつ C ≥ 0.8 | ミリ秒で `Level 4` を返し、送信元 IP を一定時間 (既定 15 分) 自動遮断。遮断はアダプターに配信され、以降のリクエストを拒否する |

**安全装置**: S ≥ 3.5 でも確信度 C が 0.8 未満なら自動遮断せず、Level 3 として人間の承認キューに回す。ネットワークの瞬断やアプリのバグで正常なユーザーを締め出さないため。
LLM が推奨した対処も、アカウント削除のような取り消せない操作も、管理者が承認するまで実行されない。

## アーキテクチャ

```
  Your application                                  jev-argos
  ================                                  =========

  [ Frontend ]
       | HTTP
       v
  [ Main BFF (Node.js / Go) ]                       [ jev-argos-server (Go) ]
    + adapter (middleware /  ---- gRPC signal ---->   Signal Receiver          :50051 (gRPC) / :8080 (HTTP)
      interceptor)                (async, after          |
       ^                           the response)         v
       |                                               Sliding Window stats     -- Redis (optional)
       +---- blocklist stream (WatchBlocklist) -----   Jev scoring -> Guardrail (Level 1-4)
       |     -> blocked IPs get 403                      |-- Level 4: auto block -> blocklist
       v                                                 |-- Level 3: approval queue          -- PostgreSQL (optional)
  [ Backend services ]                                   |-- Level 2+: decision log           -- PostgreSQL / SQLite
                                                         |-- Level 2+: LLM analysis (async)   -- Ollama (default) / Claude
                                                         +-- Level 3+: alerts                 -- Slack / Webhook
                                                                                |
                                                          Admin API :8080 (HTTP / SSE)
                                                                                v
                                                             [ Dashboard (React UI) ]
                                                               live signals, LLM analyses,
                                                               approve / reject, blocklist
```

1. BFF のミドルウェアが、応答を返した**後に**リクエストのメタデータ (IP・User-Agent・メソッド・ステータス・処理時間) を gRPC で送る。
2. `jev-argos-server` が直近の統計と合わせて Jev で採点し、Level を決めて返す (ミリ秒)。Level 4 は自動遮断し、遮断リストをアダプターへ配信する。
3. Level 2 以上は判定ログに残り、LLM が非同期に分析する。Level 3 は承認キューに入り、管理者がダッシュボードで根拠と LLM の分析を確認して承認 / 拒否する。

## 最小導入ステップ (Quick Start)

**必要なのは次の 2 つだけ**。Redis・PostgreSQL・LLM・ダッシュボードは後から追加できる (なくても動く)。

1. **jev-argos-server** (Go): 裏でシグナルを受信・判定する制御エンジン。Docker か `go run` で起動する。
2. **@jev-argos/adapter-node** (TypeScript): あなたの Node.js BFF に挟む数行のミドルウェア。Go の BFF には `pkg/client`。

### ステップ 1: コアサーバーを起動する

```bash
# リポジトリのルートでイメージをビルドして起動 (公開イメージはまだ無い)
docker build -t jev-argos/server .
docker run -d --name jev-argos -p 127.0.0.1:50051:50051 jev-argos/server

# または Go 1.26 以上で直接起動
go run ./cmd/jev-argos-server
```

gRPC のポート 50051 でシグナルを受け付ける。外部サービスへの依存は無い (統計はメモリ上で集計)。
LLM 分析は既定でローカルの Ollama (`http://localhost:11434`) を使う。Ollama が無くても判定・遮断は動く (分析だけが失敗としてログに残る。使わない場合は `JEV_ARGOS_LLM_PROVIDER=none`)。

### ステップ 2: アダプターをインストールする

```bash
pnpm add @jev-argos/adapter-node    # または npm i @jev-argos/adapter-node
```

> npm にはまだ公開していない。それまではリポジトリからパッケージを作って入れる:
>
> ```bash
> corepack enable && pnpm install && pnpm --filter @jev-argos/adapter-node build
> (cd packages/adapter-node && npm pack)     # jev-argos-adapter-node-0.1.0.tgz ができる
> pnpm add /path/to/jev-argos/packages/adapter-node/jev-argos-adapter-node-0.1.0.tgz   # あなたのアプリで
> ```

### ステップ 3: BFF に組み込む

**Express** — ルートより前に 1 行追加する。

```ts
import express from "express";
import { SignalReporter, createExpressMiddleware } from "@jev-argos/adapter-node";

const reporter = new SignalReporter({ target: "localhost:50051" }); // ステップ 1 のサーバー

const app = express();
app.use(createExpressMiddleware(reporter, { sourceService: "main-bff" }));

app.get("/users/:id", (req, res) => res.json({ id: req.params.id })); // 既存のルートはそのまま
```

**Next.js (App Router)** — Route Handler を `withJevArgos` で包む。

```ts
// app/api/users/[id]/route.ts
import { SignalReporter, withJevArgos } from "@jev-argos/adapter-node";

const reporter = new SignalReporter({ target: "localhost:50051" });
export const runtime = "nodejs"; // gRPC は Edge Runtime では動かない

export const GET = withJevArgos(reporter, { route: "/api/users/[id]", sourceService: "main-bff" },
  async (_req: Request, { params }: { params: Promise<{ id: string }> }) => {
    return Response.json({ id: (await params).id });
  },
);
```

Fastify・gRPC・ロードバランサー配下での IP の扱いは [packages/adapter-node/README.md](packages/adapter-node/README.md) を参照。

### ステップ 4: 動作を確認する

存在しないページに 1 分間で 30 回アクセスすると、エラーの集中として検知される。

```bash
for i in $(seq 30); do curl -s -o /dev/null http://localhost:3000/no-such-page-$i; done
docker logs jev-argos 2>&1 | grep "jev-argos action"
```

```
msg="jev-argos action" level=3 downgraded=true score=3.6 confidence=0.625 client_ip=127.0.0.1 method="GET (unmatched)" ip_error_count_1m=30 ...
```

スコアは遮断域 (S ≥ 3.5) だが、エラーの集中という 1 種類の兆候しか無いため確信度が足りず、
自動遮断ではなく Level 3 (承認キュー) に回っている。正常なリクエストは Level 1 なのでログには出ない。

### ステップ 5 (推奨): 遮断を有効にする

`BlocklistWatcher` を渡すと、Level 4 の自動遮断と管理者が承認した遮断が BFF に配信され、該当する IP のリクエストを 403 で拒否する。

```ts
import { BlocklistWatcher } from "@jev-argos/adapter-node";

const blocklist = new BlocklistWatcher({ target: "localhost:50051" });
app.use(createExpressMiddleware(reporter, { sourceService: "main-bff", blocklist }));
```

### Go の BFF の場合

```go
import "github.com/jev-argos/jev-argos/pkg/client"

conn, _ := grpc.NewClient("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
reporter := client.NewReporter(conn, client.ReporterOptions{})
blocklist := client.NewBlocklistWatcher(ctx, conn, nil)
opts := client.Options{SourceService: "main-bff", Blocklist: blocklist}

// net/http (Go 1.22+ の ServeMux のルートパターンがメソッド名になる)
http.ListenAndServe(":8080", client.Middleware(reporter, opts)(mux))
// gRPC
grpc.NewServer(grpc.ChainUnaryInterceptor(client.UnaryServerInterceptor(reporter, opts)))
```

gRPC を使えない環境からは、HTTP の `POST /api/signals` (JSON) でも送れる ([サーバーの README](cmd/jev-argos-server/README.md))。

## Docker Compose で一式を起動する

コアサーバー・Redis・PostgreSQL・ダッシュボードをまとめて起動する。

```bash
export JEV_ARGOS_ADMIN_TOKEN=$(openssl rand -hex 16)   # 管理 API のトークン (必須)
docker compose up --build
```

| サービス | URL | 備考 |
| --- | --- | --- |
| ダッシュボード | http://localhost:3000 | 管理 API へのトークン付与はダッシュボードの nginx が行う |
| gRPC (シグナル受信) | localhost:50051 | アダプターの `target` に指定する |
| 管理 API | http://localhost:8080 | `Authorization: Bearer $JEV_ARGOS_ADMIN_TOKEN` が必須 |
| PostgreSQL | localhost:55432 | `jevargos` / `jevargos`。判定ログ `jev_decision_logs`、承認キュー `jev_actions` |

- 起動時に疑似シグナルが流れ (`JEV_ARGOS_DEMO=true`)、ダッシュボードに承認待ちアラートと遮断中の IP が表示される。不要なら `JEV_ARGOS_DEMO=false docker compose up`。
- LLM 分析はホストの Ollama (`http://localhost:11434`) を使う。Ollama もコンテナで動かす場合:
  ```bash
  JEV_ARGOS_OLLAMA_URL=http://ollama:11434 docker compose --profile llm up --build
  docker compose exec ollama ollama pull qwen2.5:3b   # 初回のみ
  ```
- Slack 通知は `JEV_ARGOS_SLACK_WEBHOOK_URL`、承認された操作の実行先は `JEV_ARGOS_ACTION_WEBHOOK_URL` を指定して起動する (設定の一覧は [サーバーの README](cmd/jev-argos-server/README.md#設定))。
- コアサーバーのヘルスチェックが通ってからダッシュボードが起動する (`docker compose ps` で `healthy` を確認できる)。
- 公開ポートはすべて `127.0.0.1` に限定している。ダッシュボードに到達できる人は承認操作ができるため、外部に公開する場合は前段で管理者を認証すること。
- 停止は `docker compose down` (データも消す場合は `docker compose down -v`)。

## モノレポの構成

| パッケージ | 言語 | 役割 | ドキュメント |
| --- | --- | --- | --- |
| `cmd/jev-argos-server` + `pkg/` | Go | コントロールサーバー本体 (シグナル受信・Jev 判定・遮断・LLM 分析・通知・承認キュー・管理 API) | [README](cmd/jev-argos-server/README.md) |
| `pkg/client` | Go | Go の BFF 用アダプター (gRPC インターセプター・net/http ミドルウェア・遮断リストの購読) | 上記「Go の BFF の場合」 |
| `packages/adapter-node` | TypeScript | `@jev-argos/adapter-node` — Node.js の BFF 用アダプター | [README](packages/adapter-node/README.md) |
| `packages/dashboard` | TypeScript / React | 運用ダッシュボード (概況・シグナル一覧・LLM 分析・承認キュー・遮断中の一覧) | [README](packages/dashboard/README.md) |

```
.
├── cmd/jev-argos-server/   コントロールサーバーのエントリポイント (部品の組み立てと設定)
├── pkg/
│   ├── receiver/           シグナル受信 (gRPC / HTTP)
│   ├── buffer/             Sliding Window の統計 (メモリ / Redis)
│   ├── classifier/         Jev (スコア S と確信度 C の算出)
│   ├── guardrail/          安全境界ルール (Level の決定・格下げ)
│   ├── action/             遮断リスト (メモリ / Redis)・Level 4 の自動遮断・承認されたアクションの実行・遮断リストの配信
│   ├── approval/           承認キュー (メモリ / PostgreSQL)
│   ├── llm/                LLM 分析 (Ollama / Claude、伏せ字、結果の反映)
│   ├── notify/             Slack / Webhook 通知
│   ├── db/                 判定ログ (PostgreSQL / SQLite)・Safe View
│   ├── events/             ダッシュボードへのリアルタイム配信 (SSE)
│   ├── api/                管理 HTTP API
│   ├── webhook/            署名付き Webhook の送信・検証
│   └── client/             Go の BFF 用アダプター
├── proto/signal.proto      シグナル・遮断リストのスキーマ (Go / TypeScript 共通)
├── gen/v1/                 proto から生成した Go コード
├── packages/
│   ├── adapter-node/       @jev-argos/adapter-node
│   └── dashboard/          ダッシュボード
├── docs/jev_argos_spec.md  設計書
├── Dockerfile              コントロールサーバーのイメージ
└── docker-compose.yml      ローカル検証環境
```

## 差し替えポイント

jev-argos はライブラリとして、実際の環境に合わせて部品を差し替えられるように作っている。
差し替えが必要な箇所にはコードに `[差し替えポイント]` のコメントを付けているので、次のコマンドで一覧できる。

```bash
grep -rn "差し替えポイント" cmd pkg packages/*/src packages/dashboard/*.ts packages/dashboard/*.template
```

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
| **承認されたアクションの実行方法** | `pkg/action` の `Router` / `WebhookExecutor`、`components.go` の `newExecutor` | IP 遮断 → 遮断リスト、それ以外 → アプリの Webhook |
| **アプリ固有のアクション** | `pkg/approval` の `ActionType` | 7 種類 (IP 遮断・セッション無効化・縮小運転・アカウント停止 / 削除・データ削除・サービス停止) |
| **判定後の処理の追加・削除** | `components.go` の `newEmitters` | ログ・自動遮断・承認キュー・判定ログ・通知・LLM |
| **統計の保存先** | `pkg/buffer` の `Buffer` | メモリ / Redis |
| **LLM 用 DB ユーザーの権限** | `pkg/db` の Safe View の定義 (SQL コメント) | — (本番で設定する) |
| **ユーザー ID の取り出し方** | adapter-node の `extractUser`、Go の `client.Options.UserID` | 送らない |
| **ルートのパターンの取り出し方** (chi 等) | Go の `client.Options.Route` | ServeMux の `r.Pattern` |
| **遮断したリクエストへの応答** | adapter-node / Go の `onBlocked` / `OnBlocked` | 403 `{"error":"forbidden"}` |
| **ダッシュボードのデータ取得元** | `packages/dashboard/src/types.ts` の `DataSource`、`App.tsx` | コントロールサーバーの SSE |
| **ダッシュボードの管理者認証** | `packages/dashboard/nginx.conf.template` / `vite.config.ts` | 共有トークン (本番では前段に SSO を置く) |

## 開発

```bash
corepack enable && pnpm install   # TypeScript パッケージの依存

go test ./...                     # Go の全テスト (-race 推奨)
pnpm build                        # TypeScript パッケージ群のビルド
pnpm test                         # TypeScript パッケージ群のテスト

go run ./cmd/jev-argos-server -demo   # 疑似シグナルで判定パイプラインを確認
./scripts/gen-proto.sh                # proto/signal.proto を変更したら Go コードを再生成 (protoc が必要)
```

PostgreSQL の結合テストは `JEV_ARGOS_TEST_POSTGRES_URL` を設定したときだけ実行される。
Redis・LLM (Ollama / Claude)・Slack のテストは擬似サーバーで動くため、外部サービスは不要。

## 実装状況と既知の制約

- **Jev モデル**: 学習済みモデルの代わりに、同じインターフェースのルールベース暫定モデルで動いている (学習データが無いため)。`classifier.Model` を実装すれば差し替えられる。
- **LLM 分析の精度**: 使う LLM に依存する。既定の `qwen2.5:3b` は軽量さを優先したモデルで、精度が必要なら大きいモデルや Claude を使うこと。LLM が推奨できる対処は取り消せる操作 (IP 遮断・セッション無効化・アカウント一時停止・縮小運転) に限り、すべて承認キューを通る。
- **遮断以外のアクションの実行**: セッション無効化・アカウント操作・データ削除・縮小運転・サービス停止は、アプリが受信エンドポイント (`JEV_ARGOS_ACTION_WEBHOOK_URL`) を実装して実行する。jev-argos は署名付きで依頼するだけ。
- **複数インスタンス**: Redis (統計・遮断リスト) と PostgreSQL (承認キュー) を使うと複数インスタンスで共有される。指定しない場合はそれぞれメモリ上にあり、再起動で消える。
- **通信の暗号化と認証**: gRPC・管理 API とも TLS は内蔵していない。管理 API は共有トークン方式で、承認者名は自己申告。本番ではサービスメッシュやリバースプロキシで TLS と管理者の認証を行うこと。
- **パッケージの公開**: Docker イメージ・npm パッケージとも未公開 (ローカルでビルドして使う)。
- **性能検証**: 設計書 9 章の性能検証 (Level 4 判定までのレイテンシ、LLM 単体との比較) は未実施。

詳細な設計は [docs/jev_argos_spec.md](docs/jev_argos_spec.md) を参照。
