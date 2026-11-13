# jev-argos

**Web サービスの BFF / バックエンドに組み込む、攻撃の検知と遮断のためのライブラリ。**

```ts
app.use(createExpressMiddleware(reporter, { sourceService: "main-bff", blocklist })); // Express ならこれだけ
```

アプリにミドルウェアを 1 行足すだけで、次のことができるようになります。

| 機能 | 内容 |
| --- | --- |
| **検知** | 権限の探索 (管理 API を片っ端から試す)・エラーの集中・処理時間の急増を、送信元ごとの直近の振る舞いから見つける |
| **自動遮断** | 危険と確信できる送信元を、その場で一定時間 (既定 15 分) 403 で拒否する |
| **人間が最終判断** | 確信が持てないものは自動で遮断せず、管理者の承認を待つ。正常なユーザーを誤って締め出さないため |
| **LLM 分析** | 怪しい送信元について「何が起きているか」「どう対応すべきか」を LLM がまとめる (既定はローカルの Ollama、API キー不要) |
| **通知** | 要注意の送信元を Slack や Webhook に知らせる |

**アプリを遅くしません。** ミドルウェアは応答を返した後に情報を送るだけで、判定サーバーが止まっていてもアプリには影響しません。

---

## 目次

1. [しくみ](#しくみ)
2. [まず動かしてみる (Docker Compose)](#まず動かしてみる-docker-compose)
3. [自分のアプリに組み込む](#自分のアプリに組み込む)
4. [判定のルール](#判定のルール)
5. [機能を足す・自社の環境に合わせる](#機能を足す自社の環境に合わせる)
6. [Web ダッシュボード](#web-ダッシュボード)
7. [実装状況と既知の制約](#実装状況と既知の制約)
8. [リポジトリの構成と開発](#リポジトリの構成と開発)

---

## しくみ

jev-argos は 2 つの部品でできています。

| 部品 | どこで動くか | 役割 |
| --- | --- | --- |
| **アダプター** | あなたの BFF の中 (ライブラリ) | リクエストの情報 (送信元 IP・API・ステータス・処理時間) を送り、遮断中の送信元を拒否する。Node.js 版 `@jornjp/adapter-node`、Go 版 `pkg/client` |
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

Redis・PostgreSQL・LLM・Slack はすべて**任意**です。何も用意しなくても判定と遮断は動きます。

---

## まず動かしてみる (Docker Compose)

判定サーバー・Redis・PostgreSQL・ダッシュボードをまとめて起動し、攻撃から遮断までを手元で確かめます。

```bash
# 1. 一式を起動する
export JEV_ARGOS_ADMIN_TOKEN=$(openssl rand -hex 16)   # 管理 API のトークン (必須)
docker compose up --build

# 2. 別のターミナルで、アダプターを組み込んだテスト用 BFF を起動する (http://localhost:4000)
corepack enable && pnpm install && pnpm --filter @jornjp/adapter-node build
node examples/express-bff/server.js
```

ブラウザで **http://localhost:3000** (ダッシュボード) を開くと、承認待ちや遮断中の IP が表示されます
(起動時に疑似的なリクエストが流れるため。不要なら `JEV_ARGOS_DEMO=false docker compose up`)。

テスト用 BFF に攻撃のようなリクエストを送る手順は [examples/express-bff の README](examples/express-bff/README.md#試す) にあります。

| サービス | URL | 備考 |
| --- | --- | --- |
| ダッシュボード | http://localhost:3000 | 管理 API へのトークン付与はダッシュボードの nginx が行う |
| gRPC (受信) | localhost:50051 | アダプターの `target` に指定する |
| 管理 API | http://localhost:8080 | `Authorization: Bearer $JEV_ARGOS_ADMIN_TOKEN` が必須 |
| PostgreSQL | localhost:55432 | `jevargos` / `jevargos`。判定ログ `jev_decision_logs`、承認キュー `jev_actions` |

<details>
<summary>Docker Compose の補足 (LLM・Slack・停止方法など)</summary>

- LLM 分析はホストの Ollama (`http://localhost:11434`) を使う。Ollama もコンテナで動かす場合:
  ```bash
  JEV_ARGOS_OLLAMA_URL=http://ollama:11434 docker compose --profile llm up --build
  docker compose exec ollama ollama pull qwen2.5:3b   # 初回のみ
  ```
- Slack 通知は `JEV_ARGOS_SLACK_WEBHOOK_URL`、承認された対処の実行先は `JEV_ARGOS_ACTION_WEBHOOK_URL` を指定して起動する。
- 公開ポートはすべて `127.0.0.1` に限定している。ダッシュボードに到達できる人は承認操作ができるため、外部に公開する場合は前段で管理者を認証すること。
- 停止は `docker compose down` (データも消す場合は `docker compose down -v`)。

</details>

> `examples/express-bff` は**テスト・デモ用**です。認証はダミーなので本番では使わないでください。

---

## 自分のアプリに組み込む

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

> **npm に公開する前は**、リポジトリからパッケージを作って入れます。
>
> ```bash
> corepack enable && pnpm install && pnpm --filter @jornjp/adapter-node build
> (cd packages/adapter-node && npm pack)     # jornjp-adapter-node-0.1.0.tgz ができる
> pnpm add /path/to/jev-argos/packages/adapter-node/jornjp-adapter-node-0.1.0.tgz   # あなたのアプリで
> ```

### ステップ 3: BFF に組み込む

**Express** — ルートより前に追加します。

```ts
import express from "express";
import { BlocklistWatcher, SignalReporter, createExpressMiddleware } from "@jornjp/adapter-node";

const reporter = new SignalReporter({ target: "localhost:50051" });   // 情報を送る
const blocklist = new BlocklistWatcher({ target: "localhost:50051" }); // 遮断中の IP を受け取る

const app = express();
app.use(createExpressMiddleware(reporter, { sourceService: "main-bff", blocklist }));

app.get("/users/:id", (req, res) => res.json({ id: req.params.id })); // 既存のルートはそのまま
```

**Next.js (App Router)** — Route Handler を `withJevArgos` で包みます。

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

**Go (net/http・gRPC)**

```go
import "github.com/jornJp0201/jev-argos/pkg/client"

conn, _ := grpc.NewClient("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
reporter := client.NewReporter(conn, client.ReporterOptions{})
blocklist := client.NewBlocklistWatcher(ctx, conn, nil)
opts := client.Options{SourceService: "main-bff", Blocklist: blocklist}

http.ListenAndServe(":8080", client.Middleware(reporter, opts)(mux))                      // net/http
grpc.NewServer(grpc.ChainUnaryInterceptor(client.UnaryServerInterceptor(reporter, opts))) // gRPC
```

- Fastify・gRPC (Node.js)・ロードバランサー配下での IP の扱い → [アダプターの README](packages/adapter-node/README.md)
- gRPC を使えない環境 → HTTP の `POST /api/signals` (JSON) でも送れる ([判定サーバーの README](cmd/jev-argos-server/README.md#api))

### ステップ 4: 動作を確認する

存在しないページに 1 分間で 30 回アクセスすると、「エラーの集中」として検知されます。

```bash
# localhost:3000 はあなたのアプリのアドレスに置き換える
for i in $(seq 30); do curl -s -o /dev/null http://localhost:3000/no-such-page-$i; done
docker logs jev-argos 2>&1 | grep "jev-argos action"
```

```
msg="jev-argos action" level=3 downgraded=true score=3.6 confidence=0.625 client_ip=127.0.0.1 method="GET (unmatched)" ip_error_count_1m=30 ...
```

スコアは危険域 (3.6) ですが確信度が足りない (0.625) ため、自動遮断ではなく**承認キュー**に入りました (`level=3 downgraded=true`)。
正常なリクエストはログに出ません。

---

## 判定のルール

判定エンジン **Jev** は、1 件のリクエストだけでなく**同じ送信元の直近の振る舞い**を合わせて採点します。

| 見ているもの | 何が疑われるか |
| --- | --- |
| 同じ IP の 1 分間のエラー数 | 総当たり・スキャン |
| 5 分間に権限エラーを受けた API の種類数 | 権限の探索 (いろいろな管理 API を試している) |
| その API の普段の処理時間に対する比 | 負荷をかける攻撃 |

「1 分間に 100 回エラーで遮断」のような固定の閾値では、低速な攻撃を見逃したり、正常なアクセスの急増を誤って遮断したりします。
複数の兆候を組み合わせることで、両者を見分けやすくしています。

採点結果は **リスクスコア S** (0.0〜4.0) と **確信度 C** (0.0〜1.0) の 2 つで、次の 4 段階に分けます。

| Level | 条件 | 対応 |
| --- | --- | --- |
| **1** 正常 | S < 1.5 | 何もしない (記録のみ)。大半のリクエストはここ |
| **2** 不審 | 1.5 ≤ S < 2.5 | 判定ログに残し、LLM が分析する |
| **3** 攻撃の疑い | 2.5 ≤ S < 3.5 | 「IP の一時遮断」を承認キューに提案し、Slack 等に通知する。管理者が承認すると遮断する |
| **4** 危険 | S ≥ 3.5 **かつ** C ≥ 0.8 | その場で自動遮断する (既定 15 分) |

> 表の数値は暫定の初期値です。環境変数で変更できます ([機能を足す・自社の環境に合わせる](#機能を足す自社の環境に合わせる))。

**安全装置**

- スコアが危険域 (S ≥ 3.5) でも、確信度が 0.8 未満なら自動遮断せず Level 3 (人間の判断) に回します。
- LLM が提案した対処や、アカウント削除のような取り消せない操作も、管理者が承認するまで実行されません。

**なぜ LLM だけで判定しないのか** — LLM は 1 件の判定に秒単位かかることが多く、全リクエストに使うとコストも大きくなります。
そこで Jev がすべてのリクエストを軽い計算で採点し (ミリ秒単位が目標。性能は未検証)、LLM は怪しいものだけを分析します。

---

## 機能を足す・自社の環境に合わせる

### よくある設定

| やりたいこと | 方法 |
| --- | --- |
| 判定の記録を残す | `JEV_ARGOS_POSTGRES_URL` (本番) か `JEV_ARGOS_SQLITE_PATH` (開発) を指定 |
| 判定サーバーを複数台にする | `JEV_ARGOS_REDIS_URL` と `JEV_ARGOS_POSTGRES_URL` を指定 |
| LLM 分析を使う | Ollama を入れて `ollama pull qwen2.5:3b` (Claude なら `JEV_ARGOS_LLM_PROVIDER=anthropic`) |
| Slack に通知する | `JEV_ARGOS_SLACK_WEBHOOK_URL` を指定 |
| 判定の閾値を変える | `JEV_ARGOS_BLOCK_SCORE` / `_BLOCK_CONFIDENCE` / `_LEVEL3_SCORE` / `_LEVEL2_SCORE` |
| 承認待ちを確認・承認する | 管理 API、または [Web ダッシュボード](#web-ダッシュボード) |

設定の一覧は [判定サーバーの README](cmd/jev-argos-server/README.md#設定) にあります。

### 差し替えポイント

jev-argos は部品を差し替えて自社の環境に合わせられるように作っています。
差し替えられる箇所にはコードに `[差し替えポイント]` のコメントを付けているので、次のコマンドで一覧できます。

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
| **レベルを分ける閾値** | `pkg/guardrail` の `Guardrail` (ライブラリ)、または上記の環境変数 | S ≥ 3.5 かつ C ≥ 0.8 で遮断、L3 2.5 / L2 1.5 |
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

**Web ダッシュボード**

| 何を変えるか | 場所 | 既定 |
| --- | --- | --- |
| データの取得元 | `packages/dashboard/src/types.ts` の `DataSource`、`App.tsx` | 判定サーバーの SSE |
| 管理者の認証 | `packages/dashboard/nginx.conf.template` / `vite.config.ts` | 共有トークン (本番では前段に SSO を置く) |

---

## Web ダッシュボード

動作を目で確かめたり、承認待ちを画面で操作したりするための Web アプリ (React) を同梱しています。
**利用は任意**で、管理 API を自社の管理画面から呼んでもかまいません。起動方法は [まず動かしてみる](#まず動かしてみる-docker-compose) を参照。

- **概況**: 直近 5 分のリクエスト数・Level 3 / 4 の件数・平均スコア
- **承認待ち**: 判定の根拠と LLM の分析を見て、承認 / 拒否する。取り消せない操作は対象の再入力が必要
- **遮断中の一覧**: 自動遮断・承認・手動の遮断を確認し、解除する
- **シグナル一覧と詳細**: リクエストごとの Level・スコア・確信度・特徴量・LLM 分析

詳しくは [ダッシュボードの README](packages/dashboard/README.md) を参照。

---

## 実装状況と既知の制約

| 項目 | 現状 |
| --- | --- |
| **Jev モデル** | 学習データが無いため、学習済みモデルの代わりにルールベースの暫定モデルで動いている。`classifier.Model` を実装すれば差し替えられる |
| **LLM 分析の精度** | 使う LLM に依存する。既定の `qwen2.5:3b` は軽さ優先なので、精度が必要なら大きいモデルや Claude を使う。LLM が提案できる対処は取り消せるもの (IP 遮断・セッション無効化・アカウント一時停止・縮小運転) に限り、すべて承認キューを通る |
| **遮断以外の対処の実行** | セッション無効化・アカウント操作・データ削除・縮小運転・サービス停止は、アプリが受信エンドポイント (`JEV_ARGOS_ACTION_WEBHOOK_URL`) を用意して実行する。jev-argos は署名付きで依頼するだけ |
| **複数台構成** | Redis (統計・遮断リスト) と PostgreSQL (承認キュー) を使うと複数台で共有される。指定しない場合はメモリ上にあり、再起動で消える |
| **通信の暗号化と認証** | gRPC・管理 API とも TLS は内蔵していない。管理 API は共有トークン方式で、承認者名は自己申告。本番ではサービスメッシュやリバースプロキシで TLS と管理者の認証を行う |
| **パッケージの公開** | Docker イメージ・npm パッケージとも未公開 (ローカルでビルドして使う)。Go のパッケージは `go get github.com/jornJp0201/jev-argos/pkg/client` で取得できる |
| **性能検証** | 設計書 9 章の性能検証 (判定までのレイテンシ、LLM 単体との比較) は未実施 |

詳細な設計は [docs/jev_argos_spec.md](docs/jev_argos_spec.md) を参照。

---

## リポジトリの構成と開発

| パッケージ | 言語 | 役割 | ドキュメント |
| --- | --- | --- | --- |
| `packages/adapter-node` | TypeScript | `@jornjp/adapter-node` — Node.js の BFF 用アダプター | [README](packages/adapter-node/README.md) |
| `pkg/client` | Go | Go の BFF 用アダプター | [組み込み方](#ステップ-3-bff-に組み込む) |
| `cmd/jev-argos-server` + `pkg/` | Go | 判定サーバー (受信・採点・遮断・承認キュー・LLM 分析・通知・管理 API) | [README](cmd/jev-argos-server/README.md) |
| `packages/dashboard` | TypeScript / React | 付属の Web ダッシュボード (任意) | [README](packages/dashboard/README.md) |
| `examples/express-bff` | JavaScript | テスト・デモ用の BFF (本番用ではない) | [README](examples/express-bff/README.md) |

<details>
<summary>ディレクトリ構成</summary>

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
├── examples/express-bff/   テスト・デモ用の BFF (本番用ではない)
├── docs/jev_argos_spec.md  設計書
├── Dockerfile              判定サーバーのイメージ
└── docker-compose.yml      一式を起動するローカル検証環境
```

</details>

### 開発

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

## ライセンス

[MIT License](LICENSE)
