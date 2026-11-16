# jev-argos

**Web サービスの BFF / バックエンドに組み込む、攻撃の検知と遮断のためのライブラリ。**

アプリにアダプター (ミドルウェア) を組み込むと、リクエストの情報が判定サーバーに送られ、送信元ごとの直近の振る舞いから攻撃を見つけます。
危険と確信できる送信元はその場で遮断し、確信が持てないものは人間の承認を待ちます。

| 機能 | 内容 |
| --- | --- |
| **検知** | 権限の探索 (管理 API を片っ端から試す)・エラーの集中・処理時間の急増を、送信元ごとの直近の振る舞いから見つける |
| **自動遮断** | 危険と確信できる送信元を、その場で一定時間 (既定 15 分) 403 で拒否する |
| **人間が最終判断** | 確信が持てないものは自動で遮断せず、管理者の承認を待つ。正常なユーザーを誤って締め出さないため |
| **LLM 分析** | 怪しい送信元について「何が起きているか」「どう対応すべきか」を LLM がまとめる (既定はローカルの Ollama、API キー不要) |
| **通知** | 要注意の送信元を Slack や Webhook に知らせる |

**アプリを遅くしません。** アダプターは応答を返した後に情報を送るだけで、判定サーバーが止まっていてもアプリには影響しません。

---

## 目次

1. [しくみ](#しくみ)
2. [5 分で試す](#5-分で試す)
3. [自分のアプリに組み込む](#自分のアプリに組み込む)
4. [他の言語で使う](#他の言語で使う)
5. [ドキュメント一覧](#ドキュメント一覧)
6. [実装状況と既知の制約](#実装状況と既知の制約)
7. [開発](#開発)

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
                                                 Level 3-4  : notify (Slack / Webhook)
                                                 Level 3    : approval queue
                                                 Level 2-4  : LLM analysis, decision log
```

判定エンジン **Jev** は、1 件のリクエストだけでなく同じ送信元の直近の振る舞い (1 分間のエラー数・5 分間に権限エラーを受けた API の種類数・普段に対する処理時間の比) を合わせて採点し、
**リスクスコア S** (0.0〜4.0) と **確信度 C** (0.0〜1.0) を出します。

| Level | 条件 | 対応 |
| --- | --- | --- |
| **1** 正常 | S < 1.5 | 何もしない。大半のリクエストはここ |
| **2** 不審 | 1.5 ≤ S < 2.5 | 判定ログに残し、LLM が分析する |
| **3** 攻撃の疑い | 2.5 ≤ S < 3.5、**または** S ≥ 3.5 で C < 0.8 | 「IP の一時遮断」を承認キューに提案し、通知する。管理者が承認すると遮断する |
| **4** 危険 | S ≥ 3.5 **かつ** C ≥ 0.8 | その場で自動遮断し (既定 15 分)、通知する |

- スコアが危険域でも確信度が足りなければ、自動遮断せず人間の判断 (Level 3) に回します。
- LLM が提案した対処や、取り消せない操作 (アカウント削除など) も、管理者が承認するまで実行されません。
- 閾値は暫定の初期値で、環境変数で変更できます。判定の詳細は [判定サーバーの README](cmd/jev-argos-server/README.md#判定のルール) を参照。

Redis・PostgreSQL・LLM・Slack はすべて**任意**です。何も用意しなくても判定と遮断は動きます
(LLM 分析は既定で Ollama を使うため、Ollama が無いと起動時に警告が出ます。不要なら `JEV_ARGOS_LLM_PROVIDER=none`)。

---

## 5 分で試す

判定サーバー・Redis・PostgreSQL・ダッシュボードを Docker Compose でまとめて起動し、**テスト用 BFF** に攻撃のようなリクエストを送って、遮断されるまでを確かめます。

> **本体とテスト用の区別**
> - 本体: 判定サーバー (`cmd/`, `pkg/`)、アダプター (`packages/adapter-node`, `pkg/client`)、ダッシュボード (`packages/dashboard`)
> - テスト用: `examples/test-bff` のみ。認証はダミーなので**本番では使わないでください**

```bash
# 1. 一式を起動する
export JEV_ARGOS_ADMIN_TOKEN=$(openssl rand -hex 16)   # 管理 API のトークン (Docker Compose では必須)
docker compose up --build

# 2. 別のターミナルで、テスト用 BFF を起動する (http://localhost:4000)
corepack enable && pnpm install && pnpm --filter @jornjp/adapter-node build
node examples/test-bff/server.js
```

攻撃のようなリクエストの送り方は [examples/test-bff の README](examples/test-bff/README.md#試す) にあります。
結果はブラウザの **http://localhost:3000** (ダッシュボード) で確認できます。
起動時に疑似的なリクエストが流れるため、最初から承認待ちや遮断中の IP が表示されます (不要なら `JEV_ARGOS_DEMO=false docker compose up`)。

| サービス | URL | 備考 |
| --- | --- | --- |
| ダッシュボード | http://localhost:3000 | 管理 API へのトークン付与はダッシュボードの nginx が行う |
| テスト用 BFF | http://localhost:4000 | 手順 2 で起動したもの |
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

---

## 自分のアプリに組み込む

ここでは Express の最小例を示します。Next.js・Fastify・gRPC・Go は [ドキュメント一覧](#ドキュメント一覧) の各 README を参照してください。

**1. 判定サーバーを起動する**

```bash
# リポジトリのルートで
docker build -t jev-argos/server .
docker run -d --name jev-argos \
  -p 127.0.0.1:50051:50051 -p 127.0.0.1:8080:8080 \
  -e JEV_ARGOS_ADMIN_TOKEN=$(openssl rand -hex 16) \
  jev-argos/server

# または Go 1.26 以上で直接起動
go run ./cmd/jev-argos-server
```

50051 番 (gRPC) でリクエストの情報を受け付け、8080 番で管理 API (承認・遮断の操作) を提供します。
`JEV_ARGOS_ADMIN_TOKEN` を指定しない場合は、起動ごとに一時的なトークンが作られてログに出ます (開発用)。

**2. アダプターを入れて、ルートより前に登録する**

```bash
pnpm add @jornjp/adapter-node   # npm 公開前の入れ方は packages/adapter-node の README を参照
```

```ts
import express from "express";
import { BlocklistWatcher, SignalReporter, createExpressMiddleware } from "@jornjp/adapter-node";

const reporter = new SignalReporter({ target: "localhost:50051" });   // リクエストの情報を送る
const blocklist = new BlocklistWatcher({ target: "localhost:50051" }); // 遮断中の IP を受け取る (遮断しないなら不要)

const app = express();
app.use(createExpressMiddleware(reporter, { sourceService: "main-bff", blocklist }));

app.get("/users/:id", (req, res) => res.json({ id: req.params.id })); // 既存のルートはそのまま
```

**3. 動作を確認する**

存在しないページに 1 分間で 30 回アクセスすると、「エラーの集中」として検知されます。

```bash
# localhost:4000 はあなたのアプリのアドレスに置き換える
for i in $(seq 30); do curl -s -o /dev/null http://localhost:4000/no-such-page-$i; done
docker logs jev-argos 2>&1 | grep "jev-argos action"
```

```
msg="jev-argos action" level=3 downgraded=true score=3.6 confidence=0.625 client_ip=127.0.0.1 method="GET (unmatched)" ip_error_count_1m=30 ...
```

スコアは危険域 (3.6) ですが、エラーの集中という 1 種類の兆候だけでは確信度が足りない (0.625) ため、
自動遮断ではなく**承認キュー**に入りました (`level=3 downgraded=true`)。正常なリクエストはログに出ません。

---

## 他の言語で使う

公式のアダプターは Node.js と Go だけですが、アダプターと判定サーバーのやり取りは gRPC ([proto/signal.proto](proto/signal.proto)) で決まっています。
**gRPC に対応している言語 (Java / Kotlin・C#・Python・Ruby・Rust など) なら、アダプターを書けば検知と遮断の両方が使えます。**
規模の目安は、gRPC だけなら 300〜450 行、HTTP のミドルウェアも入れると 400〜600 行です。

| 使う RPC | 用途 |
| --- | --- |
| `SignalService.ReportSignal` (バッチなら `StreamSignals`) | リクエストの情報を送る |
| `ControlService.WatchBlocklist` (サーバー側のストリーミング) | 遮断中の送信元の一覧を受け取る |

アダプターが守るべきことのうち、特に重要なのは次の 4 つです。

- **送信はアプリを待たせない**: 非同期で送り、あふれたら捨て、例外をアプリに投げない
- **`status_code` は gRPC のコード**: HTTP の 403 は 7 (`PERMISSION_DENIED`) に変換する。権限の探索の検知に使うため
- **`method` は API ごとに同じ文字列**: HTTP なら実際の URL ではなく `GET /users/:id` のようなルートのパターン。どのルートにも合わなければ `GET (unmatched)`
- **遮断の判定は手元のコピーで行う**: 遮断リストのストリームが切れたら自動で再接続し、その間は最後に受け取った一覧で判定を続ける

詳細 (フィールドごとの値・ステータスの変換表・再接続の決まり・動作確認のチェックリスト) は [docs/adapter_spec.md](docs/adapter_spec.md) にあります。

> 遮断リストを購読するため、プロセスが常駐している必要があります。PHP-FPM のようにリクエストごとにプロセスが終わる環境では、常駐の実行環境かサイドカーが必要です。
> 検知だけなら、gRPC を使わずに HTTP の `POST /api/signals` でも送れます ([判定サーバーの README](cmd/jev-argos-server/README.md#api))。

---

## ドキュメント一覧

| 知りたいこと | 読むもの |
| --- | --- |
| Node.js の BFF への組み込み (Express / Next.js / Fastify / gRPC)・オプション | [packages/adapter-node/README.md](packages/adapter-node/README.md) |
| Go の BFF への組み込み (net/http / gRPC) | [pkg/client/README.md](pkg/client/README.md) |
| 他の言語でアダプターを書く | [docs/adapter_spec.md](docs/adapter_spec.md) |
| 判定のルール・設定の一覧・LLM・Webhook・API・Docker・Kubernetes | [cmd/jev-argos-server/README.md](cmd/jev-argos-server/README.md) |
| ダッシュボードの機能・単体での起動 | [packages/dashboard/README.md](packages/dashboard/README.md) |
| テスト用 BFF で攻撃を試す | [examples/test-bff/README.md](examples/test-bff/README.md) |
| 設計の詳細 | [docs/jev_argos_spec.md](docs/jev_argos_spec.md) |

### 差し替えポイント

jev-argos は部品を差し替えて自社の環境に合わせられるように作っています (Jev モデル・閾値・LLM・通知先・対処の実行方法など)。
一覧は各 README の「差し替えポイント」の表にあり、コードの該当箇所には `[差し替えポイント]` のコメントを付けています。

| 対象 | 表の場所 |
| --- | --- |
| 判定サーバー | [cmd/jev-argos-server/README.md](cmd/jev-argos-server/README.md#差し替えポイント) |
| Node.js のアダプター | [packages/adapter-node/README.md](packages/adapter-node/README.md#差し替えポイント) |
| Go のアダプター | [pkg/client/README.md](pkg/client/README.md#差し替えポイント) |
| ダッシュボード | [packages/dashboard/README.md](packages/dashboard/README.md#差し替えポイント) |

```bash
grep -rn "差し替えポイント" cmd pkg packages/*/src packages/dashboard/*.ts packages/dashboard/*.template
```

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
| **性能検証** | 設計書 9 章の性能検証 (判定までのレイテンシ、LLM 単体との比較) は未実施。Jev の判定はミリ秒単位を目標にしている |

---

## 開発

<details>
<summary>ディレクトリ構成</summary>

```
.
├── cmd/jev-argos-server/   判定サーバーのエントリポイント (部品の組み立てと設定)
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
├── proto/signal.proto      アダプターとサーバーの通信の定義
├── gen/v1/                 proto から生成した Go コード
├── packages/
│   ├── adapter-node/       Node.js 用アダプター (@jornjp/adapter-node)
│   └── dashboard/          付属の Web ダッシュボード (任意)
├── examples/test-bff/      テスト用の BFF (本番用ではない)
├── docs/
│   ├── jev_argos_spec.md   設計書
│   └── adapter_spec.md     アダプター仕様 (他の言語で実装する人向け)
├── Dockerfile              判定サーバーのイメージ
└── docker-compose.yml      一式を起動するローカル検証環境
```

</details>

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
