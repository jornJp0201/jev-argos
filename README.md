# jev-argos

**BFF / バックエンド向けのセキュリティ・コントロールプレーン (制御基盤)。**
ミリ秒単位の 1 次リスク判定エンジン「Jev」、LLM による深層分析、誤判定を防ぐ Human-in-the-Loop 承認機能を組み合わせ、
アプリ本体の通信経路の外側から、攻撃の検知・遮断・人間による判断までを担う。

- **アプリを遅くしない**: アプリは応答を返した後に通信のメタデータを送るだけ。判定は別プロセスで行う。
- **誤遮断しない**: 確信度が足りない遮断は自動で実行せず、管理者の承認に回す。
- **導入は 2 つだけ**: 判定サーバー (`jev-argos-server`) を起動し、BFF にミドルウェア (`@jev-argos/adapter-node`) を 1 行挟む。

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
| **2** 不審 | 1.5 ≤ S < 2.5 | 判定ログを保存し、LLM で非同期に深層分析 ※ |
| **3** 攻撃の疑い | 2.5 ≤ S < 3.5 | ダッシュボードの承認キューに「IP の一時遮断」を提案し、管理者が承認 / 拒否する。Slack 通知 ※ |
| **4** 危険 | S ≥ 3.5 かつ C ≥ 0.8 | ミリ秒で `Level 4` を返す。アプリはその送信元からの以降のリクエストを遮断できる |

**安全装置**: S ≥ 3.5 でも確信度 C が 0.8 未満なら自動遮断せず、Level 3 として人間の承認キューに回す。ネットワークの瞬断やアプリのバグで正常なユーザーを締め出さないため。

※ LLM 深層分析と Slack 通知は未実装 (「[実装状況](#実装状況と既知の制約)」を参照)。

## アーキテクチャ

```
  Your application                                  jev-argos
  ================                                  =========

  [ Frontend ]
       | HTTP
       v
  [ Main BFF (Node.js) ]                            [ jev-argos-server (Go) ]
    + @jev-argos/adapter-node  --- gRPC signal --->   Signal Receiver        :50051
      (middleware / interceptor)   (async, after       |
       ^                            the response)      v
       |                                             Sliding Window stats    -- Redis (optional)
       +------------ Level 4 notification ---------  Jev scoring -> Guardrail (Level 1-4)
       |                                               |-- decision log      -- PostgreSQL (optional)
       v gRPC                                          +-- approval queue    -> Admin API :8080
  [ Backend services ]                                                              |
                                                                                    | HTTP / SSE
                                                                                    v
                                                                   [ Dashboard (React UI) ]
                                                                     risk overview, approve / reject
```

1. BFF のミドルウェアが、応答を返した**後に**リクエストのメタデータ (IP・User-Agent・メソッド・ステータス・処理時間) を gRPC で送る。
2. `jev-argos-server` が直近の統計と合わせて Jev で採点し、Level を決めて返す (ミリ秒)。
3. Level 2 以上は判定ログに残り、Level 3 は承認キューに入る。管理者はダッシュボードで根拠を確認して承認 / 拒否する。

## 最小導入ステップ (Quick Start)

**必要なのは次の 2 つだけ**。Redis・PostgreSQL・ダッシュボードは後から追加できる (なくても動く)。

1. **jev-argos-server** (Go): 裏でシグナルを受信・判定する制御エンジン。Docker か `go run` で起動する。
2. **@jev-argos/adapter-node** (TypeScript): あなたの Node.js BFF に挟む数行のミドルウェア。

### ステップ 1: コアサーバーを起動する

```bash
# リポジトリのルートでイメージをビルドして起動 (公開イメージはまだ無い)
docker build -t jev-argos/server .
docker run -d --name jev-argos -p 127.0.0.1:50051:50051 jev-argos/server

# または Go 1.24 以上で直接起動
go run ./cmd/jev-argos-server
```

gRPC のポート 50051 でシグナルを受け付ける。外部サービスへの依存は無い (統計はメモリ上で集計)。

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

Fastify・gRPC サーバー / クライアント・ロードバランサー配下での IP の扱いは
[packages/adapter-node/README.md](packages/adapter-node/README.md) を参照。

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

### 次のステップ

- **Level 4 で遮断する**: `SignalReporter` の `onResponse` で `immediate_action_level >= 4` を受け取り、その IP を遮断リストに入れる ([adapter-node の README](packages/adapter-node/README.md#level-4-即時遮断-の通知を受けて遮断する))。
- **ダッシュボード・Redis・PostgreSQL を含めて動かす**: 下の Docker Compose で一式を起動できる。
- **本番運用**: 環境変数・ヘルスチェック・Kubernetes は [cmd/jev-argos-server/README.md](cmd/jev-argos-server/README.md) を参照。

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
| PostgreSQL | localhost:55432 | `jevargos` / `jevargos`。判定ログは `jev_decision_logs` テーブル |

- 起動時に疑似シグナルが流れ (`JEV_ARGOS_DEMO=true`)、ダッシュボードに承認待ちアラートが表示される。不要なら `JEV_ARGOS_DEMO=false docker compose up`。
- コアサーバーのヘルスチェックが通ってからダッシュボードが起動する (`docker compose ps` で `healthy` を確認できる)。
- 公開ポートはすべて `127.0.0.1` に限定している。ダッシュボードに到達できる人は承認操作ができるため、外部に公開する場合は前段で管理者を認証すること。
- 停止は `docker compose down` (判定ログも消す場合は `docker compose down -v`)。

## モノレポの構成

| パッケージ | 言語 | 役割 | ドキュメント |
| --- | --- | --- | --- |
| `cmd/jev-argos-server` + `pkg/` | Go | コントロールサーバー本体 (シグナル受信・Jev 判定・Redis / PostgreSQL 連携・承認キュー・管理 API) | [README](cmd/jev-argos-server/README.md) |
| `packages/adapter-node` | TypeScript | `@jev-argos/adapter-node` — Node.js の BFF に組み込む送信ミドルウェア | [README](packages/adapter-node/README.md) |
| `packages/dashboard` | TypeScript / React | 運用ダッシュボード (リスク概況・シグナル一覧・承認待ちアラート) | [README](packages/dashboard/README.md) |

```
.
├── cmd/jev-argos-server/   コントロールサーバーのエントリポイント
├── pkg/
│   ├── receiver/           gRPC Signal Receiver
│   ├── buffer/             Sliding Window の統計 (メモリ / Redis)
│   ├── classifier/         Jev (スコア S と確信度 C の算出)
│   ├── guardrail/          安全境界ルール (Level の決定・格下げ)
│   ├── db/                 判定ログ (PostgreSQL)
│   ├── approval/           承認キュー (Human-in-the-Loop)
│   └── api/                管理 HTTP API (+ SSE)
├── proto/signal.proto      シグナルのスキーマ (Go / TypeScript 共通)
├── gen/v1/                 proto から生成した Go コード
├── packages/
│   ├── adapter-node/       @jev-argos/adapter-node
│   └── dashboard/          ダッシュボード
├── docs/jev_argos_spec.md  設計書
├── Dockerfile              コントロールサーバーのイメージ
└── docker-compose.yml      ローカル検証環境
```

## 開発

```bash
corepack enable && pnpm install   # TypeScript パッケージの依存

go test ./...                     # Go の全テスト (-race 推奨)
pnpm build                        # TypeScript パッケージ群のビルド
pnpm test                         # TypeScript パッケージ群のテスト

go run ./cmd/jev-argos-server -demo   # 疑似シグナルで判定パイプラインを確認
./scripts/gen-proto.sh                # proto/signal.proto を変更したら Go コードを再生成 (protoc が必要)
```

## 実装状況と既知の制約

- **Jev モデル**: 学習済みモデルの代わりに、同じインターフェースのルールベース暫定モデルで動いている。Level 2/3 の境界値 (1.5 / 2.5) も暫定値。
- **LLM 深層分析・Slack 通知**: 未実装。ダッシュボードの解析結果は「モック」と明示した文面。
- **遮断の実行**: Level 4 はアダプターの `onResponse` でアプリ側が遮断する。承認キューで承認されたアクションは記録とログ出力のみで、BFF・ゲートウェイへの遮断コマンド発行は未実装。
- **承認キュー**: メモリ上に保持するため、再起動で消え、複数レプリカでは共有されない。
- **ダッシュボードのシグナル一覧**: コントロールサーバーに配信 API が無いため、ブラウザ内のシミュレーターのデータ (画面に「デモデータ」と表示)。承認待ちアラートは実データ。
- **通信の暗号化と認証**: gRPC・管理 API とも TLS は内蔵していない。管理 API は共有トークン方式。
- **パッケージの公開**: Docker イメージ・npm パッケージとも未公開 (ローカルでビルドして使う)。
- `packages/core`・`packages/adapter-pg`・`packages/adapter-redis` は初期セットアップ時のプレースホルダーで未使用 (Redis / PostgreSQL 対応は Go 側の `pkg/buffer`・`pkg/db` に実装)。

詳細な設計は [docs/jev_argos_spec.md](docs/jev_argos_spec.md) を参照。
