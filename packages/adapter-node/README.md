# @jev-argos/adapter-node

**jev-argos の Node.js 用アダプター。** Express / Next.js / Fastify / gRPC などの Node.js BFF に組み込み、
リクエストごとのメタデータを jev-argos のコントロールサーバーへ非同期に送る軽量ミドルウェア。

```ts
app.use(createExpressMiddleware(reporter, { sourceService: "main-bff" })); // Express ならこれだけ
```

## jev-argos とは

**BFF / バックエンド向けのセキュリティ・コントロールプレーン (制御基盤)。**
ミリ秒単位の 1 次リスク判定エンジン「Jev」、LLM による深層分析、誤判定を防ぐ Human-in-the-Loop 承認機能を組み合わせ、
アプリ本体の通信経路の外側から、攻撃の検知・遮断・人間による判断までを担う。

### 解決する課題 (Why jev-argos?)

| 従来の方法 | 問題 |
| --- | --- |
| **WAF / 固定ルール** | 閾値が固定。低速スキャンや分散した攻撃、未知のパターンを見逃す。閾値を下げると、正常なアクセスの急増を誤遮断する |
| **LLM の直接利用** | 1 件の判定に 1〜3 秒かかり、リクエストの処理中には使えない。全リクエストに使うとトークンコストが莫大になる |

jev-argos では、すべてのリクエストを Jev が送信元の直近の振る舞い (エラーの頻度・権限エラーの広がり・レイテンシの変化) と合わせてミリ秒で採点し、
LLM と人間は本当に必要なものだけを見る。

| Level | jev-argos の対応 |
| --- | --- |
| **1** 正常 / 軽微 | 記録のみ。大半の通信はここで終わり、LLM を呼ばない |
| **2** 不審 | 判定ログを保存し、LLM で非同期に深層分析 ※ |
| **3** 攻撃の疑い | ダッシュボードの承認キューに「IP の一時遮断」を提案し、管理者が承認 / 拒否する。Slack 通知 ※ |
| **4** 危険 | ミリ秒で `Level 4` を返す。アプリはその送信元からの以降のリクエストを遮断できる |

危険なスコアでも確信度が 0.8 未満なら自動遮断せず、Level 3 として人間の承認キューに回す (誤遮断の防止)。
※ LLM 深層分析と Slack 通知はコントロールサーバー側で未実装。

### アーキテクチャと、このパッケージの位置

```
  Your application                                  jev-argos
  ================                                  =========

  [ Frontend ]
       | HTTP
       v
  [ Main BFF (Node.js) ]                            [ jev-argos-server (Go) ]
    + @jev-argos/adapter-node  --- gRPC signal --->   Signal Receiver        :50051
      ^^^^^^^^^^^^^^^^^^^^^^^      (async, after       |
      THIS PACKAGE                  the response)      v
       ^                                             Sliding Window stats    -- Redis (optional)
       +------------ Level 4 notification ---------  Jev scoring -> Guardrail (Level 1-4)
                                                       |-- decision log      -- PostgreSQL (optional)
                                                       +-- approval queue    -> Admin API :8080
                                                                                    | HTTP / SSE
                                                                                    v
                                                                   [ Dashboard (React UI) ]
```

**このパッケージの役割**は、BFF の中で動き、各リクエストの IP・User-Agent・メソッド・ステータス・処理時間を集めて
コントロールサーバーへ gRPC で送ること。判定そのものはコントロールサーバーが行う。

- **アプリを遅くしない**: 送信は応答の後に `setImmediate` で回す Fire-and-Forget。コントロールサーバーが停止・遅延していても、アプリの応答は影響を受けない。
- **アプリを壊さない**: 送信の失敗・タイムアウト・過負荷時の破棄はすべて内部で吸収し、例外を投げない。
- **安全な既定値**: URL ではなくルートのパターンを送る。エラーメッセージやヘッダーは既定で送らない。認証トークンは送らずハッシュだけを送る。

## 最小導入ステップ (Quick Start)

**必要なのは次の 2 つだけ**。

1. **jev-argos-server** (Go): 裏でシグナルを受信・判定する制御エンジン。
2. **@jev-argos/adapter-node** (このパッケージ): あなたの Node.js BFF に挟む数行のミドルウェア。

### ステップ 1: コアサーバーを起動する

jev-argos のリポジトリのルートで:

```bash
docker build -t jev-argos/server .
docker run -d --name jev-argos -p 127.0.0.1:50051:50051 jev-argos/server

# または Go 1.24 以上で直接起動
go run ./cmd/jev-argos-server
```

gRPC のポート 50051 でシグナルを受け付ける。詳細は jev-argos リポジトリの `cmd/jev-argos-server/README.md` を参照。

### ステップ 2: インストールする

```bash
pnpm add @jev-argos/adapter-node
# または
npm i @jev-argos/adapter-node
```

> npm にはまだ公開していない。それまでは jev-argos のリポジトリでパッケージを作って入れる:
>
> ```bash
> corepack enable && pnpm install && pnpm --filter @jev-argos/adapter-node build
> (cd packages/adapter-node && npm pack)     # jev-argos-adapter-node-0.1.0.tgz ができる
> pnpm add /path/to/jev-argos/packages/adapter-node/jev-argos-adapter-node-0.1.0.tgz   # あなたのアプリで
> ```

### ステップ 3: BFF に組み込む

#### Express

```ts
import express from "express";
import { SignalReporter, createExpressMiddleware } from "@jev-argos/adapter-node";

const reporter = new SignalReporter({ target: "localhost:50051" }); // ステップ 1 のサーバー

const app = express();
app.use(createExpressMiddleware(reporter, { sourceService: "main-bff" })); // ルートより前に登録

app.get("/users/:id", (req, res) => res.json({ id: req.params.id })); // 既存のルートはそのまま
```

- クライアント IP には `req.ip` を使う。ロードバランサーの背後では `app.set("trust proxy", ...)` を設定すること。
- ルートは `/users/:id` のようなパターンで送る (URL 中の ID は送らない)。どのルートにも一致しなかったリクエストは `(unmatched)` になる。

#### Next.js (App Router)

Route Handler を `withJevArgos` で包む。

```ts
// lib/jev-argos.ts
import { SignalReporter } from "@jev-argos/adapter-node";

// 開発時のホットリロードで接続が増えないよう、プロセスで 1 つだけ作る
const g = globalThis as { jevArgosReporter?: SignalReporter };
export const reporter = (g.jevArgosReporter ??= new SignalReporter({
  target: process.env.JEV_ARGOS_TARGET ?? "localhost:50051",
}));
```

```ts
// app/api/users/[id]/route.ts
import { withJevArgos } from "@jev-argos/adapter-node";
import { reporter } from "@/lib/jev-argos";

export const runtime = "nodejs"; // gRPC は Edge Runtime では動かないため Node.js ランタイムを使う

export const GET = withJevArgos(
  reporter,
  { route: "/api/users/[id]", sourceService: "main-bff" },
  async (_req: Request, { params }: { params: Promise<{ id: string }> }) => {
    const { id } = await params;
    return Response.json({ id });
  },
);
```

- Next.js の Middleware は Edge Runtime で動き、応答のステータスも取れないため使わない。
- クライアント IP は既定で `x-forwarded-for` の先頭 (無ければ `x-real-ip`) を使う。このヘッダーはクライアントが偽装できるため、Vercel やリバースプロキシなど、ヘッダーを上書きする信頼できる基盤の背後でのみ既定のまま使うこと。それ以外は `getClientIp` で取り出し方を指定する。
- handler が例外を投げた場合は、ステータス 500 として送ったうえで例外をそのまま投げ直す。

### ステップ 4: 動作を確認する

存在しないページに 1 分間で 30 回アクセスすると、エラーの集中として検知される。

```bash
for i in $(seq 30); do curl -s -o /dev/null http://localhost:3000/no-such-page-$i; done
docker logs jev-argos 2>&1 | grep "jev-argos action"
# msg="jev-argos action" level=3 downgraded=true score=3.6 confidence=0.625 ... method="GET (unmatched)" ip_error_count_1m=30
```

アプリ側では `reporter.stats` (`{ sent, failed, dropped, inFlight }`) で送信状況を確認できる。

## その他の組み込み方

### Fastify

```ts
import Fastify from "fastify";
import { SignalReporter, reportHttp } from "@jev-argos/adapter-node";

const reporter = new SignalReporter({ target: "localhost:50051" });
const app = Fastify(); // プロキシの背後なら trustProxy を設定する

app.addHook("onResponse", async (request, reply) => {
  reportHttp(reporter, {
    method: request.method,
    route: request.routeOptions.url ?? "(unmatched)", // "/users/:id" 形式
    statusCode: reply.statusCode,
    clientIp: request.ip,
    userAgent: request.headers["user-agent"],
    latencyMs: reply.elapsedTime,
  }, { sourceService: "main-bff" });
});

app.addHook("onClose", async () => reporter.close());
```

`reportHttp` はフレームワークに依存しないので、他のフレームワークでも応答後のフックから同じように呼べる。

### gRPC (サーバー / クライアント インターセプター)

gRPC では IP・User-Agent・ステータス・レイテンシをインターセプターが自動で取得する。

```ts
import * as grpc from "@grpc/grpc-js";
import { SignalReporter, createClientInterceptor, createServerInterceptor } from "@jev-argos/adapter-node";

const reporter = new SignalReporter({ target: "localhost:50051" });

// gRPC サーバーとして RPC を受ける場合: 接続元 IP は TCP 接続から取得
const server = new grpc.Server({
  interceptors: [createServerInterceptor(reporter, { sourceService: "main-bff" })],
});

// BFF からバックエンドを呼ぶ場合: エンドユーザーの IP は、BFF が送信メタデータに載せた x-forwarded-for から取得
const userClient = new UserServiceClient("user-service:50051", grpc.credentials.createInsecure(), {
  interceptors: [
    createClientInterceptor(reporter, {
      sourceService: "main-bff",
      extractUser: (md) => ({ userId: md.get("x-user-id")[0]?.toString() }),
    }),
  ],
});
```

### Level 4 (即時遮断) の通知を受けて遮断する

シグナルは応答の後に送るため、Level 4 と判定されたリクエスト自体は止まらない。
通知を受けて、その送信元からの**以降の**リクエストを遮断する。

```ts
const blocked = new Map<string, number>(); // IP -> 遮断の期限

const reporter = new SignalReporter({
  target: "localhost:50051",
  onResponse: (res, signal) => {
    if (res.immediate_action_level >= 4) {
      blocked.set(signal.user_context.client_ip, Date.now() + 15 * 60_000); // 15 分間遮断
    }
  },
});

app.use((req, res, next) => {
  const until = blocked.get(req.ip ?? "");
  if (until && until > Date.now()) return res.status(403).end();
  next();
});
```

### 終了処理

```ts
process.on("SIGTERM", async () => {
  await reporter.close(); // 送信中のシグナルを待ってから接続を閉じる
  process.exit(0);
});
```

## 設定オプション

### `new SignalReporter(options)`

| オプション | 型 | 既定値 | 内容 |
| --- | --- | --- | --- |
| `target` | `string` | (必須) | コントロールサーバーの gRPC アドレス (例: `"localhost:50051"`, `"jev-argos:50051"`) |
| `timeoutMs` | `number` | `500` | 1 件の送信のタイムアウト (ミリ秒) |
| `maxInFlight` | `number` | `1000` | 同時に送信中にできる件数。超えた分は破棄する (アプリのメモリを守るため) |
| `credentials` | `grpc.ChannelCredentials` | 平文 | 接続の認証情報。TLS を使う場合は `grpc.credentials.createSsl()` |
| `onResponse` | `(res, signal) => void` | — | サーバーの応答 (`immediate_action_level` を含む) を受け取る |
| `onError` | `(err, signal) => void` | — | 送信失敗を受け取る (ログやメトリクス用) |
| `protoPath` | `string` | 同梱の `proto/signal.proto` | スキーマファイルの場所 |

- `reporter.stats` で `{ sent, failed, dropped, inFlight }` を取得できる。
- `reporter.close()` は新規の受付を止め、送信中のシグナルを待ってから接続を閉じる。
- コールバック内で例外が起きても無視され、アプリには伝わらない。
- このパッケージ自体は環境変数を読まない。上の例の `JEV_ARGOS_TARGET` はアプリ側の慣習。

### `createExpressMiddleware(reporter, options)` / `reportHttp(reporter, observation, options)`

| オプション | 内容 |
| --- | --- |
| `sourceService` | 送信元サービス名 (必須)。ダッシュボードや判定ログでの識別に使う |

`reportHttp` に渡す `observation`:

| フィールド | 内容 |
| --- | --- |
| `method` | HTTP メソッド |
| `route` | ルートの**パターン** (`/users/:id`)。実際の URL を渡すと ID 等の個人情報が送られ、同じ API が別々に集計される |
| `statusCode` | HTTP ステータス。gRPC のコードに変換して送る (下表) |
| `clientIp` | クライアント IP。`::ffff:1.2.3.4` 形式は `1.2.3.4` に正規化する |
| `latencyMs` | 処理時間 (ミリ秒) |
| `userAgent` / `userId` / `userRole` / `traceId` | 任意 |

### `withJevArgos(reporter, options, handler)`

| オプション | 内容 |
| --- | --- |
| `route` | ルートのパターン (例: `"/api/users/[id]"`)。必須 |
| `sourceService` | 送信元サービス名。必須 |
| `getClientIp` | `(req: Request) => string`。既定は `x-forwarded-for` の先頭 → `x-real-ip` |

### `createServerInterceptor` / `createClientInterceptor` のオプション

| オプション | 既定値 | 内容 |
| --- | --- | --- |
| `sourceService` | (必須) | 送信元サービス名 |
| `trustProxyHeaders` | `false` | (サーバー側) `x-forwarded-for` / `x-real-ip` を信頼するか。信頼できるロードバランサーの背後でのみ `true` にする |
| `extractUser` | — | メタデータから `{ userId, userRole }` を取り出す関数 |
| `includeMetadataKeys` | `[]` | `metadata_masked` に含めるキー。機密キー (authorization, cookie, token, api-key 等) の値は `***` になる |
| `sessionHashSalt` | `""` | `session_hash` (認証トークンの SHA-256) のソルト |
| `includeErrorMessage` | `false` | 失敗時のステータス詳細を送るか。個人情報を含みうるため既定では送らない |

### HTTP ステータスの変換

Jev は gRPC のステータスコードで判定するため、HTTP ステータスは次のように変換して送る。
特に **403 → `PERMISSION_DENIED`** は、権限の探索行為 (複数の API で拒否される) の検知に使われる。

| HTTP | gRPC |
| --- | --- |
| 1xx〜3xx | `OK` (0) |
| 400 | `INVALID_ARGUMENT` (3) |
| 401 | `UNAUTHENTICATED` (16) |
| 403 | `PERMISSION_DENIED` (7) |
| 404 | `NOT_FOUND` (5) |
| 408 / 504 | `DEADLINE_EXCEEDED` (4) |
| 409 | `ALREADY_EXISTS` (6) |
| 429 | `RESOURCE_EXHAUSTED` (8) |
| 501 | `UNIMPLEMENTED` (12) |
| 502 / 503 | `UNAVAILABLE` (14) |
| その他の 4xx / 5xx | `FAILED_PRECONDITION` (9) / `INTERNAL` (13) |

## 動作要件

- Node.js 20 以上
- ES Modules (`import`) のみ対応。CommonJS からは `await import("@jev-argos/adapter-node")` で読み込む。
- Next.js では Node.js ランタイムで使う (gRPC は Edge Runtime では動かない)。
- `@grpc/grpc-js` と `@grpc/proto-loader` は依存として一緒に入る。シグナルのスキーマ (`signal.proto`) はパッケージに同梱されている。

## セキュリティ上の注意

- **クライアント IP の偽装**: `x-forwarded-for` はクライアントが自由に付けられる。信頼できるプロキシの背後でない限り信頼しないこと (Express の `trust proxy`、Fastify の `trustProxy` も同様)。偽装を許すと攻撃者が判定を回避できる。
- **個人情報**: `route` には URL ではなくパターンを渡す。エラーメッセージとメタデータは既定で送らない。
- **通信の暗号化**: 既定は平文。コントロールサーバーとの間がクラスタ外を通る場合は `credentials` で TLS を使うこと。

## 開発

```bash
pnpm build   # proto/ をコピーして tsc でビルド
pnpm test    # ビルドして node --test で実行 (npm run test でも可)
```
