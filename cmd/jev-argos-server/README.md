# jev-argos-server

**jev-argos のコントロールサーバー本体 (Go)。** BFF から届くシグナルの受信、Jev によるリスク判定、
Redis / PostgreSQL との連携、人間の承認キューを担う制御エンジン。

```bash
docker build -t jev-argos/server . && docker run -d -p 127.0.0.1:50051:50051 jev-argos/server
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

jev-argos では、すべてのリクエストを Jev が送信元の直近の振る舞いと合わせてミリ秒で採点し、
LLM と人間は本当に必要なものだけを見る。

| Level | 判定 | jev-argos の対応 |
| --- | --- | --- |
| **1** 正常 / 軽微 | S < 1.5 | 記録のみ。大半の通信はここで終わり、LLM を呼ばない |
| **2** 不審 | 1.5 ≤ S < 2.5 | 判定ログを保存し、LLM で非同期に深層分析 ※ |
| **3** 攻撃の疑い | 2.5 ≤ S < 3.5 | 承認キューに「IP の一時遮断」を提案し、管理者がダッシュボードで承認 / 拒否する。Slack 通知 ※ |
| **4** 危険 | S ≥ 3.5 かつ C ≥ 0.8 | ミリ秒で `immediate_action_level = 4` を返す。アプリはその送信元からの以降のリクエストを遮断できる |

S はリスクスコア (0.0〜4.0)、C は確信度 (0.0〜1.0)。S ≥ 3.5 でも C < 0.8 なら自動遮断せず、Level 3 として承認キューに回す (誤遮断の防止)。
※ LLM 深層分析と Slack 通知は未実装。

### アーキテクチャと、このサーバーの位置

```
  Your application                                  jev-argos
  ================                                  =========

  [ Frontend ]
       | HTTP
       v
  [ Main BFF (Node.js) ]                            [ jev-argos-server (Go) ]  <== THIS SERVER
    + @jev-argos/adapter-node  --- gRPC signal --->   Signal Receiver        :50051
      (middleware / interceptor)   (async, after       |
       ^                            the response)      v
       |                                             Sliding Window stats    -- Redis (optional)
       +------------ Level 4 notification ---------  Jev scoring -> Guardrail (Level 1-4)
                                                       |-- decision log      -- PostgreSQL (optional)
                                                       +-- approval queue    -> Admin API :8080
                                                                                    | HTTP / SSE
                                                                                    v
                                                                   [ Dashboard (React UI) ]
```

**このサーバーの役割**:

| 機能 | 内容 | パッケージ |
| --- | --- | --- |
| シグナル受信 | gRPC `jevargos.v1.SignalService` (`ReportSignal` / バッチ用の `StreamSignals`) | `pkg/receiver` |
| Sliding Window | 送信元ごとの直近の統計 (1 分間のエラー数・5 分間に権限エラーを受けた API の種類数・レイテンシの比)。メモリまたは Redis | `pkg/buffer` |
| Jev スコアリング | 統計から S と C を算出 | `pkg/classifier` |
| 安全境界ルール | S と C から Level を決め、確信度不足なら格下げ | `pkg/guardrail` |
| 判定ログ | Level 2〜4 を PostgreSQL に保存 | `pkg/db` |
| 承認キュー | Level 3 に「IP の一時遮断」を提案し、承認 / 拒否を記録 | `pkg/approval` |
| 管理 API | 承認キューの一覧・承認・拒否と、変更の SSE 配信 (ダッシュボード用) | `pkg/api` |

判定は RPC の中で同期的に行い (ミリ秒)、結果の Level を応答で返す。判定ログの保存や承認キューへの登録などの後続処理は
非同期のワーカーで行うため、RPC の応答は待たされない。

| ポート | プロトコル | 用途 |
| --- | --- | --- |
| 50051 | gRPC (平文) | シグナル受信、gRPC ヘルスチェック |
| 8080 | HTTP | 管理 API (承認キュー)、`/api/healthz` |

## 最小導入ステップ (Quick Start)

**必要なのは次の 2 つだけ**。Redis・PostgreSQL・ダッシュボードは後から追加できる (なくても動く)。

1. **jev-argos-server** (このサーバー): 裏でシグナルを受信・判定する制御エンジン。
2. **@jev-argos/adapter-node** (TypeScript): あなたの Node.js BFF に挟む数行のミドルウェア。

### ステップ 1: このサーバーを起動する

```bash
# リポジトリのルートでイメージをビルドして起動 (公開イメージはまだ無い)
docker build -t jev-argos/server .
docker run -d --name jev-argos -p 127.0.0.1:50051:50051 jev-argos/server

# または Go 1.24 以上で直接起動 (このディレクトリで)
go run main.go
```

### ステップ 2-3: BFF にアダプターを組み込む

```bash
pnpm add @jev-argos/adapter-node   # npm 未公開の間の入れ方は packages/adapter-node/README.md を参照
```

```ts
import { SignalReporter, createExpressMiddleware } from "@jev-argos/adapter-node";

const reporter = new SignalReporter({ target: "localhost:50051" }); // ステップ 1 のサーバー
app.use(createExpressMiddleware(reporter, { sourceService: "main-bff" })); // Express の場合
```

Next.js・Fastify・gRPC への組み込み方は `packages/adapter-node/README.md` を参照。

### ステップ 4: 動作を確認する

存在しないページに 1 分間で 30 回アクセスすると、エラーの集中として検知される (Level 2 以上はログに出る)。

```bash
for i in $(seq 30); do curl -s -o /dev/null http://localhost:3000/no-such-page-$i; done
docker logs jev-argos 2>&1 | grep "jev-argos action"
# msg="jev-argos action" level=3 downgraded=true score=3.6 confidence=0.625 ... method="GET (unmatched)" ip_error_count_1m=30
```

エラーの集中という 1 種類の兆候だけでは確信度が 0.8 に届かないため、自動遮断ではなく Level 3 (承認キュー) に回る。

## 起動のバリエーション

Go 1.24 以上が必要。外部依存なし (インメモリ) で起動できる。

```sh
# このディレクトリで
go run main.go

# リポジトリのルートから
go run ./cmd/jev-argos-server

# 疑似シグナルを流して動作確認 (管理 API が有効ならデモ後も起動し続ける)
go run ./cmd/jev-argos-server -demo

# Redis / PostgreSQL を使う本番相当の構成
JEV_ARGOS_REDIS_URL=redis://localhost:6379/0 \
JEV_ARGOS_POSTGRES_URL='postgres://jevargos:secret@localhost:5432/jevargos?sslmode=disable' \
JEV_ARGOS_ADMIN_TOKEN=$(openssl rand -hex 16) \
go run ./cmd/jev-argos-server
```

`SIGINT` / `SIGTERM` で停止する。停止時はヘルスチェックを NOT_SERVING にしてから新規の受付を止め、
処理中の RPC と後続処理のキューを処理し終えてから終了する。

## 設定

すべてフラグでも環境変数でも指定できる (フラグが優先)。
環境変数は他のアプリと衝突しないよう `JEV_ARGOS_` 接頭辞を付けている。

| 環境変数 | フラグ | 既定値 | 内容 |
| --- | --- | --- | --- |
| `JEV_ARGOS_GRPC_ADDR` | `-addr` | `:50051` | gRPC (シグナル受信) の待受アドレス |
| `JEV_ARGOS_API_ADDR` | `-api-addr` | `127.0.0.1:8080` | 管理 API の待受アドレス。空文字で無効化 |
| `JEV_ARGOS_ADMIN_TOKEN` | `-admin-token` | (起動ごとに生成してログに出力) | 管理 API の Bearer トークン。本番では必ず指定する |
| `JEV_ARGOS_REDIS_URL` | `-redis-url` | (インメモリ) | Sliding Window の統計を Redis で共有する。複数インスタンス構成では必須 |
| `JEV_ARGOS_POSTGRES_URL` | `-postgres-url` | (保存しない) | Level 2〜4 の判定ログを保存する。テーブル `jev_decision_logs` は起動時に自動作成 |
| `JEV_ARGOS_DEMO` | `-demo` | `false` | `true` で起動時に疑似シグナルを流す |

- Redis / PostgreSQL に起動時に接続できない場合は、エラーで終了する (設定ミスに気付けるように)。
- 起動後に Redis が停止した場合、`ReportSignal` は `UNAVAILABLE` を返す。送信側は Fire-and-Forget のため、アプリ本体には影響しない。
- 管理 API の待受の既定は `127.0.0.1` (同じホストからのみ)。コンテナでは `:8080` にする (Docker イメージは設定済み)。

## ヘルスチェック

| 方法 | 対象 | 用途 |
| --- | --- | --- |
| gRPC Health Checking Protocol (`grpc.health.v1.Health/Check`) | サービス名 `""` または `jevargos.v1.SignalService` | Kubernetes の `grpc` プローブ、`grpc_health_probe` |
| `GET /api/healthz` (認証不要) | 管理 API | HTTP のヘルスチェック、ロードバランサー |
| `jev-argos-server -healthcheck` | 上記 2 つ (管理 API が無効なら gRPC のみ) | シェルの無いコンテナイメージの `HEALTHCHECK` |

`-healthcheck` は同じ設定 (`JEV_ARGOS_GRPC_ADDR` / `JEV_ARGOS_API_ADDR`) で起動中のサーバーに接続し、
正常なら終了コード 0、異常なら 1 を返す。

```sh
$ jev-argos-server -healthcheck
healthy
```

ヘルスチェックはプロセスが受付可能かを見るもので、Redis / PostgreSQL の死活は含まない。

## Docker

イメージは distroless (`gcr.io/distroless/static-debian12:nonroot`) で、非 root ユーザーで動く。
`HEALTHCHECK` (`-healthcheck`) が組み込まれている。

```sh
# リポジトリのルートでビルド
docker build -t jev-argos/server .

docker run --rm \
  -p 127.0.0.1:50051:50051 -p 127.0.0.1:8080:8080 \
  -e JEV_ARGOS_ADMIN_TOKEN=$(openssl rand -hex 16) \
  jev-argos/server

docker inspect --format '{{.State.Health.Status}}' <container>   # healthy
```

Redis・PostgreSQL・ダッシュボードを含む一式は、ルートの `docker-compose.yml` で起動できる ([ルートの README](../../README.md#docker-compose-で一式を起動する))。

## Kubernetes

最小構成の例。ポートとヘルスチェックの組み合わせを示すためのもので、実際の環境に合わせて調整すること。

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: jev-argos
type: Opaque
stringData:
  admin-token: change-me                # openssl rand -hex 16 などで生成する
  postgres-url: postgres://jevargos:change-me@postgres:5432/jevargos?sslmode=require
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jev-argos-server
spec:
  replicas: 1                           # 「スケールについて」を参照
  selector:
    matchLabels: { app: jev-argos-server }
  template:
    metadata:
      labels: { app: jev-argos-server }
    spec:
      terminationGracePeriodSeconds: 30
      containers:
        - name: server
          image: registry.example.com/jev-argos/server:0.1.0
          ports:
            - { name: grpc, containerPort: 50051 }
            - { name: http, containerPort: 8080 }
          env:
            - { name: JEV_ARGOS_REDIS_URL, value: "redis://redis:6379/0" }
            - name: JEV_ARGOS_POSTGRES_URL
              valueFrom: { secretKeyRef: { name: jev-argos, key: postgres-url } }
            - name: JEV_ARGOS_ADMIN_TOKEN
              valueFrom: { secretKeyRef: { name: jev-argos, key: admin-token } }
          readinessProbe:
            grpc: { port: 50051, service: jevargos.v1.SignalService }
            periodSeconds: 5
          livenessProbe:
            httpGet: { path: /api/healthz, port: http }
            periodSeconds: 10
            failureThreshold: 3
          resources:
            requests: { cpu: 100m, memory: 128Mi }
            limits: { memory: 512Mi }
          securityContext:
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
---
apiVersion: v1
kind: Service
metadata:
  name: jev-argos-server
spec:
  selector: { app: jev-argos-server }
  ports:
    - { name: grpc, port: 50051, targetPort: grpc, appProtocol: grpc }
    - { name: http, port: 8080, targetPort: http }
```

- `grpc` プローブは Kubernetes 1.24 以上で使える。
- 管理 API (8080) は承認操作ができるため、Ingress で外部に公開する場合は前段で管理者を認証すること。

### スケールについて

- **シグナル受信と判定**は、`JEV_ARGOS_REDIS_URL` を指定すれば複数レプリカで動く (Sliding Window の統計を Redis で共有する)。
  インメモリのまま複数レプリカにすると、IP ごとの統計がレプリカに分散し、攻撃を見逃す。
- **承認待ちアクション**は現在プロセスのメモリに保持しているため、レプリカごとに別々の一覧になり、再起動で消える。
  承認機能を使う場合は当面 `replicas: 1` で運用すること。

## セキュリティ上の注意

- gRPC・管理 API ともに TLS を内蔵していない。クラスタ内のネットワークに閉じるか、サービスメッシュ (mTLS) やロードバランサーで TLS を終端すること。
- 管理 API は共有トークン方式で、承認者名は自己申告。本番ではダッシュボードの前段で管理者を認証すること。
- `JEV_ARGOS_ADMIN_TOKEN` を指定しない場合、起動ごとにトークンを生成してログに出力する (開発用)。ログが共有される環境では必ず指定すること。

## 開発

```sh
go test ./...                 # 全テスト (-race 推奨)
./scripts/gen-proto.sh        # proto/signal.proto を変更したら gen/v1 を再生成 (protoc が必要)
```

主なパッケージ: `pkg/receiver` (gRPC 受信) / `pkg/buffer` (Sliding Window) / `pkg/classifier` (Jev) /
`pkg/guardrail` (安全境界ルール) / `pkg/db` (判定ログ) / `pkg/approval` (承認待ち) / `pkg/api` (管理 API)
