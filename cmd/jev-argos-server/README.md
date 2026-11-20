# jev-argos-server

**jev-argos のコントロールサーバー本体 (Go)。** BFF から届くシグナルの受信、Jev によるリスク判定、
Redis / PostgreSQL との連携、人間の承認キューを担う制御エンジン。

jev-argos の全体像と、Docker Compose で一式を試す手順は [ルートの README](../../README.md) を参照。

```bash
# リポジトリのルートで
docker build -t jev-argos/server .
docker run -d --name jev-argos \
  -p 127.0.0.1:50051:50051 -p 127.0.0.1:8080:8080 \
  -e JEV_ARGOS_ADMIN_TOKEN=$(openssl rand -hex 16) \
  jev-argos/server
```

## 判定のルール

判定エンジン **Jev** は、1 件のリクエストだけでなく**同じ送信元の直近の振る舞い**を合わせて採点する。

| 見ているもの | 何が疑われるか |
| --- | --- |
| 同じ IP の 1 分間のエラー数 | 総当たり・スキャン |
| 5 分間に権限エラーを受けた API の種類数 | 権限の探索 (いろいろな管理 API を試している) |
| その API の普段の処理時間に対する比 | 負荷をかける攻撃 |

「1 分間に 100 回エラーで遮断」のような固定の閾値では、低速な攻撃を見逃したり、正常なアクセスの急増を誤って遮断したりする。
複数の兆候を組み合わせることで、両者を見分けやすくしている。

採点結果は **リスクスコア S** (0.0〜4.0) と **確信度 C** (0.0〜1.0) の 2 つで、次の 4 段階に分ける。

| Level | 条件 | jev-argos の対応 |
| --- | --- | --- |
| **1** 正常 | S < 1.5 | 何もしない。大半の通信はここで終わり、LLM を呼ばない |
| **2** 不審 | 1.5 ≤ S < 2.5 | 判定ログを保存し、LLM で非同期に分析する |
| **3** 攻撃の疑い | 2.5 ≤ S < 3.5、**または** S ≥ 3.5 で C < 0.8 (格下げ) | 承認キューに「IP の一時遮断」を提案し、Slack / Webhook に通知する。管理者が承認すると遮断する |
| **4** 危険 | S ≥ 3.5 **かつ** C ≥ 0.8 | その場で `immediate_action_level = 4` を返し、送信元 IP を自動遮断して通知する。遮断はアダプターに配信され、以降のリクエストを拒否する |

- **確信度による格下げ**: S が遮断域でも C が足りなければ自動遮断せず、Level 3 として人間の判断に回す (誤遮断の防止)。
- **LLM と人間の承認**: LLM が提案した対処や、取り消せない操作 (アカウント削除など) も、管理者が承認するまで実行されない。
- **閾値**: 表の数値は実測ではなく安全側の初期値。[判定の閾値](#設定) の環境変数で変更できる。

**なぜ LLM だけで判定しないのか** — LLM は 1 件の判定に秒単位かかることが多く、全リクエストに使うとコストも大きくなる。
そこで Jev がすべてのリクエストを軽い計算で採点し (ミリ秒単位が目標。性能は未検証)、LLM は怪しいものだけを分析する。

## アーキテクチャと、このサーバーの位置

```
  Your application                                  jev-argos
  ================                                  =========

  [ Frontend ]
       | HTTP
       v
  [ Main BFF (Node.js) ]                            [ jev-argos-server (Go) ]  <== THIS SERVER
    + @jornjp/adapter-node  --- gRPC signal --->   Signal Receiver        :50051
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
| シグナル受信 | gRPC `jevargos.v1.SignalService` (`ReportSignal` / バッチ用の `StreamSignals`)、HTTP `POST /api/signals` | `pkg/receiver` |
| Sliding Window | 送信元ごとの直近の統計 (1 分間のエラー数・5 分間に権限エラーを受けた API の種類数・レイテンシの比)。メモリまたは Redis | `pkg/buffer` |
| Jev スコアリング | 統計から S と C を算出 | `pkg/classifier` |
| 安全境界ルール | S と C から Level を決め、確信度不足なら格下げ | `pkg/guardrail` |
| 遮断 | Level 4 の自動遮断と承認された遮断を遮断リストに登録し、`ControlService.WatchBlocklist` でアダプターへ配信。メモリまたは Redis | `pkg/action` |
| 承認キュー | Level 3 (Jev)・LLM の推奨・管理者の起票を承認待ちにし、承認されたら実行 (IP 遮断 / アプリの Webhook)。メモリまたは PostgreSQL | `pkg/approval`, `pkg/action` |
| LLM 分析 | Level 2 以上を非同期に分析 (Ollama / Claude)。結果を判定ログ・承認キュー・ダッシュボードへ | `pkg/llm` |
| 判定ログ | Level 2〜4 と LLM 分析を保存。PostgreSQL または SQLite。LLM 用の Safe View | `pkg/db` |
| 通知 | Level 3 以上を Slack / Webhook へ (同じ送信元は間引く) | `pkg/notify` |
| 管理 API | 承認キュー・遮断リストの操作、判定と分析のリアルタイム配信 (SSE) | `pkg/api`, `pkg/events` |

判定は RPC の中で同期的に行い (軽い計算のみ)、結果の Level を応答で返す。遮断・判定ログ・LLM 分析・通知などの後続処理は
非同期のワーカーで行うため、RPC の応答は待たされない。後続処理は処理ごとに専用のキューとワーカーを持つ (`receiver.Lane`)。
そのため、通知などの遅い処理が詰まっても、Level 4 の自動遮断は待たされず、捨てられない。

| ポート | プロトコル | 用途 |
| --- | --- | --- |
| 50051 | gRPC (平文) | シグナル受信、遮断リストの配信、gRPC ヘルスチェック |
| 8080 | HTTP | 管理 API、HTTP でのシグナル受信、`/api/healthz` |

BFF へのアダプターの組み込み方は [Node.js 版](../../packages/adapter-node/README.md) / [Go 版](../../pkg/client/README.md) を参照。

## 起動のバリエーション

Go 1.26 以上が必要。外部依存なし (インメモリ) で起動できる。

```sh
# このディレクトリで
go run .

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

すべてフラグでも環境変数でも指定できる (フラグが優先。`jev-argos-server -h` で一覧)。
環境変数は他のアプリと衝突しないよう `JEV_ARGOS_` 接頭辞を付けている。指定しなければ外部サービス無しで動く。

**基本**

| 環境変数 | 既定値 | 内容 |
| --- | --- | --- |
| `JEV_ARGOS_GRPC_ADDR` | `:50051` | gRPC の待受アドレス |
| `JEV_ARGOS_API_ADDR` | `127.0.0.1:8080` | 管理 API の待受アドレス。空文字で無効化 |
| `JEV_ARGOS_ADMIN_TOKEN` | (起動ごとに生成してログに出力) | 管理 API の Bearer トークン。本番では必ず指定する |
| `JEV_ARGOS_INGEST_TOKEN` | (無効) | HTTP でのシグナル受信 (`POST /api/signals`) の送信専用トークン。管理用とは別にする |
| `JEV_ARGOS_DEMO` | `false` | `true` で起動時に疑似シグナルを流す |

**判定の閾値** (Jev のスコア S と確信度 C から Level を決める境界。いずれも実測ではなく安全側の初期値で、運用で調整する)

| 環境変数 | 既定 | 内容 |
| --- | --- | --- |
| `JEV_ARGOS_BLOCK_SCORE` | `3.5` | この S 以上かつ確信度条件を満たすと Level 4 (自動遮断) |
| `JEV_ARGOS_BLOCK_CONFIDENCE` | `0.8` | 自動遮断に必要な確信度 C。未満なら S が遮断域でも Level 3 に格下げ (誤遮断の防止) |
| `JEV_ARGOS_LEVEL3_SCORE` | `2.5` | この S 以上で Level 3 (承認キュー) |
| `JEV_ARGOS_LEVEL2_SCORE` | `1.5` | この S 以上で Level 2 (LLM 分析) |

ライブラリとして使う場合は `guardrail.New(...)` で作って `receiver.Options.Guardrail` に渡す (環境変数と同じ既定値)。

**保存先** (指定しなければメモリ上。再起動で消え、複数インスタンスで共有されない)

| 環境変数 | 内容 |
| --- | --- |
| `JEV_ARGOS_REDIS_URL` | 統計と遮断リストを Redis で共有する (複数インスタンス構成では必須) |
| `JEV_ARGOS_POSTGRES_URL` | 判定ログ (`jev_decision_logs`) と承認キュー (`jev_actions`) を保存する。テーブルは起動時に自動作成 |
| `JEV_ARGOS_SQLITE_PATH` | 開発用: 判定ログを SQLite ファイルに保存する (PostgreSQL を指定した場合は無視) |

**遮断と実行**

| 環境変数 | 既定値 | 内容 |
| --- | --- | --- |
| `JEV_ARGOS_BLOCK_TTL` | `15m` | Level 4 の自動遮断・承認による遮断の期間 |
| `JEV_ARGOS_ACTION_WEBHOOK_URL` | (無し) | IP 遮断以外の承認されたアクション (セッション無効化・アカウント操作など) の実行を依頼する先 ([Webhook](#webhook)) |
| `JEV_ARGOS_ACTION_WEBHOOK_SECRET` | (署名なし) | 上記の Webhook の署名鍵 |

**LLM 分析** ([LLM 分析](#llm-分析))

| 環境変数 | 既定値 | 内容 |
| --- | --- | --- |
| `JEV_ARGOS_LLM_PROVIDER` | `ollama` | `ollama` / `anthropic` / `none` |
| `JEV_ARGOS_LLM_MODEL` | `qwen2.5:3b` (Ollama) / `claude-opus-5-5` (Claude) | モデル名 |
| `JEV_ARGOS_OLLAMA_URL` | `http://localhost:11434` (`OLLAMA_HOST` も読む) | Ollama の URL |
| `ANTHROPIC_API_KEY` | — | `anthropic` の場合の API キー (Anthropic の SDK が読む) |
| `JEV_ARGOS_LLM_MASK` | `auto` | IP・ユーザー ID を伏せて送るか。`auto` は外部の LLM のときだけ伏せる。`always` / `never` |
| `JEV_ARGOS_LLM_MASK_KEY` | (起動ごとに生成) | 伏せ字の仮名を作る鍵 |
| `JEV_ARGOS_LLM_HISTORY_URL` | (判定ログの DB) | LLM の文脈として履歴を読む先。分析専用のリードレプリカを指定する (設計書 6.1) |

**通知** (Level 3 以上。同じ送信元は 10 分に 1 回、Level が上がればすぐ)

| 環境変数 | 内容 |
| --- | --- |
| `JEV_ARGOS_SLACK_WEBHOOK_URL` | Slack の Incoming Webhook |
| `JEV_ARGOS_ALERT_WEBHOOK_URL` / `JEV_ARGOS_ALERT_WEBHOOK_SECRET` | 汎用 Webhook (JSON、署名付き) |
| `JEV_ARGOS_DASHBOARD_URL` | 通知に載せるダッシュボードの URL |

- Redis / PostgreSQL に起動時に接続できない場合は、エラーで終了する (設定ミスに気付けるように)。Ollama に接続できない場合は警告を出して起動を続ける。
- 起動後に Redis が停止した場合、`ReportSignal` は `UNAVAILABLE` を返す。送信側は Fire-and-Forget のため、アプリ本体には影響しない。

## LLM 分析

Level 2 以上の判定を、専用のキューで非同期に LLM へ渡す (RPC の応答や他の処理を待たせない)。

- **コスト制御**: 同じ送信元は 5 分に 1 回だけ分析する (Level が上がれば再分析)。キューが満杯なら分析を見送る。
- **結果の反映**: 判定ログ (`llm_analysis` 列)、同じ送信元の承認待ちへの添付、ダッシュボードへの配信。
  LLM が対処を推奨すると承認キューに提案される (出どころ「LLM」)。
- **安全性**: LLM の入力には攻撃者が書いた文字列 (User-Agent 等) が含まれるため、プロンプトでデータとして扱うよう指示し、
  出力は JSON Schema で検証する。LLM が推奨できる対処は取り消せる操作 (IP 遮断・セッション無効化・アカウント一時停止・縮小運転) に限り、
  対象は LLM ではなく判定結果から決める。推奨はすべて管理者の承認を経て実行される。
- **個人情報**: 外部の LLM に送る場合は IP・ユーザー ID を鍵付きハッシュの仮名に置き換える。履歴は個人情報を含まない Safe View
  (`jev_decision_logs_safe`) から読み取り専用・2 秒のタイムアウトで読む (設計書 6.1)。本番では Safe View だけを読める DB ユーザーと
  リードレプリカを用意し、`JEV_ARGOS_LLM_HISTORY_URL` に指定すること (`pkg/db/postgres.go` の SQL コメントに例)。

```bash
# Ollama (既定): モデルを取得して起動するだけ
ollama pull qwen2.5:3b
go run ./cmd/jev-argos-server

# Claude
JEV_ARGOS_LLM_PROVIDER=anthropic ANTHROPIC_API_KEY=sk-ant-... go run ./cmd/jev-argos-server
```

Claude を使う場合は、要求が安全性の分類器に断られたときに別のモデルが引き継ぐサーバー側のフォールバックを有効にしている。
他の LLM を使う場合は `pkg/llm` の `Provider` を実装する ([差し替えポイント](#差し替えポイント))。

## Webhook

承認されたアクション (`JEV_ARGOS_ACTION_WEBHOOK_URL`) と通知 (`JEV_ARGOS_ALERT_WEBHOOK_URL`) は、署名付きの JSON を POST する。

```
POST <URL>
Content-Type: application/json
X-Jev-Argos-Timestamp: <UNIX 秒>
X-Jev-Argos-Signature: sha256=<hex(HMAC-SHA256(secret, timestamp + "." + body))>

{"type": "action.approved", "action": {"action_id": "...", "proposed_action": "suspend_account", "target": "user-42", ...}}
```

受信側は署名とタイムスタンプ (再送攻撃を防ぐため 5 分以内など) を検証し、実行できたら 2xx を返す。2xx 以外は実行失敗としてダッシュボードに表示される。
Go では `pkg/webhook` の `VerifyRequest` で検証できる:

```go
http.HandleFunc("POST /jev-argos/actions", func(w http.ResponseWriter, r *http.Request) {
	body, ok := webhook.VerifyRequest(r, os.Getenv("JEV_ARGOS_ACTION_WEBHOOK_SECRET"), 5*time.Minute)
	if !ok {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var p action.WebhookPayload
	json.Unmarshal(body, &p)
	switch p.Action.ProposedAction {
	case approval.ActionRevokeSession: // アプリのセッションストアから p.Action.Target のセッションを消す
	case approval.ActionSuspendAccount: // アカウントを停止する
	}
	w.WriteHeader(http.StatusNoContent)
})
```

## API

| エンドポイント | 認証 | 内容 |
| --- | --- | --- |
| `GET /api/healthz` | なし | 死活確認 |
| `POST /api/signals`、`POST /api/signals/batch` | 送信専用トークン | HTTP (JSON) でのシグナル受信。本文は proto と同じフィールド名 |
| `GET /api/actions[?status=pending]`、`GET /api/actions/{id}` | 管理トークン | 承認キュー |
| `POST /api/actions` | 管理トークン | 管理者による起票 |
| `POST /api/actions/{id}/approve`、`/reject` | 管理トークン | 承認 (実行) / 拒否 |
| `GET /api/blocklist`、`POST /api/blocklist`、`DELETE /api/blocklist?target=...` | 管理トークン | 遮断リストの参照・手動の遮断・解除 |
| `GET /api/actions/stream`、`/api/blocklist/stream`、`/api/events/stream` | 管理トークン | 承認キュー・遮断リスト・判定と LLM 分析の SSE 配信。判定は Level 2 以上を 1 件ずつ、Level 1 は 1 秒ごとの件数 (`summary`) で送る |

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

Redis・PostgreSQL・ダッシュボードを含む一式は、ルートの `docker-compose.yml` で起動できる ([ルートの README](../../README.md#5-分で試す))。

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

複数レプリカで動かす場合は、Redis と PostgreSQL の両方を指定する。

- **統計と遮断リスト** (`JEV_ARGOS_REDIS_URL`): IP ごとの統計と遮断がレプリカ間で共有される。どのレプリカで遮断しても、
  すべてのレプリカに接続したアダプターへ配信される。インメモリのまま複数レプリカにすると、統計が分散して攻撃を見逃す。
  判定 1 回で Redis に問い合わせるのは 1 回だけ。API ごとの平常時の処理時間 (レイテンシの基準値) は各レプリカのメモリで計算し、
  5 秒ごとに Redis とすり合わせる (正常なリクエストのたびには書き込まない)。
- **承認キュー** (`JEV_ARGOS_POSTGRES_URL`): 承認待ちがレプリカ間で共有され、変更は LISTEN/NOTIFY で全レプリカの SSE に届く。
  攻撃中に同じ送信元の提案が続いても、各レプリカは送信元ごとに最初の 1 件をすぐに書き、残りは 2 秒ごとにまとめて書く。
  判定ログも 0.5 秒ごと (または 500 件ごと) にまとめて保存する。
  同じ対象への承認待ちは DB の制約で 1 件に保たれる。
- **LLM 分析の間引き**はレプリカごとに行うため、レプリカ数だけ分析の回数が増えうる。

## 差し替えポイント

自社の環境に合わせて差し替えられる箇所。コードの該当箇所には `[差し替えポイント]` のコメントを付けている。

| 何を変えるか | 場所 | 既定 |
| --- | --- | --- |
| **Jev モデル** (学習済みモデルへの置き換え) | `pkg/classifier` の `Model` | ルールベースの暫定モデル `HeuristicModel` |
| **レベルを分ける閾値** | `pkg/guardrail` の `Guardrail` (ライブラリ)、または[判定の閾値](#設定)の環境変数 | S ≥ 3.5 かつ C ≥ 0.8 で遮断、L3 2.5 / L2 1.5 |
| **LLM** (OpenAI・社内ゲートウェイ等) | `pkg/llm` の `Provider`、`components.go` の `newLLMProvider` | Ollama `qwen2.5:3b` (Claude も同梱) |
| **LLM に送る情報の伏せ方** | `pkg/llm` の `Masker` | 外部の LLM のときだけ IP・ユーザー ID を仮名化 |
| **分析の観点 (プロンプト)** | `pkg/llm` の `DefaultSystemPrompt` / `Analyzer.SystemPrompt` | 汎用のセキュリティ分析 |
| **LLM 分析の頻度・並列数** | `pkg/llm` の `Emitter` (`Cooldown` / `Workers`) | 同じ IP は 5 分に 1 回、並列 2 |
| **分析結果の配信先** (チケット起票・SIEM 等) | `pkg/llm` の `Sink` | 判定ログ・承認キュー・ダッシュボード |
| **通知先** (PagerDuty・Teams 等) | `pkg/notify` の `Notifier`、`components.go` の `newNotifiers` | Slack / 汎用 Webhook |
| **通知の文面** | `pkg/notify` の `SlackText` | 日本語の要約 |
| **承認された対処の実行方法** | `pkg/action` の `Router` / `WebhookExecutor`、`components.go` の `newExecutor` | IP 遮断 → 遮断リスト、それ以外 → アプリの Webhook |
| **アプリ固有の対処** | `pkg/approval` の `ActionType` | 7 種類 (IP 遮断・セッション無効化・縮小運転・アカウント停止 / 削除・データ削除・サービス停止) |
| **判定後の処理の追加・削除** | `components.go` の `newLanes` | ログ・自動遮断・承認キュー・判定ログ・通知・LLM (処理ごとのキューとワーカー数) |
| **統計の保存先** | `pkg/buffer` の `Buffer` | メモリ / Redis |
| **LLM 用 DB ユーザーの権限** | `pkg/db` の Safe View の定義 (SQL コメント) | — (本番で設定する) |

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
