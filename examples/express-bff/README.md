# examples/express-bff (テスト用 BFF)

> **これはテスト・デモ用の BFF です。本番では使わないでください。**
> 認証・データはすべてダミーで、`x-user-id` ヘッダーで誰にでもなりすませます。
> jev-argos の動作確認と、「アプリにどう組み込むか」の実例を示すためだけに置いています。

`@jornjp/adapter-node` を組み込んだ Express アプリです。
このアプリへのリクエストが jev-argos に送られて判定され、Level 4 で遮断された送信元は以降 `403 {"error":"forbidden"}` で弾かれます。

```
  curl (正常なユーザー / 攻撃者)
        |  HTTP :4000
        v
  [ examples/express-bff ]  --- シグナル (gRPC) --->  [ jev-argos-server :50051 ]  ---> ダッシュボード :3000
    + @jornjp/adapter-node  <--- 遮断リストの配信 ---
```

## jev-argos の組み込み箇所

`server.js` のうち、jev-argos に関係するのは次の 3 か所だけです (コメントの「jev-argos の組み込み (1/3)」〜「(3/3)」)。

1. `SignalReporter` (シグナルの送信) と `BlocklistWatcher` (遮断リストの購読) を作る
2. ルートより前に `app.use(createExpressMiddleware(reporter, { sourceService, blocklist }))` を登録する
3. 終了時に `reporter.close()` で送信中のシグナルを送り切る

## 起動

リポジトリのルートで実行します。jev-argos-server が先に起動している必要があります (README の「付属: Web ダッシュボード」の Docker Compose で起動できます)。

```bash
corepack pnpm install
corepack pnpm --filter @jornjp/adapter-node build
node examples/express-bff/server.js        # http://localhost:4000
```

| 環境変数 | 既定 | 内容 |
| --- | --- | --- |
| `PORT` | `4000` | このアプリのポート |
| `JEV_ARGOS_TARGET` | `localhost:50051` | jev-argos-server の gRPC アドレス |
| `TRUST_PROXY` | `true` | `X-Forwarded-For` を信頼するか (下記) |

## API (すべてダミー)

| API | 内容 |
| --- | --- |
| `GET /api/health` | 稼働確認 |
| `POST /api/login` | `{"id":"bob","password":"bob-pass"}`。間違えると 401 |
| `GET /api/me`、`GET /api/orders/:id` | ログインが必要 (`x-user-id: bob`) |
| `GET /api/products` | 誰でも見られる |
| `/api/admin/*` (users、audit-logs、settings、export、`DELETE users/:id`) | 管理者 (`x-user-id: alice`) 専用。一般ユーザーは 403 |

## 試す

1 台のマシンから複数の送信元を再現するため、テスト用に `X-Forwarded-For` を信頼する設定にしています (`TRUST_PROXY=false` で無効)。
本番で同じ設定にすると、攻撃者がヘッダーで IP を偽装できてしまう点に注意してください。

```bash
# 正常なユーザー
curl -s localhost:4000/api/me -H 'x-user-id: bob' -H 'X-Forwarded-For: 192.0.2.10'

# 攻撃: 一般ユーザーが管理者 API を総当たりする (権限探索)
for i in $(seq 6); do
  for p in users audit-logs settings; do
    curl -s -o /dev/null -w '%{http_code}\n' localhost:4000/api/admin/$p -H 'x-user-id: bob' -H 'X-Forwarded-For: 203.0.113.50'
  done
  curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:4000/api/admin/export -H 'x-user-id: bob' -H 'X-Forwarded-For: 203.0.113.50'
  curl -s -o /dev/null -w '%{http_code}\n' -X DELETE localhost:4000/api/admin/users/alice -H 'x-user-id: bob' -H 'X-Forwarded-For: 203.0.113.50'
done

# 遮断の確認: 攻撃者は正しいリクエストでも 403 {"error":"forbidden"}、他のユーザーはそのまま使える
curl -s localhost:4000/api/products -H 'X-Forwarded-For: 203.0.113.50'
curl -s localhost:4000/api/products -H 'X-Forwarded-For: 192.0.2.10'
```

ダッシュボード (http://localhost:3000) には、判定の Level・LLM の分析・承認待ちの提案・遮断リストが表示されます。
