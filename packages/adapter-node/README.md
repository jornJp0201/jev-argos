# @jev-argos/adapter-node

Node.js (BFF / gRPC サービス) から jev-argos コントロールサーバーへ、RPC ごとのセキュリティシグナルを送るアダプター。

送信は `setImmediate` でバックグラウンドに回す Fire-and-Forget 方式で、アプリの応答を待たせません。
コントロールサーバーが停止・遅延していても、アプリの RPC は影響を受けません。

## 使い方

```ts
import * as grpc from "@grpc/grpc-js";
import { SignalReporter, createServerInterceptor, createClientInterceptor } from "@jev-argos/adapter-node";

const reporter = new SignalReporter({
  target: "jev-argos:50051",
  onResponse: (res, signal) => {
    if (res.immediate_action_level >= 4) {
      // 例: 送信元 IP を一時遮断リストに追加する
    }
  },
});

// gRPC サーバー側 (受信した RPC を監視)
const server = new grpc.Server({
  interceptors: [createServerInterceptor(reporter, { sourceService: "main-bff" })],
});

// gRPC クライアント側 (BFF → バックエンドの呼び出しを監視)
// エンドユーザーの IP は、送信メタデータの x-forwarded-for から取得する
const client = new UserServiceClient(target, creds, {
  interceptors: [createClientInterceptor(reporter, { sourceService: "main-bff" })],
});

// 終了時: 送信中のシグナルを待ってから接続を閉じる
await reporter.close();
```

## 主なオプション (`SignalOptions`)

| オプション | 既定 | 内容 |
| --- | --- | --- |
| `sourceService` | (必須) | 送信元サービス名 |
| `trustProxyHeaders` | `false` | サーバー側で `x-forwarded-for` / `x-real-ip` を信頼するか。信頼できるロードバランサーの背後でのみ `true` にする (IP 偽装対策) |
| `extractUser` | なし | メタデータから `user_id` / `user_role` を取り出す関数 |
| `includeMetadataKeys` | `[]` | `metadata_masked` に含めるキー。機密キー (authorization, cookie, token 等) の値は `***` になる |
| `sessionHashSalt` | `""` | `session_hash` (認証トークンの SHA-256) のソルト |
| `includeErrorMessage` | `false` | 失敗時のステータス詳細を送るか。PII を含みうるため既定は送らない |

## 開発

```sh
pnpm build   # proto/ をコピーして tsc でビルド
pnpm test    # ビルドして node --test で実行 (npm run test でも可)
```
