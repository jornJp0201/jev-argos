# pkg/client

**jev-argos の Go 用アダプター。** Go の BFF / バックエンド (net/http・gRPC) に組み込み、リクエストの情報を判定サーバーへ非同期に送り、遮断中の送信元を拒否する。
jev-argos の全体像は [ルートの README](../../README.md) を参照。

```bash
go get github.com/jornJp0201/jev-argos/pkg/client
```

## 組み込み方

```go
import "github.com/jornJp0201/jev-argos/pkg/client"

conn, _ := grpc.NewClient("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
reporter := client.NewReporter(conn, client.ReporterOptions{})  // リクエストの情報を送る
blocklist := client.NewBlocklistWatcher(ctx, conn, nil)        // 遮断中の IP を受け取る (遮断しないなら不要)
opts := client.Options{SourceService: "main-bff", Blocklist: blocklist}

http.ListenAndServe(":8080", client.Middleware(reporter, opts)(mux))                      // net/http
grpc.NewServer(grpc.ChainUnaryInterceptor(client.UnaryServerInterceptor(reporter, opts))) // gRPC
```

- 送信はすべてバックグラウンドで行い、失敗してもアプリの処理には影響しない (Fire-and-Forget)。
- `BlocklistWatcher` は遮断リストの手元のコピーを見るだけなので、リクエストごとの通信は発生しない。接続が切れても自動で再接続する。
- HTTP のルートは Go 1.22+ の ServeMux が設定する `r.Pattern` を送る (URL 中の ID は送らない)。どのルートにも一致しなかったリクエストは `(unmatched)` になる。

## 差し替えポイント

| 何を変えるか | 場所 | 既定 |
| --- | --- | --- |
| ユーザー ID の取り出し方 (認証方式に合わせる) | `client.Options.UserID` | 送らない |
| ルートのパターンの取り出し方 (chi 等) | `client.Options.Route` | ServeMux の `r.Pattern` |
| 遮断したリクエストへの応答 | `client.Options.OnBlocked` | 403 `{"error":"forbidden"}` |
| 判定サーバーとの通信の暗号化 | `grpc.NewClient` の認証情報 | 平文 (クラスタ外を通る場合は TLS にする) |
