# dashboard

jev-argos のコントロール用ダッシュボード (Vite + React + TypeScript + Tailwind CSS + lucide-react)。

- **Overview**: 直近 5 分のリクエスト数・Level 3 アラート数 (うち 4→3 格下げ数)・Level 4 遮断数・平均 Jev スコアと、直近 60 秒のレベル別タイムライン
- **承認待ちアラート / 遮断中**: 承認キューと遮断リスト (下記)
- **Signal Stream**: レベル別カラーバッジ・IP・メソッド・ステータス・スコア・確信度 (0.8 の境界線付き) の一覧。レベル / IP / メソッドで絞り込み、一時停止が可能
- **詳細分析ビュー**: スコア (0.0〜4.0 とレベル境界)、安全境界ルールの判定過程、Sliding Window 特徴量、LLM 要因解析 (要約・根拠・推奨対応・使った LLM)

## データソース

シグナル一覧・概況・LLM 分析は、コントロールサーバーの `GET /api/events/stream` (SSE) から受け取る
(接続直後に直近 500 件の判定と分析が送られ、以降はリアルタイムに届く)。

サーバー無しで画面だけ確認する場合は、ブラウザ内のシミュレーターで動かせる (画面右上に「デモデータ」と表示):

```sh
VITE_JEV_ARGOS_DEMO=true pnpm --filter dashboard dev
```

[差し替えポイント] 独自の配信基盤を使う場合は `DataSource` インターフェース (`src/types.ts`) を実装し、
`src/App.tsx` の `source` を差し替える。

## 遮断中の一覧

Level 4 の自動遮断・承認による遮断・手動の遮断を表示し、解除や手動の遮断ができる
(`/api/blocklist`、変更は `/api/blocklist/stream` で即時に反映)。

## 承認待ちアラート (Human-in-the-Loop)

「承認待ちアラート」はコントロールサーバーの管理 API (`/api/actions`) のデータを表示する。
提案の出どころは 3 つ: Jev (Level 3 の判定 → IP の一時遮断)、LLM (分析で推奨された対処)、管理者 (「起票」ボタン)。
承認すると実行され (IP 遮断は遮断リストへ、それ以外はアプリの Webhook へ)、実行結果も表示される。
取り消せない操作 (アカウント削除・データ削除・サービス停止) は、対象を入力しないと承認できない。
変更は SSE (`/api/actions/stream`) で配信され、他の管理者の決定も即座に反映される。

管理 API はトークン認証が必須。開発サーバーのプロキシがトークンを付与するため、ブラウザにトークンは渡らない。

```sh
# 1. コントロールサーバー (gRPC :50051 + 管理 API 127.0.0.1:8080)。-demo で承認待ちを発生させる
export JEV_ARGOS_ADMIN_TOKEN=$(openssl rand -hex 16)
go run ./cmd/jev-argos-server -demo

# 2. 同じ JEV_ARGOS_ADMIN_TOKEN を設定してダッシュボードを起動
pnpm --filter dashboard dev
```

本番ではダッシュボードの前段 (リバースプロキシ等) で管理者を認証し、トークンを付与すること。

## 開発

```sh
pnpm --filter dashboard dev     # http://localhost:5173
pnpm --filter dashboard build   # 型チェック + 本番ビルド
```
