# dashboard

jev-argos のコントロール用ダッシュボード (Vite + React + TypeScript + Tailwind CSS + lucide-react)。

- **Overview**: 直近 5 分のリクエスト数・Level 3 アラート数 (うち 4→3 格下げ数)・Level 4 遮断数・平均 Jev スコアと、直近 60 秒のレベル別タイムライン
- **Signal Stream**: レベル別カラーバッジ・IP・メソッド・ステータス・スコア・確信度 (0.8 の境界線付き) の一覧。レベル / IP / メソッドで絞り込み、一時停止が可能
- **詳細分析ビュー**: スコア (0.0〜4.0 とレベル境界)、安全境界ルールの判定過程、Sliding Window 特徴量、LLM 要因解析

## データソース

コントロールサーバーにはまだ読み出し API が無いため、現在は `src/data/demoSource.ts` のシミュレーターで動作する
(画面右上に「デモデータ」と表示)。シミュレーターはサーバーと同じ集計ルールと判定ルールで疑似シグナルを評価する。
LLM 解析もモック文面 (「モック (LLM 未接続)」と表示) である。

API ができたら `DataSource` インターフェース (`src/types.ts`) を実装し、`src/App.tsx` の `source` を差し替える。

## 承認待ちアラート (Human-in-the-Loop)

「承認待ちアラート」はコントロールサーバーの管理 API (`/api/actions`) の実データを表示する。
確信度不足で自動遮断を保留した判定 (Level 3) ごとに IP 一時遮断が提案され、管理者が承認 / 拒否する。
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
