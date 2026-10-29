import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// 開発サーバーは /api をコントロールサーバーの管理 API へ中継し、その際に Bearer トークンを付与する。
// [差し替えポイント] 本番ではこの開発サーバーを使わず、ダッシュボードの前段 (nginx.conf.template や社内の
// リバースプロキシ) で管理者を認証 (SSO 等) したうえでトークンを付与すること。
// トークンはブラウザに渡さない (VITE_ 接頭辞を付けないのでクライアントのバンドルにも含まれない)。
//   JEV_ARGOS_API_URL      管理 API の URL (既定 http://127.0.0.1:8080)
//   JEV_ARGOS_ADMIN_TOKEN  管理 API のトークン (コントロールサーバーと同じ値)
export default defineConfig(({ mode }) => {
  const env = { ...loadEnv(mode, process.cwd(), "JEV_ARGOS_"), ...process.env };
  const token = env.JEV_ARGOS_ADMIN_TOKEN ?? "";
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: env.JEV_ARGOS_API_URL ?? "http://127.0.0.1:8080",
          changeOrigin: true,
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        },
      },
    },
  };
});
