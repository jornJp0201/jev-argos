# jev-argos ダッシュボード: 静的ビルドを nginx で配信し、/api をコアサーバーへ中継する。
# ビルドコンテキストはリポジトリのルート (pnpm workspace のため)。
FROM node:22-alpine AS build
WORKDIR /repo
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages/dashboard/package.json packages/dashboard/
RUN pnpm install --frozen-lockfile --filter dashboard
COPY packages/dashboard packages/dashboard
RUN pnpm --filter dashboard run build

FROM nginx:1.27-alpine
# /etc/nginx/templates/*.template は起動時に環境変数が展開される (nginx 公式イメージの機能)
COPY packages/dashboard/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /repo/packages/dashboard/dist /usr/share/nginx/html
EXPOSE 8080
