// フレームワーク向けの組み込みヘルパー (Express のミドルウェア、Next.js の Route Handler ラッパー)。
// フレームワーク自体には依存しない (必要な部分だけを構造的な型で受け取る)。

import { reportHttp, type HttpSignalOptions } from "./http.js";
import type { Reporter } from "./reporter.js";

/** Express (および互換フレームワーク) のリクエストのうち、使う部分だけの型。 */
export interface ExpressLikeRequest {
  method: string;
  /** Express では `trust proxy` 設定を反映したクライアント IP。 */
  ip?: string | undefined;
  baseUrl?: string | undefined;
  /** ルーティング後に設定される一致したルート (`path` が "/users/:id" 等のパターン)。 */
  route?: { path?: unknown } | undefined;
  get(name: string): string | undefined;
}

export interface ExpressLikeResponse {
  statusCode: number;
  on(event: "finish", listener: () => void): unknown;
}

/**
 * 応答の完了後にシグナルを送る Express ミドルウェアを返す。ルートより前に `app.use()` で登録する。
 *
 *   app.use(createExpressMiddleware(reporter, { sourceService: "main-bff" }));
 *
 * クライアント IP には `req.ip` を使う。ロードバランサーの背後では Express の `trust proxy` を設定すること。
 */
export function createExpressMiddleware(reporter: Reporter, opts: HttpSignalOptions) {
  return (req: ExpressLikeRequest, res: ExpressLikeResponse, next: () => void): void => {
    const start = performance.now();
    res.on("finish", () => {
      const pattern = req.route?.path;
      reportHttp(
        reporter,
        {
          method: req.method,
          // 実際の URL ではなくルートのパターンを使う (ID 等を送らず、同じ API を 1 つとして集計するため)
          route: pattern === undefined ? "(unmatched)" : `${req.baseUrl ?? ""}${String(pattern)}`,
          statusCode: res.statusCode,
          clientIp: req.ip ?? "",
          userAgent: req.get("user-agent"),
          latencyMs: performance.now() - start,
        },
        opts,
      );
    });
    next();
  };
}

export interface RouteHandlerOptions extends HttpSignalOptions {
  /** ルートのパターン (例: "/api/users/[id]")。 */
  route: string;
  /**
   * リクエストからクライアント IP を取り出す関数。
   * 既定は x-forwarded-for の先頭 → x-real-ip。これらのヘッダーはクライアントが偽装できるため、
   * Vercel やリバースプロキシなど、ヘッダーを上書きする信頼できる基盤の背後でのみ既定のまま使うこと。
   */
  getClientIp?: ((req: Request) => string) | undefined;
}

function defaultClientIp(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || req.headers.get("x-real-ip")?.trim() || "";
}

/**
 * Next.js (App Router) の Route Handler などの `(Request) => Promise<Response>` をラップし、
 * 応答後にシグナルを送る。handler が例外を投げた場合はステータス 500 として送り、例外はそのまま投げ直す。
 *
 *   export const GET = withJevArgos(reporter, { route: "/api/users/[id]", sourceService: "main-bff" }, handler);
 */
export function withJevArgos<A extends unknown[]>(
  reporter: Reporter,
  opts: RouteHandlerOptions,
  handler: (req: Request, ...rest: A) => Response | Promise<Response>,
): (req: Request, ...rest: A) => Promise<Response> {
  const getClientIp = opts.getClientIp ?? defaultClientIp;
  return async (req, ...rest) => {
    const start = performance.now();
    let statusCode = 500;
    try {
      const res = await handler(req, ...rest);
      statusCode = res.status;
      return res;
    } finally {
      let clientIp = "";
      try {
        clientIp = getClientIp(req);
      } catch {
        // IP が取れなくても送信は続ける
      }
      reportHttp(
        reporter,
        {
          method: req.method,
          route: opts.route,
          statusCode,
          clientIp,
          userAgent: req.headers.get("user-agent") ?? undefined,
          latencyMs: performance.now() - start,
        },
        opts,
      );
    }
  };
}
