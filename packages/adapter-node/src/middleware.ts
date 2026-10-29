// フレームワーク向けの組み込みヘルパー (Express のミドルウェア、Next.js の Route Handler ラッパー)。
// フレームワーク自体には依存しない (必要な部分だけを構造的な型で受け取る)。

import type { BlockChecker } from "./blocklist.js";
import { reportHttp, type HttpSignalOptions } from "./http.js";
import type { Reporter } from "./reporter.js";
import { normalizeIp } from "./signal.js";

const BLOCKED_BODY = JSON.stringify({ error: "forbidden" });

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
  setHeader(name: string, value: string): unknown;
  end(chunk: string): unknown;
}

export interface ExpressMiddlewareOptions extends HttpSignalOptions {
  /**
   * 遮断リスト (通常は BlocklistWatcher)。指定すると、遮断中の IP からのリクエストを 403 で拒否する
   * (Level 4 の自動遮断と、管理者が承認した遮断)。
   */
  blocklist?: BlockChecker | undefined;
  /**
   * [差し替えポイント] 遮断したリクエストへの応答。既定は 403 と {"error":"forbidden"}。
   * 独自のエラーページやエラー形式を返す場合に指定する。
   */
  onBlocked?: ((req: ExpressLikeRequest, res: ExpressLikeResponse) => void) | undefined;
}

/**
 * 応答の完了後にシグナルを送る Express ミドルウェアを返す。ルートより前に `app.use()` で登録する。
 *
 *   app.use(createExpressMiddleware(reporter, { sourceService: "main-bff" }));
 *
 * クライアント IP には `req.ip` を使う。ロードバランサーの背後では Express の `trust proxy` を設定すること。
 */
export function createExpressMiddleware(reporter: Reporter, opts: ExpressMiddlewareOptions) {
  return (req: ExpressLikeRequest, res: ExpressLikeResponse, next: () => void): void => {
    const start = performance.now();
    const blocked = opts.blocklist?.isBlocked(normalizeIp(req.ip)) ?? false;
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
    if (blocked) {
      // 遮断中の送信元: ルートの処理に進ませない (このリクエストもシグナルとして送る)
      if (opts.onBlocked) {
        opts.onBlocked(req, res);
      } else {
        res.statusCode = 403;
        res.setHeader("Content-Type", "application/json");
        res.end(BLOCKED_BODY);
      }
      return;
    }
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
  /** 遮断リスト (通常は BlocklistWatcher)。指定すると、遮断中の IP からのリクエストを 403 で拒否する。 */
  blocklist?: BlockChecker | undefined;
  /** [差し替えポイント] 遮断したリクエストへの応答。既定は 403 と {"error":"forbidden"}。 */
  onBlocked?: ((req: Request) => Response) | undefined;
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
    let clientIp = "";
    try {
      clientIp = getClientIp(req);
    } catch {
      // IP が取れなくても処理と送信は続ける
    }
    let statusCode = 500;
    try {
      if (opts.blocklist?.isBlocked(normalizeIp(clientIp))) {
        const res =
          opts.onBlocked?.(req) ??
          new Response(BLOCKED_BODY, { status: 403, headers: { "Content-Type": "application/json" } });
        statusCode = res.status;
        return res;
      }
      const res = await handler(req, ...rest);
      statusCode = res.status;
      return res;
    } finally {
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
