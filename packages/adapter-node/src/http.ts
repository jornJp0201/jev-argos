// HTTP ベースの BFF (Express / Fastify / Next.js 等) 向けのシグナル組み立て。
//
// Jev は gRPC のステータスコード体系で判定するため、HTTP ステータスを対応する gRPC コードに変換する。
// 特に 403 → PERMISSION_DENIED (7) は権限探索の検知 (unique_denied_methods_5m) に使われる。

import { randomUUID } from "node:crypto";
import type { Reporter } from "./reporter.js";
import { normalizeIp, type SecuritySignal } from "./signal.js";

export interface HttpObservation {
  /** HTTP メソッド (例: "GET")。 */
  method: string;
  /**
   * ルートのパターン (例: "/users/:id")。実際の URL ではなくパターンを渡すこと。
   * URL に含まれる ID 等の個人情報を送らず、同じ API を 1 つのメソッドとして集計するため。
   */
  route: string;
  statusCode: number;
  /** クライアント IP。プロキシの背後では、信頼できるプロキシ設定を経た値を渡すこと。 */
  clientIp: string;
  userAgent?: string | undefined;
  latencyMs: number;
  userId?: string | undefined;
  userRole?: string | undefined;
  traceId?: string | undefined;
}

export interface HttpSignalOptions {
  /** シグナルの送信元サービス名 (例: "main-bff")。 */
  sourceService: string;
}

/** HTTP ステータスを gRPC ステータスコードに変換する。 */
export function httpStatusToGrpc(status: number): number {
  if (status < 400) return 0; // OK
  switch (status) {
    case 400:
      return 3; // INVALID_ARGUMENT
    case 401:
      return 16; // UNAUTHENTICATED
    case 403:
      return 7; // PERMISSION_DENIED
    case 404:
      return 5; // NOT_FOUND
    case 408:
    case 504:
      return 4; // DEADLINE_EXCEEDED
    case 409:
      return 6; // ALREADY_EXISTS
    case 429:
      return 8; // RESOURCE_EXHAUSTED
    case 501:
      return 12; // UNIMPLEMENTED
    case 502:
    case 503:
      return 14; // UNAVAILABLE
  }
  return status < 500 ? 9 : 13; // FAILED_PRECONDITION / INTERNAL
}

/** HTTP リクエストの観測結果から SecuritySignal を組み立てる。 */
export function buildHttpSignal(obs: HttpObservation, opts: HttpSignalOptions): SecuritySignal {
  return {
    signal_id: randomUUID(),
    timestamp: new Date().toISOString(),
    source_service: opts.sourceService,
    user_context: {
      user_id: obs.userId ?? "",
      user_role: obs.userRole ?? "",
      client_ip: normalizeIp(obs.clientIp), // "::ffff:1.2.3.4" (Express の req.ip 等) → "1.2.3.4"
      user_agent: obs.userAgent ?? "",
      session_hash: "",
    },
    request_context: {
      protocol: "http",
      method: `${obs.method.toUpperCase()} ${obs.route}`,
      metadata_masked: {},
      payload_summary: "",
    },
    response_context: {
      status_code: httpStatusToGrpc(obs.statusCode),
      error_code: obs.statusCode >= 400 ? String(obs.statusCode) : "",
      error_message: "",
      latency_ms: Math.round(obs.latencyMs),
    },
    trace_id: obs.traceId ?? "",
  };
}

/** HTTP リクエストのシグナルを非同期に送る。例外は投げない (監視の失敗でアプリを止めない)。 */
export function reportHttp(reporter: Reporter, obs: HttpObservation, opts: HttpSignalOptions): void {
  try {
    reporter.report(buildHttpSignal(obs, opts));
  } catch {
    // 無視する
  }
}
