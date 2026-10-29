// SecuritySignal (proto/signal.proto) の組み立て。
// フィールド名は proto と同じ snake_case (proto-loader の keepCase: true で読み込む)。

import { createHash, randomUUID } from "node:crypto";
import type { Metadata } from "@grpc/grpc-js";

export interface UserContext {
  user_id: string;
  user_role: string;
  client_ip: string;
  user_agent: string;
  session_hash: string;
}

export interface RequestContext {
  protocol: "grpc" | "http";
  method: string;
  metadata_masked: Record<string, string>;
  payload_summary: string;
}

export interface ResponseContext {
  status_code: number;
  error_code: string;
  error_message: string;
  latency_ms: number;
}

export interface SecuritySignal {
  signal_id: string;
  timestamp: string;
  source_service: string;
  user_context: UserContext;
  request_context: RequestContext;
  response_context: ResponseContext;
  trace_id: string;
}

export interface ReportResponse {
  accepted: boolean;
  immediate_action_level: number;
}

/**
 * メタデータから利用者情報を取り出す関数。
 * [差し替えポイント] 認証方式はアプリごとに異なるため利用側で指定する (例: 認証済みのメタデータ x-user-id、JWT の sub)。
 */
export type UserExtractor = (metadata: Metadata) => { userId?: string | undefined; userRole?: string | undefined } | undefined;

export interface SignalOptions {
  /** シグナルの送信元サービス名 (例: "main-bff")。 */
  sourceService: string;
  /**
   * x-forwarded-for / x-real-ip を信頼してクライアント IP とするか (既定 false)。
   * 信頼できるプロキシ (ロードバランサー等) の背後にある場合のみ true にすること。
   * 直接公開されたサーバーで true にすると、攻撃者がヘッダーで IP を偽装し判定を回避できる。
   */
  trustProxyHeaders?: boolean;
  /** metadata_masked に含めるメタデータキー (既定: なし)。機密キーは値をマスクする。 */
  includeMetadataKeys?: readonly string[];
  /** user_id / user_role の取り出し方。 */
  extractUser?: UserExtractor;
  /** session_hash 計算時のソルト。設定するとハッシュから元トークンの総当たり照合を困難にできる。 */
  sessionHashSalt?: string;
  /**
   * 失敗時のステータス詳細を error_message として送るか (既定 false)。
   * 詳細メッセージには PII が含まれうるため、マスク済みであることを確認してから有効にすること。
   */
  includeErrorMessage?: boolean;
}

const SENSITIVE_KEY = /authorization|cookie|token|secret|password|api[-_]?key/i;
const MASK = "***";
const TRACE_KEYS = ["x-trace-id", "x-request-id", "traceparent"];

/** メタデータの最初の文字列値を返す。 */
export function firstValue(metadata: Metadata, key: string): string | undefined {
  const v = metadata.get(key)[0];
  return typeof v === "string" ? v : undefined;
}

/** 接続元アドレスを正規化する (IPv4-mapped IPv6 "::ffff:1.2.3.4" → "1.2.3.4")。 */
export function normalizeIp(address: string | undefined): string {
  if (!address) return "";
  const ip = address.trim();
  return ip.startsWith("::ffff:") && ip.includes(".") ? ip.slice("::ffff:".length) : ip;
}

/** クライアント IP を決める。trustProxyHeaders なら x-forwarded-for の先頭、x-real-ip の順に優先する。 */
export function resolveClientIp(metadata: Metadata, connectionIp: string, trustProxyHeaders = false): string {
  if (trustProxyHeaders) {
    const forwarded = firstValue(metadata, "x-forwarded-for")?.split(",")[0]?.trim();
    if (forwarded) return normalizeIp(forwarded);
    const real = firstValue(metadata, "x-real-ip")?.trim();
    if (real) return normalizeIp(real);
  }
  return connectionIp;
}

/** 選択したメタデータキーを、機密値をマスクして返す。 */
export function maskMetadata(metadata: Metadata, keys: readonly string[] = []): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of keys) {
    const k = key.toLowerCase();
    if (k.endsWith("-bin")) continue; // バイナリ値は送らない
    const v = firstValue(metadata, k);
    if (v !== undefined) out[k] = SENSITIVE_KEY.test(k) ? MASK : v;
  }
  return out;
}

/** 認証トークンを難読化したハッシュ (同一セッションの紐付け用。トークン自体は送らない)。 */
export function sessionHash(metadata: Metadata, salt = ""): string {
  const token = firstValue(metadata, "authorization") ?? firstValue(metadata, "cookie");
  if (!token) return "";
  return createHash("sha256").update(salt).update(token).digest("hex").slice(0, 32);
}

export interface CallObservation {
  method: string;
  /** リクエストのメタデータ (受信側では受信メタデータ、送信側では送信メタデータ)。 */
  metadata: Metadata;
  /** 接続元 IP (受信側のみ。送信側では空文字)。 */
  connectionIp: string;
  statusCode: number;
  errorMessage: string;
  latencyMs: number;
}

/** 1 回の RPC の観測結果から SecuritySignal を組み立てる。 */
export function buildSignal(obs: CallObservation, opts: SignalOptions): SecuritySignal {
  const user = opts.extractUser?.(obs.metadata);
  return {
    signal_id: randomUUID(),
    timestamp: new Date().toISOString(),
    source_service: opts.sourceService,
    user_context: {
      user_id: user?.userId ?? "",
      user_role: user?.userRole ?? "",
      client_ip: resolveClientIp(obs.metadata, obs.connectionIp, opts.trustProxyHeaders),
      user_agent: firstValue(obs.metadata, "user-agent") ?? "",
      session_hash: sessionHash(obs.metadata, opts.sessionHashSalt),
    },
    request_context: {
      protocol: "grpc",
      method: obs.method,
      metadata_masked: maskMetadata(obs.metadata, opts.includeMetadataKeys),
      payload_summary: "",
    },
    response_context: {
      status_code: obs.statusCode,
      error_code: "",
      error_message: opts.includeErrorMessage && obs.statusCode !== 0 ? obs.errorMessage.slice(0, 256) : "",
      latency_ms: Math.round(obs.latencyMs),
    },
    trace_id: TRACE_KEYS.map((k) => firstValue(obs.metadata, k)).find((v) => v) ?? "",
  };
}
