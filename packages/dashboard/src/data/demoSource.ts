// デモ用データソース: 通常トラフィックに攻撃キャンペーンを混ぜた疑似シグナルを生成し、
// サーバーと同じ集計 (Sliding Window) と判定ルールで評価する。
// LLM 解析は未接続のため、特徴量から組み立てたモック文面を返す。

import { decide, evaluate } from "../lib/jev";
import type { DataSource, DecisionEvent, Features, LlmAnalysis, SecuritySignal } from "../types";

const TICK_MS = 300;

const NORMAL_METHODS = [
  "/user.UserService/GetUser",
  "/user.UserService/UpdateProfile",
  "/order.OrderService/ListOrders",
  "/order.OrderService/Create",
  "/catalog.CatalogService/Search",
  "/payment.PaymentService/Authorize",
];
const ADMIN_METHODS = [
  "/admin.AdminService/ListUsers",
  "/admin.AdminService/UpdateRole",
  "/admin.AdminService/ExportBilling",
  "/admin.AdminService/ReadAuditLog",
  "/admin.AdminService/RotateKeys",
  "/admin.AdminService/DeleteUser",
];
const USER_AGENTS = [
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148",
];
const BASE_LATENCY: Record<string, number> = {};
[...NORMAL_METHODS, ...ADMIN_METHODS].forEach((m, i) => (BASE_LATENCY[m] = 18 + ((i * 37) % 90)));

type CampaignKind = "probe" | "burst" | "slow";
interface Campaign {
  kind: CampaignKind;
  ip: string;
  userAgent: string;
  endsAt: number;
}

const rand = (n: number) => Math.floor(Math.random() * n);
const pick = <T,>(xs: readonly T[]): T => xs[rand(xs.length)]!;
const normalIps = Array.from({ length: 24 }, (_, i) => `192.0.2.${10 + i * 7}`);

class Windows {
  private errors = new Map<string, number[]>();
  private denied = new Map<string, Map<string, number>>();
  private latency = new Map<string, number>();

  observe(s: SecuritySignal, now: number): Features {
    const ip = s.user_context.client_ip;
    const method = s.request_context.method;
    const { status_code: code, latency_ms } = s.response_context;

    const baseline = this.latency.get(method);
    const ratio = baseline ? latency_ms / baseline : 1;
    if (code === 0) this.latency.set(method, baseline ? baseline + 0.1 * (latency_ms - baseline) : latency_ms);

    const errs = (this.errors.get(ip) ?? []).filter((t) => t > now - 300_000);
    if (code !== 0) errs.push(now);
    this.errors.set(ip, errs);

    const den = this.denied.get(ip) ?? new Map<string, number>();
    if (code === 7) den.set(method, now);
    for (const [m, t] of den) if (t <= now - 300_000) den.delete(m);
    this.denied.set(ip, den);

    return {
      ip_error_count_1m: errs.filter((t) => t > now - 60_000).length,
      unique_denied_methods_5m: den.size,
      latency_spike_ratio: ratio,
    };
  }
}

function mockAnalysis(e: DecisionEvent): LlmAnalysis {
  const f = e.features;
  const ip = e.signal.user_context.client_ip;
  const factors: string[] = [];
  if (f.unique_denied_methods_5m >= 3)
    factors.push(`5 分間に ${f.unique_denied_methods_5m} 種類の API で PERMISSION_DENIED。権限境界の探索 (フットプリンティング) の可能性`);
  if (f.ip_error_count_1m >= 10) factors.push(`同一 IP から 1 分間に ${f.ip_error_count_1m} 件の異常応答`);
  if (f.latency_spike_ratio >= 2)
    factors.push(`レイテンシが平常時の ${f.latency_spike_ratio.toFixed(1)} 倍。リソース枯渇系の負荷の可能性`);
  if (factors.length === 0) factors.push("単発の異常。現時点で攻撃パターンとの一致は弱い");

  const probing = f.unique_denied_methods_5m >= 3;
  const summary = probing
    ? `${ip} は管理系 API を順に試行しており、権限昇格を狙った探索行為と推定されます。`
    : f.latency_spike_ratio >= 2
      ? `${e.signal.request_context.method} の応答遅延が急上昇しています。高負荷リクエストの集中が疑われます。`
      : `${ip} からのエラーが集中しています。クライアントの不具合と攻撃の両面で確認が必要です。`;
  const recommendation =
    e.level === 4
      ? "自動遮断を継続。遮断期間終了後の再発を監視してください。"
      : e.downgraded
        ? "スコアは遮断域ですが確信度不足のため自動遮断していません。ログを確認のうえ、必要なら手動で遮断を承認してください。"
        : e.level === 3
          ? "担当者による確認を推奨します。同一ユーザーの他セッションも確認してください。"
          : "経過観察。スコアが上昇した場合は再解析します。";
  return { status: "done", model: "mock", summary, factors, recommendation };
}

export class DemoDataSource implements DataSource {
  readonly label = "デモデータ (シミュレーター)";
  readonly isDemo = true;

  subscribe(handlers: Parameters<DataSource["subscribe"]>[0]): () => void {
    const windows = new Windows();
    const campaigns: Campaign[] = [];
    const timers = new Set<ReturnType<typeof setTimeout>>();
    let seq = 0;
    let nextCampaignAt = Date.now() + 3_000;

    const emit = (ip: string, ua: string, method: string, code: number, latency: number) => {
      const now = Date.now();
      seq++;
      const signal: SecuritySignal = {
        signal_id: crypto.randomUUID(),
        timestamp: new Date(now).toISOString(),
        source_service: method.startsWith("/admin") ? "admin-bff" : "main-bff",
        trace_id: `trace-${seq.toString(16).padStart(6, "0")}`,
        user_context: { user_id: `user-${(ip.split(".").pop() ?? "0").padStart(3, "0")}`, user_role: "user", client_ip: ip, user_agent: ua },
        request_context: { protocol: "grpc", method },
        response_context: { status_code: code, latency_ms: Math.round(latency) },
      };
      const features = windows.observe(signal, now);
      const { score, confidence } = evaluate(features);
      const event: DecisionEvent = { signal, features, score, confidence, ...decide(score, confidence) };
      if (event.level >= 2) {
        event.llm = { status: "pending" };
        const t = setTimeout(() => {
          timers.delete(t);
          handlers.onLlmUpdate(signal.signal_id, mockAnalysis(event));
        }, 1_200 + rand(1_800));
        timers.add(t);
      }
      handlers.onEvent(event);
    };

    const tick = () => {
      const now = Date.now();
      // 通常トラフィック
      for (let i = 0, n = 2 + rand(4); i < n; i++) {
        const method = pick(NORMAL_METHODS);
        const r = Math.random();
        const code = r < 0.03 ? 5 : r < 0.05 ? 3 : r < 0.055 ? 16 : 0;
        emit(pick(normalIps), pick(USER_AGENTS), method, code, BASE_LATENCY[method]! * (0.7 + Math.random() * 0.6));
      }
      // 攻撃キャンペーン
      if (now >= nextCampaignAt) {
        const kind = pick<CampaignKind>(["probe", "probe", "burst", "slow"]);
        campaigns.push({
          kind,
          ip: `203.0.113.${1 + rand(250)}`,
          userAgent: kind === "probe" ? "python-requests/2.32.3" : pick(USER_AGENTS),
          endsAt: now + 8_000 + rand(6_000),
        });
        nextCampaignAt = now + 12_000 + rand(10_000);
      }
      for (let i = campaigns.length - 1; i >= 0; i--) {
        const c = campaigns[i]!;
        if (now > c.endsAt) {
          campaigns.splice(i, 1);
          continue;
        }
        if (c.kind === "probe") {
          const method = pick(ADMIN_METHODS);
          emit(c.ip, c.userAgent, method, 7, BASE_LATENCY[method]! * 0.5);
        } else if (c.kind === "burst") {
          emit(c.ip, c.userAgent, "/order.OrderService/Create", Math.random() < 0.8 ? 13 : 3, 40 + rand(30));
        } else {
          const method = "/catalog.CatalogService/Search";
          emit(c.ip, c.userAgent, method, 0, BASE_LATENCY[method]! * (4 + Math.random() * 4));
        }
      }
    };

    const interval = setInterval(tick, TICK_MS);
    return () => {
      clearInterval(interval);
      timers.forEach(clearTimeout);
    };
  }
}
