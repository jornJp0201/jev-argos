// 管理 API (Go: pkg/api) の承認待ちアクション。
// 認証ヘッダーは開発サーバーのプロキシ (vite.config.ts) または本番のリバースプロキシが付与する。

export type ActionStatus = "pending" | "approved" | "rejected";

export interface ActionEvidence {
  score: number;
  confidence: number;
  level: number;
  downgraded: boolean;
  ip_error_count_1m: number;
  unique_denied_methods_5m: number;
  latency_spike_ratio: number;
  client_ip: string;
  user_id: string;
  method: string;
  source_service: string;
  signal_timestamp: string;
}

export interface PendingAction {
  action_id: string;
  signal_id: string;
  proposed_action: "block_ip" | string;
  target: string;
  reason: string;
  status: ActionStatus;
  evidence: ActionEvidence;
  event_count: number;
  created_at: string;
  updated_at: string;
  decided_at?: string;
  decided_by?: string;
  decision_note?: string;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    /** 409 (他の管理者が決定済み) のときの最新状態。 */
    readonly action?: PendingAction,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, headers: { "Content-Type": "application/json", ...init?.headers } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg =
      res.status === 401
        ? "管理 API の認証に失敗しました (JEV_ARGOS_ADMIN_TOKEN を確認してください)"
        : (body as { error?: string }).error ?? `HTTP ${res.status}`;
    throw new ApiError(res.status, msg, (body as { action?: PendingAction }).action);
  }
  return body as T;
}

export const actionsApi = {
  list: () => request<{ actions: PendingAction[] }>("/api/actions").then((r) => r.actions),

  decide: (id: string, decision: "approve" | "reject", decidedBy: string, note: string) =>
    request<PendingAction>(`/api/actions/${encodeURIComponent(id)}/${decision}`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy, note }),
    }),

  /** アクションの作成・更新を購読する。EventSource は切断時に自動で再接続する。 */
  subscribe(handlers: { onAction: (a: PendingAction) => void; onOpen: () => void; onError: () => void }): () => void {
    const es = new EventSource("/api/actions/stream");
    es.addEventListener("open", handlers.onOpen);
    es.addEventListener("error", handlers.onError);
    es.addEventListener("action", (e) => handlers.onAction(JSON.parse((e as MessageEvent<string>).data) as PendingAction));
    return () => es.close();
  },
};
