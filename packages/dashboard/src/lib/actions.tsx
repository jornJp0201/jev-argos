import type { ActionType, PendingAction } from "../data/actionsApi";

export const ACTION_INFO: Record<ActionType, { label: string; target: string; irreversible: boolean }> = {
  block_ip: { label: "IP の一時遮断", target: "IP アドレス", irreversible: false },
  revoke_session: { label: "セッションの無効化", target: "ユーザー ID", irreversible: false },
  enable_fallback: { label: "縮小運転への切り替え", target: "サービス名", irreversible: false },
  suspend_account: { label: "アカウントの一時停止", target: "ユーザー ID", irreversible: false },
  delete_account: { label: "アカウントの永久削除", target: "ユーザー ID", irreversible: true },
  delete_data: { label: "データの削除", target: "対象 (ユーザー ID 等)", irreversible: true },
  stop_service: { label: "サービスの停止", target: "サービス名", irreversible: true },
};

export const actionLabel = (t: string) => ACTION_INFO[t as ActionType]?.label ?? t;

export const SOURCE_LABEL: Record<string, string> = { jev: "Jev", llm: "LLM", admin: "管理者" };

export function SourceBadge({ source }: { source: PendingAction["source"] }) {
  const style =
    source === "llm"
      ? "text-violet-300 ring-violet-400/30"
      : source === "admin"
        ? "text-sky-300 ring-sky-400/30"
        : "text-slate-300 ring-white/15";
  return <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset ${style}`}>{SOURCE_LABEL[source] ?? source}</span>;
}

export function IrreversibleBadge() {
  return (
    <span className="rounded bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-rose-200 ring-1 ring-inset ring-rose-400/40" title="取り消せない操作">
      不可逆
    </span>
  );
}
