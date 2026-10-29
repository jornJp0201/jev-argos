import { Bot, Loader2, TriangleAlert } from "lucide-react";
import type { LlmAnalysis } from "../types";

const ACTION_NAMES: Record<string, string> = {
  block_ip: "IP の一時遮断",
  revoke_session: "セッションの無効化",
  suspend_account: "アカウントの一時停止",
  enable_fallback: "縮小運転への切り替え",
};

/** LLM 分析の提供元の表示 (モック / LLM 名 + 伏せたか)。 */
export function LlmProviderBadge({ llm }: { llm: LlmAnalysis | undefined }) {
  if (!llm?.provider) return null;
  if (llm.provider === "mock") {
    return (
      <span className="rounded bg-violet-500/10 px-1.5 py-0.5 text-[10px] font-medium text-violet-300 ring-1 ring-inset ring-violet-400/30">
        モック (LLM 未接続)
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1">
      <span className="rounded bg-violet-500/10 px-1.5 py-0.5 font-mono text-[10px] text-violet-200 ring-1 ring-inset ring-violet-400/30">
        {llm.provider}
      </span>
      {llm.masked && (
        <span className="rounded px-1.5 py-0.5 text-[10px] text-slate-400 ring-1 ring-inset ring-white/10" title="IP・ユーザー ID を伏せて送信">
          伏せ字
        </span>
      )}
    </span>
  );
}

/** LLM 分析の本文。llm が無ければ emptyText を表示する。 */
export function LlmAnalysisView({ llm, emptyText, note }: { llm: LlmAnalysis | undefined; emptyText: string; note?: string }) {
  if (!llm) return <p className="text-xs text-slate-500">{emptyText}</p>;
  if (llm.status === "pending") {
    return (
      <p className="flex items-center gap-2 text-xs text-slate-400">
        <Loader2 className="h-3.5 w-3.5 animate-spin" /> 解析中…
      </p>
    );
  }
  if (llm.status === "failed") {
    return (
      <div className="space-y-1 text-xs">
        <p className="flex gap-1.5 text-amber-200">
          <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" /> LLM 分析に失敗しました
        </p>
        {llm.error && <p className="break-all font-mono text-[11px] text-slate-500">{llm.error}</p>}
      </div>
    );
  }
  return (
    <div className="space-y-3 text-sm">
      {note && <p className="text-[11px] text-slate-500">{note}</p>}
      <p className="leading-relaxed text-slate-200">{llm.summary}</p>
      {llm.factors && llm.factors.length > 0 && (
        <ul className="space-y-1.5">
          {llm.factors.map((x) => (
            <li key={x} className="flex gap-2 text-xs leading-relaxed text-slate-400">
              <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-violet-400" />
              {x}
            </li>
          ))}
        </ul>
      )}
      {llm.recommendation && (
        <div className="rounded-md border-l-2 border-violet-400/60 bg-violet-500/5 px-3 py-2 text-xs text-slate-300">
          {llm.recommendation}
          {llm.recommended_action && (
            <p className="mt-1.5 flex items-center gap-1.5 text-[11px] text-violet-200">
              <Bot className="h-3 w-3" /> 推奨: {ACTION_NAMES[llm.recommended_action] ?? llm.recommended_action} (承認キューに提案済み)
            </p>
          )}
        </div>
      )}
    </div>
  );
}
