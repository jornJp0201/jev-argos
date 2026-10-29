import { ChevronRight, FilePlus2, Hourglass, PlugZap, UserCheck } from "lucide-react";
import { useEffect, useState } from "react";
import type { PendingAction } from "../data/actionsApi";
import type { ConnectionState } from "../data/useActions";
import { fmtAgo } from "../lib/format";
import { IrreversibleBadge, SourceBadge, actionLabel } from "../lib/actions";
import { StatusChip } from "./ActionModal";

interface Props {
  pending: PendingAction[];
  decided: PendingAction[];
  connection: ConnectionState;
  error: string | undefined;
  onOpen: (a: PendingAction) => void;
  onCreate: () => void;
}

function ConnectionPill({ state }: { state: ConnectionState }) {
  const s = {
    live: ["bg-emerald-400", "text-emerald-300", "API 接続中"],
    connecting: ["bg-slate-400", "text-slate-400", "接続中…"],
    offline: ["bg-rose-500", "text-rose-300", "API 未接続"],
  }[state];
  return (
    <span className={`flex items-center gap-1.5 text-[11px] ${s[1]}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s[0]} ${state === "live" ? "animate-pulse" : ""}`} />
      {s[2]}
    </span>
  );
}

export function PendingActions({ pending, decided, connection, error, onOpen, onCreate }: Props) {
  // 経過時間表示の更新
  const [, tick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 5_000);
    return () => clearInterval(t);
  }, []);

  const unavailable = connection === "offline" && pending.length === 0 && decided.length === 0;

  return (
    <section className="rounded-xl border border-amber-400/15 bg-gradient-to-b from-amber-500/[0.04] to-slate-900/60">
      <header className="flex flex-wrap items-center gap-3 px-4 py-3">
        <Hourglass className="h-4 w-4 text-amber-300" />
        <h2 className="text-sm font-semibold text-slate-100">承認待ちアラート</h2>
        <span
          className={`rounded-full px-2 py-0.5 font-mono text-xs font-semibold ${
            pending.length ? "bg-amber-400 text-slate-950" : "bg-slate-800 text-slate-400"
          }`}
        >
          {pending.length}
        </span>
        <span className="hidden text-xs text-slate-500 xl:inline">Jev・LLM・管理者が提案した対処 — 承認されるまで実行されません</span>
        <span className="ml-auto flex items-center gap-3">
          <ConnectionPill state={connection} />
          <button
            onClick={onCreate}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-300 ring-1 ring-inset ring-white/10 hover:bg-white/5"
          >
            <FilePlus2 className="h-3.5 w-3.5" /> 起票
          </button>
        </span>
      </header>

      {unavailable ? (
        <p className="flex items-center gap-2 border-t border-white/5 px-4 py-3 text-xs text-slate-400">
          <PlugZap className="h-4 w-4 text-rose-300" />
          管理 API に接続できません。<code className="text-slate-300">jev-argos-server</code> を起動し、
          ダッシュボードの開発サーバーに <code className="text-slate-300">JEV_ARGOS_ADMIN_TOKEN</code> を設定してください。
        </p>
      ) : (
        <div className="border-t border-white/5">
          {error && <p className="px-4 pt-2 text-xs text-rose-300">{error}</p>}
          {pending.length === 0 ? (
            <p className="px-4 py-3 text-xs text-slate-500">承認待ちのアクションはありません。</p>
          ) : (
            <ul className="grid max-h-48 gap-2 overflow-auto p-3 md:grid-cols-2">
              {pending.map((a) => (
                <li key={a.action_id}>
                  <button
                    onClick={() => onOpen(a)}
                    className="group flex w-full items-center gap-3 rounded-lg border border-white/5 bg-slate-950/50 px-3 py-2.5 text-left transition hover:border-amber-400/40 hover:bg-slate-950/80"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm text-slate-100">{a.target}</span>
                        <span className="rounded bg-rose-500/10 px-1.5 py-0.5 text-[10px] font-medium text-rose-300 ring-1 ring-inset ring-rose-400/30">
                          {actionLabel(a.proposed_action)}
                        </span>
                        <SourceBadge source={a.source} />
                        {a.irreversible && <IrreversibleBadge />}
                        {a.evidence.downgraded && (
                          <span className="rounded px-1.5 py-0.5 text-[10px] text-amber-200/80 ring-1 ring-inset ring-amber-400/30">4→3</span>
                        )}
                      </div>
                      <div className="mt-1 flex gap-3 font-mono text-[11px] text-slate-500">
                        {a.source !== "admin" && (
                          <>
                            <span>
                              S <span className="text-amber-300">{a.evidence.score.toFixed(2)}</span>
                            </span>
                            <span>
                              C <span className="text-slate-300">{a.evidence.confidence.toFixed(2)}</span>
                            </span>
                            <span>{a.event_count} 件</span>
                          </>
                        )}
                        {a.analysis?.status === "done" && <span className="text-violet-300">LLM 分析あり</span>}
                        <span>{fmtAgo(a.updated_at)}</span>
                      </div>
                    </div>
                    <span className="flex items-center text-xs text-slate-400 group-hover:text-amber-200">
                      確認 <ChevronRight className="h-4 w-4" />
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {decided.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 border-t border-white/5 px-4 py-2 text-xs text-slate-500">
              <UserCheck className="h-3.5 w-3.5" /> 最近の決定:
              {decided.slice(0, 4).map((a) => (
                <button key={a.action_id} onClick={() => onOpen(a)} className="flex items-center gap-1.5 rounded px-1.5 py-0.5 hover:bg-white/5">
                  <span className="font-mono text-slate-300">{a.target}</span>
                  <StatusChip status={a.status} />
                  <span>{a.decided_by}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
