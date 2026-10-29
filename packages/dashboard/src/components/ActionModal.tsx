import { Bot, Check, CircleCheck, CircleX, Cpu, Loader2, ShieldAlert, ShieldCheck, TriangleAlert, X } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError, actionsApi, type PendingAction } from "../data/actionsApi";
import { IrreversibleBadge, SourceBadge, actionLabel } from "../lib/actions";
import { fmtAgo, fmtTime } from "../lib/format";
import { BLOCK_CONFIDENCE, BLOCK_SCORE, SATURATION, normalizedFeatures } from "../lib/jev";
import type { Level } from "../types";
import { FeatureRow, ScoreScale } from "./DetailPanel";
import { LlmAnalysisView, LlmProviderBadge } from "./LlmAnalysisView";

export { actionLabel };

const DECIDER_KEY = "jev-argos.decided-by";

export function loadDecider(): string {
  try {
    return localStorage.getItem(DECIDER_KEY) ?? "";
  } catch {
    return "";
  }
}

export function saveDecider(name: string) {
  try {
    localStorage.setItem(DECIDER_KEY, name);
  } catch {
    // 保存できなくても入力は続けられる
  }
}

export function StatusChip({ status }: { status: PendingAction["status"] }) {
  const style = {
    pending: "bg-amber-500/10 text-amber-300 ring-amber-400/30",
    approved: "bg-rose-500/10 text-rose-300 ring-rose-400/30",
    rejected: "bg-slate-500/10 text-slate-300 ring-slate-400/30",
  }[status];
  const label = { pending: "承認待ち", approved: "承認済み", rejected: "拒否" }[status];
  return <span className={`rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${style}`}>{label}</span>;
}

function Section({ title, icon, aside, children }: { title: string; icon?: ReactNode; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-white/5 bg-slate-950/40 p-4">
      <h3 className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
        {icon}
        {title}
        {aside && <span className="ml-auto normal-case tracking-normal">{aside}</span>}
      </h3>
      {children}
    </section>
  );
}

function ExecutionResult({ action }: { action: PendingAction }) {
  if (action.status !== "approved") return null;
  if (!action.executed_at) {
    return (
      <p className="flex items-center gap-1.5 text-xs text-slate-400">
        <Loader2 className="h-3.5 w-3.5 animate-spin" /> 実行中…
      </p>
    );
  }
  if (action.execution_error) {
    return (
      <div className="space-y-1 text-xs">
        <p className="flex items-center gap-1.5 text-rose-300">
          <CircleX className="h-3.5 w-3.5" /> 実行に失敗しました ({fmtTime(action.executed_at)})
        </p>
        <p className="break-all font-mono text-[11px] text-slate-500">{action.execution_error}</p>
      </div>
    );
  }
  return (
    <p className="flex items-center gap-1.5 text-xs text-emerald-300">
      <CircleCheck className="h-3.5 w-3.5" />
      {action.proposed_action === "block_ip" ? "遮断リストに登録しました" : "アプリへ実行を依頼しました"} ({fmtTime(action.executed_at)})
    </p>
  );
}

interface Props {
  action: PendingAction;
  onClose: () => void;
  onDecided: (a: PendingAction) => void;
}

export function ActionModal({ action, onClose, onDecided }: Props) {
  const ev = action.evidence;
  const [decidedBy, setDecidedBy] = useState(loadDecider);
  const [note, setNote] = useState("");
  const [confirming, setConfirming] = useState<"approve" | "reject">();
  // 不可逆な操作は、対象を入力しないと承認できない
  const [typedTarget, setTypedTarget] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string>();
  // このモーダルで決定したか (他の管理者による決定と区別する)
  const [decidedHere, setDecidedHere] = useState(false);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const pending = action.status === "pending";
  const isBlock = action.proposed_action === "block_ip";
  const targetConfirmed = !action.irreversible || typedTarget.trim() === action.target;
  const canSubmit = pending && decidedBy.trim() !== "" && !submitting;
  // Jev の判定に基づく提案か (管理者の起票には判定の根拠が無い)
  const hasJudgement = action.source !== "admin";

  const submit = async (decision: "approve" | "reject") => {
    if (confirming !== decision) {
      setConfirming(decision);
      return;
    }
    setSubmitting(true);
    setError(undefined);
    try {
      saveDecider(decidedBy.trim());
      onDecided(await actionsApi.decide(action.action_id, decision, decidedBy.trim(), note.trim()));
      setDecidedHere(true);
    } catch (e) {
      if (e instanceof ApiError && e.action) onDecided(e.action); // 他の管理者が先に決定していた
      setError((e as Error).message);
    } finally {
      setSubmitting(false);
      setConfirming(undefined);
    }
  };

  const [nErr, nDenied, nLatency] = normalizedFeatures(ev);
  const level = Math.min(4, Math.max(1, ev.level)) as Level;
  const approveLabel = isBlock ? "遮断を承認" : "実行を承認";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-sm"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
      role="dialog"
      aria-modal="true"
      aria-labelledby="action-modal-title"
    >
      <div className="flex max-h-[90vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-white/10 bg-slate-900 shadow-2xl shadow-black/50">
        <header className="flex items-start gap-3 border-b border-white/5 px-6 py-4">
          <div
            className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg ring-1 ring-inset ${
              action.irreversible ? "bg-rose-500/10 ring-rose-400/40" : "bg-amber-500/10 ring-amber-400/30"
            }`}
          >
            <ShieldAlert className={`h-5 w-5 ${action.irreversible ? "text-rose-300" : "text-amber-300"}`} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 id="action-modal-title" className="text-base font-semibold text-slate-50">
                {actionLabel(action.proposed_action)}: <span className="font-mono">{action.target}</span>
              </h2>
              <StatusChip status={action.status} />
              <SourceBadge source={action.source} />
              {action.irreversible && <IrreversibleBadge />}
            </div>
            <p className="mt-0.5 font-mono text-[11px] text-slate-500">
              {action.action_id} · 提案 {fmtTime(action.created_at)} · 最終更新 {fmtAgo(action.updated_at)}
              {hasJudgement && ` · 判定 ${action.event_count} 件`}
            </p>
          </div>
          <button ref={closeRef} onClick={onClose} className="rounded-md p-1 text-slate-400 hover:bg-white/5 hover:text-slate-200" aria-label="閉じる">
            <X className="h-5 w-5" />
          </button>
        </header>

        <div className="grid gap-4 overflow-auto p-6 md:grid-cols-2">
          <div className="space-y-4">
            <Section title={hasJudgement ? "AI の判定根拠" : "起票の理由"} icon={<ShieldCheck className="h-3.5 w-3.5" />}>
              {hasJudgement && (
                <>
                  <ScoreScale score={ev.score} level={level} />
                  <div className="mt-4 space-y-1.5 rounded-md bg-slate-900/80 p-3 font-mono text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">S ≥ {BLOCK_SCORE}</span>
                      <span className={ev.score >= BLOCK_SCORE ? "text-rose-300" : "text-slate-500"}>
                        {ev.score.toFixed(2)} {ev.score >= BLOCK_SCORE ? "✓" : "✗"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">C ≥ {BLOCK_CONFIDENCE}</span>
                      <span className={ev.confidence >= BLOCK_CONFIDENCE ? "text-rose-300" : "text-slate-500"}>
                        {ev.confidence.toFixed(2)} {ev.confidence >= BLOCK_CONFIDENCE ? "✓" : "✗"}
                      </span>
                    </div>
                  </div>
                </>
              )}
              <p className={`flex gap-1.5 text-xs leading-relaxed text-amber-100/90 ${hasJudgement ? "mt-3" : ""}`}>
                <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300" />
                {action.reason}
              </p>
            </Section>

            {hasJudgement && (
              <Section title="Sliding Window 特徴量" icon={<Cpu className="h-3.5 w-3.5" />}>
                <div className="space-y-3">
                  <FeatureRow label="ip_error_count_1m" display={String(ev.ip_error_count_1m)} norm={nErr} hint={`${SATURATION.ip_error_count_1m} で最大寄与`} />
                  <FeatureRow label="unique_denied_methods_5m" display={String(ev.unique_denied_methods_5m)} norm={nDenied} hint={`${SATURATION.unique_denied_methods_5m} で最大寄与`} />
                  <FeatureRow label="latency_spike_ratio" display={`×${ev.latency_spike_ratio.toFixed(2)}`} norm={nLatency} hint={`×${SATURATION.latency_spike_ratio} で最大寄与`} />
                </div>
              </Section>
            )}
          </div>

          <div className="space-y-4">
            {hasJudgement && (
              <Section title="最新の根拠シグナル">
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 font-mono text-xs">
                  {(
                    [
                      ["client_ip", ev.client_ip],
                      ["user_id", ev.user_id || "—"],
                      ["method", ev.method],
                      ["source", ev.source_service || "—"],
                      ["timestamp", ev.signal_timestamp || "—"],
                      ["signal_id", action.signal_id || "—"],
                    ] as const
                  ).map(([k, v]) => (
                    <div key={k} className="contents">
                      <dt className="text-slate-500">{k}</dt>
                      <dd className="break-all text-slate-200">{v}</dd>
                    </div>
                  ))}
                </dl>
              </Section>
            )}

            <Section title="LLM 要因解析" icon={<Bot className="h-3.5 w-3.5" />} aside={<LlmProviderBadge llm={action.analysis} />}>
              <LlmAnalysisView
                llm={action.analysis}
                emptyText={hasJudgement ? "この対象の LLM 分析はまだありません。判定根拠と特徴量をもとに判断してください。" : "管理者の起票のため LLM 分析はありません。"}
              />
            </Section>

            <Section title="管理者の判断">
              {pending ? (
                <div className="space-y-3">
                  {action.irreversible && (
                    <div className="rounded-md border border-rose-400/30 bg-rose-500/5 p-3 text-xs text-rose-100">
                      <p className="font-semibold">取り消せない操作です。</p>
                      <p className="mt-1 text-rose-100/80">
                        承認すると、アプリへ「{actionLabel(action.proposed_action)}」の実行を依頼します。確認のため対象{" "}
                        <code className="text-rose-50">{action.target}</code> を入力してください。
                      </p>
                      <input
                        value={typedTarget}
                        onChange={(e) => setTypedTarget(e.target.value)}
                        placeholder={action.target}
                        aria-label="確認のための対象の入力"
                        className="mt-2 w-full rounded-md border border-rose-400/30 bg-slate-950/60 px-2.5 py-1.5 font-mono text-sm text-slate-100 placeholder:text-slate-600 focus:border-rose-400/60 focus:outline-none"
                      />
                    </div>
                  )}
                  <label className="block text-xs text-slate-400">
                    担当者名 <span className="text-rose-300">*</span>
                    <input
                      value={decidedBy}
                      onChange={(e) => setDecidedBy(e.target.value)}
                      maxLength={100}
                      placeholder="例: 山田 (SRE)"
                      className="mt-1 w-full rounded-md border border-white/10 bg-slate-950/60 px-2.5 py-1.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-sky-500/50 focus:outline-none"
                    />
                  </label>
                  <label className="block text-xs text-slate-400">
                    メモ (任意)
                    <textarea
                      value={note}
                      onChange={(e) => setNote(e.target.value)}
                      maxLength={1000}
                      rows={2}
                      placeholder="判断理由など (監査ログに残ります)"
                      className="mt-1 w-full resize-none rounded-md border border-white/10 bg-slate-950/60 px-2.5 py-1.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-sky-500/50 focus:outline-none"
                    />
                  </label>
                  {confirming && (
                    <p className="text-xs text-amber-200">
                      {confirming === "approve"
                        ? `${actionLabel(action.proposed_action)} (${action.target}) を実行します。もう一度「${approveLabel}」を押すと確定します。`
                        : "この提案を拒否します。もう一度「拒否」を押すと確定します。"}
                    </p>
                  )}
                </div>
              ) : (
                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-2">
                    <StatusChip status={action.status} />
                    <span className="text-slate-300">
                      {action.decided_by} · {action.decided_at && fmtTime(action.decided_at)}
                    </span>
                  </div>
                  {action.decision_note && <p className="text-xs text-slate-400">「{action.decision_note}」</p>}
                  <ExecutionResult action={action} />
                  {!decidedHere && <p className="text-xs text-sky-300">他の管理者によって決定されました。</p>}
                </div>
              )}
              {error && <p className="mt-2 text-xs text-rose-300">{error}</p>}
            </Section>
          </div>
        </div>

        {pending && (
          <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-white/5 bg-slate-950/30 px-6 py-3">
            <button
              onClick={() => submit("reject")}
              disabled={!canSubmit}
              className={`inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-sm font-medium ring-1 ring-inset transition disabled:cursor-not-allowed disabled:opacity-40 ${
                confirming === "reject" ? "bg-slate-200 text-slate-900 ring-slate-200" : "text-slate-200 ring-white/15 hover:bg-white/5"
              }`}
            >
              <X className="h-4 w-4" /> {confirming === "reject" ? "拒否を確定" : "拒否 (Reject)"}
            </button>
            <button
              onClick={() => submit("approve")}
              disabled={!canSubmit || !targetConfirmed}
              title={!targetConfirmed ? "確認のため対象を入力してください" : undefined}
              className={`inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-40 ${
                confirming === "approve" ? "bg-rose-500 text-white ring-2 ring-rose-300" : "bg-rose-500/90 text-white hover:bg-rose-500"
              }`}
            >
              {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
              {confirming === "approve" ? "実行を確定" : `${approveLabel} (Approve)`}
            </button>
          </footer>
        )}
      </div>
    </div>
  );
}
