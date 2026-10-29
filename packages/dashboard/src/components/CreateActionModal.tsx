import { FilePlus2, Loader2, X } from "lucide-react";
import { useEffect, useState } from "react";
import { actionsApi, type ActionType, type PendingAction } from "../data/actionsApi";
import { ACTION_INFO } from "../lib/actions";
import { loadDecider, saveDecider } from "./ActionModal";

/** 管理者がアクションを起票する (例: 調査の結果、アカウントの停止を提案する)。起票したアクションも承認待ちになる。 */
export function CreateActionModal({ onClose, onCreated }: { onClose: () => void; onCreated: (a: PendingAction) => void }) {
  const [type, setType] = useState<ActionType>("suspend_account");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const [createdBy, setCreatedBy] = useState(loadDecider);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const info = ACTION_INFO[type];
  const valid = target.trim() !== "" && reason.trim() !== "" && createdBy.trim() !== "";

  const submit = async () => {
    setSubmitting(true);
    setError(undefined);
    try {
      saveDecider(createdBy.trim());
      onCreated(await actionsApi.create(type, target.trim(), reason.trim(), createdBy.trim()));
    } catch (e) {
      setError((e as Error).message);
      setSubmitting(false);
    }
  };

  const input =
    "mt-1 w-full rounded-md border border-white/10 bg-slate-950/60 px-2.5 py-1.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-sky-500/50 focus:outline-none";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-sm"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
      role="dialog"
      aria-modal="true"
      aria-labelledby="create-action-title"
    >
      <div className="w-full max-w-md overflow-hidden rounded-2xl border border-white/10 bg-slate-900 shadow-2xl shadow-black/50">
        <header className="flex items-center gap-2 border-b border-white/5 px-5 py-3">
          <FilePlus2 className="h-4 w-4 text-sky-300" />
          <h2 id="create-action-title" className="text-sm font-semibold text-slate-50">
            アクションを起票
          </h2>
          <button onClick={onClose} className="ml-auto rounded-md p-1 text-slate-400 hover:bg-white/5" aria-label="閉じる">
            <X className="h-4 w-4" />
          </button>
        </header>
        <div className="space-y-3 p-5 text-xs text-slate-400">
          <label className="block">
            操作
            <select value={type} onChange={(e) => setType(e.target.value as ActionType)} className={input}>
              {(Object.keys(ACTION_INFO) as ActionType[]).map((t) => (
                <option key={t} value={t}>
                  {ACTION_INFO[t].label}
                  {ACTION_INFO[t].irreversible ? " (不可逆)" : ""}
                </option>
              ))}
            </select>
          </label>
          {info.irreversible && (
            <p className="rounded-md border border-rose-400/30 bg-rose-500/5 px-3 py-2 text-rose-100">
              取り消せない操作です。承認されるとアプリへ実行を依頼します (承認時に対象の再入力が必要です)。
            </p>
          )}
          <label className="block">
            対象 ({info.target}) <span className="text-rose-300">*</span>
            <input value={target} onChange={(e) => setTarget(e.target.value)} maxLength={200} className={`${input} font-mono`} />
          </label>
          <label className="block">
            理由 <span className="text-rose-300">*</span>
            <textarea value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} rows={3} className={`${input} resize-none`} />
          </label>
          <label className="block">
            起票者 <span className="text-rose-300">*</span>
            <input value={createdBy} onChange={(e) => setCreatedBy(e.target.value)} maxLength={100} className={input} />
          </label>
          {error && <p className="text-rose-300">{error}</p>}
        </div>
        <footer className="flex justify-end gap-2 border-t border-white/5 bg-slate-950/30 px-5 py-3">
          <button onClick={onClose} className="rounded-lg px-3 py-1.5 text-sm text-slate-300 ring-1 ring-inset ring-white/15 hover:bg-white/5">
            キャンセル
          </button>
          <button
            onClick={submit}
            disabled={!valid || submitting}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500/90 px-3 py-1.5 text-sm font-semibold text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {submitting && <Loader2 className="h-4 w-4 animate-spin" />}承認待ちに追加
          </button>
        </footer>
      </div>
    </div>
  );
}
