import { Ban, Loader2, Plus, X } from "lucide-react";
import { useState } from "react";
import { blocklistApi, useBlocklist, type BlockEntry } from "../data/blocklistApi";
import { loadDecider, saveDecider } from "./ActionModal";

const SOURCE: Record<string, { label: string; style: string }> = {
  jev_level4: { label: "Level 4 自動", style: "text-rose-300 ring-rose-400/30" },
  approval: { label: "承認", style: "text-amber-300 ring-amber-400/30" },
  admin: { label: "手動", style: "text-sky-300 ring-sky-400/30" },
};

function remaining(e: BlockEntry, now: number): string {
  if (!e.expires_at) return "無期限";
  const s = Math.max(0, Math.round((Date.parse(e.expires_at) - now) / 1000));
  return s >= 60 ? `残り ${Math.floor(s / 60)} 分` : `残り ${s} 秒`;
}

/** 遮断中の IP の一覧 (Level 4 の自動遮断・承認・手動)。解除と手動の遮断ができる。 */
export function BlocklistPanel() {
  const { entries, error, now } = useBlocklist();
  const [busy, setBusy] = useState<string>();
  const [actionError, setActionError] = useState<string>();
  const [adding, setAdding] = useState(false);
  const [ip, setIp] = useState("");
  const [minutes, setMinutes] = useState(15);

  const unblock = async (e: BlockEntry) => {
    setBusy(e.target);
    setActionError(undefined);
    try {
      await blocklistApi.unblock(e.target, e.target_type);
    } catch (err) {
      setActionError((err as Error).message);
    } finally {
      setBusy(undefined);
    }
  };

  const block = async () => {
    const by = loadDecider();
    if (!by) {
      setActionError("担当者名が未設定です。承認待ちアラートで一度担当者名を入力してください。");
      return;
    }
    setBusy("add");
    setActionError(undefined);
    try {
      saveDecider(by);
      await blocklistApi.block(ip.trim(), minutes * 60, "ダッシュボードから手動で遮断", by);
      setIp("");
      setAdding(false);
    } catch (err) {
      setActionError((err as Error).message);
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <section className="flex min-h-0 flex-col rounded-xl border border-rose-400/15 bg-gradient-to-b from-rose-500/[0.04] to-slate-900/60">
      <header className="flex items-center gap-2 px-4 py-3">
        <Ban className="h-4 w-4 text-rose-300" />
        <h2 className="text-sm font-semibold text-slate-100">遮断中</h2>
        <span className={`rounded-full px-2 py-0.5 font-mono text-xs font-semibold ${entries.length ? "bg-rose-500 text-white" : "bg-slate-800 text-slate-400"}`}>
          {entries.length}
        </span>
        <button
          onClick={() => setAdding((v) => !v)}
          className="ml-auto inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-300 ring-1 ring-inset ring-white/10 hover:bg-white/5"
        >
          <Plus className="h-3.5 w-3.5" /> 手動で遮断
        </button>
      </header>
      {adding && (
        <div className="flex flex-wrap items-center gap-2 border-t border-white/5 px-4 py-2 text-xs">
          <input
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="IP アドレス"
            className="w-36 rounded-md border border-white/10 bg-slate-950/60 px-2 py-1 font-mono text-slate-100 placeholder:text-slate-600 focus:border-rose-400/50 focus:outline-none"
          />
          <select
            value={minutes}
            onChange={(e) => setMinutes(Number(e.target.value))}
            className="rounded-md border border-white/10 bg-slate-950/60 px-2 py-1 text-slate-100"
          >
            {[15, 60, 360, 1440].map((m) => (
              <option key={m} value={m}>
                {m < 60 ? `${m} 分` : `${m / 60} 時間`}
              </option>
            ))}
          </select>
          <button
            onClick={block}
            disabled={!ip.trim() || busy === "add"}
            className="inline-flex items-center gap-1 rounded-md bg-rose-500/90 px-2.5 py-1 font-semibold text-white hover:bg-rose-500 disabled:opacity-40"
          >
            {busy === "add" && <Loader2 className="h-3 w-3 animate-spin" />}遮断
          </button>
        </div>
      )}
      {(error || actionError) && <p className="px-4 pb-1 text-xs text-rose-300">{actionError ?? error}</p>}
      <ul className="max-h-48 min-h-0 flex-1 divide-y divide-white/[0.04] overflow-auto border-t border-white/5">
        {entries.length === 0 && <li className="px-4 py-3 text-xs text-slate-500">遮断中の送信元はありません。</li>}
        {entries.map((e) => {
          const src = SOURCE[e.source] ?? { label: e.source, style: "text-slate-300 ring-white/15" };
          return (
            <li key={`${e.target_type}:${e.target}`} className="flex items-center gap-2 px-4 py-2" title={e.reason}>
              <span className="font-mono text-sm text-slate-100">{e.target}</span>
              <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset ${src.style}`}>{src.label}</span>
              <span className="text-[11px] text-slate-500">{remaining(e, now)}</span>
              <button
                onClick={() => unblock(e)}
                disabled={busy === e.target}
                className="ml-auto inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-slate-400 hover:bg-white/5 hover:text-slate-200 disabled:opacity-40"
                aria-label={`${e.target} の遮断を解除`}
              >
                {busy === e.target ? <Loader2 className="h-3 w-3 animate-spin" /> : <X className="h-3 w-3" />} 解除
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
