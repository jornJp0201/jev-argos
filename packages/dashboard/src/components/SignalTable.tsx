import { Pause, Play, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { fmtTime, splitMethod } from "../lib/format";
import { BLOCK_CONFIDENCE, GRPC_STATUS, MAX_SCORE } from "../lib/jev";
import type { DecisionEvent, Level } from "../types";
import { LEVEL_STYLE, LevelBadge } from "./LevelBadge";

const ROW_LIMIT = 200;

function ConfidenceBar({ value }: { value: number }) {
  const low = value < BLOCK_CONFIDENCE;
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-1.5 w-16 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full rounded-full ${low ? "bg-slate-400" : "bg-sky-400"}`} style={{ width: `${value * 100}%` }} />
        <div className="absolute inset-y-0 w-px bg-slate-200/60" style={{ left: `${BLOCK_CONFIDENCE * 100}%` }} />
      </div>
      <span className={`font-mono text-xs tabular-nums ${low ? "text-slate-400" : "text-slate-200"}`}>{value.toFixed(2)}</span>
    </div>
  );
}

interface Props {
  events: DecisionEvent[];
  selectedId: string | undefined;
  onSelect: (e: DecisionEvent) => void;
  paused: boolean;
  onTogglePause: () => void;
}

export function SignalTable({ events, selectedId, onSelect, paused, onTogglePause }: Props) {
  const [levels, setLevels] = useState<Set<Level>>(new Set([1, 2, 3, 4]));
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const out: DecisionEvent[] = [];
    for (const e of events) {
      if (!levels.has(e.level)) continue;
      if (q && !e.signal.user_context.client_ip.includes(q) && !e.signal.request_context.method.toLowerCase().includes(q)) continue;
      out.push(e);
      if (out.length >= ROW_LIMIT) break;
    }
    return out;
  }, [events, levels, query]);

  const toggle = (l: Level) =>
    setLevels((prev) => {
      const next = new Set(prev);
      if (next.has(l)) next.delete(l);
      else next.add(l);
      return next;
    });

  return (
    <section className="flex min-h-0 flex-col rounded-xl border border-white/5 bg-slate-900/60">
      <header className="flex flex-wrap items-center gap-3 border-b border-white/5 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-100">Signal Stream</h2>
        <div className="flex gap-1">
          {([1, 2, 3, 4] as Level[]).map((l) => (
            <button
              key={l}
              onClick={() => toggle(l)}
              className={`rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset transition ${
                levels.has(l) ? LEVEL_STYLE[l].badge : "text-slate-500 ring-white/5 hover:text-slate-300"
              }`}
              aria-pressed={levels.has(l)}
            >
              L{l}
            </button>
          ))}
        </div>
        <label className="relative ml-auto">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="IP / メソッドで絞り込み"
            className="w-56 rounded-md border border-white/10 bg-slate-950/60 py-1 pl-7 pr-2 text-xs text-slate-200 placeholder:text-slate-600 focus:border-sky-500/50 focus:outline-none"
          />
        </label>
        <button
          onClick={onTogglePause}
          className="inline-flex items-center gap-1.5 rounded-md border border-white/10 px-2.5 py-1 text-xs text-slate-300 hover:bg-white/5"
        >
          {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
          {paused ? "再開" : "一時停止"}
        </button>
      </header>

      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 z-10 bg-slate-900/95 text-[11px] uppercase tracking-wider text-slate-500 backdrop-blur">
            <tr>
              <th className="px-4 py-2 font-medium">Time</th>
              <th className="px-2 py-2 font-medium">Level</th>
              <th className="px-2 py-2 font-medium">Client IP</th>
              <th className="px-2 py-2 font-medium">Method</th>
              <th className="px-2 py-2 font-medium">Status</th>
              <th className="px-2 py-2 text-right font-medium">Score</th>
              <th className="px-4 py-2 font-medium">Confidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.03]">
            {rows.map((e) => {
              const { service, rpc } = splitMethod(e.signal.request_context.method);
              const code = e.signal.response_context.status_code;
              const selected = e.signal.signal_id === selectedId;
              return (
                <tr
                  key={e.signal.signal_id}
                  onClick={() => onSelect(e)}
                  className={`cursor-pointer transition-colors ${
                    selected ? "bg-sky-500/10" : e.level === 4 ? "bg-rose-500/[0.04] hover:bg-white/[0.03]" : "hover:bg-white/[0.03]"
                  }`}
                >
                  <td className="whitespace-nowrap px-4 py-1.5 font-mono text-xs text-slate-500">{fmtTime(e.signal.timestamp)}</td>
                  <td className="px-2 py-1.5">
                    <LevelBadge level={e.level} downgraded={e.downgraded} />
                  </td>
                  <td className="px-2 py-1.5 font-mono text-xs text-slate-300">{e.signal.user_context.client_ip}</td>
                  <td className="max-w-[18rem] truncate px-2 py-1.5 text-xs" title={e.signal.request_context.method}>
                    <span className="text-slate-500">{service}/</span>
                    <span className="text-slate-200">{rpc}</span>
                  </td>
                  <td className={`px-2 py-1.5 font-mono text-[11px] ${code === 0 ? "text-slate-500" : code === 7 ? "text-rose-300" : "text-amber-300"}`}>
                    {GRPC_STATUS[code] ?? code}
                  </td>
                  <td className={`px-2 py-1.5 text-right font-mono text-xs tabular-nums ${LEVEL_STYLE[e.level].text}`}>
                    {e.score.toFixed(2)}
                    <span className="text-slate-600">/{MAX_SCORE.toFixed(1)}</span>
                  </td>
                  <td className="px-4 py-1.5">
                    <ConfidenceBar value={e.confidence} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {rows.length === 0 && <p className="p-8 text-center text-sm text-slate-500">該当するシグナルはありません</p>}
      </div>
      <footer className="border-t border-white/5 px-4 py-2 text-[11px] text-slate-500">
        最新 {rows.length} 件を表示{paused && <span className="ml-2 text-amber-300">· 一時停止中 (受信は継続)</span>}
      </footer>
    </section>
  );
}
