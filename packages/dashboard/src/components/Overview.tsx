import { Activity, Ban, Gauge, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { fmtNum } from "../lib/format";
import type { DecisionEvent, Level } from "../types";
import { LEVEL_STYLE } from "./LevelBadge";

const WINDOW_MS = 5 * 60_000;
const TIMELINE_BUCKETS = 60; // 直近 60 秒を 1 秒刻み

function Stat(props: { icon: ReactNode; label: string; value: string; sub: ReactNode; accent: string }) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-white/5 bg-slate-900/60 p-4">
      <div className={`absolute inset-x-0 top-0 h-px ${props.accent}`} />
      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-slate-400">
        {props.icon}
        {props.label}
      </div>
      <div className="mt-2 font-mono text-3xl font-semibold tabular-nums text-slate-50">{props.value}</div>
      <div className="mt-1 text-xs text-slate-500">{props.sub}</div>
    </div>
  );
}

export function Overview({ events }: { events: DecisionEvent[] }) {
  // 表示が停止中でも時間窓を進めるため 1 秒ごとに再計算する
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1_000);
    return () => clearInterval(t);
  }, []);

  const m = useMemo(() => {
    const byLevel: Record<Level, number> = { 1: 0, 2: 0, 3: 0, 4: 0 };
    const timeline = Array.from({ length: TIMELINE_BUCKETS }, () => ({ 1: 0, 2: 0, 3: 0, 4: 0 }) as Record<Level, number>);
    let total = 0;
    let scoreSum = 0;
    let downgraded = 0;
    let lastMinute = 0;
    const blockedIps = new Set<string>();
    for (const e of events) {
      // now は 1 秒ごとにしか更新しないため、それより新しいイベントは経過 0 として扱う
      const age = Math.max(0, now - Date.parse(e.signal.timestamp));
      if (age > WINDOW_MS) break; // events は新しい順
      total++;
      scoreSum += e.score;
      byLevel[e.level]++;
      if (e.downgraded) downgraded++;
      if (e.level === 4) blockedIps.add(e.signal.user_context.client_ip);
      if (age < 60_000) lastMinute++;
      const bucket = TIMELINE_BUCKETS - 1 - Math.floor(age / 1_000);
      if (bucket >= 0) timeline[bucket]![e.level]++;
    }
    return { total, byLevel, avgScore: total ? scoreSum / total : 0, downgraded, blockedIps: blockedIps.size, rps: lastMinute / 60, timeline };
  }, [events, now]);

  const peak = Math.max(1, ...m.timeline.map((b) => b[1] + b[2] + b[3] + b[4]));

  return (
    <section className="grid gap-4 lg:grid-cols-[repeat(4,minmax(0,1fr))_minmax(0,1.6fr)]">
      <Stat
        icon={<Activity className="h-3.5 w-3.5" />}
        label="Requests · 5m"
        value={fmtNum(m.total)}
        sub={`${m.rps.toFixed(1)} req/s (直近 1 分)`}
        accent="bg-gradient-to-r from-transparent via-emerald-400/60 to-transparent"
      />
      <Stat
        icon={<ShieldAlert className="h-3.5 w-3.5" />}
        label="L3 Alerts · 5m"
        value={fmtNum(m.byLevel[3])}
        sub={<>うち格下げ (4→3) <span className="text-amber-300">{m.downgraded}</span> 件</>}
        accent="bg-gradient-to-r from-transparent via-amber-400/70 to-transparent"
      />
      <Stat
        icon={<Ban className="h-3.5 w-3.5" />}
        label="L4 Blocks · 5m"
        value={fmtNum(m.byLevel[4])}
        sub={<>遮断対象 IP <span className="text-rose-300">{m.blockedIps}</span> 件</>}
        accent="bg-gradient-to-r from-transparent via-rose-500/80 to-transparent"
      />
      <Stat
        icon={<Gauge className="h-3.5 w-3.5" />}
        label="Avg Jev Score"
        value={m.avgScore.toFixed(2)}
        sub="S ∈ [0.0, 4.0] · 5 分平均"
        accent="bg-gradient-to-r from-transparent via-sky-400/60 to-transparent"
      />

      <div className="rounded-xl border border-white/5 bg-slate-900/60 p-4">
        <div className="flex items-center justify-between text-xs font-medium uppercase tracking-wider text-slate-400">
          <span>Live · 直近 60 秒</span>
          <span className="flex gap-3 normal-case tracking-normal">
            {([1, 2, 3, 4] as Level[]).map((l) => (
              <span key={l} className="flex items-center gap-1">
                <span className={`h-2 w-2 rounded-sm ${LEVEL_STYLE[l].bar}`} />L{l}
              </span>
            ))}
          </span>
        </div>
        <div className="mt-3 flex h-[68px] items-end gap-[2px]" aria-label="直近 60 秒のレベル別シグナル数">
          {m.timeline.map((b, i) => (
            <div key={i} className="flex h-full flex-1 flex-col-reverse" title={`${TIMELINE_BUCKETS - 1 - i} 秒前: L1 ${b[1]} / L2 ${b[2]} / L3 ${b[3]} / L4 ${b[4]}`}>
              {([1, 2, 3, 4] as Level[]).map((l) =>
                b[l] ? <div key={l} className={`${LEVEL_STYLE[l].bar} first:rounded-b-[1px] last:rounded-t-[1px]`} style={{ height: `${(b[l] / peak) * 100}%` }} /> : null,
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
