import { LEVEL_INFO } from "../lib/jev";
import type { Level } from "../types";

export const LEVEL_STYLE: Record<Level, { badge: string; dot: string; bar: string; text: string }> = {
  1: { badge: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/25", dot: "bg-emerald-400", bar: "bg-emerald-500/70", text: "text-emerald-300" },
  2: { badge: "bg-sky-500/10 text-sky-300 ring-sky-500/30", dot: "bg-sky-400", bar: "bg-sky-500/80", text: "text-sky-300" },
  3: { badge: "bg-amber-500/10 text-amber-300 ring-amber-500/30", dot: "bg-amber-400", bar: "bg-amber-500/90", text: "text-amber-300" },
  4: { badge: "bg-rose-500/15 text-rose-300 ring-rose-500/40", dot: "bg-rose-500", bar: "bg-rose-500", text: "text-rose-300" },
};

export function LevelBadge({ level, downgraded = false }: { level: Level; downgraded?: boolean }) {
  const s = LEVEL_STYLE[level];
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset ${s.badge}`}
        title={LEVEL_INFO[level].action}
      >
        <span className={`h-1.5 w-1.5 rounded-full ${s.dot} ${level === 4 ? "animate-pulse" : ""}`} />
        {LEVEL_INFO[level].label}
      </span>
      {downgraded && (
        <span
          className="rounded px-1.5 py-0.5 text-[10px] font-medium text-amber-200/80 ring-1 ring-inset ring-amber-400/30"
          title="スコアは遮断域 (S ≥ 3.5) だが確信度 C < 0.8 のため Level 3 に格下げ"
        >
          4→3
        </span>
      )}
    </span>
  );
}
