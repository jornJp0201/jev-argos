import { Bot, Cpu, Fingerprint, MousePointerClick, ShieldCheck, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { fmtTime } from "../lib/format";
import {
  BLOCK_CONFIDENCE,
  BLOCK_SCORE,
  GRPC_STATUS,
  LEVEL2_SCORE,
  LEVEL3_SCORE,
  LEVEL_INFO,
  MAX_SCORE,
  SATURATION,
  normalizedFeatures,
} from "../lib/jev";
import type { DecisionEvent, LlmAnalysis } from "../types";
import { LlmAnalysisView, LlmProviderBadge } from "./LlmAnalysisView";
import { LEVEL_STYLE, LevelBadge } from "./LevelBadge";

function Card({ title, icon, children, aside }: { title: string; icon: ReactNode; children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="rounded-lg border border-white/5 bg-slate-950/40 p-4">
      <h3 className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
        {icon}
        {title}
        {aside && <span className="ml-auto normal-case tracking-normal">{aside}</span>}
      </h3>
      {children}
    </div>
  );
}

/** 0.0〜4.0 のスコアを、レベル境界付きの横棒で表示する。 */
export function ScoreScale({ score, level }: { score: number; level: DecisionEvent["level"] }) {
  const pct = (v: number) => `${(v / MAX_SCORE) * 100}%`;
  return (
    <div>
      <div className="flex items-baseline gap-2">
        <span className={`font-mono text-4xl font-semibold tabular-nums ${LEVEL_STYLE[level].text}`}>{score.toFixed(2)}</span>
        <span className="font-mono text-sm text-slate-500">/ {MAX_SCORE.toFixed(1)}</span>
      </div>
      <div className="relative mt-3 h-2 rounded-full bg-gradient-to-r from-emerald-500/30 via-amber-500/30 to-rose-500/40">
        <div className="absolute inset-y-0 left-0 rounded-full bg-white/10" style={{ width: pct(score) }} />
        {[LEVEL2_SCORE, LEVEL3_SCORE, BLOCK_SCORE].map((t) => (
          <div key={t} className="absolute -top-1 h-4 w-px bg-slate-400/50" style={{ left: pct(t) }} />
        ))}
        <div
          className="absolute top-1/2 h-3.5 w-3.5 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-slate-950 bg-white shadow"
          style={{ left: pct(score) }}
        />
      </div>
      <div className="relative mt-1.5 h-4 font-mono text-[10px] text-slate-500">
        {[0, LEVEL2_SCORE, LEVEL3_SCORE, BLOCK_SCORE, MAX_SCORE].map((t) => (
          <span key={t} className="absolute -translate-x-1/2 first:translate-x-0 last:-translate-x-full" style={{ left: pct(t) }}>
            {t.toFixed(1)}
          </span>
        ))}
      </div>
    </div>
  );
}

function GuardrailNote({ e }: { e: DecisionEvent }) {
  const scoreHit = e.score >= BLOCK_SCORE;
  const confHit = e.confidence >= BLOCK_CONFIDENCE;
  const row = (ok: boolean, label: string, value: string) => (
    <div className="flex items-center justify-between font-mono text-xs">
      <span className="text-slate-400">{label}</span>
      <span className={ok ? "text-rose-300" : "text-slate-500"}>
        {value} {ok ? "✓" : "✗"}
      </span>
    </div>
  );
  return (
    <div className="mt-4 space-y-1.5 rounded-md bg-slate-900/80 p-3">
      {row(scoreHit, `S ≥ ${BLOCK_SCORE}`, e.score.toFixed(2))}
      {row(confHit, `C ≥ ${BLOCK_CONFIDENCE}`, e.confidence.toFixed(2))}
      <div className="border-t border-white/5 pt-2 text-xs text-slate-300">
        {e.downgraded ? (
          <span className="flex gap-1.5 text-amber-200">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            確信度不足のため自動遮断せず Level 3 に格下げ (誤遮断防止)。人間の承認待ち。
          </span>
        ) : (
          <span>
            判定: <span className={LEVEL_STYLE[e.level].text}>Level {e.level}</span> — {LEVEL_INFO[e.level].action}
          </span>
        )}
      </div>
    </div>
  );
}

export function FeatureRow({ label, display, norm, hint }: { label: string; display: string; norm: number; hint: string }) {
  return (
    <div>
      <div className="flex items-baseline justify-between">
        <span className="font-mono text-xs text-slate-300">{label}</span>
        <span className="font-mono text-sm tabular-nums text-slate-100">{display}</span>
      </div>
      <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full rounded-full ${norm >= 0.5 ? "bg-rose-400" : norm > 0 ? "bg-amber-400" : "bg-slate-600"}`}
          style={{ width: `${Math.max(norm * 100, 1)}%` }}
        />
      </div>
      <p className="mt-1 text-[11px] text-slate-500">{hint}</p>
    </div>
  );
}

export function DetailPanel({
  event,
  isDemo,
  ipAnalysis,
}: {
  event: DecisionEvent | undefined;
  isDemo: boolean;
  /** 同じ送信元の直近の LLM 分析 (このシグナル自体の分析が無い場合に表示する)。 */
  ipAnalysis?: LlmAnalysis | undefined;
}) {
  if (!event) {
    return (
      <aside className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-white/10 bg-slate-900/30 p-8 text-center text-sm text-slate-500">
        <MousePointerClick className="h-6 w-6" />
        シグナルを選択すると、Jev 判定の詳細と LLM 解析結果を表示します
      </aside>
    );
  }

  const { signal: s, features: f } = event;
  const [nErr, nDenied, nLatency] = normalizedFeatures(f);
  const code = s.response_context.status_code;

  return (
    <aside className="flex min-h-0 flex-col gap-3 overflow-auto rounded-xl border border-white/5 bg-slate-900/60 p-4">
      <header>
        <div className="flex items-center gap-2">
          <LevelBadge level={event.level} downgraded={event.downgraded} />
          <span className="font-mono text-xs text-slate-500">{fmtTime(s.timestamp)}</span>
        </div>
        <h2 className="mt-2 break-all font-mono text-sm text-slate-100">{s.request_context.method}</h2>
        <p className="mt-0.5 font-mono text-[11px] text-slate-500">signal {s.signal_id}</p>
      </header>

      <Card title="Jev 判定" icon={<ShieldCheck className="h-3.5 w-3.5" />}>
        <ScoreScale score={event.score} level={event.level} />
        <GuardrailNote e={event} />
      </Card>

      <Card title="Sliding Window 特徴量" icon={<Cpu className="h-3.5 w-3.5" />}>
        <div className="space-y-3">
          <FeatureRow
            label="ip_error_count_1m"
            display={String(f.ip_error_count_1m)}
            norm={nErr}
            hint={`同一 IP の 60 秒間の異常応答数 (${SATURATION.ip_error_count_1m} で最大寄与)`}
          />
          <FeatureRow
            label="unique_denied_methods_5m"
            display={String(f.unique_denied_methods_5m)}
            norm={nDenied}
            hint={`300 秒間に PERMISSION_DENIED を受けた API 数 (${SATURATION.unique_denied_methods_5m} で最大寄与)`}
          />
          <FeatureRow
            label="latency_spike_ratio"
            display={`×${f.latency_spike_ratio.toFixed(2)}`}
            norm={nLatency}
            hint={`平常時平均レイテンシ比 (×${SATURATION.latency_spike_ratio} で最大寄与)`}
          />
        </div>
      </Card>

      <Card title="LLM 要因解析" icon={<Bot className="h-3.5 w-3.5" />} aside={<LlmProviderBadge llm={event.llm ?? ipAnalysis} />}>
        <LlmAnalysisView
          llm={event.llm ?? ipAnalysis}
          {...(!event.llm && ipAnalysis && { note: "同じ送信元についての直近の分析です" })}
          emptyText={
            event.level === 1
              ? "Level 1 のシグナルは LLM 解析の対象外です。"
              : "このシグナルの LLM 分析はありません (同じ送信元を直近に分析済み、または LLM が無効)。"
          }
        />
      </Card>

      <Card title="シグナル" icon={<Fingerprint className="h-3.5 w-3.5" />}>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
          {(
            [
              ["client_ip", s.user_context.client_ip],
              ["user_id", s.user_context.user_id || "—"],
              ["user_agent", s.user_context.user_agent || "—"],
              ["source", s.source_service],
              ["status", `${code} ${GRPC_STATUS[code] ?? ""}`],
              ["latency", `${s.response_context.latency_ms} ms`],
              ["trace_id", s.trace_id || "—"],
            ] as const
          ).map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="font-mono text-slate-500">{k}</dt>
              <dd className="break-all font-mono text-slate-200">{v}</dd>
            </div>
          ))}
        </dl>
      </Card>

      {isDemo && <p className="text-center text-[10px] text-slate-600">表示中のデータはシミュレーターが生成したデモデータです</p>}
    </aside>
  );
}
