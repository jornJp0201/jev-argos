import { Radar } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { ActionModal } from "./components/ActionModal";
import { DetailPanel } from "./components/DetailPanel";
import { Overview } from "./components/Overview";
import { PendingActions } from "./components/PendingActions";
import { SignalTable } from "./components/SignalTable";
import { DemoDataSource } from "./data/demoSource";
import { useActions } from "./data/useActions";
import { useSignalStream } from "./data/useSignalStream";
import type { DataSource, DecisionEvent } from "./types";

// コントロールサーバーに読み出し API ができたら、ここを API 実装の DataSource に差し替える。
const source: DataSource = new DemoDataSource();

export function App() {
  const [paused, setPaused] = useState(false);
  const events = useSignalStream(source, paused);
  const [selectedId, setSelectedId] = useState<string>();
  const lastSelected = useRef<DecisionEvent>();
  const actions = useActions();
  const [openActionId, setOpenActionId] = useState<string>();
  // モーダルは ID だけを持ち、表示内容は常に最新の状態 (SSE で届いた他の管理者の決定を含む) から引く
  const openAction = openActionId
    ? (actions.pending.find((a) => a.action_id === openActionId) ?? actions.decided.find((a) => a.action_id === openActionId))
    : undefined;

  // 選択中のイベントは一覧の最新状態 (LLM 解析結果の反映) を使い、一覧から押し出された後も表示を保つ
  const selected = useMemo(() => {
    const found = selectedId ? events.find((e) => e.signal.signal_id === selectedId) : undefined;
    if (found) lastSelected.current = found;
    return selectedId ? (found ?? lastSelected.current) : undefined;
  }, [events, selectedId]);

  return (
    <div className="flex h-screen flex-col gap-4 bg-[radial-gradient(ellipse_at_top,rgba(56,189,248,0.07),transparent_55%)] p-4 lg:p-6">
      <header className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2.5">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-sky-500/10 ring-1 ring-inset ring-sky-400/30">
            <Radar className="h-5 w-5 text-sky-300" />
          </div>
          <div>
            <h1 className="text-base font-semibold tracking-tight text-slate-50">Jev-Argos Control</h1>
            <p className="text-xs text-slate-500">Security control plane · Jev classifier + guardrails</p>
          </div>
        </div>
        <div className="ml-auto flex items-center gap-2 text-xs">
          {source.isDemo && (
            <span className="rounded-full bg-violet-500/10 px-2.5 py-1 font-medium text-violet-300 ring-1 ring-inset ring-violet-400/30">
              シグナル: {source.label}
            </span>
          )}
          <span
            className={`flex items-center gap-1.5 rounded-full px-2.5 py-1 font-medium ring-1 ring-inset ${
              paused ? "bg-amber-500/10 text-amber-300 ring-amber-400/30" : "bg-emerald-500/10 text-emerald-300 ring-emerald-400/30"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${paused ? "bg-amber-400" : "animate-pulse bg-emerald-400"}`} />
            {paused ? "Paused" : "Live"}
          </span>
        </div>
      </header>

      <Overview events={events} />

      <PendingActions
        pending={actions.pending}
        decided={actions.decided}
        connection={actions.connection}
        error={actions.error}
        onOpen={(a) => setOpenActionId(a.action_id)}
      />

      <main className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[minmax(0,1fr)_400px]">
        <SignalTable
          events={events}
          selectedId={selectedId}
          onSelect={(e) => setSelectedId(e.signal.signal_id)}
          paused={paused}
          onTogglePause={() => setPaused((p) => !p)}
        />
        <DetailPanel event={selected} isDemo={source.isDemo} />
      </main>

      {openAction && <ActionModal action={openAction} onClose={() => setOpenActionId(undefined)} onDecided={actions.upsert} />}
    </div>
  );
}
