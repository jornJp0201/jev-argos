import { Radar } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { ActionModal } from "./components/ActionModal";
import { BlocklistPanel } from "./components/BlocklistPanel";
import { CreateActionModal } from "./components/CreateActionModal";
import { DetailPanel } from "./components/DetailPanel";
import { Overview } from "./components/Overview";
import { PendingActions } from "./components/PendingActions";
import { SignalTable } from "./components/SignalTable";
import { ApiDataSource } from "./data/apiSource";
import { DemoDataSource } from "./data/demoSource";
import { useActions } from "./data/useActions";
import { useSignalStream, type StreamStatus } from "./data/useSignalStream";
import type { DataSource, DecisionEvent } from "./types";

// シグナルの取得元。既定はコントロールサーバー (/api/events/stream)。
// VITE_JEV_ARGOS_DEMO=true で起動すると、サーバー無しでシミュレーターのデモデータを表示する。
// [差し替えポイント] 独自の配信基盤を使う場合は DataSource を実装してここで指定する。
const source: DataSource = import.meta.env.VITE_JEV_ARGOS_DEMO === "true" ? new DemoDataSource() : new ApiDataSource();

function SourcePill({ status, paused }: { status: StreamStatus; paused: boolean }) {
  if (source.isDemo) {
    return (
      <span className="rounded-full bg-violet-500/10 px-2.5 py-1 font-medium text-violet-300 ring-1 ring-inset ring-violet-400/30">
        シグナル: {source.label}
      </span>
    );
  }
  const [dot, text, label] =
    status === "live"
      ? ["animate-pulse bg-emerald-400", "text-emerald-300 ring-emerald-400/30 bg-emerald-500/10", paused ? "Paused" : "Live"]
      : status === "connecting"
        ? ["bg-slate-400", "text-slate-300 ring-white/15 bg-slate-500/10", "接続中…"]
        : ["bg-rose-500", "text-rose-300 ring-rose-400/30 bg-rose-500/10", "サーバー未接続"];
  return (
    <span className={`flex items-center gap-1.5 rounded-full px-2.5 py-1 font-medium ring-1 ring-inset ${text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${paused && status === "live" ? "bg-amber-400" : dot}`} />
      {label}
    </span>
  );
}

export function App() {
  const [paused, setPaused] = useState(false);
  const { events, ipAnalyses, status } = useSignalStream(source, paused);
  const [selectedId, setSelectedId] = useState<string>();
  const lastSelected = useRef<DecisionEvent>();
  const actions = useActions();
  const [openActionId, setOpenActionId] = useState<string>();
  const [creating, setCreating] = useState(false);
  // モーダルは ID だけを持ち、表示内容は常に最新の状態 (SSE で届いた他の管理者の決定・実行結果を含む) から引く
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
    <div className="flex min-h-screen flex-col gap-4 bg-[radial-gradient(ellipse_at_top,rgba(56,189,248,0.07),transparent_55%)] p-4 lg:h-screen lg:p-6">
      <header className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2.5">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-sky-500/10 ring-1 ring-inset ring-sky-400/30">
            <Radar className="h-5 w-5 text-sky-300" />
          </div>
          <div>
            <h1 className="text-base font-semibold tracking-tight text-slate-50">Jev-Argos Control</h1>
            <p className="text-xs text-slate-500">Security control plane · Jev classifier + LLM + human-in-the-loop</p>
          </div>
        </div>
        <div className="ml-auto flex items-center gap-2 text-xs">
          <SourcePill status={status} paused={paused} />
        </div>
      </header>

      <Overview events={events} />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <PendingActions
          pending={actions.pending}
          decided={actions.decided}
          connection={actions.connection}
          error={actions.error}
          onOpen={(a) => setOpenActionId(a.action_id)}
          onCreate={() => setCreating(true)}
        />
        <BlocklistPanel />
      </div>

      <main className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[minmax(0,1fr)_400px]">
        <SignalTable
          events={events}
          selectedId={selectedId}
          onSelect={(e) => setSelectedId(e.signal.signal_id)}
          paused={paused}
          onTogglePause={() => setPaused((p) => !p)}
        />
        <DetailPanel event={selected} isDemo={source.isDemo} ipAnalysis={selected && ipAnalyses.get(selected.signal.user_context.client_ip)} />
      </main>

      {openAction && <ActionModal action={openAction} onClose={() => setOpenActionId(undefined)} onDecided={actions.upsert} />}
      {creating && (
        <CreateActionModal
          onClose={() => setCreating(false)}
          onCreated={(a) => {
            actions.upsert(a);
            setCreating(false);
            setOpenActionId(a.action_id);
          }}
        />
      )}
    </div>
  );
}
