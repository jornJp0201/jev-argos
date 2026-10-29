import { useEffect, useRef, useState } from "react";
import type { DataSource, DecisionEvent, LlmAnalysis } from "../types";

/** 画面に保持するイベント数の上限 (古いものから捨てる)。 */
const MAX_EVENTS = 2_000;

export type StreamStatus = "connecting" | "live" | "offline";

/**
 * DataSource を購読し、新しい順のイベント一覧を返す。
 * paused 中も受信と集計は続け、一覧の表示だけを止める (再開時に追いつく)。
 * ipAnalyses は送信元 IP ごとの最新の LLM 分析 (同じ送信元の別のシグナルを選んでも参照できるように)。
 */
export function useSignalStream(source: DataSource, paused: boolean) {
  const store = useRef<DecisionEvent[]>([]);
  const seen = useRef(new Set<string>());
  const byIp = useRef(new Map<string, LlmAnalysis>());
  const [events, setEvents] = useState<DecisionEvent[]>([]);
  const [ipAnalyses, setIpAnalyses] = useState<ReadonlyMap<string, LlmAnalysis>>(new Map());
  const [status, setStatus] = useState<StreamStatus>("connecting");
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    let scheduled = false;
    const flush = () => {
      scheduled = false;
      if (!pausedRef.current) setEvents(store.current.slice());
      setIpAnalyses(new Map(byIp.current));
    };
    const schedule = () => {
      if (!scheduled) {
        scheduled = true;
        requestAnimationFrame(flush);
      }
    };
    const unsubscribe = source.subscribe({
      onEvent: (e) => {
        if (seen.current.has(e.signal.signal_id)) return; // 再接続時に送り直された判定
        seen.current.add(e.signal.signal_id);
        // 時刻順に並べる (再接続時の送り直しで古い判定が後から届くことがある)
        const t = Date.parse(e.signal.timestamp);
        let i = 0;
        while (i < store.current.length && Date.parse(store.current[i]!.signal.timestamp) > t) i++;
        store.current.splice(i, 0, e);
        while (store.current.length > MAX_EVENTS) seen.current.delete(store.current.pop()!.signal.signal_id);
        schedule();
      },
      onLlmUpdate: (id, ip, llm) => {
        const i = store.current.findIndex((e) => e.signal.signal_id === id);
        if (i >= 0) store.current[i] = { ...store.current[i]!, llm };
        if (llm.status !== "pending") byIp.current.set(ip, llm);
        schedule();
      },
      onStatus: setStatus,
    });
    return unsubscribe;
  }, [source]);

  useEffect(() => {
    if (!paused) setEvents(store.current.slice());
  }, [paused]);

  return { events, ipAnalyses, status };
}
