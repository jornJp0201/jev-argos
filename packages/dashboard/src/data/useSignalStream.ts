import { useEffect, useRef, useState } from "react";
import type { DataSource, DecisionEvent } from "../types";

/** 画面に保持するイベント数の上限 (古いものから捨てる)。 */
const MAX_EVENTS = 2_000;

/**
 * DataSource を購読し、新しい順のイベント一覧を返す。
 * paused 中も受信と集計は続け、一覧の表示だけを止める (再開時に追いつく)。
 */
export function useSignalStream(source: DataSource, paused: boolean) {
  const store = useRef<DecisionEvent[]>([]);
  const [events, setEvents] = useState<DecisionEvent[]>([]);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    let scheduled = false;
    const flush = () => {
      scheduled = false;
      if (!pausedRef.current) setEvents(store.current.slice());
    };
    const schedule = () => {
      if (!scheduled) {
        scheduled = true;
        requestAnimationFrame(flush);
      }
    };
    const unsubscribe = source.subscribe({
      onEvent: (e) => {
        store.current.unshift(e);
        if (store.current.length > MAX_EVENTS) store.current.length = MAX_EVENTS;
        schedule();
      },
      onLlmUpdate: (id, llm) => {
        const i = store.current.findIndex((e) => e.signal.signal_id === id);
        if (i >= 0) store.current[i] = { ...store.current[i]!, llm };
        schedule();
      },
    });
    return unsubscribe;
  }, [source]);

  useEffect(() => {
    if (!paused) setEvents(store.current.slice());
  }, [paused]);

  return events;
}
