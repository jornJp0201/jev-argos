import { useCallback, useEffect, useState } from "react";
import { actionsApi, type PendingAction } from "./actionsApi";

export type ConnectionState = "connecting" | "live" | "offline";

/**
 * 承認待ちアクションを一覧取得し、SSE で作成・更新をリアルタイムに反映する。
 * 再接続のたびに一覧を取り直し、切断中に取りこぼした更新も反映する。
 */
export function useActions() {
  const [actions, setActions] = useState<Map<string, PendingAction>>(new Map());
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [error, setError] = useState<string>();

  const upsert = useCallback((a: PendingAction) => {
    setActions((prev) => {
      const cur = prev.get(a.action_id);
      // SSE と API 応答の到着順が前後しても、古い状態で上書きしない
      if (cur && Date.parse(cur.updated_at) > Date.parse(a.updated_at)) return prev;
      return new Map(prev).set(a.action_id, a);
    });
  }, []);

  useEffect(() => {
    let disposed = false;
    const reload = () =>
      actionsApi
        .list()
        .then((list) => {
          if (disposed) return;
          setActions(new Map(list.map((a) => [a.action_id, a])));
          setError(undefined);
        })
        .catch((e: Error) => !disposed && setError(e.message));

    const unsubscribe = actionsApi.subscribe({
      onOpen: () => {
        setConnection("live");
        void reload();
      },
      onError: () => setConnection("offline"),
      onAction: upsert,
    });
    void reload();
    return () => {
      disposed = true;
      unsubscribe();
    };
  }, [upsert]);

  const sorted = [...actions.values()].sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at));
  return {
    pending: sorted.filter((a) => a.status === "pending"),
    decided: sorted.filter((a) => a.status !== "pending"),
    connection,
    error,
    upsert,
  };
}
