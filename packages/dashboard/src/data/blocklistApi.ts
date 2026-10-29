// 遮断リスト (GET/POST/DELETE /api/blocklist, GET /api/blocklist/stream)。

import { useCallback, useEffect, useState } from "react";
import { ApiError } from "./actionsApi";

export interface BlockEntry {
  target_type: string;
  target: string;
  reason: string;
  source: "jev_level4" | "approval" | "admin" | string;
  created_at: string;
  expires_at?: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, headers: { "Content-Type": "application/json", ...init?.headers } });
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, (body as { error?: string }).error ?? `HTTP ${res.status}`);
  return body as T;
}

export const blocklistApi = {
  list: () => request<{ entries: BlockEntry[] }>("/api/blocklist").then((r) => r.entries),
  block: (target: string, ttlSeconds: number, reason: string, createdBy: string) =>
    request<BlockEntry>("/api/blocklist", {
      method: "POST",
      body: JSON.stringify({ target, ttl_seconds: ttlSeconds, reason, created_by: createdBy }),
    }),
  unblock: (target: string, targetType = "ip") =>
    request<void>(`/api/blocklist?target_type=${encodeURIComponent(targetType)}&target=${encodeURIComponent(target)}`, {
      method: "DELETE",
    }),
};

const key = (e: Pick<BlockEntry, "target_type" | "target">) => `${e.target_type}:${e.target}`;

/** 遮断リストを取得し、SSE で追加・解除を反映する。期限切れは手元で取り除く。 */
export function useBlocklist() {
  const [entries, setEntries] = useState<Map<string, BlockEntry>>(new Map());
  const [error, setError] = useState<string>();
  const [now, setNow] = useState(() => Date.now());

  const reload = useCallback(
    () =>
      blocklistApi
        .list()
        .then((list) => {
          setEntries(new Map(list.map((e) => [key(e), e])));
          setError(undefined);
        })
        .catch((e: Error) => setError(e.message)),
    [],
  );

  useEffect(() => {
    const es = new EventSource("/api/blocklist/stream");
    es.addEventListener("open", () => void reload());
    es.addEventListener("block", (ev) => {
      const { kind, entry } = JSON.parse((ev as MessageEvent<string>).data) as { kind: "added" | "removed"; entry: BlockEntry };
      setEntries((prev) => {
        const next = new Map(prev);
        if (kind === "removed") next.delete(key(entry));
        else next.set(key(entry), entry);
        return next;
      });
    });
    void reload();
    const t = setInterval(() => setNow(Date.now()), 1_000);
    return () => {
      es.close();
      clearInterval(t);
    };
  }, [reload]);

  const active = [...entries.values()]
    .filter((e) => !e.expires_at || Date.parse(e.expires_at) > now)
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  return { entries: active, error, now };
}
