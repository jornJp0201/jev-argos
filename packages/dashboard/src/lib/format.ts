export const fmtTime = (iso: string) =>
  new Date(iso).toLocaleTimeString("ja-JP", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

export const fmtNum = (n: number) => n.toLocaleString("ja-JP");

/** "/admin.AdminService/ListUsers" → { service: "admin.AdminService", rpc: "ListUsers" } */
export function splitMethod(path: string): { service: string; rpc: string } {
  const [, service = "", rpc = path] = path.split("/");
  return { service, rpc };
}

export function fmtAgo(iso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 60) return `${s} 秒前`;
  if (s < 3600) return `${Math.floor(s / 60)} 分前`;
  return `${Math.floor(s / 3600)} 時間前`;
}
