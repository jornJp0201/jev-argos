// テスト・デモ用の BFF。@jornjp/adapter-node を Express に組み込む例で、本番用ではない。
//
// 認証・データはすべてダミー (x-user-id ヘッダーでユーザーを名乗れる)。
// jev-argos の組み込みに関係するのは「jev-argos の組み込み」の 3 か所だけで、それ以外は攻撃の的になる普通の API。
//
//   node examples/express-bff/server.js        (http://localhost:4000)

import express from "express";
import { BlocklistWatcher, SignalReporter, createExpressMiddleware } from "@jornjp/adapter-node";

const PORT = Number(process.env.PORT ?? 4000);
const JEV_ARGOS_TARGET = process.env.JEV_ARGOS_TARGET ?? "localhost:50051";

// --- jev-argos の組み込み (1/3): シグナルの送信と遮断リストの購読 ---
// onResponse / onChange は任意 (ここでは録画で見やすいよう、変化があったときだけログを出している)
const level4 = new Set();
const reporter = new SignalReporter({
  target: JEV_ARGOS_TARGET,
  onResponse: (res, signal) => {
    const ip = signal.user_context?.client_ip;
    if (res.immediate_action_level >= 4 && !level4.has(ip)) {
      level4.add(ip);
      console.log(`[jev-argos] Level 4: ${ip} は危険と判定されました (以降のリクエストは遮断)`);
    }
  },
});
let blocked = "";
const blocklist = new BlocklistWatcher({
  target: JEV_ARGOS_TARGET,
  onChange: (entries) => {
    const now = entries.map((e) => e.target).sort().join(", ") || "(なし)";
    if (now !== blocked) console.log(`[jev-argos] 遮断リスト: ${(blocked = now)}`);
    for (const ip of level4) if (!entries.some((e) => e.target === ip)) level4.delete(ip); // 解除されたら再び通知する
  },
});

const app = express();

// [差し替えポイント] テスト用の設定。1 台のマシンから複数の送信元を再現できるよう、X-Forwarded-For を信頼する。
// 本番では信頼できるロードバランサーの背後でのみ有効にすること (攻撃者がヘッダーで IP を偽装できるため)。
app.set("trust proxy", process.env.TRUST_PROXY !== "false");

// --- jev-argos の組み込み (2/3): ルートより前にミドルウェアを登録する ---
app.use(createExpressMiddleware(reporter, { sourceService: "example-bff", blocklist }));

// リクエストのログ (録画で見やすくするため)
app.use((req, res, next) => {
  res.on("finish", () => console.log(`${res.statusCode} ${req.method} ${req.originalUrl}  from ${req.ip}`));
  next();
});

app.use(express.json());

// --- ここから下は普通のアプリ (ダミー) ---

const USERS = {
  alice: { id: "alice", name: "Alice", role: "admin", password: "alice-pass" },
  bob: { id: "bob", name: "Bob", role: "user", password: "bob-pass" },
};

// ダミーの認証: x-user-id ヘッダーでユーザーを名乗る
function currentUser(req) {
  return USERS[req.get("x-user-id") ?? ""];
}
function requireLogin(req, res, next) {
  if (!currentUser(req)) return res.status(401).json({ error: "unauthenticated" });
  next();
}
function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "unauthenticated" });
  if (user.role !== "admin") return res.status(403).json({ error: "admin only" });
  next();
}

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.post("/api/login", (req, res) => {
  const user = USERS[req.body?.id];
  if (!user || user.password !== req.body?.password) return res.status(401).json({ error: "invalid credentials" });
  res.json({ id: user.id, name: user.name });
});

app.get("/api/me", requireLogin, (req, res) => {
  const { password: _, ...user } = currentUser(req);
  res.json(user);
});

app.get("/api/products", (_req, res) =>
  res.json([
    { id: 1, name: "Keyboard", price: 12000 },
    { id: 2, name: "Mouse", price: 4000 },
  ]),
);

app.get("/api/orders/:id", requireLogin, (req, res) => res.json({ id: req.params.id, owner: currentUser(req).id, total: 16000 }));

// 管理者専用の API (一般ユーザーが叩くと 403)
app.get("/api/admin/users", requireAdmin, (_req, res) => res.json(Object.values(USERS).map(({ password: _, ...u }) => u)));
app.get("/api/admin/audit-logs", requireAdmin, (_req, res) => res.json([]));
app.get("/api/admin/settings", requireAdmin, (_req, res) => res.json({ maintenance: false }));
app.post("/api/admin/export", requireAdmin, (_req, res) => res.json({ exported: true }));
app.delete("/api/admin/users/:id", requireAdmin, (req, res) => res.json({ deleted: req.params.id }));

const server = app.listen(PORT, () => {
  console.log(`example BFF (テスト用) listening on http://localhost:${PORT}  →  jev-argos: ${JEV_ARGOS_TARGET}`);
});

// --- jev-argos の組み込み (3/3): 終了時に送信中のシグナルを送り切る ---
async function shutdown() {
  server.close();
  blocklist.close();
  await reporter.close();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
