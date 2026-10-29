import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { describe, it } from "node:test";
import { createExpressMiddleware, withJevArgos, type ExpressLikeRequest } from "../middleware.js";
import type { BlockChecker } from "../blocklist.js";
import type { Reporter } from "../reporter.js";
import type { SecuritySignal } from "../signal.js";

class MemoryReporter implements Reporter {
  signals: SecuritySignal[] = [];
  report(s: SecuritySignal): void {
    this.signals.push(s);
  }
}

class FakeResponse extends EventEmitter {
  statusCode = 200;
  headers: Record<string, string> = {};
  body: string | undefined;
  setHeader(name: string, value: string) {
    this.headers[name] = value;
  }
  end(chunk: string) {
    this.body = chunk;
    this.emit("finish");
  }
}

function fakeExpress(overrides: Partial<ExpressLikeRequest> = {}) {
  const req: ExpressLikeRequest = {
    method: "GET",
    ip: "::ffff:198.51.100.7",
    baseUrl: "/api",
    get: (name) => (name === "user-agent" ? "curl/8.7" : undefined),
    ...overrides,
  };
  const res = new FakeResponse();
  return { req, res };
}

describe("createExpressMiddleware", () => {
  it("reports after the response finishes, using the matched route pattern", () => {
    const reporter = new MemoryReporter();
    const mw = createExpressMiddleware(reporter, { sourceService: "main-bff" });
    const { req, res } = fakeExpress();
    let nextCalled = false;

    mw(req, res, () => (nextCalled = true));
    assert.ok(nextCalled, "next() must be called");
    assert.equal(reporter.signals.length, 0, "nothing is sent before the response finishes");

    req.route = { path: "/users/:id" }; // ルーティング後に Express が設定する
    res.statusCode = 403;
    res.emit("finish");

    const s = reporter.signals[0]!;
    assert.equal(s.request_context.method, "GET /api/users/:id");
    assert.equal(s.response_context.status_code, 7);
    assert.equal(s.user_context.client_ip, "198.51.100.7");
    assert.equal(s.user_context.user_agent, "curl/8.7");
    assert.equal(s.source_service, "main-bff");
  });

  it("labels requests that matched no route", () => {
    const reporter = new MemoryReporter();
    const { req, res } = fakeExpress();
    createExpressMiddleware(reporter, { sourceService: "bff" })(req, res, () => {});
    res.statusCode = 404;
    res.emit("finish");
    assert.equal(reporter.signals[0]!.request_context.method, "GET (unmatched)");
  });
});

describe("withJevArgos", () => {
  const opts = { route: "/api/users/[id]", sourceService: "main-bff" };

  it("returns the handler's response and reports its status", async () => {
    const reporter = new MemoryReporter();
    const handler = withJevArgos(reporter, opts, async (_req: Request, ctx: { params: Promise<{ id: string }> }) =>
      Response.json({ id: (await ctx.params).id }, { status: 201 }),
    );
    const req = new Request("http://localhost/api/users/42", {
      method: "POST",
      headers: { "x-forwarded-for": "203.0.113.9, 10.0.0.1", "user-agent": "next-test" },
    });

    const res = await handler(req, { params: Promise.resolve({ id: "42" }) });
    assert.equal(res.status, 201);
    assert.deepEqual(await res.json(), { id: "42" });

    const s = reporter.signals[0]!;
    assert.equal(s.request_context.method, "POST /api/users/[id]");
    assert.equal(s.response_context.status_code, 0);
    assert.equal(s.user_context.client_ip, "203.0.113.9");
    assert.equal(s.user_context.user_agent, "next-test");
  });

  it("reports 500 and rethrows when the handler throws", async () => {
    const reporter = new MemoryReporter();
    const handler = withJevArgos(reporter, opts, async () => {
      throw new Error("boom");
    });
    await assert.rejects(handler(new Request("http://localhost/x")), /boom/);
    assert.equal(reporter.signals[0]!.response_context.status_code, 13);
  });

  it("uses a custom client IP resolver", async () => {
    const reporter = new MemoryReporter();
    const handler = withJevArgos(reporter, { ...opts, getClientIp: () => "192.0.2.1" }, () => new Response("ok"));
    await handler(new Request("http://localhost/x", { headers: { "x-forwarded-for": "6.6.6.6" } }));
    assert.equal(reporter.signals[0]!.user_context.client_ip, "192.0.2.1");
  });
});

const blockOnly = (ip: string): BlockChecker => ({ isBlocked: (x) => x === ip });

describe("blocking", () => {
  it("Express: rejects blocked IPs with 403 without calling next, and still reports", () => {
    const reporter = new MemoryReporter();
    const mw = createExpressMiddleware(reporter, { sourceService: "bff", blocklist: blockOnly("198.51.100.7") });
    const { req, res } = fakeExpress(); // req.ip は "::ffff:198.51.100.7" (正規化して照合する)
    let nextCalled = false;
    mw(req, res, () => (nextCalled = true));

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 403);
    assert.equal(res.body, JSON.stringify({ error: "forbidden" }));
    assert.equal(reporter.signals[0]!.response_context.status_code, 7);
  });

  it("Express: lets other IPs through and supports a custom response", () => {
    const reporter = new MemoryReporter();
    const { req, res } = fakeExpress({ ip: "10.0.0.1" });
    let nextCalled = false;
    createExpressMiddleware(reporter, { sourceService: "bff", blocklist: blockOnly("198.51.100.7") })(req, res, () => (nextCalled = true));
    assert.ok(nextCalled);

    const blocked = fakeExpress();
    createExpressMiddleware(reporter, {
      sourceService: "bff",
      blocklist: blockOnly("198.51.100.7"),
      onBlocked: (_req, r) => {
        r.statusCode = 429;
        r.end("slow down");
      },
    })(blocked.req, blocked.res, () => {});
    assert.equal(blocked.res.statusCode, 429);
    assert.equal(blocked.res.body, "slow down");
  });

  it("Next.js: returns 403 without calling the handler", async () => {
    const reporter = new MemoryReporter();
    let called = false;
    const handler = withJevArgos(reporter, { route: "/x", sourceService: "bff", blocklist: blockOnly("203.0.113.9") }, () => {
      called = true;
      return new Response("ok");
    });
    const res = await handler(new Request("http://localhost/x", { headers: { "x-forwarded-for": "203.0.113.9" } }));
    assert.equal(res.status, 403);
    assert.equal(called, false);
    assert.equal(reporter.signals[0]!.response_context.status_code, 7);
  });
});
