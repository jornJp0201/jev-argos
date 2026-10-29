import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import * as grpc from "@grpc/grpc-js";
import { createClientInterceptor, createServerInterceptor } from "../interceptor.js";
import type { Reporter } from "../reporter.js";
import { SignalReporter } from "../reporter.js";
import type { SecuritySignal } from "../signal.js";
import { newEchoClient, say, startApp, startCollector, type Collector } from "./helpers.js";

/** 受け取ったシグナルを配列に貯める Reporter。 */
class MemoryReporter implements Reporter {
  signals: SecuritySignal[] = [];
  report(s: SecuritySignal): void {
    this.signals.push(s);
  }
}

async function until(cond: () => boolean, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe("createServerInterceptor", () => {
  const reporter = new MemoryReporter();
  let app: Awaited<ReturnType<typeof startApp>>;

  before(async () => {
    app = await startApp([createServerInterceptor(reporter, { sourceService: "payment-backend" })]);
  });
  after(() => app.close());

  it("reports IP, user agent, status and latency of a successful call", async () => {
    reporter.signals = [];
    const client = newEchoClient(app.target, { "grpc.primary_user_agent": "main-bff/2.3" });
    const md = new grpc.Metadata();
    md.set("authorization", "Bearer token-123");
    const { err, res } = await say(client, "slow:30", md);
    client.close();

    assert.equal(err, null);
    assert.equal(res?.toString(), "echo:slow:30");
    await until(() => reporter.signals.length === 1);
    const s = reporter.signals[0]!;
    assert.equal(s.source_service, "payment-backend");
    assert.equal(s.request_context.method, "/test.EchoService/Say");
    assert.equal(s.user_context.client_ip, "127.0.0.1");
    assert.match(s.user_context.user_agent, /^main-bff\/2\.3/);
    assert.match(s.user_context.session_hash, /^[0-9a-f]{32}$/);
    assert.equal(s.response_context.status_code, 0);
    assert.ok(s.response_context.latency_ms >= 25, `latency ${s.response_context.latency_ms}ms`);
  });

  it("reports PERMISSION_DENIED and keeps the app's error unchanged", async () => {
    reporter.signals = [];
    const client = newEchoClient(app.target);
    const { err } = await say(client, "deny");
    client.close();

    assert.equal(err?.code, grpc.status.PERMISSION_DENIED);
    assert.equal(err?.details, "user 42 may not access /admin");
    await until(() => reporter.signals.length === 1);
    assert.equal(reporter.signals[0]!.response_context.status_code, grpc.status.PERMISSION_DENIED);
    assert.equal(reporter.signals[0]!.response_context.error_message, "", "error message is opt-in");
  });

  it("reports calls the client cancels", async () => {
    reporter.signals = [];
    const client = newEchoClient(app.target);
    const call = client.Say(Buffer.from("slow:500"), new grpc.Metadata(), {}, () => {});
    setTimeout(() => call.cancel(), 20);
    await until(() => reporter.signals.length === 1);
    client.close();
    assert.equal(reporter.signals[0]!.response_context.status_code, grpc.status.CANCELLED);
  });

  it("does not trust x-forwarded-for unless configured", async () => {
    reporter.signals = [];
    const client = newEchoClient(app.target);
    const md = new grpc.Metadata();
    md.set("x-forwarded-for", "203.0.113.9");
    await say(client, "hi", md);
    client.close();
    await until(() => reporter.signals.length === 1);
    assert.equal(reporter.signals[0]!.user_context.client_ip, "127.0.0.1");
  });
});

describe("createServerInterceptor resilience", () => {
  it("keeps serving when reporting throws", async () => {
    const throwing: Reporter = {
      report() {
        throw new Error("reporter broken");
      },
    };
    const app = await startApp([createServerInterceptor(throwing, { sourceService: "bff" })]);
    const client = newEchoClient(app.target);
    const { err, res } = await say(client, "hi");
    client.close();
    app.close();
    assert.equal(err, null);
    assert.equal(res?.toString(), "echo:hi");
  });
});

describe("createClientInterceptor", () => {
  it("reports outgoing calls with the end-user IP propagated by the BFF", async () => {
    const reporter = new MemoryReporter();
    const app = await startApp();
    const client = newEchoClient(app.target, {
      interceptors: [
        createClientInterceptor(reporter, {
          sourceService: "main-bff",
          extractUser: (md) => ({ userId: md.get("x-user-id")[0] as string | undefined }),
        }),
      ],
    });
    const md = new grpc.Metadata();
    md.set("x-forwarded-for", "198.51.100.7");
    md.set("x-user-id", "user-42");
    const { err } = await say(client, "deny", md);
    client.close();
    app.close();

    assert.equal(err?.code, grpc.status.PERMISSION_DENIED);
    await until(() => reporter.signals.length === 1);
    const s = reporter.signals[0]!;
    assert.equal(s.user_context.client_ip, "198.51.100.7");
    assert.equal(s.user_context.user_id, "user-42");
    assert.equal(s.request_context.method, "/test.EchoService/Say");
    assert.equal(s.response_context.status_code, grpc.status.PERMISSION_DENIED);
  });
});

describe("end to end: app → interceptor → SignalReporter → control server", () => {
  let collector: Collector;
  before(async () => {
    collector = await startCollector();
  });
  after(() => collector.close());

  it("delivers signals for every call without affecting responses", async () => {
    const reporter = new SignalReporter({ target: collector.target });
    const app = await startApp([createServerInterceptor(reporter, { sourceService: "bff" })]);
    const client = newEchoClient(app.target);

    const results = await Promise.all(["a", "deny", "b"].map((body) => say(client, body)));
    assert.deepEqual(
      results.map((r) => r.err?.code ?? 0),
      [0, grpc.status.PERMISSION_DENIED, 0],
    );

    const signals = await collector.waitFor(3);
    assert.deepEqual(signals.map((s) => s.response_context.status_code).sort(), [0, 0, 7]);
    client.close();
    app.close();
    await reporter.close();
  });

  it("app keeps working when the control server is unreachable", async () => {
    const reporter = new SignalReporter({ target: "127.0.0.1:1", timeoutMs: 100 });
    const app = await startApp([createServerInterceptor(reporter, { sourceService: "bff" })]);
    const client = newEchoClient(app.target);
    const { err, res } = await say(client, "hi");
    client.close();
    app.close();
    await reporter.close();

    assert.equal(err, null);
    assert.equal(res?.toString(), "echo:hi");
    assert.equal(reporter.stats.failed, 1);
  });
});
