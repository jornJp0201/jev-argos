import assert from "node:assert/strict";
import { describe, it } from "node:test";
import * as grpc from "@grpc/grpc-js";
import { BlocklistWatcher } from "../blocklist.js";
import { createServerInterceptor } from "../interceptor.js";
import type { Reporter } from "../reporter.js";
import type { SecuritySignal } from "../signal.js";
import { newEchoClient, say, startApp, startControl } from "./helpers.js";

async function until(cond: () => boolean, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 5));
  }
}

const entry = (ip: string, expires = 0) => ({ target_type: "ip", target: ip, reason: "test", source: "jev_level4", expires_at_unix_ms: expires });

describe("BlocklistWatcher", () => {
  it("loads the snapshot and follows additions and removals", async () => {
    const control = await startControl([entry("203.0.113.9")]);
    const changes: number[] = [];
    const watcher = new BlocklistWatcher({ target: control.target, onChange: (list) => changes.push(list.length) });
    try {
      await until(() => watcher.ready);
      assert.ok(watcher.isBlocked("203.0.113.9"));
      assert.ok(watcher.isBlocked("::ffff:203.0.113.9"), "IPv4-mapped form is normalized");
      assert.equal(watcher.isBlocked("10.0.0.1"), false);

      control.push("ADDED", [entry("10.0.0.1")]);
      await until(() => watcher.isBlocked("10.0.0.1"));
      control.push("REMOVED", [entry("203.0.113.9")]);
      await until(() => !watcher.isBlocked("203.0.113.9"));
      assert.deepEqual(changes, [1, 2, 1]);
    } finally {
      watcher.close();
      control.close();
    }
  });

  it("treats expired entries as unblocked", async () => {
    const control = await startControl([entry("10.0.0.1", Date.now() - 1), entry("10.0.0.2", Date.now() + 60_000)]);
    const watcher = new BlocklistWatcher({ target: control.target });
    try {
      await until(() => watcher.ready);
      assert.equal(watcher.isBlocked("10.0.0.1"), false);
      assert.ok(watcher.isBlocked("10.0.0.2"));
      assert.deepEqual(watcher.list().map((e) => e.target), ["10.0.0.2"]);
    } finally {
      watcher.close();
      control.close();
    }
  });

  it("reconnects when the stream ends and receives a fresh snapshot", async () => {
    const control = await startControl([entry("10.0.0.1")]);
    const watcher = new BlocklistWatcher({ target: control.target, maxReconnectDelayMs: 50 });
    try {
      await until(() => watcher.ready && control.connections === 1);
      control.endStreams();
      await until(() => control.connections === 2);
      control.push("ADDED", [entry("10.0.0.2")]);
      await until(() => watcher.isBlocked("10.0.0.2"));
      assert.ok(watcher.isBlocked("10.0.0.1"));
    } finally {
      watcher.close();
      control.close();
    }
  });
});

describe("createServerInterceptor with blocklist", () => {
  it("rejects blocked IPs with PERMISSION_DENIED before the handler runs", async () => {
    const signals: SecuritySignal[] = [];
    const reporter: Reporter = { report: (s) => void signals.push(s) };
    const app = await startApp([
      createServerInterceptor(reporter, { sourceService: "bff", blocklist: { isBlocked: (ip) => ip === "127.0.0.1" } }),
    ]);
    const client = newEchoClient(app.target);
    const { err } = await say(client, "hi");
    client.close();
    app.close();

    assert.equal(err?.code, grpc.status.PERMISSION_DENIED);
    assert.equal(err?.details, "blocked by jev-argos");
    await until(() => signals.length === 1);
    assert.equal(signals[0]!.response_context.status_code, grpc.status.PERMISSION_DENIED);
  });
});
