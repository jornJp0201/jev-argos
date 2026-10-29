import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SignalReporter } from "../reporter.js";
import { buildSignal, type ReportResponse, type SecuritySignal } from "../signal.js";
import { Metadata } from "@grpc/grpc-js";
import { startCollector } from "./helpers.js";

function signal(method = "/a.A/Get"): SecuritySignal {
  return buildSignal(
    { method, metadata: new Metadata(), connectionIp: "10.0.0.1", statusCode: 0, errorMessage: "", latencyMs: 1 },
    { sourceService: "test" },
  );
}

describe("SignalReporter", () => {
  it("returns immediately and sends in the background", async () => {
    const collector = await startCollector();
    const reporter = new SignalReporter({ target: collector.target });
    try {
      reporter.report(signal("/a.A/One"));
      assert.equal(collector.signals.length, 0, "must not send synchronously");
      assert.equal(reporter.stats.inFlight, 1);

      const [got] = await collector.waitFor(1);
      assert.equal(got?.request_context.method, "/a.A/One");
      await reporter.close();
      assert.deepEqual(reporter.stats, { sent: 1, failed: 0, dropped: 0, inFlight: 0 });
    } finally {
      collector.close();
    }
  });

  it("passes the server response (immediate_action_level) to onResponse", async () => {
    const collector = await startCollector(() => ({ accepted: true, immediate_action_level: 4 }));
    const responses: ReportResponse[] = [];
    const reporter = new SignalReporter({ target: collector.target, onResponse: (res) => responses.push(res) });
    try {
      reporter.report(signal());
      await reporter.close();
      assert.deepEqual(responses, [{ accepted: true, immediate_action_level: 4 }]);
    } finally {
      collector.close();
    }
  });

  it("absorbs failures when the control server is down", async () => {
    const collector = await startCollector();
    const target = collector.target;
    collector.close();

    const errors: Error[] = [];
    const reporter = new SignalReporter({
      target,
      timeoutMs: 200,
      onError: (err) => {
        errors.push(err);
        throw new Error("callback errors are swallowed too");
      },
    });
    assert.doesNotThrow(() => reporter.report(signal()));
    await reporter.close();
    assert.equal(errors.length, 1);
    assert.equal(reporter.stats.failed, 1);
  });

  it("drops signals beyond maxInFlight and after close", async () => {
    const collector = await startCollector();
    const reporter = new SignalReporter({ target: collector.target, maxInFlight: 2 });
    try {
      for (let i = 0; i < 5; i++) reporter.report(signal());
      assert.equal(reporter.stats.dropped, 3);
      await reporter.close();
      reporter.report(signal());
      assert.deepEqual(reporter.stats, { sent: 2, failed: 0, dropped: 4, inFlight: 0 });
    } finally {
      collector.close();
    }
  });
});
