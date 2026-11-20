import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Metadata } from "@grpc/grpc-js";
import { SignalReporter } from "../reporter.js";
import { Sampler } from "../sampling.js";
import { buildSignal, type SecuritySignal } from "../signal.js";
import { startCollector } from "./helpers.js";

function signal(latencyMs: number, statusCode = 0, method = "/a.A/Get"): SecuritySignal {
  return buildSignal(
    { method, metadata: new Metadata(), connectionIp: "10.0.0.1", statusCode, errorMessage: "", latencyMs },
    { sourceService: "test" },
  );
}

/** 乱数が r を返す Sampler (rate 0.1)。 */
function fixed(r: number, opts: { slowThresholdMs?: number } = {}): Sampler {
  return Sampler.create({ rate: 0.1, random: () => r, ...opts })!;
}

describe("Sampler", () => {
  it("is disabled unless 0 < rate < 1", () => {
    for (const rate of [0, 1, -1, 2, Number.NaN]) assert.equal(Sampler.create({ rate }), undefined, `rate ${rate}`);
    assert.equal(Sampler.create(undefined), undefined);
  });

  it("always keeps errors without sample_rate", () => {
    const s = signal(10, 7);
    assert.equal(fixed(0.99).keep(s), true);
    assert.equal(s.sample_rate, undefined);
  });

  it("keeps the first response of a method and slow responses", () => {
    const sp = fixed(0.99); // 乱数では必ず間引かれる
    assert.equal(sp.keep(signal(50)), true, "first response seeds the server's baseline");
    assert.equal(sp.keep(signal(60)), false);
    const slow = signal(200); // 平均 (約 51ms) の 2 倍を超える
    assert.equal(sp.keep(slow), true);
    assert.equal(slow.sample_rate, undefined);

    const abs = fixed(0.99, { slowThresholdMs: 30 });
    abs.keep(signal(50));
    assert.equal(abs.keep(signal(40)), true, "slower than slowThresholdMs");
  });

  it("sets sample_rate on sampled responses", () => {
    const sp = fixed(0.05);
    sp.keep(signal(50));
    const s = signal(50);
    assert.equal(sp.keep(s), true);
    assert.equal(s.sample_rate, 0.1);
  });
});

describe("SignalReporter with sampling", () => {
  it("skips sampled-out responses and sends sample_rate", async () => {
    const collector = await startCollector();
    const randoms = [0.99, 0.05]; // 2 件目は間引き、3 件目は送る
    const reporter = new SignalReporter({
      target: collector.target,
      sampling: { rate: 0.1, random: () => randoms.shift()! },
    });
    try {
      for (let i = 0; i < 3; i++) reporter.report(signal(50));
      await reporter.close();
      const rates = collector.signals.map((s) => s.sample_rate).sort();
      assert.deepEqual(rates, [0, 0.1]); // 未指定は 0 として届く
      assert.equal(reporter.stats.skipped, 1);
      assert.equal(reporter.stats.sent, 2);
    } finally {
      collector.close();
    }
  });
});
