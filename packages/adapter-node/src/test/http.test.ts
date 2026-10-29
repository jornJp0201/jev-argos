import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildHttpSignal, httpStatusToGrpc, reportHttp } from "../http.js";
import type { Reporter } from "../reporter.js";
import type { SecuritySignal } from "../signal.js";
import { startCollector } from "./helpers.js";
import { SignalReporter } from "../reporter.js";

describe("httpStatusToGrpc", () => {
  it("maps HTTP statuses to the gRPC codes Jev scores on", () => {
    const cases: Array<[number, number]> = [
      [200, 0], [204, 0], [302, 0],
      [400, 3], [401, 16], [403, 7], [404, 5], [408, 4], [409, 6], [429, 8], [418, 9],
      [500, 13], [501, 12], [502, 14], [503, 14], [504, 4], [599, 13],
    ];
    for (const [http, grpc] of cases) assert.equal(httpStatusToGrpc(http), grpc, `HTTP ${http}`);
  });
});

describe("buildHttpSignal", () => {
  it("uses the route pattern as method and protocol http", () => {
    const s = buildHttpSignal(
      {
        method: "get",
        route: "/users/:id",
        statusCode: 403,
        clientIp: "198.51.100.7",
        userAgent: "curl/8.7",
        latencyMs: 12.4,
        userId: "user-42",
        traceId: "req-1",
      },
      { sourceService: "main-bff" },
    );
    assert.equal(s.request_context.protocol, "http");
    assert.equal(s.request_context.method, "GET /users/:id");
    assert.equal(s.response_context.status_code, 7);
    assert.equal(s.response_context.error_code, "403");
    assert.equal(s.response_context.latency_ms, 12);
    assert.deepEqual(s.user_context, {
      user_id: "user-42",
      user_role: "",
      client_ip: "198.51.100.7",
      user_agent: "curl/8.7",
      session_hash: "",
    });
    assert.equal(s.source_service, "main-bff");
    assert.equal(s.trace_id, "req-1");
  });

  it("normalizes IPv4-mapped IPv6 client addresses (e.g. Express req.ip)", () => {
    const s = buildHttpSignal({ method: "GET", route: "/", statusCode: 200, clientIp: "::ffff:198.51.100.7", latencyMs: 1 }, { sourceService: "bff" });
    assert.equal(s.user_context.client_ip, "198.51.100.7");
  });

  it("leaves error_code empty for successful responses", () => {
    const s = buildHttpSignal({ method: "POST", route: "/orders", statusCode: 201, clientIp: "10.0.0.1", latencyMs: 3 }, { sourceService: "bff" });
    assert.equal(s.response_context.status_code, 0);
    assert.equal(s.response_context.error_code, "");
  });
});

describe("reportHttp", () => {
  it("never throws even if the reporter does", () => {
    const broken: Reporter = {
      report() {
        throw new Error("broken");
      },
    };
    assert.doesNotThrow(() =>
      reportHttp(broken, { method: "GET", route: "/", statusCode: 200, clientIp: "10.0.0.1", latencyMs: 1 }, { sourceService: "bff" }),
    );
  });

  it("delivers HTTP signals to the control server", async () => {
    const collector = await startCollector();
    const reporter = new SignalReporter({ target: collector.target });
    try {
      reportHttp(reporter, { method: "DELETE", route: "/admin/users/:id", statusCode: 403, clientIp: "203.0.113.9", latencyMs: 8 }, { sourceService: "bff" });
      const [got] = (await collector.waitFor(1)) as SecuritySignal[];
      assert.equal(got?.request_context.protocol, "http");
      assert.equal(got?.request_context.method, "DELETE /admin/users/:id");
      assert.equal(got?.response_context.status_code, 7);
      await reporter.close();
    } finally {
      collector.close();
    }
  });
});
