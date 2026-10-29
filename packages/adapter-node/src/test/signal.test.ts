import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Metadata } from "@grpc/grpc-js";
import { buildSignal, maskMetadata, resolveClientIp, sessionHash } from "../signal.js";

function md(entries: Record<string, string>): Metadata {
  const m = new Metadata();
  for (const [k, v] of Object.entries(entries)) m.set(k, v);
  return m;
}

describe("resolveClientIp", () => {
  const headers = md({ "x-forwarded-for": "198.51.100.7, 10.0.0.1", "x-real-ip": "198.51.100.8" });

  it("ignores proxy headers by default (prevents IP spoofing)", () => {
    assert.equal(resolveClientIp(headers, "10.0.0.1"), "10.0.0.1");
  });

  it("uses the first x-forwarded-for entry when proxy headers are trusted", () => {
    assert.equal(resolveClientIp(headers, "10.0.0.1", true), "198.51.100.7");
  });

  it("falls back to x-real-ip, then the connection IP", () => {
    assert.equal(resolveClientIp(md({ "x-real-ip": "198.51.100.8" }), "10.0.0.1", true), "198.51.100.8");
    assert.equal(resolveClientIp(md({}), "10.0.0.1", true), "10.0.0.1");
  });

  it("normalizes IPv4-mapped IPv6 addresses", () => {
    assert.equal(resolveClientIp(md({ "x-forwarded-for": "::ffff:203.0.113.9" }), "", true), "203.0.113.9");
  });
});

describe("maskMetadata", () => {
  const headers = md({ authorization: "Bearer secret", "x-tenant": "acme", "x-api-key": "k", cookie: "sid=1" });

  it("includes only listed keys and masks sensitive values", () => {
    assert.deepEqual(maskMetadata(headers, ["Authorization", "x-tenant", "x-api-key", "missing"]), {
      authorization: "***",
      "x-tenant": "acme",
      "x-api-key": "***",
    });
  });

  it("includes nothing by default", () => {
    assert.deepEqual(maskMetadata(headers), {});
  });
});

describe("sessionHash", () => {
  it("is stable per token, differs by salt, and never contains the token", () => {
    const h = sessionHash(md({ authorization: "Bearer secret" }));
    assert.match(h, /^[0-9a-f]{32}$/);
    assert.equal(h, sessionHash(md({ authorization: "Bearer secret" })));
    assert.notEqual(h, sessionHash(md({ authorization: "Bearer secret" }), "salt"));
    assert.notEqual(h, sessionHash(md({ authorization: "Bearer other" })));
    assert.ok(!h.includes("secret"));
  });

  it("is empty without credentials", () => {
    assert.equal(sessionHash(md({})), "");
  });
});

describe("buildSignal", () => {
  const obs = {
    method: "/user.UserService/GetUser",
    metadata: md({ "user-agent": "app/1.0", "x-request-id": "req-1", "x-user": "u-1" }),
    connectionIp: "10.0.0.1",
    statusCode: 7,
    errorMessage: "user u-1 denied",
    latencyMs: 12.6,
  };

  it("fills every context from the observation", () => {
    const s = buildSignal(obs, {
      sourceService: "main-bff",
      extractUser: (m) => ({ userId: m.get("x-user")[0] as string, userRole: "user" }),
    });
    assert.match(s.signal_id, /^[0-9a-f-]{36}$/);
    assert.ok(!Number.isNaN(Date.parse(s.timestamp)));
    assert.equal(s.source_service, "main-bff");
    assert.deepEqual(s.user_context, {
      user_id: "u-1",
      user_role: "user",
      client_ip: "10.0.0.1",
      user_agent: "app/1.0",
      session_hash: "",
    });
    assert.equal(s.request_context.method, "/user.UserService/GetUser");
    assert.equal(s.request_context.protocol, "grpc");
    assert.equal(s.response_context.status_code, 7);
    assert.equal(s.response_context.latency_ms, 13);
    assert.equal(s.trace_id, "req-1");
  });

  it("omits the error message unless explicitly enabled (may contain PII)", () => {
    assert.equal(buildSignal(obs, { sourceService: "bff" }).response_context.error_message, "");
    assert.equal(
      buildSignal(obs, { sourceService: "bff", includeErrorMessage: true }).response_context.error_message,
      "user u-1 denied",
    );
  });
});
