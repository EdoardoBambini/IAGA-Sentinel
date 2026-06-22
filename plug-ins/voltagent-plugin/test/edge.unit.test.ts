// Edge cases surfaced by the adversarial enumeration sweep — real behavior pins
// that a future change could silently regress.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ToolDeniedError } from "@voltagent/core";
import { createSentinelHooks, SentinelClient, defaultInferActionType } from "../dist/index.js";
import { makeFetch, startArgs, endArgs, verdict } from "./helpers.mjs";

const isDenied = (code: string) => (e: unknown) =>
  e instanceof ToolDeniedError && (e as { code: string }).code === code;

// inferActionType substring/boundary quirks
test("inferActionType('openai_call') -> file_read (the 'open' substring beats http)", () => {
  assert.equal(defaultInferActionType("openai_call"), "file_read");
});
test("inferActionType('ssh') -> custom ('sh' needs a boundary)", () => {
  assert.equal(defaultInferActionType("ssh"), "custom");
});
test("inferActionType('query_api') -> db_query (db family beats http)", () => {
  assert.equal(defaultInferActionType("query_api"), "db_query");
});

// client: empty apiKey is falsy -> no Authorization header
test("empty-string apiKey -> no Authorization header", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/inspect": { json: {} } });
  const client = new SentinelClient({ baseUrl: "http://x", timeoutMs: 100, apiKey: "", fetch: fetchImpl } as never);
  await client.inspect({ agentId: "a", framework: "f", action: { type: "custom", toolName: "t", payload: {} } });
  assert.equal((calls[0].headers as Record<string, string>).Authorization, undefined);
});

// firewall: blocked must be strictly === true
test("scanInput: fw.blocked=1 (truthy non-boolean) is NOT a block -> proceeds to inspect", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/firewall/scan": { json: { blocked: 1 } }, "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanInput: true });
  await hooks.onToolStart!(startArgs() as never);
  assert.ok(calls.some((c) => c.url.endsWith("/v1/inspect")));
});
test("scanInput: fw.blocked absent -> not blocked, proceeds to inspect", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/firewall/scan": { json: {} }, "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanInput: true });
  await hooks.onToolStart!(startArgs() as never);
  assert.ok(calls.some((c) => c.url.endsWith("/v1/inspect")));
});

// firewall fails open, then inspect blocks -> the block code wins (not a firewall/unreachable code)
test("scanInput firewall error + failClosed=false, inspect blocks -> IAGA_BLOCK", async () => {
  const { fetchImpl } = makeFetch({ "/v1/firewall/scan": { throws: true }, "/v1/inspect": { json: verdict("block") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanInput: true, failClosed: false });
  await assert.rejects(hooks.onToolStart!(startArgs() as never), isDenied("IAGA_BLOCK"));
});

// missing risk object must not crash
test("allow verdict with no risk object -> resolves (no crash on risk?.score)", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { json: { traceId: "t", decision: "allow" } } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await hooks.onToolStart!(startArgs() as never);
});
test("block verdict with no risk and no policyFindings -> IAGA_BLOCK with default reason", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { json: { traceId: "t", decision: "block" } } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await assert.rejects(hooks.onToolStart!(startArgs() as never), (e: unknown) =>
    isDenied("IAGA_BLOCK")(e) && /blocked by IAGA Sentinel/.test((e as Error).message),
  );
});

// response scan: raw output passed through (string NOT wrapped in {value})
test("response/scan: string output is passed raw as responsePayload", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/response/scan": { json: { requestId: "r", decision: "allow", riskScore: 0, findings: [] } } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanOutput: true });
  await hooks.onToolEnd!(endArgs("shell", "plain string output") as never);
  assert.equal(calls[0].body.responsePayload, "plain string output");
});

// concurrency: no shared mutable state — many calls in flight resolve independently
test("20 concurrent allow calls all resolve and each makes its own request", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await Promise.all(Array.from({ length: 20 }, (_v, i) => hooks.onToolStart!(startArgs("read_file", { i }) as never)));
  assert.equal(calls.length, 20);
});

test("20 concurrent block calls all reject with IAGA_BLOCK", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { json: verdict("block") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  const results = await Promise.allSettled(Array.from({ length: 20 }, () => hooks.onToolStart!(startArgs() as never)));
  assert.ok(results.every((r) => r.status === "rejected" && isDenied("IAGA_BLOCK")((r as PromiseRejectedResult).reason)));
});

// MCP tools surface in the same registry — a colon-namespaced name is governed identically
test("MCP-style tool name (github:create_issue) is governed and sent verbatim", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/inspect": { json: verdict("block") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await assert.rejects(hooks.onToolStart!(startArgs("github:create_issue", { title: "x" }) as never), isDenied("IAGA_BLOCK"));
  assert.equal(calls[0].body.action.toolName, "github:create_issue"); // colon name sent verbatim
  assert.equal(calls[0].body.action.type, "file_write"); // heuristic still fires on namespaced names ("create")
});

// logger wiring
test("logger receives a debug line on allow and a warn on fail-closed", async () => {
  const log: Array<[string, string]> = [];
  const logger = {
    debug: (m: string) => log.push(["debug", m]),
    info: (m: string) => log.push(["info", m]),
    warn: (m: string) => log.push(["warn", m]),
    error: (m: string) => log.push(["error", m]),
  };
  const allow = makeFetch({ "/v1/inspect": { json: verdict("allow") } });
  await createSentinelHooks({ fetch: allow.fetchImpl, logger }).onToolStart!(startArgs() as never);
  assert.ok(log.some(([lvl, m]) => lvl === "debug" && /allow/.test(m)));

  const dead = makeFetch({ "/v1/inspect": { throws: true } });
  await assert.rejects(createSentinelHooks({ fetch: dead.fetchImpl, logger }).onToolStart!(startArgs() as never));
  assert.ok(log.some(([lvl, m]) => lvl === "warn" && /inspect failed/.test(m)));
});
