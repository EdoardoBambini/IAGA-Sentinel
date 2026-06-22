import { test } from "node:test";
import assert from "node:assert/strict";
import { ToolDeniedError } from "@voltagent/core";
import { createSentinelHooks } from "../dist/index.js";
import { makeFetch, startArgs, endArgs, verdict } from "./helpers.mjs";

const isDenied = (code: string) => (e: unknown) =>
  e instanceof ToolDeniedError && (e as { code: string }).code === code;

// ── verdict mapping ──────────────────────────────────────────────────────────
test("allow -> resolves (no-op)", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await hooks.onToolStart!(startArgs() as never);
});

test("block -> ToolDeniedError(IAGA_BLOCK) with the risk reasons", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { json: verdict("block") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await assert.rejects(hooks.onToolStart!(startArgs() as never), (e: unknown) =>
    isDenied("IAGA_BLOCK")(e) && /block reason/.test((e as Error).message),
  );
});

test("review default (onReview=block) -> IAGA_REVIEW", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { json: verdict("review") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await assert.rejects(hooks.onToolStart!(startArgs() as never), isDenied("IAGA_REVIEW"));
});

test("review with onReview=allow -> resolves", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { json: verdict("review") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, onReview: "allow" });
  await hooks.onToolStart!(startArgs() as never);
});

test("reasonOf falls back to policyFindings when risk.reasons is empty", async () => {
  const v = { traceId: "t", decision: "block", risk: { score: 90, decision: "block", reasons: [] }, policyFindings: ["pf-1", "pf-2"] };
  const { fetchImpl } = makeFetch({ "/v1/inspect": { json: v } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await assert.rejects(hooks.onToolStart!(startArgs() as never), (e: unknown) => /pf-1; pf-2/.test((e as Error).message));
});

test("reasonOf falls back to a default string when nothing is present", async () => {
  const v = { traceId: "t", decision: "block", risk: { score: 90, decision: "block", reasons: [] } };
  const { fetchImpl } = makeFetch({ "/v1/inspect": { json: v } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await assert.rejects(hooks.onToolStart!(startArgs() as never), (e: unknown) => /blocked by IAGA Sentinel/.test((e as Error).message));
});

// ── request building ─────────────────────────────────────────────────────────
test("inspect body: ids, framework, action, enforcement + sessionId metadata", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, agentId: "a1", framework: "voltagent", sessionId: "s1", workspaceId: "w1" });
  await hooks.onToolStart!(startArgs("read_file", { path: "x" }) as never);
  const b = calls[0].body;
  assert.equal(b.agentId, "a1");
  assert.equal(b.framework, "voltagent");
  assert.equal(b.action.type, "file_read");
  assert.equal(b.action.toolName, "read_file");
  assert.deepEqual(b.action.payload, { path: "x" });
  assert.equal(b.metadata.enforcement, "agent-loop");
  assert.equal(b.metadata.sessionId, "s1");
  assert.equal(b.workspaceId, "w1");
});

test("no sessionId -> metadata has no sessionId; no workspaceId -> omitted", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await hooks.onToolStart!(startArgs() as never);
  assert.equal(calls[0].body.metadata.sessionId, undefined);
  assert.equal("workspaceId" in calls[0].body, false);
});

test("missing tool.name -> toolName 'unknown'", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await hooks.onToolStart!(startArgs(null) as never);
  assert.equal(calls[0].body.action.toolName, "unknown");
});

for (const [label, args, expected] of [
  ["array", [1, 2], { value: [1, 2] }],
  ["primitive", 42, { value: 42 }],
  ["null", null, { value: null }],
  ["string", "hi", { value: "hi" }],
  ["object", { a: 1 }, { a: 1 }],
] as Array<[string, unknown, unknown]>) {
  test(`toPayload of ${label} args`, async () => {
    const { fetchImpl, calls } = makeFetch({ "/v1/inspect": { json: verdict("allow") } });
    const hooks = createSentinelHooks({ fetch: fetchImpl });
    await hooks.onToolStart!(startArgs("custom", args) as never);
    assert.deepEqual(calls[0].body.action.payload, expected);
  });
}

// ── error / transport ────────────────────────────────────────────────────────
test("inspect network error + failClosed (default) -> IAGA_UNREACHABLE", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { throws: true } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await assert.rejects(hooks.onToolStart!(startArgs() as never), isDenied("IAGA_UNREACHABLE"));
});

test("inspect network error + failClosed=false -> resolves (fail open)", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { throws: true } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, failClosed: false });
  await hooks.onToolStart!(startArgs() as never);
});

test("inspect 4xx (agent not registered) + failClosed -> IAGA_UNREACHABLE", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { status: 404, json: "agent not found" } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await assert.rejects(hooks.onToolStart!(startArgs() as never), isDenied("IAGA_UNREACHABLE"));
});

test("inspect 4xx + failClosed=false -> resolves", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { status: 404, json: "x" } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, failClosed: false });
  await hooks.onToolStart!(startArgs() as never);
});

// ── input scan (firewall) ────────────────────────────────────────────────────
test("scanInput=false -> firewall is never called", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/firewall/scan": { json: { blocked: true } }, "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await hooks.onToolStart!(startArgs() as never);
  assert.equal(calls.some((c) => c.url.endsWith("/v1/firewall/scan")), false);
});

test("scanInput blocked -> IAGA_FIREWALL_BLOCK with the summary", async () => {
  const { fetchImpl } = makeFetch({ "/v1/firewall/scan": { json: { blocked: true, summary: "ignore previous instructions" } }, "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanInput: true });
  await assert.rejects(hooks.onToolStart!(startArgs() as never), (e: unknown) =>
    isDenied("IAGA_FIREWALL_BLOCK")(e) && /ignore previous/.test((e as Error).message),
  );
});

test("scanInput clean -> proceeds to inspect", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/firewall/scan": { json: { blocked: false } }, "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanInput: true });
  await hooks.onToolStart!(startArgs() as never);
  assert.ok(calls.some((c) => c.url.endsWith("/v1/firewall/scan")));
  assert.ok(calls.some((c) => c.url.endsWith("/v1/inspect")));
});

test("scanInput firewall error + failClosed -> IAGA_UNREACHABLE", async () => {
  const { fetchImpl } = makeFetch({ "/v1/firewall/scan": { throws: true }, "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanInput: true });
  await assert.rejects(hooks.onToolStart!(startArgs() as never), isDenied("IAGA_UNREACHABLE"));
});

test("scanInput firewall error + failClosed=false -> proceeds to inspect", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/firewall/scan": { throws: true }, "/v1/inspect": { json: verdict("allow") } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanInput: true, failClosed: false });
  await hooks.onToolStart!(startArgs() as never);
  assert.ok(calls.some((c) => c.url.endsWith("/v1/inspect")));
});

// ── output scan (onToolEnd) ──────────────────────────────────────────────────
test("scanOutput disabled -> onToolEnd never scans", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/response/scan": { json: { findings: [] } } });
  const hooks = createSentinelHooks({ fetch: fetchImpl });
  await hooks.onToolEnd!(endArgs() as never);
  assert.equal(calls.length, 0);
});

test("scanOutput + error present -> returns undefined, no scan", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/response/scan": { json: {} } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanOutput: true });
  const r = await hooks.onToolEnd!(endArgs("shell", "out", new Error("boom")) as never);
  assert.equal(r, undefined);
  assert.equal(calls.length, 0);
});

test("scanOutput + output undefined -> returns undefined, no scan", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/response/scan": { json: {} } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanOutput: true });
  const r = await hooks.onToolEnd!({ tool: { name: "shell" }, output: undefined, error: undefined } as never);
  assert.equal(r, undefined);
  assert.equal(calls.length, 0);
});

test("scanOutput + redactOutput -> substitutes redactedPayload when decision != allow", async () => {
  const { fetchImpl } = makeFetch({ "/v1/response/scan": { json: { requestId: "r", decision: "review", riskScore: 70, findings: ["secret"], redactedPayload: "REDACTED" } } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanOutput: true, redactOutput: true });
  const r = await hooks.onToolEnd!(endArgs("shell", "AKIA-secret") as never);
  assert.deepEqual(r, { output: "REDACTED" });
});

test("scanOutput + redactOutput but decision=allow -> no substitution", async () => {
  const { fetchImpl } = makeFetch({ "/v1/response/scan": { json: { requestId: "r", decision: "allow", riskScore: 0, findings: [], redactedPayload: "REDACTED" } } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanOutput: true, redactOutput: true });
  const r = await hooks.onToolEnd!(endArgs() as never);
  assert.equal(r, undefined);
});

test("scanOutput + redactOutput but redactedPayload missing -> no substitution", async () => {
  const { fetchImpl } = makeFetch({ "/v1/response/scan": { json: { requestId: "r", decision: "block", riskScore: 80, findings: ["x"] } } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanOutput: true, redactOutput: true });
  const r = await hooks.onToolEnd!(endArgs() as never);
  assert.equal(r, undefined);
});

test("scanOutput without redactOutput -> records findings, no substitution", async () => {
  const { fetchImpl } = makeFetch({ "/v1/response/scan": { json: { requestId: "r", decision: "review", riskScore: 70, findings: ["pii"], redactedPayload: "X" } } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanOutput: true });
  const r = await hooks.onToolEnd!(endArgs() as never);
  assert.equal(r, undefined);
});

test("scanOutput response/scan throws -> swallowed, returns undefined", async () => {
  const { fetchImpl } = makeFetch({ "/v1/response/scan": { throws: true } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanOutput: true, redactOutput: true });
  const r = await hooks.onToolEnd!(endArgs() as never);
  assert.equal(r, undefined);
});

test("response/scan request body shape", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/response/scan": { json: { requestId: "r", decision: "allow", riskScore: 0, findings: [] } } });
  const hooks = createSentinelHooks({ fetch: fetchImpl, scanOutput: true, agentId: "a1", sessionId: "s1" });
  await hooks.onToolEnd!(endArgs("shell", { stdout: "hi" }) as never);
  const b = calls[0].body;
  assert.equal(b.agentId, "a1");
  assert.equal(b.toolName, "shell");
  assert.deepEqual(b.responsePayload, { stdout: "hi" });
  assert.equal(b.metadata.sessionId, "s1");
  assert.ok(typeof b.requestId === "string" && b.requestId.length > 0);
});
