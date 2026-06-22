// REAL end-to-end test: a genuine VoltAgent Agent, driven by a mock model that
// emits one tool-call, governed by IAGA Sentinel hooks. Proves that when IAGA
// blocks, the tool's execute() NEVER runs — through the real VoltAgent tool
// pipeline (no LLM, no API key) — and that the run's signed receipts verify
// offline (CHAIN OK).
//
//   DATABASE_URL=... IAGA_SENTINEL_URL=http://localhost:4010 node test/e2e.agent.mjs
//
// Standalone (not node:test) because VoltAgent keeps an observability handle
// open; node --test's forced teardown trips a libuv assertion on Windows.
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import { Agent, createTool } from "@voltagent/core";
import { MockLanguageModelV3 } from "ai/test";
import { z } from "zod";
import { createSentinelHooks } from "@iaga-sentinel/voltagent";

const URL = process.env.IAGA_SENTINEL_URL ?? "http://localhost:4010";
const AGENT = process.env.IAGA_SENTINEL_AGENT_ID ?? "openclaw-builder-01";
const FRAMEWORK = process.env.IAGA_SENTINEL_FRAMEWORK ?? "openclaw";
const SESSION = `e2e-agent-${Date.now()}`;
const RUN_ID = `${AGENT}:${SESSION}`;
const DB = process.env.DATABASE_URL;
const root = join(import.meta.dirname, "..", "..", "..");
const IAGA_BIN =
  process.env.IAGA_BIN ??
  [join(root, "target/release/iaga.exe"), join(root, "target/release/iaga")].find(existsSync);

const reachable = await fetch(`${URL}/health`).then((r) => r.ok).catch(() => false);
if (!reachable) {
  console.log(`SKIP: IAGA Sentinel sidecar not reachable at ${URL}`);
  process.exit(0);
}

function modelCalling(toolName, input) {
  let n = 0;
  return new MockLanguageModelV3({
    doGenerate: async () => {
      n++;
      if (n === 1) {
        return {
          content: [{ type: "tool-call", toolCallId: "call-1", toolName, input: JSON.stringify(input) }],
          finishReason: "tool-calls",
          usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
          warnings: [],
        };
      }
      return {
        content: [{ type: "text", text: "done" }],
        finishReason: "stop",
        usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
        warnings: [],
      };
    },
  });
}

async function runAgent(toolName, input) {
  let ran = false;
  const tool = createTool({
    name: toolName,
    description: `test tool ${toolName}`,
    parameters: z.object({}).passthrough(),
    execute: async () => {
      ran = true;
      return "EXECUTED";
    },
  });
  const agent = new Agent({
    name: "e2e-agent",
    instructions: "test agent",
    model: modelCalling(toolName, input),
    tools: [tool],
    hooks: createSentinelHooks({
      baseUrl: URL,
      agentId: AGENT,
      framework: FRAMEWORK,
      sessionId: SESSION,
      failClosed: true,
    }),
  });
  await agent.generateText(`use ${toolName}`);
  return ran;
}

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL  ${name}: ${e.message}`);
  }
}

console.log(`Real VoltAgent e2e (agent=${AGENT}, session=${SESSION})\n`);

const allowRan = await runAgent("filesystem.read", { path: "README.md" });
check("allow: an approved tool's execute() actually runs", () =>
  assert.equal(allowRan, true),
);

const blockRan = await runAgent("terminal.exec", { command: "rm -rf /" });
check("block: a destructive tool's execute() never runs", () =>
  assert.equal(blockRan, false),
);

if (IAGA_BIN && DB) {
  let out = "";
  try {
    out = execFileSync(IAGA_BIN, ["replay", RUN_ID, "--verify-only", "--db", DB], { encoding: "utf8" });
  } catch (e) {
    out = (e.stdout || "") + (e.stderr || "");
  }
  console.log(`  ${out.trim()}`);
  check("verify: the run's signed receipt chain verifies offline (CHAIN OK)", () =>
    assert.match(out, /CHAIN OK/),
  );
} else {
  console.log("  (CHAIN OK step skipped: set IAGA_BIN and DATABASE_URL)");
}

console.log(`\n${failures === 0 ? "ALL PASSED" : `${failures} FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
