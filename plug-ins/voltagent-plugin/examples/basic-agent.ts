/**
 * Wire IAGA Sentinel into a VoltAgent agent.
 *
 * The hooks govern every tool call through a local Sentinel sidecar
 * (`iaga serve`, default http://localhost:4010 in open mode). A blocked tool
 * throws a ToolDeniedError before `execute` runs, so the tool never fires.
 *
 * This file is runnable WITHOUT an LLM/API key: it exercises the gate directly
 * by calling the onToolStart hook on a safe and a dangerous tool call. The
 * commented Agent block shows the real wiring you would use with a model.
 *
 *   1. iaga serve            # or: docker compose up   (open mode, :4010)
 *   2. npx tsx examples/basic-agent.ts
 *
 * Uses the demo agent `openclaw-builder-01` that `iaga serve` seeds, so it runs
 * with no profile registration. In your app, register your own agent and pass
 * its id + framework.
 */
import { createSentinelHooks } from "@iaga-sentinel/voltagent";

const AGENT_ID = process.env.IAGA_SENTINEL_AGENT_ID ?? "openclaw-builder-01";

const hooks = createSentinelHooks({
  agentId: AGENT_ID,
  framework: process.env.IAGA_SENTINEL_FRAMEWORK ?? "openclaw",
  sessionId: `demo-${Date.now()}`, // chains all actions into one verifiable run
  failClosed: true,
  // logger: console, // uncomment for verdict logging
});

async function tryTool(name: string, args: unknown): Promise<void> {
  try {
    await hooks.onToolStart!({ tool: { name }, args } as never);
    console.log(`  allow  -> ${name} would run`);
  } catch (err) {
    console.log(`  DENIED -> ${name}: ${(err as Error).message}`);
  }
}

async function main(): Promise<void> {
  console.log(`IAGA Sentinel x VoltAgent demo (agent=${AGENT_ID})\n`);
  await tryTool("filesystem.read", { path: "README.md" });
  await tryTool("terminal.exec", { command: "rm -rf /" });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

/*
// ── Real agent wiring (needs an LLM provider + API key) ──────────────────────
import { Agent, createTool } from "@voltagent/core";
import { openai } from "@ai-sdk/openai";
import { z } from "zod";

const shell = createTool({
  name: "shell",
  description: "Run a shell command",
  parameters: z.object({ command: z.string() }),
  execute: async ({ command }) => {
    // ... only reached when IAGA Sentinel allows it
    return `ran: ${command}`;
  },
});

const agent = new Agent({
  name: "governed-agent",
  instructions: "You can run shell commands.",
  model: openai("gpt-4o-mini"),
  tools: [shell],
  hooks, // <-- every tool call is governed + receipted
});

await agent.generateText("Delete everything with rm -rf /");
// -> the shell tool is denied by IAGA Sentinel; execute never runs.
*/
