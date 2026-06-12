/*
 * Registers a fresh pool of agents + permissive workspaces for smoke.cjs and
 * prints the comma-separated agent ids on stdout (everything else on stderr).
 *
 * Mirrors the Python conftest pool: each smoke check gets its OWN agent and
 * workspace so per-agent behavioral risk never bleeds between checks; the
 * injection firewall still hard-blocks the dangerous payloads regardless of
 * the permissive thresholds.
 *
 * Usage (sidecar running in open mode, or set IAGA_API_KEY):
 *   IAGA_SMOKE_AGENTS="$(node sdks/typescript/register-smoke-agents.cjs)" \
 *     node sdks/typescript/smoke.cjs
 */
const BASE_URL = process.env.IAGA_BASE_URL || "http://localhost:4010";
const API_KEY = process.env.IAGA_API_KEY || "";
const POOL_SIZE = Number(process.env.IAGA_SMOKE_POOL || 8);

const HEADERS = { "content-type": "application/json" };
if (API_KEY) HEADERS.authorization = `Bearer ${API_KEY}`;

const TOOLS = [
  { toolName: "filesystem.read", allowedActionTypes: ["file_read"], maxDecision: "allow", requiresHumanReview: false },
  { toolName: "shell", allowedActionTypes: ["shell"], maxDecision: "allow", requiresHumanReview: false },
  { toolName: "openai.chat.completions.create", allowedActionTypes: ["http"], maxDecision: "allow", requiresHumanReview: false },
];

async function post(path, body) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: HEADERS,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`POST ${path} -> ${res.status}: ${await res.text()}`);
  }
}

async function main() {
  const nonce = `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
  const agents = [];
  for (let i = 0; i < POOL_SIZE; i++) {
    const agentId = `ts-smoke-${nonce}-${i}`;
    const workspaceId = `ws-ts-smoke-${nonce}-${i}`;
    await post("/v1/workspaces", {
      workspaceId,
      allowedProtocols: ["http-function", "mcp"],
      allowedDomains: ["*"],
      tools: TOOLS,
      // Permissive thresholds: smoke allow-paths must stay deterministic;
      // block-paths are exercised through the injection firewall instead.
      thresholdReview: 900,
      thresholdBlock: 950,
    });
    await post("/v1/profiles", {
      agentId,
      workspaceId,
      framework: "ts-smoke",
      role: "builder",
      approvedTools: TOOLS.map((t) => t.toolName),
      approvedSecrets: [],
      baselineActionTypes: ["file_read", "shell", "http"],
    });
    agents.push(agentId);
  }
  console.error(`registered ${agents.length} smoke agents against ${BASE_URL}`);
  console.log(agents.join(","));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
