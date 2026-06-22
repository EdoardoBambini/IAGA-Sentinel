import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveOptions, defaultInferActionType } from "../dist/index.js";

// ── defaultInferActionType: every branch + precedence + boundaries ───────────
const inferCases: Array<[string, string]> = [
  // shell (checked first)
  ["shell", "shell"],
  ["exec_command", "shell"],
  ["bash", "shell"],
  ["run", "shell"],
  ["spawn", "shell"],
  ["terminal.exec", "shell"],
  ["SHELL", "shell"], // case-insensitive
  // file_write (before file_read, so "write" beats "read")
  ["write_file", "file_write"],
  ["create_doc", "file_write"],
  ["edit", "file_write"],
  ["delete_path", "file_write"],
  ["rm", "file_write"],
  ["mkdir", "file_write"],
  ["upload", "file_write"],
  ["read_write_file", "file_write"], // precedence: write wins over read
  // file_read
  ["read_file", "file_read"],
  ["cat", "file_read"],
  ["view_image", "file_read"],
  ["ls", "file_read"],
  ["glob", "file_read"],
  ["grep", "file_read"],
  ["download", "file_read"],
  // db_query
  ["sql_select", "db_query"],
  ["db_lookup", "db_query"],
  ["postgres_query", "db_query"],
  ["mongo_find", "db_query"],
  // http
  ["http_get", "http"],
  ["fetch_url", "http"],
  ["web_search", "http"],
  ["api_call", "http"],
  ["curl", "http"],
  // email
  ["send_email", "email"],
  ["smtp_relay", "email"],
  // custom (fallback)
  ["calculator", "custom"],
  ["translate", "custom"],
  ["", "custom"],
  ["weather", "custom"],
];

for (const [name, expected] of inferCases) {
  test(`inferActionType("${name}") -> ${expected}`, () => {
    assert.equal(defaultInferActionType(name), expected);
  });
}

// ── resolveOptions: defaults ─────────────────────────────────────────────────
test("resolveOptions defaults (no env, no options)", () => {
  const saved = { u: process.env.IAGA_SENTINEL_URL, k: process.env.IAGA_SENTINEL_API_KEY, a: process.env.IAGA_SENTINEL_AGENT_ID };
  delete process.env.IAGA_SENTINEL_URL;
  delete process.env.IAGA_SENTINEL_API_KEY;
  delete process.env.IAGA_SENTINEL_AGENT_ID;
  try {
    const c = resolveOptions();
    assert.equal(c.baseUrl, "http://localhost:4010");
    assert.equal(c.apiKey, undefined);
    assert.equal(c.agentId, "voltagent-agent");
    assert.equal(c.framework, "voltagent");
    assert.equal(c.failClosed, true);
    assert.equal(c.onReview, "block");
    assert.equal(c.scanInput, false);
    assert.equal(c.scanOutput, false);
    assert.equal(c.redactOutput, false);
    assert.equal(c.timeoutMs, 5000);
    assert.equal(typeof c.inferActionType, "function");
  } finally {
    if (saved.u !== undefined) process.env.IAGA_SENTINEL_URL = saved.u;
    if (saved.k !== undefined) process.env.IAGA_SENTINEL_API_KEY = saved.k;
    if (saved.a !== undefined) process.env.IAGA_SENTINEL_AGENT_ID = saved.a;
  }
});

// ── resolveOptions: env fallbacks ────────────────────────────────────────────
test("resolveOptions reads env fallbacks", () => {
  const saved = { u: process.env.IAGA_SENTINEL_URL, k: process.env.IAGA_SENTINEL_API_KEY, a: process.env.IAGA_SENTINEL_AGENT_ID };
  process.env.IAGA_SENTINEL_URL = "http://envhost:9";
  process.env.IAGA_SENTINEL_API_KEY = "env-key";
  process.env.IAGA_SENTINEL_AGENT_ID = "env-agent";
  try {
    const c = resolveOptions();
    assert.equal(c.baseUrl, "http://envhost:9");
    assert.equal(c.apiKey, "env-key");
    assert.equal(c.agentId, "env-agent");
  } finally {
    for (const [name, v] of [["IAGA_SENTINEL_URL", saved.u], ["IAGA_SENTINEL_API_KEY", saved.k], ["IAGA_SENTINEL_AGENT_ID", saved.a]] as const) {
      if (v === undefined) delete process.env[name];
      else process.env[name] = v;
    }
  }
});

// ── resolveOptions: explicit options win over env ────────────────────────────
test("resolveOptions explicit options beat env", () => {
  const saved = process.env.IAGA_SENTINEL_URL;
  process.env.IAGA_SENTINEL_URL = "http://envhost:9";
  try {
    const c = resolveOptions({ baseUrl: "http://explicit:1", agentId: "explicit", onReview: "allow", failClosed: false, timeoutMs: 1234 });
    assert.equal(c.baseUrl, "http://explicit:1");
    assert.equal(c.agentId, "explicit");
    assert.equal(c.onReview, "allow");
    assert.equal(c.failClosed, false);
    assert.equal(c.timeoutMs, 1234);
  } finally {
    if (saved === undefined) delete process.env.IAGA_SENTINEL_URL;
    else process.env.IAGA_SENTINEL_URL = saved;
  }
});

test("resolveOptions keeps a custom inferActionType override", () => {
  const c = resolveOptions({ inferActionType: () => "email" });
  assert.equal(c.inferActionType("anything"), "email");
});

// ── nullish (??) boundaries: a future switch to || would break these ─────────
test("timeoutMs=0 is honored (nullish, not falsy -> not coerced to 5000)", () => {
  assert.equal(resolveOptions({ timeoutMs: 0 }).timeoutMs, 0);
});

test("explicit baseUrl='' is kept (?? keeps a defined empty string)", () => {
  const saved = process.env.IAGA_SENTINEL_URL;
  process.env.IAGA_SENTINEL_URL = "http://env:4";
  try {
    assert.equal(resolveOptions({ baseUrl: "" }).baseUrl, "");
  } finally {
    if (saved === undefined) delete process.env.IAGA_SENTINEL_URL;
    else process.env.IAGA_SENTINEL_URL = saved;
  }
});

test("apiKey has no default -> undefined when option and env both absent", () => {
  const saved = process.env.IAGA_SENTINEL_API_KEY;
  delete process.env.IAGA_SENTINEL_API_KEY;
  try {
    assert.equal(resolveOptions({}).apiKey, undefined);
  } finally {
    if (saved !== undefined) process.env.IAGA_SENTINEL_API_KEY = saved;
  }
});
