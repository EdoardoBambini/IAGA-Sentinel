// Smoke test for the Node/TypeScript offline verifier. Run: node verify.smoke.mjs
//
// The load-bearing check is the golden-vector parity: it verifies a chain
// signed by the canonical Rust code (../conformance/golden_chain.json), so a
// pass proves the JS re-serialization of the signed bytes is byte-identical to
// serde_json — Rust and Node agree on what a valid chain is.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import process from "node:process";

import { verifyExport, ed25519Verify, Unsupported } from "./verify.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = join(here, "..", "conformance", "golden_chain.json");
const loadGolden = () => JSON.parse(readFileSync(GOLDEN, "utf8"));

let passed = 0;
let failed = 0;
function check(name, cond) {
  if (cond) {
    passed++;
    console.log(`  ok  ${name}`);
  } else {
    failed++;
    console.error(`FAIL  ${name}`);
  }
}

// 1. Ed25519 primitive: RFC 8032 known-answer vector (test 1).
{
  const pub = Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex");
  const sig = Buffer.from(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "hex",
  );
  check("ed25519 RFC8032 vector 1 verifies", ed25519Verify(pub, sig, Buffer.alloc(0)) === true);
  const bad = Buffer.from(sig);
  bad[0] ^= 0x01;
  check("ed25519 rejects flipped signature", ed25519Verify(pub, bad, Buffer.alloc(0)) === false);
  check("ed25519 rejects wrong message", ed25519Verify(pub, sig, Buffer.from("x")) === false);
}

// 2. Parity against the Rust-signed golden vector.
{
  const e = loadGolden();
  const embedded = verifyExport(e);
  check("golden verifies (embedded key)", embedded.ok && embedded.keySource === "embedded");
  check("golden receipt count", embedded.receiptCount === e.receipts.length);

  const pinned = verifyExport(e, e.signer_verifying_key);
  check("golden verifies (pinned key)", pinned.ok && pinned.keySource === "pinned");

  const tampered = JSON.parse(JSON.stringify(e));
  tampered.receipts[tampered.receipts.length - 1].risk_score = 999;
  const t = verifyExport(tampered);
  check("tampered field breaks chain", !t.ok && t.brokenSeq === tampered.receipts.length - 1);

  const wrong = verifyExport(e, "00".repeat(32));
  check("wrong pinned key rejected", !wrong.ok && (wrong.reason || "").includes("signer_key_id mismatch"));

  const forged = JSON.parse(JSON.stringify(e));
  forged.signer_key_id = "ed25519-0000000000000000";
  const f = verifyExport(forged);
  check("lying signer_key_id rejected", !f.ok && (f.reason || "").includes("signer_key_id mismatch"));

  const poisoned = JSON.parse(JSON.stringify(e));
  poisoned.receipts[0].ml_scores = { prompt_injection: 0.5 };
  let refused = false;
  try {
    verifyExport(poisoned);
  } catch (err) {
    refused = err instanceof Unsupported;
  }
  check("float body refused, not guessed", refused);

  // The vector must keep exercising nested camelCase objects + arrays-of-objects.
  check("vector has nested camelCase object", e.receipts.some((r) => "apl_eval_trace" in r));
  check("vector has array-of-objects", e.receipts.some((r) => Array.isArray(r.plugin_digests) && r.plugin_digests.length > 0));
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
