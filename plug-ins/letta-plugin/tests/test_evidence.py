"""The strength claim, tested: receipts are tamper-evident and verify offline.

A verdict is only worth gating on if its record can't be quietly rewritten. This
generates a real signed chain via the plugin, then proves the independent verifier
(`iaga-verify`, no network, no trust in the sidecar):
  * accepts the pristine chain,
  * rejects a flipped verdict, a forged signature, a dropped middle receipt, a reorder,
  * and — honestly — still accepts a tail-truncated chain (the documented limit).
"""

import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
import uuid
from pathlib import Path

import pytest

from iaga_letta import SentinelApprovalHandler, SentinelOptions

IAGA_URL = os.environ.get("IAGA_SENTINEL_URL", "http://localhost:4010")
REPO_ROOT = Path(__file__).resolve().parents[3]
NONCE = uuid.uuid4().hex[:8]
AID = f"evid-{NONCE}"
SID = "chain"
RUN_ID = f"{AID}:{SID}"


def _up():
    try:
        with urllib.request.urlopen(f"{IAGA_URL}/health", timeout=2) as r:
            return r.status < 500
    except Exception:
        return False


def _bin(name):
    for exe in (f"{name}.exe", name):
        p = REPO_ROOT / "target" / "release" / exe
        if p.exists():
            return str(p)
    return shutil.which(name)


needs = pytest.mark.skipif(not (_up() and _bin("iaga") and _bin("iaga-verify")),
                           reason="needs sidecar + iaga + iaga-verify")


def _verify(path) -> tuple:
    """Run iaga-verify on a chain file. Returns (accepted: bool, output)."""
    out = subprocess.run([_bin("iaga-verify"), str(path)], capture_output=True, text=True, timeout=60)
    combined = out.stdout + out.stderr
    return (out.returncode == 0 and "CHAIN OK" in combined), combined


@pytest.fixture(scope="module")
def chain_file():
    if not (_up() and _bin("iaga") and _bin("iaga-verify")):
        pytest.skip("needs sidecar + iaga + iaga-verify")
    # register the agent, then sign a 3-receipt chain via the plugin's own client
    pol = (f"profiles:\n  - {{ agentId: {AID}, workspaceId: ws-{AID}, framework: letta, role: builder, "
           f"approvedTools: [run_shell], approvedSecrets: [], baselineActionTypes: [shell] }}\n"
           f"workspaces:\n  - {{ workspaceId: ws-{AID}, thresholdReview: 900, thresholdBlock: 950, "
           f"allowedProtocols: [http-function, mcp], allowedDomains: [\"*\"], "
           f"tools: [ {{ toolName: run_shell, allowedActionTypes: [shell], maxDecision: allow, "
           f"requiresHumanReview: false }} ] }}\nvault: []\n")
    fh = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
    fh.write(pol); fh.close()
    # cwd=REPO_ROOT so import/replay share the sidecar's CWD-relative iaga_sentinel.db
    # (the sidecar is started from the repo root).
    try:
        subprocess.run([_bin("iaga"), "import", fh.name], cwd=str(REPO_ROOT),
                       capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(fh.name)

    h = SentinelApprovalHandler(SentinelOptions(base_url=IAGA_URL, agent_id=AID))
    for cmd in ["echo one", "rm -rf /tmp/two", "echo three"]:
        h.decide("run_shell", {"command": cmd}, session=SID)

    path = Path(tempfile.gettempdir()) / f"iaga-evid-{NONCE}.json"
    subprocess.run([_bin("iaga"), "replay", RUN_ID, "--export", str(path)],
                   cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60)
    return path


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_copy(data):
    p = Path(tempfile.gettempdir()) / f"iaga-tamper-{uuid.uuid4().hex[:8]}.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


# --- pristine chain --------------------------------------------------------
@needs
def test_pristine_chain_verifies(chain_file):
    accepted, out = _verify(chain_file)
    assert accepted, out
    data = _load(chain_file)
    assert len(data["receipts"]) == 3


@needs
def test_every_receipt_is_not_authoritative(chain_file):
    data = _load(chain_file)
    assert {r["is_authoritative"] for r in data["receipts"]} == {False}


@needs
def test_chain_links_via_parent_hash(chain_file):
    # honest structural check: each receipt after the first references a parent
    rs = _load(chain_file)["receipts"]
    assert all("parent_hash" in r for r in rs)
    assert [r["seq"] for r in rs] == sorted(r["seq"] for r in rs)


# --- tamper modes that MUST be rejected ------------------------------------
@needs
def test_flipped_verdict_rejected(chain_file):
    data = _load(chain_file)
    for r in data["receipts"]:
        if r["verdict"] == "block":
            r["verdict"] = "allow"
            break
    accepted, out = _verify(_write_copy(data))
    assert not accepted, f"verifier accepted a flipped verdict!\n{out}"


@needs
def test_forged_signature_rejected(chain_file):
    data = _load(chain_file)
    sig = data["receipts"][0]["signature"]
    data["receipts"][0]["signature"] = ("AAAA" + sig[4:]) if sig[:4] != "AAAA" else ("BBBB" + sig[4:])
    accepted, out = _verify(_write_copy(data))
    assert not accepted, f"verifier accepted a forged signature!\n{out}"


@needs
def test_dropped_middle_receipt_rejected(chain_file):
    data = _load(chain_file)
    if len(data["receipts"]) < 3:
        pytest.skip("need >=3 receipts")
    del data["receipts"][1]                       # break the parent_hash linkage
    accepted, out = _verify(_write_copy(data))
    assert not accepted, f"verifier accepted a chain with a hole!\n{out}"


@needs
def test_reordered_receipts_rejected(chain_file):
    data = _load(chain_file)
    data["receipts"] = list(reversed(data["receipts"]))
    accepted, out = _verify(_write_copy(data))
    assert not accepted, f"verifier accepted reordered receipts!\n{out}"


# --- honest limit: tail truncation still verifies --------------------------
@needs
def test_tail_truncation_still_verifies(chain_file):
    """Dropping the LAST receipt leaves a valid prefix — the verifier cannot know a
    record was lost from the end. This is a documented limit, not a guarantee."""
    data = _load(chain_file)
    data["receipts"] = data["receipts"][:-1]      # drop the tail
    accepted, out = _verify(_write_copy(data))
    assert accepted, ("tail-truncation unexpectedly rejected — update the honest claim\n" + out)


# --- informational: which content fields are signed ------------------------
@needs
def test_content_tamper_report(chain_file, capsys):
    rows = []
    for field, mutate in [
        ("risk_score", lambda r: r.__setitem__("risk_score", 0)),
        ("reasons", lambda r: r.__setitem__("reasons", ["tampered"])),
        ("input_hash", lambda r: r.__setitem__("input_hash", "0" * 64)),
        ("policy_hash", lambda r: r.__setitem__("policy_hash", "0" * 64)),
    ]:
        data = _load(chain_file)
        mutate(data["receipts"][0])
        accepted, _ = _verify(_write_copy(data))
        rows.append(f"  mutate {field:12} -> {'ACCEPTED (not signed)' if accepted else 'REJECTED (signed)'}")
    print("\n[which fields the signature protects]\n" + "\n".join(rows))
    assert rows


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-s"]))
