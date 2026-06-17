"""Tests for the pure-Python offline receipt-chain verifier.

The load-bearing test is `test_golden_chain_*`: it verifies a chain signed by
the canonical Rust code (`sdks/conformance/golden_chain.json`, emitted by
`cargo run -p iaga-sentinel-verify --example emit_golden_export`). A green run
proves the Python re-serialization of the signed bytes is byte-identical to
serde_json — i.e. Rust and Python agree on what a valid chain is, which is the
whole point of the multilingual verifier (roadmap 1.3).
"""

import copy
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import iaga_verify  # noqa: E402

GOLDEN = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "conformance", "golden_chain.json",
)


def _load_golden():
    with open(GOLDEN, "r", encoding="utf-8") as fh:
        return json.load(fh)


# --- Ed25519 primitive: RFC 8032 known-answer vector (test 1) ---------------


def test_ed25519_rfc8032_vector_1():
    pub = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert iaga_verify.ed25519_verify(pub, sig, b"") is True
    # A single flipped signature byte must not verify.
    bad = bytearray(sig)
    bad[0] ^= 0x01
    assert iaga_verify.ed25519_verify(pub, bytes(bad), b"") is False
    # Wrong message must not verify.
    assert iaga_verify.ed25519_verify(pub, sig, b"x") is False


# --- Parity against the Rust-signed golden vector ---------------------------


def test_golden_chain_verifies_with_embedded_key():
    export = _load_golden()
    res = iaga_verify.verify_export(export)  # embedded key
    assert res.ok, res.reason
    assert res.key_source == "embedded"
    assert res.receipt_count == len(export["receipts"])
    assert res.signer_key_id == export["signer_key_id"]


def test_golden_chain_verifies_with_pinned_key():
    export = _load_golden()
    res = iaga_verify.verify_export(export, export["signer_verifying_key"])
    assert res.ok, res.reason
    assert res.key_source == "pinned"


def test_tampered_reason_breaks_chain():
    export = _load_golden()
    tampered = copy.deepcopy(export)
    # Mutate any signed field on the last receipt; the signature must fail.
    last = tampered["receipts"][-1]
    last.setdefault("reasons", []).append("tampered")
    res = iaga_verify.verify_export(tampered)
    assert not res.ok
    assert res.broken_seq == last["seq"]


def test_wrong_pinned_key_is_rejected():
    export = _load_golden()
    # A different (valid hex) 32-byte key that did not sign the chain.
    wrong = "00" * 32
    res = iaga_verify.verify_export(export, wrong)
    assert not res.ok
    assert "signer_key_id mismatch" in (res.reason or "")


def test_lying_signer_id_is_rejected():
    export = _load_golden()
    forged = copy.deepcopy(export)
    forged["signer_key_id"] = "ed25519-0000000000000000"
    res = iaga_verify.verify_export(forged)
    assert not res.ok
    assert "signer_key_id mismatch" in (res.reason or "")


# --- Honest refusal on shapes we cannot canonicalize ------------------------


def test_float_body_is_refused_not_guessed():
    export = _load_golden()
    poisoned = copy.deepcopy(export)
    poisoned["receipts"][0]["ml_scores"] = {"prompt_injection": 0.5}
    with pytest.raises(iaga_verify.Unsupported):
        iaga_verify.verify_export(poisoned)


# --- The vector must keep exercising the hard canonicalization shapes -------


def test_golden_exercises_nested_and_array_shapes():
    receipts = _load_golden()["receipts"]
    # A nested camelCase object (apl_eval_trace) — order/casing must round-trip.
    assert any("apl_eval_trace" in r for r in receipts)
    # An array-of-objects with optional fields present and elided.
    assert any(r.get("plugin_digests") for r in receipts)
    # Inner elision: a trace whose empty policiesFired / absent evidenceSha256 are dropped.
    traces = [r["apl_eval_trace"] for r in receipts if "apl_eval_trace" in r]
    assert any("policiesFired" not in t and "evidenceSha256" not in t for t in traces)


# --- CLI surface + exit codes mirror the Rust binary ------------------------


def test_cli_ok_exit_zero(capsys):
    code = iaga_verify.main([GOLDEN, "--key", _load_golden()["signer_verifying_key"]])
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("CHAIN OK")
    assert "seq=0.." in out


def test_cli_missing_file_exit_three(capsys):
    code = iaga_verify.main(["does-not-exist.json"])
    assert code == 3


def test_cli_no_args_exit_two():
    assert iaga_verify.main([]) == 2
