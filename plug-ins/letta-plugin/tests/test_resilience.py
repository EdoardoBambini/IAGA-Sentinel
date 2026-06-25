"""Resilience: how the plugin behaves when the IAGA sidecar is unreachable.

These use the REAL SentinelClient against a dead address (no mock) so the transport
fail-closed / fail-open policy is exercised end to end through urllib.
"""

from iaga_letta import SentinelApprovalHandler, SentinelOptions

DEAD = "http://127.0.0.1:9"   # nothing listens here -> connection refused


def test_fail_closed_denies_when_sidecar_down():
    h = SentinelApprovalHandler(SentinelOptions(base_url=DEAD, fail_closed=True, timeout_ms=1000))
    d = h.decide("run_shell", '{"command": "ls"}')
    assert d.action == "deny"
    assert "failing closed" in d.reason


def test_fail_open_approves_when_sidecar_down():
    h = SentinelApprovalHandler(SentinelOptions(base_url=DEAD, fail_closed=False, timeout_ms=1000))
    d = h.decide("run_shell", '{"command": "ls"}')
    assert d.action == "approve"
    assert "failing open" in d.reason


def test_fail_closed_is_the_default():
    # the safe default must be deny-on-outage
    assert SentinelOptions().fail_closed is True
    h = SentinelApprovalHandler(SentinelOptions(base_url=DEAD, timeout_ms=1000))
    assert h.decide("run_shell", "{}").action == "deny"


def test_scan_input_unreachable_fails_closed():
    h = SentinelApprovalHandler(SentinelOptions(
        base_url=DEAD, scan_input=True, fail_closed=True, timeout_ms=1000))
    d = h.decide("run_shell", '{"command": "ls"}')
    assert d.action == "deny"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
