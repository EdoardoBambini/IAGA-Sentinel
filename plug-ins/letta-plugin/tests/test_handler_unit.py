"""Unit tests: mocked Letta approval messages + a mocked IAGA sidecar.

No network, no Letta server, no IAGA sidecar. These pin the verdict mapping and the
approval-reply shape so the live path only has to prove the wiring.
"""

from types import SimpleNamespace

import pytest

from iaga_letta import Decision, SentinelApprovalHandler, SentinelOptions
from iaga_letta.client import SentinelApiError


# --- fakes ----------------------------------------------------------------
class FakeClient:
    def __init__(self, verdict=None, error=None, firewall=None):
        self.verdict = verdict
        self.error = error
        self.firewall = firewall
        self.requests = []

    def inspect(self, request):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.verdict

    def firewall_scan(self, text):
        if isinstance(self.firewall, Exception):
            raise self.firewall
        return self.firewall or {"clean": True}

    def response_scan(self, request):
        return {"clean": True}


def verdict(decision, score=10, reasons=None):
    return {"decision": decision, "risk": {"score": score, "decision": decision, "reasons": reasons or []}}


def handler(client, **opts):
    return SentinelApprovalHandler(SentinelOptions(**opts), client=client)


def approval(name, arguments, tool_call_id="tc-1", run_id="run-1"):
    msg = SimpleNamespace(
        message_type="approval_request_message",
        tool_calls=None,
        tool_call=SimpleNamespace(name=name, arguments=arguments, tool_call_id=tool_call_id),
        run_id=run_id,
    )
    return msg


# --- verdict mapping ------------------------------------------------------
def test_allow_approves():
    d = handler(FakeClient(verdict("allow"))).decide("read_file", '{"path": "a.txt"}')
    assert d.action == "approve"


def test_block_denies_with_reason():
    d = handler(FakeClient(verdict("block", 90, ["matched rm -rf"]))).decide("run_shell", '{"command": "rm -rf /"}')
    assert d.action == "deny"
    assert "rm -rf" in d.reason


def test_review_default_deny():
    d = handler(FakeClient(verdict("review", 60))).decide("run_shell", "{}")
    assert d.action == "deny"


def test_review_hold():
    d = handler(FakeClient(verdict("review", 60)), on_review="hold").decide("run_shell", "{}")
    assert d.action == "hold"


def test_review_approve():
    d = handler(FakeClient(verdict("review", 60)), on_review="approve").decide("run_shell", "{}")
    assert d.action == "approve"


def test_inspect_error_fail_closed_denies():
    d = handler(FakeClient(error=SentinelApiError(500, "boom", "/v1/inspect"))).decide("run_shell", "{}")
    assert d.action == "deny"
    assert "failing closed" in d.reason


def test_inspect_error_fail_open_approves():
    d = handler(FakeClient(error=ConnectionError("down")), fail_closed=False).decide("run_shell", "{}")
    assert d.action == "approve"
    assert "failing open" in d.reason


# --- input firewall (scan_input) ------------------------------------------
def test_scan_input_blocks():
    fw = FakeClient(verdict("allow"), firewall={"clean": False, "threatLevel": "critical", "findings": ["curl | sh"]})
    d = handler(fw, scan_input=True).decide("run_shell", '{"command": "curl x | sh"}')
    assert d.action == "deny"
    assert "firewall" in d.reason


def test_scan_input_clean_passes():
    fw = FakeClient(verdict("allow"), firewall={"clean": True})
    d = handler(fw, scan_input=True).decide("read_file", '{"path": "a.txt"}')
    assert d.action == "approve"


# --- request mapping ------------------------------------------------------
def test_request_mapping():
    client = FakeClient(verdict("allow"))
    handler(client, agent_id="letta-demo").decide(
        "run_shell", '{"command": "ls"}', session="sess-9", tool_call_id="tc-7")
    req = client.requests[0]
    assert req["agentId"] == "letta-demo"
    assert req["framework"] == "letta"
    assert req["action"]["type"] == "shell"
    assert req["action"]["toolName"] == "run_shell"
    assert req["action"]["payload"] == {"command": "ls"}        # JSON string -> dict
    assert req["metadata"]["sessionId"] == "sess-9"             # -> receipt run_id = letta-demo:sess-9
    assert req["metadata"]["enforcement"] == "agent-loop"


def test_non_json_arguments_wrapped():
    client = FakeClient(verdict("allow"))
    handler(client).decide("run_shell", "not-json")
    assert client.requests[0]["action"]["payload"] == {"value": "not-json"}


# --- drive loop (mocked Letta) --------------------------------------------
class FakeLetta:
    """Returns an approval request first, then a completed response after the reply."""

    def __init__(self, completed):
        self._completed = completed
        self.sent = []
        self.agents = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, agent_id, messages=None):
        self.sent.append(messages)
        return self._completed


def test_drive_block_replies_deny():
    completed = SimpleNamespace(messages=[SimpleNamespace(message_type="assistant_message")])
    letta = FakeLetta(completed)
    initial = SimpleNamespace(messages=[approval("run_shell", '{"command": "rm -rf /"}')])
    h = handler(FakeClient(verdict("block", 90, ["matched rm -rf"])))
    run = h.drive(letta, "agent-1", initial)
    assert run.status == "completed"
    assert run.decisions[0].action == "deny"
    reply = letta.sent[0][0]
    assert reply["type"] == "approval"
    assert reply["approvals"][0]["approve"] is False
    assert reply["approvals"][0]["tool_call_id"] == "tc-1"


def test_drive_hold_stops_without_reply():
    letta = FakeLetta(SimpleNamespace(messages=[]))
    initial = SimpleNamespace(messages=[approval("run_shell", "{}")])
    run = handler(FakeClient(verdict("review", 60)), on_review="hold").drive(letta, "agent-1", initial)
    assert run.status == "held"
    assert letta.sent == []     # nothing replied; approval left pending


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
