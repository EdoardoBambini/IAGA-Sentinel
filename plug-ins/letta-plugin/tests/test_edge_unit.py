"""Edge-case unit tests (no network). Robustness of the handler's plumbing."""

from types import SimpleNamespace

import pytest

from iaga_letta import (
    Decision,
    SentinelApprovalHandler,
    SentinelOptions,
    govern_run,
    infer_action_type,
    resolve,
)


class FakeClient:
    def __init__(self, verdict=None):
        self.verdict = verdict or {"decision": "allow", "risk": {"score": 1, "reasons": []}}
        self.requests = []

    def inspect(self, request):
        self.requests.append(request)
        return self.verdict

    def firewall_scan(self, text):
        return {"clean": True}

    def response_scan(self, request):
        return {"clean": True}


def H(client=None, **opts):
    return SentinelApprovalHandler(SentinelOptions(**opts), client=client or FakeClient())


# --- action-type inference: every bucket -----------------------------------
@pytest.mark.parametrize("name,expected", [
    ("run_shell", "shell"), ("bash", "shell"), ("exec_command", "shell"),
    ("read_file", "file_read"), ("cat_file", "file_read"), ("list_dir", "file_read"),
    ("write_file", "file_write"), ("delete_record", "file_write"), ("mkdir", "file_write"),
    ("database_query", "db_query"), ("postgres_query", "db_query"),
    ("http_get", "http"), ("fetch_url", "http"), ("web_search", "http"),
    ("send_email", "email"), ("smtp_send", "email"),
    ("xyzzy", "custom"), ("", "custom"),
])
def test_infer_action_type(name, expected):
    # substring matching is intentional (ported verbatim from the VoltAgent plugin):
    # "run_sql" -> shell (run_), "frobnicate" -> file_read (cat). "custom" is the fallback.
    assert infer_action_type(name) == expected


# --- payload coercion ------------------------------------------------------
@pytest.mark.parametrize("arguments,expected", [
    ('{"command": "ls"}', {"command": "ls"}),
    ({"command": "ls"}, {"command": "ls"}),
    ("[1, 2, 3]", {"value": [1, 2, 3]}),          # non-object JSON -> wrapped
    ("plain text", {"value": "plain text"}),       # invalid JSON -> wrapped
    (42, {"value": 42}),                            # non-str/dict -> wrapped
])
def test_payload_coercion(arguments, expected):
    c = FakeClient()
    H(c).decide("run_shell", arguments)
    assert c.requests[0]["action"]["payload"] == expected


# --- reason fallbacks ------------------------------------------------------
def test_reason_uses_policy_findings_when_no_risk_reasons():
    c = FakeClient({"decision": "block", "risk": {"score": 80, "reasons": []},
                    "policyFindings": ["workspace denies this tool"]})
    d = H(c).decide("run_shell", "{}")
    assert d.action == "deny" and "workspace denies" in d.reason


def test_block_with_no_reasons_has_generic_message():
    c = FakeClient({"decision": "block", "risk": {"score": 80}})
    d = H(c).decide("run_shell", "{}")
    assert d.action == "deny" and d.reason


def test_missing_risk_block_does_not_crash():
    d = H(FakeClient({"decision": "block"})).decide("run_shell", "{}")
    assert d.action == "deny" and d.risk == 0


# --- session precedence ----------------------------------------------------
def test_session_precedence_explicit_wins():
    c = FakeClient()
    H(c, session="opt-session").decide("run_shell", "{}", session="explicit")
    assert c.requests[0]["metadata"]["sessionId"] == "explicit"


def test_session_falls_back_to_option():
    c = FakeClient()
    H(c, session="opt-session").decide("run_shell", "{}")
    assert c.requests[0]["metadata"]["sessionId"] == "opt-session"


def test_adjudicate_uses_run_id_as_session():
    c = FakeClient()
    msg = SimpleNamespace(
        message_type="approval_request_message", tool_calls=None,
        tool_call=SimpleNamespace(name="run_shell", arguments="{}", tool_call_id="tc"),
        run_id="run-from-letta")
    H(c).adjudicate(msg)
    assert c.requests[0]["metadata"]["sessionId"] == "run-from-letta"


# --- batch: multiple tool_calls in one approval ----------------------------
def test_adjudicate_batch_of_tool_calls():
    c = FakeClient()
    msg = SimpleNamespace(
        message_type="approval_request_message",
        tool_call=None,
        tool_calls=[
            SimpleNamespace(name="read_file", arguments='{"p":"a"}', tool_call_id="tc-1"),
            SimpleNamespace(name="run_shell", arguments='{"command":"ls"}', tool_call_id="tc-2"),
        ],
        run_id="r")
    decisions = H(c).adjudicate(msg)
    assert [d.tool_call_id for d in decisions] == ["tc-1", "tc-2"]
    assert len(c.requests) == 2


def test_adjudicate_empty_returns_nothing():
    msg = SimpleNamespace(message_type="approval_request_message", tool_call=None, tool_calls=None)
    assert H().adjudicate(msg) == []


# --- env resolution --------------------------------------------------------
def test_resolve_env_fallbacks(monkeypatch):
    monkeypatch.setenv("IAGA_SENTINEL_URL", "http://example:9999")
    monkeypatch.setenv("IAGA_SENTINEL_API_KEY", "k-123")
    monkeypatch.setenv("IAGA_SENTINEL_AGENT_ID", "from-env")
    opts = resolve(SentinelOptions())
    assert opts.base_url == "http://example:9999"
    assert opts.api_key == "k-123"
    assert opts.agent_id == "from-env"


def test_resolve_explicit_overrides_env(monkeypatch):
    monkeypatch.setenv("IAGA_SENTINEL_AGENT_ID", "from-env")
    opts = resolve(SentinelOptions(agent_id="explicit"))
    assert opts.agent_id == "explicit"


def test_resolve_defaults():
    opts = resolve(SentinelOptions())
    # only meaningful when env is unset; assert the shape, not a specific value
    assert opts.base_url.startswith("http")
    assert opts.agent_id


# --- drive: batch reply, tool_call_id None, max_steps ----------------------
class FakeLetta:
    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = []
        self.agents = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, agent_id, messages=None):
        self.sent.append(messages)
        return self._responses.pop(0) if self._responses else SimpleNamespace(messages=[])


def _appr(name, args, tcid):
    return SimpleNamespace(message_type="approval_request_message", tool_calls=None,
                           tool_call=SimpleNamespace(name=name, arguments=args, tool_call_id=tcid),
                           run_id="r")


def test_drive_skips_reply_when_tool_call_id_missing():
    # a malformed approval with no tool_call_id should not crash; nothing to reply
    c = FakeClient({"decision": "block", "risk": {"score": 90, "reasons": ["x"]}})
    completed = SimpleNamespace(messages=[])
    letta = FakeLetta([completed])
    initial = SimpleNamespace(messages=[_appr("run_shell", "{}", None)])
    run = SentinelApprovalHandler(SentinelOptions(), client=c).drive(letta, "a", initial)
    # one decision made, but the reply list was empty (no tool_call_id) -> still sent an (empty) approval
    assert run.decisions[0].action == "deny"


def test_drive_max_steps_cap():
    # every response keeps asking for approval -> loop hits the cap
    c = FakeClient({"decision": "allow", "risk": {"score": 1, "reasons": []}})
    always = SimpleNamespace(messages=[_appr("run_shell", "{}", "tc")])
    letta = FakeLetta([always] * 50)
    run = SentinelApprovalHandler(SentinelOptions(), client=c).drive(letta, "a", always, max_steps=3)
    assert run.status == "max_steps"
    assert len(letta.sent) == 3


def test_module_level_govern_run(monkeypatch):
    c = FakeClient({"decision": "allow", "risk": {"score": 1, "reasons": []}})
    completed = SimpleNamespace(messages=[])
    letta = FakeLetta([SimpleNamespace(messages=[_appr("run_shell", "{}", "tc")]), completed])
    # inject our fake client by patching the handler the convenience fn builds
    import iaga_letta.handler as H
    monkeypatch.setattr(H, "SentinelClient", lambda *a, **k: c)
    run = govern_run(letta, "agent-1", "do it", SentinelOptions())
    assert run.status == "completed"
    assert run.decisions[0].action == "approve"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
