"""Unit tests for the governance helpers (mocked Letta).

These lock the mechanisms that were empirically verified to gate the loop:
tool-level `default_requires_approval` and agent-level `requires_approval` tool
rules — NOT the per-agent `update_approval` toggle (which doesn't gate).
"""

from types import SimpleNamespace

from iaga_letta import govern_agent, govern_tool, require_approval


class FakeAgents:
    def __init__(self, tool_rules=None, tools=None):
        self._tool_rules = tool_rules or []
        self._tools = tools or []
        self.updated = None
        self.tools = SimpleNamespace(list=lambda agent_id: self._tools)

    def retrieve(self, agent_id):
        return SimpleNamespace(tool_rules=list(self._tool_rules))

    def update(self, agent_id, tool_rules=None):
        self.updated = tool_rules
        return SimpleNamespace(id=agent_id, tool_rules=tool_rules)


class FakeLetta:
    def __init__(self, tool_rules=None, tools=None):
        self.upserted = None
        self.tools = SimpleNamespace(upsert=self._upsert)
        self.agents = FakeAgents(tool_rules, tools)

    def _upsert(self, **kw):
        self.upserted = kw
        return SimpleNamespace(id="tool-x", name=kw.get("name", "run_shell"))


def _rule(type_, tool_name):
    # mimic a pydantic rule with model_dump(exclude_none=...)
    return SimpleNamespace(model_dump=lambda exclude_none=False, t=type_, n=tool_name: {"type": t, "tool_name": n})


def test_govern_tool_sets_default_requires_approval():
    letta = FakeLetta()
    govern_tool(letta, "def f(): pass")
    assert letta.upserted["default_requires_approval"] is True
    assert letta.upserted["source_code"] == "def f(): pass"


def test_require_approval_adds_agent_rule():
    letta = FakeLetta(tool_rules=[])
    require_approval(letta, "agent-1", "run_shell", True)
    assert {"type": "requires_approval", "tool_name": "run_shell"} in letta.agents.updated


def test_require_approval_preserves_other_rules():
    letta = FakeLetta(tool_rules=[_rule("exit_loop", "send_message")])
    require_approval(letta, "agent-1", "run_shell", True)
    types = [r["type"] for r in letta.agents.updated]
    assert "exit_loop" in types and "requires_approval" in types


def test_require_approval_false_removes_rule():
    letta = FakeLetta(tool_rules=[_rule("requires_approval", "run_shell")])
    require_approval(letta, "agent-1", "run_shell", False)
    assert not any(
        r["type"] == "requires_approval" and r["tool_name"] == "run_shell"
        for r in letta.agents.updated
    )


def test_govern_agent_dedupes_and_rules_all_tools():
    tools = [
        SimpleNamespace(name="run_shell", id="t1"),
        SimpleNamespace(name="run_shell", id="t1"),   # Letta's paginated list repeats
        SimpleNamespace(name="memory_insert", id="t2"),
    ]
    letta = FakeLetta(tool_rules=[], tools=tools)
    governed = govern_agent(letta, "agent-1")
    assert sorted(governed) == ["memory_insert", "run_shell"]
    rule_tools = sorted(r["tool_name"] for r in letta.agents.updated if r["type"] == "requires_approval")
    assert rule_tools == ["memory_insert", "run_shell"]


def test_govern_agent_only_filter():
    tools = [SimpleNamespace(name="run_shell", id="t1"), SimpleNamespace(name="memory_insert", id="t2")]
    letta = FakeLetta(tool_rules=[], tools=tools)
    assert govern_agent(letta, "agent-1", only=["run_shell"]) == ["run_shell"]
