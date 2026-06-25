"""Helpers to opt Letta tools/agents into the approval gate (the IAGA seam).

A tool only reaches the approval handler if it requires approval. Two Letta
mechanisms actually gate the agent loop — both verified against a live server:

  * tool-level:  ``tools.upsert(default_requires_approval=True)`` gates the tool
    when it is attached to an agent.
  * agent-level: a ``{"type": "requires_approval"}`` tool rule on the agent gates
    that tool, and applies **retroactively** to an existing agent.

Note: Letta also exposes ``agents.tools.update_approval`` (a per-agent toggle), but
on Letta 0.16.8 it does NOT pause the loop, so it is deliberately not used here.
"""

from __future__ import annotations

from typing import Any, List, Optional


def govern_tool(letta: Any, source_code: str, *, requires_approval: bool = True, **upsert_kwargs: Any) -> Any:
    """Upsert a tool that requires approval before running (tool-level gate).

    Returns the created/updated tool, ready to attach via ``tool_ids=[tool.id]``.
    """
    return letta.tools.upsert(
        source_code=source_code, default_requires_approval=requires_approval, **upsert_kwargs
    )


def _rule_dump(rule: Any) -> dict:
    if isinstance(rule, dict):
        return rule
    if hasattr(rule, "model_dump"):
        return rule.model_dump(exclude_none=True)
    return dict(rule)


def _set_approval_rules(letta: Any, agent_id: str, tool_names: List[str], requires: bool) -> List[str]:
    """Merge/remove `requires_approval` tool rules on an agent, preserving the rest."""
    agent = letta.agents.retrieve(agent_id)
    rules = [_rule_dump(r) for r in (getattr(agent, "tool_rules", None) or [])]
    # drop any existing requires_approval rule for the target tools, then re-add
    rules = [
        r for r in rules
        if not (r.get("type") == "requires_approval" and r.get("tool_name") in tool_names)
    ]
    if requires:
        rules += [{"type": "requires_approval", "tool_name": n} for n in tool_names]
    letta.agents.update(agent_id, tool_rules=rules)
    return tool_names


def _attached_tool_names(letta: Any, agent_id: str, only: Optional[List[str]]) -> List[str]:
    names: List[str] = []
    for t in letta.agents.tools.list(agent_id):
        name = getattr(t, "name", None) if not isinstance(t, dict) else t.get("name")
        if name and name not in names and (only is None or name in only):
            names.append(name)
    return names


def require_approval(letta: Any, agent_id: str, tool_name: str, requires: bool = True) -> List[str]:
    """Gate (or un-gate) one tool on an existing agent via an agent tool rule."""
    return _set_approval_rules(letta, agent_id, [tool_name], requires)


def govern_agent(letta: Any, agent_id: str, requires: bool = True, *, only: Optional[List[str]] = None) -> List[str]:
    """Opt a whole agent into governance: every attached tool requires approval.

    ``only`` restricts to the given tool names. Returns the tool names governed.
    """
    names = _attached_tool_names(letta, agent_id, only)
    if not names:
        return []
    return _set_approval_rules(letta, agent_id, names, requires)
