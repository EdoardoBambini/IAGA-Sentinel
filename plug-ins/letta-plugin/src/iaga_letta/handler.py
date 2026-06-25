"""The HITL adjudication loop: turn Letta approval requests into IAGA verdicts.

Letta has no in-process pre-tool hook. Its interception seam is the
``requires_approval`` mechanism: when a governed tool is about to run, Letta pauses
the agent loop and returns an ``approval_request_message``; the action does not run
until the caller replies approve/deny. This module reads that request, asks IAGA
``/v1/inspect`` for a verdict, and sends the reply. Letta holds the tool; IAGA
supplies and signs the verdict. It is cooperative governance, not enforcement —
every receipt the OSS sidecar signs is ``is_authoritative: false``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, List, Optional

from .client import SentinelClient
from .config import infer_action_type, resolve
from .types import Decision, SentinelOptions


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    """Read a field whether ``obj`` is a pydantic model or a plain dict (tests/mocks)."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _parse_args(arguments: Any) -> dict:
    """Letta's ``tool_call.arguments`` is a JSON string; coerce to a payload dict."""
    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, str):
        try:
            value = json.loads(arguments)
        except (ValueError, TypeError):
            return {"value": arguments}
        return value if isinstance(value, dict) else {"value": value}
    return {"value": arguments}


def _reason(verdict: dict) -> str:
    risk = verdict.get("risk") or {}
    reasons = risk.get("reasons") or verdict.get("policyFindings") or []
    return "; ".join(str(r) for r in reasons)


@dataclass
class GovernedRun:
    """Result of driving a run: final response, every decision, and why we stopped."""

    status: str                                   # "completed" | "held" | "max_steps"
    response: Any
    decisions: List[Decision] = field(default_factory=list)
    scan_findings: List[dict] = field(default_factory=list)   # populated when scan_output is on


class SentinelApprovalHandler:
    """Adjudicates Letta ``approval_request_message``s through IAGA ``/v1/inspect``."""

    def __init__(self, options: Optional[SentinelOptions] = None, *, client: Optional[SentinelClient] = None):
        self.opts = resolve(options)
        self.client = client or SentinelClient(self.opts.base_url, self.opts.api_key, self.opts.timeout_ms)

    # --- one verdict ------------------------------------------------------
    def decide(self, tool_name: str, arguments: Any, *, session: Optional[str] = None,
               tool_call_id: Optional[str] = None) -> Decision:
        session = session or self.opts.session or "default"
        payload = _parse_args(arguments)

        if self.opts.scan_input:
            blocked, why = self._firewall(payload)
            if blocked is None and self.opts.fail_closed:
                return Decision("deny", "IAGA Sentinel firewall unreachable, failing closed",
                                tool_call_id=tool_call_id)
            if blocked:
                return Decision("deny", f"input firewall: {why}", tool_call_id=tool_call_id)

        request = {
            "agentId": self.opts.agent_id,
            "framework": self.opts.framework,
            "action": {"type": infer_action_type(tool_name), "toolName": tool_name, "payload": payload},
            "metadata": {"enforcement": "agent-loop", "sessionId": session},
        }
        try:
            verdict = self.client.inspect(request)
        except Exception as exc:  # URLError / timeout / SentinelApiError
            if self.opts.fail_closed:
                return Decision("deny", f"IAGA Sentinel unreachable, failing closed: {exc}",
                                tool_call_id=tool_call_id)
            return Decision("approve", f"IAGA Sentinel unreachable, failing open: {exc}",
                            tool_call_id=tool_call_id)
        return self._map(verdict, tool_call_id)

    def _map(self, verdict: dict, tool_call_id: Optional[str]) -> Decision:
        decision = verdict.get("decision")
        risk = int((verdict.get("risk") or {}).get("score", 0) or 0)
        reason = _reason(verdict)
        if decision == "allow":
            return Decision("approve", reason or "allowed", risk, verdict, tool_call_id)
        if decision == "block":
            return Decision("deny", reason or "blocked by IAGA Sentinel", risk, verdict, tool_call_id)
        # review -> on_review policy ("deny" | "hold" | "approve")
        return Decision(self.opts.on_review, f"review: {reason}" if reason else "review required",
                        risk, verdict, tool_call_id)

    def _firewall(self, payload: dict):
        try:
            res = self.client.firewall_scan(json.dumps(payload))
        except Exception:
            return None, "unreachable"
        # Defensive across both observed response shapes: OpenAPI {clean, threatLevel}
        # and the VoltAgent-transcribed {blocked, summary}.
        blocked = (res.get("blocked") is True or res.get("clean") is False
                   or res.get("threatLevel") in ("high", "critical"))
        why = res.get("summary") or "; ".join(res.get("findings") or []) or "prompt injection detected"
        return blocked, why

    # --- adjudicate one approval message ----------------------------------
    def adjudicate(self, approval_msg: Any, *, session: Optional[str] = None) -> List[Decision]:
        """Decide every tool call in one ``approval_request_message``."""
        # A configured session wins, so the receipt run_id is the predictable
        # `agent:session` the caller can verify; only then fall back to Letta's run id.
        session = session or self.opts.session or _attr(approval_msg, "run_id")
        calls = _attr(approval_msg, "tool_calls") or []
        if not calls:
            single = _attr(approval_msg, "tool_call")
            calls = [single] if single is not None else []
        return [
            self.decide(_attr(tc, "name"), _attr(tc, "arguments"),
                        session=session, tool_call_id=_attr(tc, "tool_call_id"))
            for tc in calls if tc is not None
        ]

    def _scan_output(self, response: Any) -> List[dict]:
        """Detection only: scan tool-return contents via /v1/response/scan. Never rewrites."""
        findings: List[dict] = []
        for m in _attr(response, "messages", []):
            if _attr(m, "message_type") != "tool_return_message":
                continue
            content = (_attr(m, "tool_return") or _attr(m, "return_value")
                       or _attr(m, "content") or "")
            text = content if isinstance(content, str) else json.dumps(content, default=str)
            if not text:
                continue
            try:
                res = self.client.response_scan({"text": text, "agentId": self.opts.agent_id})
            except Exception:
                continue
            if res.get("clean") is False or res.get("findings"):
                findings.append({"tool_call_id": _attr(m, "tool_call_id"), "result": res})
        return findings

    # --- drive a run to completion ----------------------------------------
    def drive(self, letta: Any, agent_id: str, response: Any, *, session: Optional[str] = None,
              max_steps: int = 20) -> GovernedRun:
        """Loop: adjudicate pending approvals, reply, repeat until the run settles."""
        decisions: List[Decision] = []
        scan_findings: List[dict] = []
        for _ in range(max_steps):
            if self.opts.scan_output:
                scan_findings.extend(self._scan_output(response))
            requests = [m for m in _attr(response, "messages", [])
                        if _attr(m, "message_type") == "approval_request_message"]
            if not requests:
                return GovernedRun("completed", response, decisions, scan_findings)
            replies = []
            held = False
            for msg in requests:
                for d in self.adjudicate(msg, session=session):
                    decisions.append(d)
                    if d.action == "hold":
                        held = True
                    elif d.tool_call_id:
                        replies.append({"type": "approval", "tool_call_id": d.tool_call_id,
                                        "approve": d.action == "approve", "reason": d.reason})
            if held:
                # on_review="hold": leave the step pending for a human (Article 14 path).
                return GovernedRun("held", response, decisions, scan_findings)
            response = letta.agents.messages.create(
                agent_id, messages=[{"type": "approval", "approvals": replies}])
        return GovernedRun("max_steps", response, decisions, scan_findings)

    def govern_run(self, letta: Any, agent_id: str, message: str, *, session: Optional[str] = None,
                   max_steps: int = 20) -> GovernedRun:
        """Send a user message and govern the whole resulting run."""
        response = letta.agents.messages.create(agent_id, messages=[{"role": "user", "content": message}])
        return self.drive(letta, agent_id, response, session=session, max_steps=max_steps)


def govern_run(letta: Any, agent_id: str, message: str, options: Optional[SentinelOptions] = None,
               **kwargs: Any) -> GovernedRun:
    """One-call convenience: govern a fresh message end to end."""
    return SentinelApprovalHandler(options).govern_run(letta, agent_id, message, **kwargs)
