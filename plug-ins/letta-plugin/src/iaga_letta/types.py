"""Option and verdict types for the IAGA Sentinel Letta plugin.

ponytail: only the public surface is typed. Wire bodies (the /v1/inspect request
and response) stay plain dicts — the handler reads the two fields it needs
(`decision`, `risk.reasons`) directly, so a mirrored dataclass would be dead code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

try:
    from typing import Literal
except ImportError:  # pragma: no cover - Python <3.8 only
    from typing_extensions import Literal  # type: ignore

# What a "review" verdict maps to, and what we reply to Letta.
ReviewPolicy = Literal["deny", "hold", "approve"]
Action = Literal["approve", "deny", "hold"]


@dataclass
class SentinelOptions:
    """Plugin options. Unset string fields fall back to env vars in ``config.resolve``."""

    base_url: Optional[str] = None        # env IAGA_SENTINEL_URL, default http://localhost:4010
    api_key: Optional[str] = None         # env IAGA_SENTINEL_API_KEY (Bearer; omit in open mode)
    agent_id: Optional[str] = None        # env IAGA_SENTINEL_AGENT_ID, default "letta-agent"
    framework: str = "letta"
    session: Optional[str] = None         # -> metadata.sessionId -> receipt run_id = agentId:session
    fail_closed: bool = True              # deny when the sidecar is unreachable
    on_review: ReviewPolicy = "deny"      # how a review verdict maps to the approve/deny reply
    scan_input: bool = False              # pre-scan tool args via /v1/firewall/scan
    scan_output: bool = False             # post-scan tool output via /v1/response/scan (detection only)
    timeout_ms: int = 5000


@dataclass
class Decision:
    """The verdict for one tool call, ready to become a Letta approval reply."""

    action: Action                        # "approve" | "deny" | "hold"
    reason: str
    risk: int = 0
    verdict: Optional[dict] = None        # raw /v1/inspect response (None on transport error)
    tool_call_id: Optional[str] = None
