"""IAGA Sentinel governance plugin for Letta.

Adjudicates Letta's Human-in-the-Loop tool approvals through a local IAGA Sentinel
sidecar (allow/review/block) and turns each verdict into an Ed25519-signed,
offline-verifiable receipt. Cooperative governance, not enforcement; every OSS
receipt is ``is_authoritative: false``.
"""

from .client import SentinelApiError, SentinelClient
from .config import infer_action_type, resolve
from .handler import GovernedRun, SentinelApprovalHandler, govern_run
from .tools import govern_agent, govern_tool, require_approval
from .types import Decision, SentinelOptions

__version__ = "0.1.0"

__all__ = [
    "SentinelClient",
    "SentinelApiError",
    "SentinelApprovalHandler",
    "GovernedRun",
    "govern_run",
    "SentinelOptions",
    "Decision",
    "govern_tool",
    "require_approval",
    "govern_agent",
    "infer_action_type",
    "resolve",
]
