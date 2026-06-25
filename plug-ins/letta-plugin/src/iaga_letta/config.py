"""Option resolution (env fallbacks) and tool-name -> action-type inference."""

from __future__ import annotations

import os
import re
from dataclasses import replace
from typing import Optional

from .types import SentinelOptions

DEFAULT_URL = "http://localhost:4010"
DEFAULT_AGENT_ID = "letta-agent"


def resolve(options: Optional[SentinelOptions] = None) -> SentinelOptions:
    """Fill unset string options from env vars, matching the VoltAgent plugin."""
    opts = options or SentinelOptions()
    return replace(
        opts,
        base_url=opts.base_url or os.environ.get("IAGA_SENTINEL_URL") or DEFAULT_URL,
        api_key=opts.api_key or os.environ.get("IAGA_SENTINEL_API_KEY"),
        agent_id=opts.agent_id or os.environ.get("IAGA_SENTINEL_AGENT_ID") or DEFAULT_AGENT_ID,
    )


# ponytail: regexes ported verbatim from plug-ins/voltagent-plugin/src/config.ts so
# both plugins bucket tool names into the same /v1/inspect action types.
_RULES = (
    ("shell", re.compile(r"(^|[_:.\- ])(shell|exec|bash|sh|cmd|command|terminal|run|spawn)([_:.\- ]|$)")),
    ("file_write", re.compile(r"(write|create|edit|save|patch|append|delete|remove|rm|mkdir|put|upload)")),
    ("file_read", re.compile(r"(read|cat|view|open|load|ls|list|glob|grep|get_file|download)")),
    ("db_query", re.compile(r"(sql|query|db|database|select|insert|mongo|postgres|mysql|redis)")),
    ("http", re.compile(r"(http|fetch|request|url|web|api|curl|browse|crawl|scrape)")),
    ("email", re.compile(r"(email|smtp|mail|sendgrid|mailgun)")),
)


def infer_action_type(tool_name: str) -> str:
    """Best-effort tool name -> action type; defaults to the safe "custom" bucket."""
    name = (tool_name or "").lower()
    for action_type, pattern in _RULES:
        if pattern.search(name):
            return action_type
    return "custom"
