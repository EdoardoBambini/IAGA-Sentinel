"""Runnable demo: govern a Letta agent's tool calls through IAGA Sentinel.

Creates an agent with one shell tool that requires approval, then sends a dangerous
request and watches the call get DENIED with the policy reason. The decision is
recorded as a signed receipt you can verify offline.

Run (after the quickstart in README.md brings up both servers):

    IAGA_LETTA_URL=http://localhost:8283 LETTA_PASSWORD=pw \
    LETTA_TEST_MODEL=openai/gpt-4o-mini \
    python examples/governed_agent.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iaga_letta import SentinelApprovalHandler, SentinelOptions, govern_tool  # noqa: E402

IAGA_URL = os.environ.get("IAGA_SENTINEL_URL", "http://localhost:4010")
LETTA_URL = os.environ.get("IAGA_LETTA_URL", "http://localhost:8283")
LETTA_PASSWORD = os.environ.get("LETTA_PASSWORD")
MODEL = os.environ.get("LETTA_TEST_MODEL", "openai/gpt-4o-mini")
EMBEDDING = os.environ.get("LETTA_TEST_EMBEDDING")
AGENT_ID = "letta-demo"          # must be registered on the sidecar (see README)
SESSION = "demo-1"

SHELL_TOOL = (
    "def run_shell(command: str):\n"
    '    """Run a shell command.\n\n    Args:\n        command (str): the command line to run.\n    """\n'
    "    return {'ran': command}\n"
)


def main() -> None:
    from letta_client import Letta

    letta = Letta(base_url=LETTA_URL, api_key=LETTA_PASSWORD)

    # govern_tool upserts the tool with default_requires_approval=True, so every
    # call pauses at Letta's approval boundary for IAGA to adjudicate.
    tool = govern_tool(letta, SHELL_TOOL)
    kwargs = dict(
        name="iaga-governed-demo",
        system="You are a shell runner. For every request, call run_shell with the exact command. Never refuse.",
        model=MODEL,
        tool_ids=[tool.id],
    )
    if EMBEDDING:
        kwargs["embedding"] = EMBEDDING
    agent = letta.agents.create(**kwargs)

    handler = SentinelApprovalHandler(SentinelOptions(
        base_url=IAGA_URL, agent_id=AGENT_ID, session=SESSION, on_review="deny"))

    print("> asking the agent to run a dangerous command...")
    run = handler.govern_run(letta, agent.id, "Run the cleanup command: rm -rf /tmp/iaga-demo-cache")
    for d in run.decisions:
        mark = "DENIED " if d.action == "deny" else d.action.upper() + " "
        print(f"  {mark}{d.reason} (risk={d.risk})")

    print(f"\nrun status: {run.status}")
    print(f"verify the signed receipt chain offline:\n  iaga replay {AGENT_ID}:{SESSION} --verify-only")

    try:
        letta.agents.delete(agent.id)
    except Exception:
        pass


if __name__ == "__main__":
    main()
