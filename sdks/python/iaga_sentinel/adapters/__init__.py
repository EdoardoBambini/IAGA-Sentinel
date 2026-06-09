"""Framework adapters for the IAGA Sentinel Python SDK."""

from .autogen import AutoGenSentinelHook
from .crewai import SentinelGuardrail
from .langchain import SentinelCallbackHandler
from .langgraph import GovernedToolNode
from .llamaindex import IagaCallbackHandler
from .mcp import govern_tool
from .microsoft_agent_framework import sentinel_middleware
from .openai import SentinelOpenAIWrapper, sentinel_wrap_openai
from .openai_agents import iaga_tool_guardrail

# Note: `governed_tool` exists in both `pydantic_ai` and `openai_agents`; import
# it from the specific submodule (e.g. `from iaga_sentinel.adapters.pydantic_ai
# import governed_tool`) to avoid the name clash.

__all__ = [
    "SentinelCallbackHandler",
    "SentinelGuardrail",
    "SentinelOpenAIWrapper",
    "AutoGenSentinelHook",
    "GovernedToolNode",
    "IagaCallbackHandler",
    "govern_tool",
    "iaga_tool_guardrail",
    "sentinel_middleware",
    "sentinel_wrap_openai",
]
