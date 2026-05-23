# IAGA Sentinel Python SDK

`iaga-sentinel` wraps the IAGA Sentinel HTTP API for Python applications and ships
lightweight adapters for common agent frameworks.

## Highlights

- `SentinelClient` and `AsyncSentinelClient` cover governance, policy, plugin, audit,
  telemetry, and threat intel endpoints exposed by the runtime
- `InspectRequest` supports `session_id`, encoded into `metadata.sessionId` for
  sequence-aware governance
- dependency-light adapters exist for OpenAI, LangChain, CrewAI, and AutoGen

## Quick start

```python
from iaga_sentinel import ActionDetail, ActionType, SentinelClient, InspectRequest

client = SentinelClient(api_key="ak-local")
result = client.inspect(
    InspectRequest(
        agent_id="builder-01",
        workspace_id="ws-demo",
        framework="openai",
        session_id="session-123",
        action=ActionDetail(
            type=ActionType.FILE_READ,
            tool_name="filesystem.read",
            payload={"path": "README.md"},
        ),
    )
)

print(result.decision.value, result.trace_id)
```

## Adapters

```python
from openai import OpenAI

from iaga_sentinel.adapters import SentinelCallbackHandler, SentinelGuardrail, sentinel_wrap_openai

openai_client = sentinel_wrap_openai(OpenAI(), agent_id="builder-01", api_key="ak-local")
langchain_handler = SentinelCallbackHandler(agent_id="builder-01", api_key="ak-local")
crewai_guardrail = SentinelGuardrail(agent_id="builder-01", api_key="ak-local")
```
