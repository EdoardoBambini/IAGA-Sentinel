"""Dependency-light LangChain callback helpers for IAGA Sentinel."""

from __future__ import annotations

from typing import Any, Optional

from ..types import ActionType
from ._common import (
    AdapterConfig,
    build_request,
    infer_action_type,
    inspect_async,
    inspect_sync,
)


class SentinelCallbackHandler:
    """Minimal callback handler compatible with LangChain-style tool hooks."""

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:4010",
        framework: str = "langchain",
        workspace_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ):
        self._config = AdapterConfig(
            agent_id=agent_id,
            api_key=api_key,
            base_url=base_url,
            framework=framework,
            workspace_id=workspace_id,
            tenant_id=tenant_id,
            session_id=session_id,
            metadata=metadata,
        )

    def guard_tool(
        self,
        tool_name: str,
        payload: dict[str, Any],
        action_type: ActionType = ActionType.CUSTOM,
    ) -> None:
        inspect_sync(
            self._config,
            build_request(
                self._config,
                tool_name=tool_name,
                action_type=action_type,
                payload=payload,
            ),
        )

    async def aguard_tool(
        self,
        tool_name: str,
        payload: dict[str, Any],
        action_type: ActionType = ActionType.CUSTOM,
    ) -> None:
        await inspect_async(
            self._config,
            build_request(
                self._config,
                tool_name=tool_name,
                action_type=action_type,
                payload=payload,
            ),
        )

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = str(serialized.get("name") or serialized.get("id") or "langchain.tool")
        action_type = infer_action_type(tool_name)
        payload = {"input": input_str, "kwargs": kwargs}
        self.guard_tool(tool_name, payload, action_type=action_type)

    async def aon_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = str(serialized.get("name") or serialized.get("id") or "langchain.tool")
        action_type = infer_action_type(tool_name)
        payload = {"input": input_str, "kwargs": kwargs}
        await self.aguard_tool(tool_name, payload, action_type=action_type)
