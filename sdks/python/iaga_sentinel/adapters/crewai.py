"""Dependency-light CrewAI guardrail helpers for IAGA Sentinel."""

from __future__ import annotations

from typing import Any, Optional

from ..types import ActionType
from ._common import AdapterConfig, build_request, inspect_async, inspect_sync


class SentinelGuardrail:
    """Guardrail object that can be called before a CrewAI tool/action runs."""

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:4010",
        framework: str = "crewai",
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

    def validate(
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

    async def avalidate(
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

    def __call__(
        self,
        tool_name: str,
        payload: dict[str, Any],
        action_type: ActionType = ActionType.CUSTOM,
    ) -> dict[str, Any]:
        self.validate(tool_name, payload, action_type=action_type)
        return payload
