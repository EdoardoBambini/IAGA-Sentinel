"""Shared helpers for dependency-light framework adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..client import SentinelClient, AsyncSentinelClient
from ..types import ActionDetail, ActionType, GovernanceResult, InspectRequest


@dataclass(frozen=True)
class AdapterConfig:
    agent_id: str
    api_key: Optional[str] = None
    base_url: str = "http://localhost:4010"
    framework: str = "sdk-adapter"
    workspace_id: Optional[str] = None
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


def build_request(
    config: AdapterConfig,
    *,
    tool_name: str,
    action_type: ActionType,
    payload: dict[str, Any],
    metadata: Optional[dict[str, Any]] = None,
) -> InspectRequest:
    combined_metadata = dict(config.metadata or {})
    combined_metadata.update(metadata or {})
    return InspectRequest(
        agent_id=config.agent_id,
        tenant_id=config.tenant_id,
        workspace_id=config.workspace_id,
        framework=config.framework,
        action=ActionDetail(type=action_type, tool_name=tool_name, payload=payload),
        metadata=combined_metadata or None,
        session_id=config.session_id,
    )


def ensure_allowed(result: GovernanceResult, tool_name: str) -> None:
    if result.blocked:
        raise PermissionError(
            f"IAGA Sentinel blocked '{tool_name}' (risk={result.risk.score}): "
            f"{', '.join(result.risk.reasons)}"
        )
    if result.needs_review:
        raise PermissionError(
            f"IAGA Sentinel requires review for '{tool_name}' "
            f"(review_id={result.review_request_id}, risk={result.risk.score})"
        )


def serialize_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"args": list(args)}
    payload.update(kwargs)
    return payload


def infer_action_type(tool_name: str, default: ActionType = ActionType.CUSTOM) -> ActionType:
    tool = tool_name.lower()
    if "http" in tool or "openai" in tool or "response" in tool:
        return ActionType.HTTP
    if "shell" in tool or "terminal" in tool:
        return ActionType.SHELL
    if "read" in tool or "file" in tool:
        return ActionType.FILE_READ
    if "write" in tool:
        return ActionType.FILE_WRITE
    return default


def inspect_sync(config: AdapterConfig, request: InspectRequest) -> GovernanceResult:
    with SentinelClient(base_url=config.base_url, api_key=config.api_key) as client:
        result = client.inspect(request)
    ensure_allowed(result, request.action.tool_name)
    return result


async def inspect_async(config: AdapterConfig, request: InspectRequest) -> GovernanceResult:
    async with AsyncSentinelClient(
        base_url=config.base_url,
        api_key=config.api_key,
    ) as client:
        result = await client.inspect(request)
    ensure_allowed(result, request.action.tool_name)
    return result


def run_guarded_sync(
    config: AdapterConfig,
    *,
    tool_name: str,
    action_type: ActionType,
    payload: dict[str, Any],
    metadata: Optional[dict[str, Any]] = None,
    call: Callable[[], Any],
) -> Any:
    inspect_sync(
        config,
        build_request(
            config,
            tool_name=tool_name,
            action_type=action_type,
            payload=payload,
            metadata=metadata,
        ),
    )
    return call()


async def run_guarded_async(
    config: AdapterConfig,
    *,
    tool_name: str,
    action_type: ActionType,
    payload: dict[str, Any],
    metadata: Optional[dict[str, Any]] = None,
    call: Callable[[], Any],
) -> Any:
    await inspect_async(
        config,
        build_request(
            config,
            tool_name=tool_name,
            action_type=action_type,
            payload=payload,
            metadata=metadata,
        ),
    )
    return await call()
