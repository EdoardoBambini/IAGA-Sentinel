"""Shared helpers for dependency-light framework adapters."""

from __future__ import annotations

import asyncio
import functools
import inspect
from dataclasses import dataclass
from typing import Any, Callable, Optional

import httpx

from ..client import SentinelClient, AsyncSentinelClient
from ..types import (
    ActionDetail,
    ActionType,
    GovernanceResult,
    InspectRequest,
    resolve_unreachable,
)


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
    fail_closed: bool = False


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
    try:
        with SentinelClient(base_url=config.base_url, api_key=config.api_key) as client:
            result = client.inspect(request)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code < 500:
            raise
        return resolve_unreachable(
            request.action.tool_name, exc, fail_closed=config.fail_closed
        )
    except httpx.TransportError as exc:
        return resolve_unreachable(
            request.action.tool_name, exc, fail_closed=config.fail_closed
        )
    ensure_allowed(result, request.action.tool_name)
    return result


async def inspect_async(config: AdapterConfig, request: InspectRequest) -> GovernanceResult:
    try:
        async with AsyncSentinelClient(
            base_url=config.base_url,
            api_key=config.api_key,
        ) as client:
            result = await client.inspect(request)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code < 500:
            raise
        return resolve_unreachable(
            request.action.tool_name, exc, fail_closed=config.fail_closed
        )
    except httpx.TransportError as exc:
        return resolve_unreachable(
            request.action.tool_name, exc, fail_closed=config.fail_closed
        )
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


def _safe_value(val: Any) -> Any:
    if isinstance(val, (str, int, float, bool, type(None))):
        return val
    if isinstance(val, (list, tuple)):
        return [_safe_value(v) for v in val]
    if isinstance(val, dict):
        return {str(k): _safe_value(v) for k, v in val.items()}
    return str(val)


def named_payload(
    func: Callable,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    exclude: tuple[str, ...] = ("self", "ctx", "context"),
) -> dict[str, Any]:
    """Build a payload from a function's named arguments, skipping ``exclude``."""
    try:
        params = list(inspect.signature(func).parameters.keys())
    except (TypeError, ValueError):
        params = []
    payload: dict[str, Any] = {}
    for i, arg in enumerate(args):
        name = params[i] if i < len(params) else f"arg{i}"
        if name in exclude:
            continue
        payload[name] = _safe_value(arg)
    for key, value in kwargs.items():
        if key in exclude:
            continue
        payload[key] = _safe_value(value)
    return payload


def governed_callable(
    config: AdapterConfig,
    func: Callable,
    *,
    tool_name: Optional[str] = None,
    action_type: Optional[ActionType] = None,
    exclude: tuple[str, ...] = ("self", "ctx", "context"),
) -> Callable:
    """Wrap a tool function so each call is inspected before it runs.

    Preserves sync/async. The payload is built from the call's named arguments
    (minus ``exclude``); block/review raise PermissionError, transport errors
    follow the fail-open/closed policy on ``config``.
    """
    name = tool_name or getattr(func, "__name__", "tool")
    resolved_type = action_type or infer_action_type(name)

    if asyncio.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            return await run_guarded_async(
                config,
                tool_name=name,
                action_type=resolved_type,
                payload=named_payload(func, args, kwargs, exclude=exclude),
                call=lambda: func(*args, **kwargs),
            )

        return async_wrapper

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        return run_guarded_sync(
            config,
            tool_name=name,
            action_type=resolved_type,
            payload=named_payload(func, args, kwargs, exclude=exclude),
            call=lambda: func(*args, **kwargs),
        )

    return sync_wrapper
