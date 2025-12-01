# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/routers/tool_testing.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Tool Testing Router.

This module provides FastAPI routes for testing tools via JSON-RPC,
mirroring the Admin UI "Test Tool" behavior but exposing it as a clean API:

1) GET  /tool-testing/tools/{tool_id}
   - Fetch the tool definition (including input_schema).
   - Clients (Postman/docs/UI) can inspect input_schema and know which params to send.

2) POST /tool-testing/tools/{tool_id}/run
   - Client sends ONLY the logical params (matching the input_schema).
   - This router:
       * Looks up the tool name.
       * Builds a JSON-RPC payload internally:
           { "jsonrpc": "2.0", "id": <timestamp>, "method": tool.name, "params": {...} }
       * POSTs that payload to /rpc on the same gateway.
       * Returns both the JSON-RPC request and the /rpc response.

Permissions:
    - GET  requires "tools.read"
    - POST requires "tools.invoke"

Visibility (private/team/public) is enforced the same way as other tool routes,
via RBAC and ToolService.
"""

# Standard
from datetime import datetime, UTC
from typing import Any, Dict, Optional

# Third-Party
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.db import SessionLocal
from mcpgateway.middleware.rbac import (
    require_permission,
    get_current_user_with_permissions,
)
from mcpgateway.schemas import ToolRead
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.tool_service import ToolService

# Initialize logging
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)

# Create router
tool_testing_router = APIRouter()


def get_db():
    """Database dependency.

    Yields:
        Session: SQLAlchemy database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ToolRunRequest(BaseModel):
    """Request body for running a tool test.

    Client sends ONLY the logical parameters that match the tool's input schema.
    Example:
        {
          "params": {
            "a": 1,
            "b": 2
          }
        }
    """

    params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Tool parameters matching the tool input schema.",
    )


class ToolRunResponse(BaseModel):
    """Response body for a tool test.

    We expose:
      - rpc_request: the JSON-RPC envelope we sent to /rpc
      - rpc_response: the JSON response returned by /rpc
    """

    rpc_request: Dict[str, Any]
    rpc_response: Dict[str, Any]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@tool_testing_router.get(
    "/tools/{tool_id}",
    response_model=ToolRead,
)
@require_permission("tools.read")
async def get_tool_for_testing(
    tool_id: str,
    team_id: Optional[str] = None,  # optional query param for context
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> ToolRead:
    """Get a specific tool for testing.

    Client flow:
      1) Call this to fetch the tool definition.
      2) Inspect tool.input_schema.properties to know which params to send.

    Args:
        tool_id: Tool UUID
        team_id: Optional team UUID (for logging / future scoping)
        db: Database session
        user: Authenticated user with permissions

    Returns:
        ToolRead: Tool definition including input_schema
    """
    service = ToolService()
    try:
        tool = await service.get_tool(db, tool_id)

        # user can be dict or object; handle both safely
        user_email = getattr(user, "email", None)
        if user_email is None and isinstance(user, dict):
            user_email = user.get("email", "unknown")

        logger.info(
            "Tool fetched for testing",
            extra={
                "tool_id": tool_id,
                "team_id": team_id,
                "user": user_email,
                "visibility": getattr(tool, "visibility", None),
            },
        )
        return tool

    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        logger.error(f"Error fetching tool {tool_id} for testing: {msg}")
        raise HTTPException(
            status_code=500,
            detail="Failed to fetch tool for testing",
        ) from exc


@tool_testing_router.post(
    "/tools/{tool_id}/run",
    response_model=ToolRunResponse,
)
@require_permission("tools.execute")
async def run_tool_test_api(
    tool_id: str,
    body: ToolRunRequest,
    request: Request,
    team_id: Optional[str] = None,  # optional query param for context
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> ToolRunResponse:
    """Run a test invocation of a tool via JSON-RPC.

    Client sends ONLY:
        {
          "params": {
            "a": 1,
            "b": 2
          }
        }

    This endpoint:
      1. Fetches the tool by ID to get its name.
      2. Builds a JSON-RPC envelope:
            {
              "jsonrpc": "2.0",
              "id": <timestamp_ms>,
              "method": tool.name,
              "params": { ... }
            }
      3. POSTs that envelope to /rpc on the same gateway, reusing cookies
         (so jwt_token/auth behaves just like Admin UI).
      4. Returns both the JSON-RPC request and the JSON response from /rpc.

    Args:
        tool_id: Tool UUID
        body: ToolRunRequest containing params
        request: FastAPI Request (used for base_url and cookies)
        team_id: Optional team UUID (for logging / future scoping)
        db: Database session
        user: Authenticated user with permissions

    Returns:
        ToolRunResponse: Contains rpc_request and rpc_response.
    """
    service = ToolService()

    # Generate JSON-RPC id similar to JS Date.now()
    rpc_id: int = int(datetime.now(tz=UTC).timestamp() * 1000)

    try:
        # 1. Resolve tool to get its MCP method name
        tool = await service.get_tool(db, tool_id)
        tool_name = tool.name

        # user can be dict or object
        user_email = getattr(user, "email", None)
        if user_email is None and isinstance(user, dict):
            user_email = user.get("email", "unknown")

        logger.info(
            "Running tool test via /rpc",
            extra={
                "tool_id": tool_id,
                "tool_name": tool_name,
                "team_id": team_id,
                "user": user_email,
                "remote_addr": request.client.host if request.client else None,
                "visibility": getattr(tool, "visibility", None),
            },
        )

        # 2. Build JSON-RPC envelope (what Admin UI JS does before POST /rpc)
        rpc_envelope: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": tool_name,
            "params": body.params or {},
        }

        # 3. POST to /rpc on this same gateway
        base_url = str(request.base_url).rstrip("/")  # e.g. http://10.17.191.8:8029
        rpc_url = f"{base_url}/rpc"

        async with httpx.AsyncClient() as client:
            rpc_res = await client.post(
                rpc_url,
                json=rpc_envelope,
                cookies=request.cookies,  # send jwt_token cookie, etc.
                headers={
                    "Accept": "application/json",
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                },
                timeout=60.0,
            )

        try:
            rpc_res_json = rpc_res.json()
        except Exception:  # noqa: BLE001
            rpc_res_json = {
                "status_code": rpc_res.status_code,
                "text": rpc_res.text,
            }

        if rpc_res.is_error:
            # Surface /rpc errors, but still show what was sent and received
            logger.warning(
                "RPC call for tool test returned error",
                extra={
                    "tool_id": tool_id,
                    "status_code": rpc_res.status_code,
                    "rpc_request": rpc_envelope,
                    "rpc_response": rpc_res_json,
                },
            )
            raise HTTPException(
                status_code=rpc_res.status_code,
                detail={
                    "message": "RPC call failed",
                    "rpc_request": rpc_envelope,
                    "rpc_response": rpc_res_json,
                },
            )

        # 4. Return both what we sent and what we got
        return ToolRunResponse(
            rpc_request=rpc_envelope,
            rpc_response=rpc_res_json,
        )

    except HTTPException:
        # re-raise FastAPI HTTPExceptions as-is
        raise
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        logger.error(
            f"Tool test failed for tool_id={tool_id}, team_id={team_id}: {msg}"
        )
        raise HTTPException(
            status_code=500,
            detail="Tool test failed due to an internal error",
        ) from exc
