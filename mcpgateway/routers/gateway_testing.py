# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/routers/gateway_testing.py

Gateway inspection + bulk tool testing routes.
"""

# Standard
from datetime import datetime, UTC
from typing import Any, Dict, List, Optional

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.db import SessionLocal
from mcpgateway.db import Tool as DbTool
from mcpgateway.middleware.rbac import (
    require_permission,
    get_current_user_with_permissions,
)
from mcpgateway.schemas import (
    GatewayRead,
    ToolRead,
    PromptRead,
    ResourceRead,
)
from mcpgateway.services.gateway_service import GatewayService
from mcpgateway.services.tool_service import ToolService
from mcpgateway.services.prompt_service import PromptService
from mcpgateway.services.resource_service import ResourceService
from mcpgateway.services.logging_service import LoggingService


logging_service = LoggingService()
logger = logging_service.get_logger(__name__)

gateway_testing_router = APIRouter(prefix="/gateway-testing", tags=["Gateway Testing"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- Pydantic models ----------

class GatewayInspectionResponse(BaseModel):
    """Everything the UI needs to build a testing screen for a gateway."""
    gateway: GatewayRead
    tools: List[ToolRead]
    prompts: List[PromptRead]
    resources: List[ResourceRead]


class BulkToolTestItem(BaseModel):
    """One tool test entry inside the bulk request."""
    tool_id: str = Field(..., description="Tool ID (from GatewayInspectionResponse.tools[].id)")
    params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments matching this tool's input_schema",
    )


class BulkToolTestRequest(BaseModel):
    """Request to test multiple tools for a given gateway."""
    tests: List[BulkToolTestItem]


class SingleToolTestResult(BaseModel):
    tool_id: str
    tool_name: str
    success: bool
    rpc: Dict[str, Any] = Field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class BulkToolTestResponse(BaseModel):
    gateway_id: str
    results: List[SingleToolTestResult]


# ---------- ROUTE 1: Inspect gateway (server info + tools + prompts + resources) ----------

@gateway_testing_router.get(
    "/gateways/{gateway_id}/inspect",
    response_model=GatewayInspectionResponse,
)
@require_permission("gateways.read")   # adjust if you use a different permission name
async def inspect_gateway(
    gateway_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> GatewayInspectionResponse:
    """
    Inspect a gateway:

    - Gateway (server) info
    - All tools for this gateway (including input_schema = parameters)
    - All prompts
    - All resources

    NOTE: in Context Forge, your *remote MCP server* is stored as a "Gateway".
    """
    gateway_service = GatewayService()
    tool_service = ToolService()
    prompt_service = PromptService()
    resource_service = ResourceService()

    # user can be object or dict
    user_email = getattr(user, "email", None)
    if user_email is None and isinstance(user, dict):
        user_email = user.get("email", "unknown")

    try:
        # 1) Gateway info
        gateway: GatewayRead = await gateway_service.get_gateway(db, gateway_id)

        # 2) Tools belonging to THIS gateway
        #    There is NO list_gateway_tools() method, so we query DbTool directly
        db_tools: List[DbTool] = (
            db.query(DbTool)
            .filter(DbTool.gateway_id == gateway_id)
            .filter(DbTool.enabled == True)  # noqa: E712
            .all()
        )
        tools: List[ToolRead] = [tool_service._convert_tool_to_read(t) for t in db_tools]

        # 3) Prompts (currently global, not gateway-scoped)
        prompts: List[PromptRead] = await prompt_service.list_prompts(db, include_inactive=False)

        # 4) Resources (also global)
        resources: List[ResourceRead] = await resource_service.list_resources(
            db, include_inactive=False
        )

        logger.info(
            "Gateway inspected",
            extra={
                "gateway_id": gateway_id,
                "tool_count": len(tools),
                "prompt_count": len(prompts),
                "resource_count": len(resources),
                "user": user_email,
            },
        )

        return GatewayInspectionResponse(
            gateway=gateway,
            tools=tools,
            prompts=prompts,
            resources=resources,
        )

    except HTTPException:
        # let explicit HTTP exceptions bubble up
        raise
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error(
            "Failed to inspect gateway",
            extra={"gateway_id": gateway_id, "error": str(exc), "user": user_email},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to inspect gateway",
        ) from exc


# ---------- ROUTE 2: Bulk test tools for a gateway ----------

@gateway_testing_router.post(
    "/gateways/{gateway_id}/tools/bulk-test",
    response_model=BulkToolTestResponse,
)
@require_permission("tools.invoke")
async def bulk_test_gateway_tools(
    gateway_id: str,
    body: BulkToolTestRequest,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> BulkToolTestResponse:
    """
    Test *multiple* tools belonging to a single gateway in one call.

    - You don't have to call /tools/{tool_id}/run repeatedly.
    - Request body contains a list of {tool_id, params} entries.
    - For each tool:
        * verify it belongs to this gateway
        * build the JSON-RPC envelope internally
        * call ToolService.invoke_tool
    """
    tool_service = ToolService()

    # user can be object or dict
    user_email = getattr(user, "email", None)
    if user_email is None and isinstance(user, dict):
        user_email = user.get("email", "unknown")

    results: List[SingleToolTestResult] = []

    for test in body.tests:
        # We'll fill this in below so we can always append something, even on errors
        rpc_envelope: Dict[str, Any] = {}
        result_payload: Optional[Dict[str, Any]] = None
        success = False
        error_msg: Optional[str] = None
        tool_name = "<unknown>"

        # Derive JSON-RPC id like Date.now()
        rpc_id = int(datetime.now(tz=UTC).timestamp() * 1000)

        try:
            # Make sure the tool actually exists and belongs to this gateway
            db_tool: Optional[DbTool] = db.get(DbTool, test.tool_id)
            if not db_tool:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Tool not found: {test.tool_id}",
                )

            if str(db_tool.gateway_id) != gateway_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Tool {test.tool_id} does not belong to gateway {gateway_id}",
                )

            tool_name = db_tool.name

            logger.info(
                "Bulk testing tool",
                extra={
                    "gateway_id": gateway_id,
                    "tool_id": test.tool_id,
                    "tool_name": tool_name,
                    "remote_addr": request.client.host if request.client else None,
                    "user": user_email,
                },
            )

            # Build JSON-RPC envelope (for debugging)
            rpc_envelope = {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "method": tool_name,
                "params": test.params or {},
            }

            # Invoke tool via standard ToolService
            tool_result = await tool_service.invoke_tool(
                db=db,
                name=tool_name,
                arguments=test.params or {},
            )

            result_payload = tool_result.model_dump(by_alias=True, mode="json")
            success = not result_payload.get("is_error", False)

        except HTTPException as http_exc:
            error_msg = http_exc.detail if isinstance(http_exc.detail, str) else str(http_exc.detail)
        except Exception as exc:  # pragma: no cover - defensive logging
            error_msg = str(exc)

        results.append(
            SingleToolTestResult(
                tool_id=test.tool_id,
                tool_name=tool_name,
                success=success,
                rpc=rpc_envelope,
                result=result_payload,
                error=error_msg,
            )
        )

    return BulkToolTestResponse(
        gateway_id=gateway_id,
        results=results,
    )
