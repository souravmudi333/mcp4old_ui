# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/routers/email_auth.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Email Authentication Router.
This module provides FastAPI routes for email-based authentication
including login, registration, password management, and user profile endpoints.

Examples:
    >>> from fastapi import FastAPI
    >>> from mcpgateway.routers.email_auth import email_auth_router
    >>> app = FastAPI()
    >>> app.include_router(email_auth_router, prefix="/auth/email", tags=["Email Auth"])
    >>> isinstance(email_auth_router, APIRouter)
    True
"""

# Standard
from datetime import datetime, timedelta, UTC
from typing import Optional, Dict, Any    

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from mcpgateway.middleware.rbac import get_current_user_with_permissions

# First-Party
from mcpgateway.auth import get_current_user
from mcpgateway.config import settings
from mcpgateway.db import EmailUser, SessionLocal
from mcpgateway.middleware.rbac import require_permission
from mcpgateway.schemas import (
    AuthenticationResponse,
    AuthEventResponse,
    ChangePasswordRequest,
    EmailLoginRequest,
    EmailRegistrationRequest,
    EmailUserResponse,
    SuccessResponse,
    UserListResponse,
)
from mcpgateway.services.email_auth_service import AuthenticationError, EmailAuthService, EmailValidationError, PasswordValidationError, UserExistsError
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.utils.create_jwt_token import create_jwt_token

# Initialize logging
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)

# Create router
email_auth_router = APIRouter()

# Security scheme
bearer_scheme = HTTPBearer(auto_error=False)


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


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request.

    Args:
        request: FastAPI request object

    Returns:
        str: Client IP address
    """
    # Check for X-Forwarded-For header (proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    # Check for X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fall back to direct client IP
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    """Extract user agent from request.

    Args:
        request: FastAPI request object

    Returns:
        str: User agent string
    """
    return request.headers.get("User-Agent", "unknown")


async def create_access_token(user: EmailUser, token_scopes: Optional[dict] = None, jti: Optional[str] = None) -> tuple[str, int]:
    """Create JWT access token for user with enhanced scoping.

    Args:
        user: EmailUser instance
        token_scopes: Optional token scoping information
        jti: Optional JWT ID for revocation tracking

    Returns:
        Tuple of (token_string, expires_in_seconds)
    """
    now = datetime.now(tz=UTC)
    expires_delta = timedelta(minutes=settings.token_expiry)
    expire = now + expires_delta

    # Get user's teams for namespace information
    teams = user.get_teams()

    # Create enhanced JWT payload with team and namespace information
    payload = {
        # Standard JWT claims
        "sub": user.email,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": jti or str(__import__("uuid").uuid4()),
        # User profile information
        "user": {
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": user.is_admin,
            "auth_provider": user.auth_provider,
        },
        # Team memberships for authorization
        "teams": [
            {"id": team.id, "name": team.name, "slug": team.slug, "is_personal": team.is_personal, "role": next((m.role for m in user.team_memberships if m.team_id == team.id), "member")}
            for team in teams
        ],
        # Namespace access (backwards compatible)
        "namespaces": [f"user:{user.email}", *[f"team:{team.slug}" for team in teams], "public"],
        # Token scoping (if provided)
        "scopes": token_scopes or {"server_id": None, "permissions": ["*"], "ip_restrictions": [], "time_restrictions": {}},  # Full access for regular user tokens
    }

    # Generate token using centralized token creation
    token = await create_jwt_token(payload)

    return token, int(expires_delta.total_seconds())


async def create_legacy_access_token(user: EmailUser) -> tuple[str, int]:
    """Create legacy JWT access token for backwards compatibility.

    Args:
        user: EmailUser instance

    Returns:
        Tuple of (token_string, expires_in_seconds)
    """
    now = datetime.now(tz=UTC)
    expires_delta = timedelta(minutes=settings.token_expiry)
    expire = now + expires_delta

    # Create simple JWT payload (original format)
    payload = {
        "sub": user.email,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.is_admin,
        "auth_provider": user.auth_provider,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }

    # Generate token using centralized token creation
    token = await create_jwt_token(payload)

    return token, int(expires_delta.total_seconds())


@email_auth_router.post("/login", response_model=AuthenticationResponse)
async def login(login_request: EmailLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate user with email and password.

    Args:
        login_request: Login credentials
        request: FastAPI request object
        db: Database session

    Returns:
        AuthenticationResponse: Access token and user info

    Examples:
        >>> import asyncio
        >>> asyncio.iscoroutinefunction(login)
        True

    Raises:
        HTTPException: If authentication fails

    Examples:
        Request JSON:
            {
              "email": "user@example.com",
              "password": "secure_password"
            }
    """
    auth_service = EmailAuthService(db)
    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)

    try:
        # Authenticate user
        user = await auth_service.authenticate_user(email=login_request.email, password=login_request.password, ip_address=ip_address, user_agent=user_agent)

        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        # Create access token
        access_token, expires_in = await create_access_token(user)

        # Return authentication response
        return AuthenticationResponse(
            access_token=access_token, token_type="bearer", expires_in=expires_in, user=EmailUserResponse.from_email_user(user)
        )  # nosec B106 - OAuth2 token type, not a password

    except Exception as e:
        logger.error(f"Login error for {login_request.email}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authentication service error")


@email_auth_router.post("/register", response_model=AuthenticationResponse)
async def register(registration_request: EmailRegistrationRequest, request: Request, db: Session = Depends(get_db)):
    """Register a new user account.

    Args:
        registration_request: Registration information
        request: FastAPI request object
        db: Database session

    Returns:
        AuthenticationResponse: Access token and user info

    Raises:
        HTTPException: If registration fails

    Examples:
        Request JSON:
            {
              "email": "new@example.com",
              "password": "secure_password",
              "full_name": "New User"
            }
    """
    auth_service = EmailAuthService(db)
    get_client_ip(request)
    get_user_agent(request)

    try:
        # Create new user
        user = await auth_service.create_user(
            email=registration_request.email,
            password=registration_request.password,
            full_name=registration_request.full_name,
            is_admin=False,  # Regular users cannot self-register as admin
            auth_provider="local",
        )

        # Create access token
        access_token, expires_in = await create_access_token(user)

        logger.info(f"New user registered: {user.email}")

        return AuthenticationResponse(
            access_token=access_token, token_type="bearer", expires_in=expires_in, user=EmailUserResponse.from_email_user(user)
        )  # nosec B106 - OAuth2 token type, not a password

    except EmailValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PasswordValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except UserExistsError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        logger.error(f"Registration error for {registration_request.email}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Registration service error")


@email_auth_router.post("/change-password", response_model=SuccessResponse)
async def change_password(password_request: ChangePasswordRequest, request: Request, current_user: EmailUser = Depends(get_current_user), db: Session = Depends(get_db)):
    """Change user's password.

    Args:
        password_request: Old and new passwords
        request: FastAPI request object
        current_user: Currently authenticated user
        db: Database session

    Returns:
        SuccessResponse: Success confirmation

    Raises:
        HTTPException: If password change fails

    Examples:
        Request JSON (with Bearer token in Authorization header):
            {
              "old_password": "current_password",
              "new_password": "new_secure_password"
            }
    """
    auth_service = EmailAuthService(db)
    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)

    try:
        # Change password
        success = await auth_service.change_password(
            email=current_user.email, old_password=password_request.old_password, new_password=password_request.new_password, ip_address=ip_address, user_agent=user_agent
        )

        if success:
            return SuccessResponse(success=True, message="Password changed successfully")
        else:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to change password")

    except AuthenticationError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except PasswordValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Password change error for {current_user.email}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Password change service error")


@email_auth_router.get("/me", response_model=EmailUserResponse)
async def get_current_user_profile(current_user: EmailUser = Depends(get_current_user)):
    """Get current user's profile information.

    Args:
        current_user: Currently authenticated user

    Returns:
        EmailUserResponse: User profile information

    Raises:
        HTTPException: If user authentication fails

    Examples:
        >>> # GET /auth/email/me
        >>> # Headers: Authorization: Bearer <token>
    """
    return EmailUserResponse.from_email_user(current_user)


@email_auth_router.get("/events", response_model=list[AuthEventResponse])
async def get_auth_events(limit: int = 50, offset: int = 0, current_user: EmailUser = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get authentication events for the current user.

    Args:
        limit: Maximum number of events to return
        offset: Number of events to skip
        current_user: Currently authenticated user
        db: Database session

    Returns:
        List[AuthEventResponse]: Authentication events

    Raises:
        HTTPException: If user authentication fails

    Examples:
        >>> # GET /auth/email/events?limit=10&offset=0
        >>> # Headers: Authorization: Bearer <token>
    """
    auth_service = EmailAuthService(db)

    try:
        events = await auth_service.get_auth_events(email=current_user.email, limit=limit, offset=offset)

        return [AuthEventResponse.model_validate(event) for event in events]

    except Exception as e:
        logger.error(f"Error getting auth events for {current_user.email}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve authentication events")


# Admin-only endpoints
@email_auth_router.get("/admin/users", response_model=UserListResponse)
@require_permission("admin.user_management")
async def list_users(limit: int = 100, offset: int = 0, user = Depends(get_current_user_with_permissions), db: Session = Depends(get_db)):
    """List all users (admin only).

    Args:
        limit: Maximum number of users to return
        offset: Number of users to skip
        current_user: Currently authenticated user
        db: Database session

    Returns:
        UserListResponse: List of users with pagination

    Raises:
        HTTPException: If user is not admin

    Examples:
        >>> # GET /auth/email/admin/users?limit=10&offset=0
        >>> # Headers: Authorization: Bearer <admin_token>
    """

    auth_service = EmailAuthService(db)

    try:
        users = await auth_service.list_users(limit=limit, offset=offset)
        total_count = await auth_service.count_users()

        return UserListResponse(users=[EmailUserResponse.from_email_user(user) for user in users], total_count=total_count, limit=limit, offset=offset)

    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve user list")


@email_auth_router.get("/admin/events", response_model=list[AuthEventResponse])
@require_permission("admin.user_management")
async def list_all_auth_events(
    limit: int = 100,
    offset: int = 0,
    user_email: Optional[str] = None,
    user = Depends(get_current_user_with_permissions),  # ✅ provides the dict with email/db/ip/user_agent
    db: Session = Depends(get_db),
):
    auth_service = EmailAuthService(db)
    try:
        events = await auth_service.get_auth_events(email=user_email, limit=limit, offset=offset)
        return [AuthEventResponse.model_validate(event) for event in events]
    except Exception as e:
        logger.error(f"Error getting auth events: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve authentication events")

@email_auth_router.post("/admin/users", response_model=EmailUserResponse, status_code=status.HTTP_201_CREATED)
@require_permission("admin.user_management")
async def create_user(user_request: EmailRegistrationRequest, user = Depends(get_current_user_with_permissions), db: Session = Depends(get_db)):
    """Create a new user account (admin only).

    Args:
        user_request: User creation information
        current_user: Currently authenticated admin user
        db: Database session

    Returns:
        EmailUserResponse: Created user information

    Raises:
        HTTPException: If user creation fails

    Examples:
        Request JSON:
            {
              "email": "newuser@example.com",
              "password": "secure_password",
              "full_name": "New User",
              "is_admin": false
            }
    """
    auth_service = EmailAuthService(db)

    try:
        # Create new user with admin privileges
        user = await auth_service.create_user(
            email=user_request.email,
            password=user_request.password,
            full_name=user_request.full_name,
            is_admin=getattr(user_request, "is_admin", False),
            auth_provider="local",
        )

        logger.info(f"Admin {user.email} created user: {user.email}")

        return EmailUserResponse.from_email_user(user)

    except EmailValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PasswordValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except UserExistsError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        logger.error(f"Admin user creation error: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User creation failed")


@email_auth_router.get("/admin/users/{user_email}", response_model=EmailUserResponse)
@require_permission("admin.user_management")
async def get_user(user_email: str, user = Depends(get_current_user_with_permissions), db: Session = Depends(get_db)):
    """Get user by email (admin only).

    Args:
        user_email: Email of user to retrieve
        current_user: Currently authenticated admin user
        db: Database session

    Returns:
        EmailUserResponse: User information

    Raises:
        HTTPException: If user not found
    """
    auth_service = EmailAuthService(db)

    try:
        user = await auth_service.get_user_by_email(user_email)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        return EmailUserResponse.from_email_user(user)

    except Exception as e:
        logger.error(f"Error retrieving user {user_email}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve user")



@email_auth_router.put("/admin/users/{user_email}", response_model=EmailUserResponse)
@require_permission("admin.user_management")
async def update_user_admin(
    user_email: str,
    user_request: EmailRegistrationRequest,
    skip_password_check: bool = Query(
        False,
        description="If true, skip password policy check (admin override)",
    ),
    user=Depends(get_current_user_with_permissions),  # 🔹 this is a dict
    db: Session = Depends(get_db),
) -> EmailUserResponse:
    """Update user information (admin only)."""
    auth_service = EmailAuthService(db)

    try:
        # Detect if password is actually being changed
        new_password: Optional[str] = None
        if user_request.password:
            masked_values = {"********", "*********", "**********"}
            if user_request.password not in masked_values:
                new_password = user_request.password

        updated_user = await auth_service.update_user(
            email=user_email,
            full_name=user_request.full_name,
            is_admin=getattr(user_request, "is_admin", None),
            password=new_password,
            skip_password_check=skip_password_check,
        )

        # 🔹 user is a dict here, not a model
        admin_email = None
        if isinstance(user, dict):
            admin_email = user.get("email")
        else:
            admin_email = getattr(user, "email", None)

        logger.info("Admin %s updated user: %s", admin_email, updated_user.email)

        return EmailUserResponse.from_email_user(updated_user)

    except PasswordValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e) or "Password does not meet security requirements",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        logger.error("Error updating user %s: %s", user_email, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user",
        )
        
@email_auth_router.delete("/admin/users/{user_email}", response_model=SuccessResponse)
@require_permission("admin.user_management")
async def delete_user(
    user_email: str,
    admin_ctx: Dict[str, Any] = Depends(get_current_user_with_permissions),
    db: Session = Depends(get_db),
):
    """Delete/deactivate user (admin only).

    Args:
        user_email: Email of user to delete
        admin_ctx: Admin context returned by dependency (dictionary)
        db: Database session

    Returns:
        SuccessResponse: Success confirmation

    Raises:
        HTTPException: If user not found or deletion fails
    """
    auth_service = EmailAuthService(db)

    try:
        admin_email = admin_ctx.get("email")

        # Prevent admin from deleting themselves
        if user_email == admin_email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own account")

        # Prevent deleting the last active admin user
        if await auth_service.is_last_active_admin(user_email):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete the last remaining admin user")

        # Hard delete using auth service
        await auth_service.delete_user(user_email)

        logger.info("Admin %s deleted user: %s", admin_email, user_email)

        return SuccessResponse(success=True, message=f"User {user_email} has been deleted")

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error deleting user %s: %s", user_email, e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete user")