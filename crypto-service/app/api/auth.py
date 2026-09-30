"""
FastAPI Authentication Router and Dependency Guards.
Implements opaque 256-bit server-side session tokens, Argon2 password verification,
lockout policies, role-based authorization (require_role), and recipient document ownership.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Request, Response, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.auth_db import auth_db

auth_router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])


class LoginRequest(BaseModel):
    username: str = Field(..., description="Username (head or recipient ID)")
    password: str = Field(..., description="User password")


class LoginResponse(BaseModel):
    token: str
    role: str
    username: str
    recipient_id: Optional[str] = None
    expires_at: str


class UserMeResponse(BaseModel):
    id: int
    username: str
    role: str
    recipient_id: Optional[str] = None


class DismissNotificationResponse(BaseModel):
    success: bool
    notif_id: int


def get_token_from_request(request: Request) -> Optional[str]:
    """Extracts session token from Cookie, Authorization header, or X-Session-Token."""
    # 1. Check HTTP-only cookie
    token = request.cookies.get("session_token")
    if token:
        return token

    # 2. Check Authorization: Bearer <token>
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    # 3. Check X-Session-Token header
    custom_header = request.headers.get("X-Session-Token")
    if custom_header:
        return custom_header.strip()

    return None


async def get_current_session(request: Request) -> Dict[str, Any]:
    """Validates session token against server-side session table."""
    token = get_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: No session token provided in cookie or headers.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session = auth_db.get_session(token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return session


def require_role(required_role: str):
    """
    FastAPI dependency factory enforcing role check.
    Rejects unauthorized roles with HTTP 403 Forbidden.
    """
    async def _role_guard(session: Dict[str, Any] = Depends(get_current_session)) -> Dict[str, Any]:
        if session["role"] != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Access denied. '{required_role}' authorization required (current role: '{session['role']}').",
            )
        return session

    return _role_guard


def verify_recipient_ownership(session: Dict[str, Any], target_recipient_id: str):
    """
    Strict ownership validator:
    Ensures a recipient can only access artifacts and operations tied to their own recipient_id.
    Head role retains administrative oversight.
    """
    if session["role"] == "head":
        return

    session_rec_id = session.get("recipient_id")
    if not session_rec_id or session_rec_id != target_recipient_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Recipient '{session_rec_id}' is not authorized to access documents belonging to '{target_recipient_id}'.",
        )


@auth_router.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest, response: Response):
    """
    POST /auth/login
    1. Looks up username in database.
    2. Enforces 15-minute account lockout after 5 consecutive failures.
    3. Verifies password using Argon2 (argon2-cffi).
    4. Generates an opaque 256-bit base64url session token.
    5. Sets httpOnly, SameSite=Lax cookie and returns session metadata.
    """
    user = auth_db.get_user_by_username(req.username.strip())
    if not user:
        # Constant-time mitigation: hash dummy password before failing
        auth_db.hash_password("dummy_password_constant_time")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # Check lockout
    now_iso = datetime.now(timezone.utc).isoformat()
    locked_until = user.get("locked_until")
    if locked_until and locked_until > now_iso:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account '{req.username}' is locked due to excessive failed attempts. Locked until {locked_until}.",
        )

    # Verify password with Argon2
    valid = auth_db.verify_password(user["password_hash"], req.password)
    if not valid:
        fail_status = auth_db.record_login_failure(user["id"])
        if fail_status["locked"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account locked: 5 consecutive failed login attempts reached. Account locked for 15 minutes.",
            )
        attempts_left = max(0, 5 - fail_status["attempts"])
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid username or password. {attempts_left} attempts remaining before account lockout.",
        )

    # Successful login: reset failed counters
    auth_db.reset_login_failures(user["id"])

    # Issue opaque 256-bit token stored strictly in SQLite sessions table
    token = auth_db.create_session(user, hours_valid=24)
    session = auth_db.get_session(token)

    # Set secure HTTP-only cookie on response
    response.set_cookie(
        key="session_token",
        value=token,
        max_age=86400,
        httponly=True,
        samesite="lax",
        secure=False,  # Set False for localhost/http compatibility
        path="/",
    )

    return LoginResponse(
        token=token,
        role=user["role"],
        username=user["username"],
        recipient_id=user.get("recipient_id"),
        expires_at=session["expires_at"] if session else now_iso,
    )


@auth_router.post("/logout")
async def logout(request: Request, response: Response):
    """
    POST /auth/logout
    Invalidates session row from SQLite and clears cookie.
    """
    token = get_token_from_request(request)
    if token:
        auth_db.delete_session(token)

    response.delete_cookie(key="session_token", path="/")
    return {"status": "logged_out", "detail": "Session successfully invalidated."}


@auth_router.get("/me", response_model=UserMeResponse)
async def get_me(session: Dict[str, Any] = Depends(get_current_session)):
    """
    GET /auth/me
    Returns authenticated user context from active server-side session.
    """
    return UserMeResponse(
        id=session["user_id"],
        username=session["username"],
        role=session["role"],
        recipient_id=session.get("recipient_id"),
    )
