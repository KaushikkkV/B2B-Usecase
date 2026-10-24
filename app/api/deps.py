from collections.abc import Sequence

import jwt
from fastapi import Depends, HTTPException, Request, Response, status
from pydantic import ValidationError

from app.core.rate_limit import default_rate_limiter
from app.core.security import decode_access_token
from app.schemas.auth import AuthenticatedUser, UserRole

MAX_TOKEN_LENGTH: int = 4096


async def get_current_user(request: Request) -> AuthenticatedUser:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    if len(auth_header) > MAX_TOKEN_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header exceeds allowable length",
        )

    parts = auth_header.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'",
        )

    token = parts[1]
    if not token or len(token) > MAX_TOKEN_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or truncated token",
        )

    try:
        claims = decode_access_token(token)
    except jwt.PyJWTError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {err}",
        ) from err

    if not all(k in claims for k in ("sub", "org_id", "role")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing required claims",
        )

    try:
        role = UserRole(claims["role"])
        return AuthenticatedUser(
            user_id=claims["sub"],
            org_id=claims["org_id"],
            role=role,
        )
    except (ValueError, KeyError, ValidationError) as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token claims failed schema validation",
        ) from err


class RequireRoles:
    def __init__(self, allowed_roles: Sequence[UserRole]) -> None:
        self.allowed_roles = set(allowed_roles)

    async def __call__(
        self,
        current_user: AuthenticatedUser = Depends(get_current_user),
    ) -> AuthenticatedUser:
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role.value}' lacks required permissions",
            )
        return current_user


async def check_tenant_rate_limit(
    response: Response,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> None:
    allowed, retry_after = await default_rate_limiter.is_allowed(current_user.org_id)
    if not allowed:
        response.headers["Retry-After"] = str(retry_after)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too Many Requests: Tenant rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )