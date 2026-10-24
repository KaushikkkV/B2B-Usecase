from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

SECRET_KEY = "vault-production-grade-hmac-sha256-cryptographic-secret-key-32bytes"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
MAX_PASSWORD_BYTES = 72


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt with salt."""
    pwd_bytes = password.encode("utf-8")
    if len(pwd_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError("Password cannot exceed 72 bytes")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash string."""
    plain_bytes = plain_password.encode("utf-8")
    # Defend against bcrypt 72-byte truncation flaw and unhandled ValueError crashes
    if len(plain_bytes) > MAX_PASSWORD_BYTES:
        return False
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(plain_bytes, hashed_bytes)


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """Issue a signed JWT access token containing tenant and role claims."""
    to_encode = data.copy()
    now = datetime.now(UTC)

    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and cryptographically verify a JWT."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
