from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.security import (
    ALGORITHM,
    SECRET_KEY,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


@pytest.mark.unit
def test_password_hashing_and_verification():
    raw_password = "SuperSecretPassword123!"
    hashed = hash_password(raw_password)

    assert hashed != raw_password
    assert verify_password(raw_password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


@pytest.mark.unit
def test_create_and_decode_access_token_preserves_tenant_and_role():
    payload_data = {
        "sub": "00000000-0000-0000-0000-000000000001",
        "org_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "role": "CASE_MANAGER",
    }
    token = create_access_token(data=payload_data, expires_delta=timedelta(minutes=15))
    decoded = decode_access_token(token)

    assert decoded["sub"] == payload_data["sub"]
    assert decoded["org_id"] == payload_data["org_id"]
    assert decoded["role"] == "CASE_MANAGER"
    assert "exp" in decoded


@pytest.mark.unit
def test_decode_token_rejects_expired_tokens():
    payload_data = {
        "sub": "user-123",
        "org_id": "org-456",
        "role": "CLIENT",
        "exp": datetime.now(UTC) - timedelta(minutes=1),
    }
    expired_token = jwt.encode(payload_data, SECRET_KEY, algorithm=ALGORITHM)

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(expired_token)
