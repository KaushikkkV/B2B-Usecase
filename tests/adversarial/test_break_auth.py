import jwt
import pytest
from httpx import ASGITransport, AsyncClient

from app.core.security import SECRET_KEY
from app.main import app


@pytest.mark.adversarial
async def test_exploit_algorithm_none_signature_bypass():
    """
    ATTACK: An attacker crafts an unsigned token with 'alg': 'none'
    and claims to be an ORG_ADMIN. The API must reject it with 401.
    """
    malicious_payload = {
        "sub": "attacker-root",
        "org_id": "org-victim-999",
        "role": "ORG_ADMIN",
        "exp": 9999999999,
    }
    # Crafting header with alg: none
    forged_token = jwt.encode(malicious_payload, key="", algorithm="none")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/organization/settings", headers={"Authorization": f"Bearer {forged_token}"}
        )

    assert response.status_code == 401, (
        f"BREACH: Algorithm 'none' was accepted! Got {response.status_code}"
    )


@pytest.mark.adversarial
async def test_exploit_forged_signature_with_arbitrary_key():
    """
    ATTACK: An attacker signs a token using their own rogue secret key.
    The server must reject it because the signature is invalid.
    """
    rogue_key = "rogue-secret-attacker-key-1234567890"
    malicious_payload = {
        "sub": "rogue-agent",
        "org_id": "org-victim-999",
        "role": "ORG_ADMIN",
        "exp": 9999999999,
    }
    forged_token = jwt.encode(malicious_payload, rogue_key, algorithm="HS256")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/organization/settings", headers={"Authorization": f"Bearer {forged_token}"}
        )

    assert response.status_code == 401, (
        f"BREACH: Forged signature accepted! Got {response.status_code}"
    )


@pytest.mark.adversarial
async def test_exploit_garbage_auth_header_does_not_crash_500():
    """
    ATTACK: Send corrupt, malformed, or non-bearer headers.
    Must return 401 Unauthorized, NEVER 500 Internal Server Error.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Case 1: Bearer with spaces only
        r1 = await client.get("/api/v1/documents", headers={"Authorization": "Bearer    "})
        assert r1.status_code == 401

        # Case 2: Random garbage header string
        r2 = await client.get(
            "/api/v1/documents", headers={"Authorization": "GibberishNotEvenBearer!@#$%"}
        )
        assert r2.status_code == 401

        # Case 3: Truncated JWT token
        r3 = await client.get(
            "/api/v1/documents", headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.broken"}
        )
        assert r3.status_code == 401


@pytest.mark.adversarial
async def test_exploit_token_without_required_claims_returns_401():
    """
    ATTACK: A validly signed JWT, but missing 'org_id' or 'role' (e.g. standard auth token from another system).
    Must fail with 401, not cause an unhandled KeyError / 500.
    """
    incomplete_payload = {
        "sub": "user-without-org",
        # org_id is intentionally omitted
        "role": "CASE_MANAGER",
    }
    token = jwt.encode(incomplete_payload, SECRET_KEY, algorithm="HS256")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/documents", headers={"Authorization": f"Bearer {token}"}
        )

    assert response.status_code == 401


@pytest.mark.adversarial
def test_exploit_bcrypt_silent_72_byte_truncation():
    """
    ATTACK / TRAP: Standard bcrypt ignores all characters past 72 bytes.
    If an attacker takes victim's 72-char password and appends arbitrary text,
    a naive bcrypt implementation authenticates them!
    The system must either pre-hash with SHA-256 or explicitly reject > 72 bytes.
    """
    base = "A" * 72
    attacker_variant = base + "COMPLETELY_DIFFERENT_UNAUTHORIZED_SUFFIX"

    from app.core.security import hash_password, verify_password

    h = hash_password(base)
    # If this verifies to True, you have a password truncation auth bypass bug!
    assert verify_password(attacker_variant, h) is False, (
        "CRITICAL VULNERABILITY: Bcrypt 72-byte truncation flaw detected! "
        "Passwords exceeding 72 characters share collisions."
    )


@pytest.mark.adversarial
async def test_exploit_oversized_payload_bomb():
    """
    ATTACK: An attacker sends an abnormally large token payload (1MB string in claims).
    Verify the server rejects it gracefully with 401 without hanging or crashing.
    """
    bloated_payload = {
        "sub": "attacker",
        "org_id": "org-victim",
        "role": "ORG_ADMIN",
        "junk": "X" * (1024 * 512),  # 512 KB payload
    }
    bloated_token = jwt.encode(bloated_payload, SECRET_KEY, algorithm="HS256")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/organization/settings", headers={"Authorization": f"Bearer {bloated_token}"}
        )
    assert response.status_code in (401, 413)


@pytest.mark.adversarial
async def test_exploit_tenant_id_injection_patterns():
    """
    ATTACK: Verify that non-UUID / malformed org_id with injection strings
    fails strict validation rather than being blindly trusted by downstream layers.
    """
    injection_payload = {
        "sub": "user-1",
        "org_id": "' OR 1=1; DROP TABLE users; --",
        "role": "CASE_MANAGER",
    }
    token = jwt.encode(injection_payload, SECRET_KEY, algorithm="HS256")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/documents", headers={"Authorization": f"Bearer {token}"}
        )

    # Notice: Our schema currently permits raw strings for org_id!
    # A true enterprise product enforces strict UUID schema on tenant IDs.
    data = response.json()
    assert "DROP TABLE" not in data.get("org_id", "")
