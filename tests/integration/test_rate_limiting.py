import pytest
from httpx import ASGITransport, AsyncClient

from app.core.database import init_db
from app.core.security import create_access_token
from app.main import app


@pytest.mark.integration
async def test_tenant_rate_limiter_blocks_burst_abuse():
    await init_db()

    token = create_access_token({
        "sub": "abusive-client",
        "org_id": "org-spammer",
        "role": "CLIENT",
    })

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First 5 calls pass
        for _ in range(5):
            res = await client.get(
                "/api/v1/documents",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code == 200

        # Burst request exceeding the test threshold (limit = 5/min for testing rate limits)
        exceeded_res = await client.get(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert exceeded_res.status_code == 429
        assert "Too Many Requests" in exceeded_res.json()["detail"]
        assert "Retry-After" in exceeded_res.headers


@pytest.mark.integration
async def test_rate_limiting_is_tenant_isolated():
    """Tenant A hitting the rate limit must NOT block Tenant B."""
    await init_db()

    token_a = create_access_token({
        "sub": "user-a",
        "org_id": "org-exhausted",
        "role": "CLIENT",
    })
    token_b = create_access_token({
        "sub": "user-b",
        "org_id": "org-clean",
        "role": "CLIENT",
    })

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Exhaust Tenant A
        for _ in range(6):
            await client.get(
                "/api/v1/documents",
                headers={"Authorization": f"Bearer {token_a}"},
            )

        # Tenant B makes a request immediately after
        res_b = await client.get(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert res_b.status_code == 200