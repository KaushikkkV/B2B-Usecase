import pytest
from httpx import ASGITransport, AsyncClient

from app.core.rate_limit import RedisRateLimiter
from app.core.security import create_access_token
from app.main import app


@pytest.mark.asyncio
async def test_redis_limiter_sliding_window_logic():
    limiter = RedisRateLimiter(redis_url=None, requests_per_window=3, window_seconds=10)

    # First 3 allowed
    assert (await limiter.is_allowed("tenant-abc"))[0] is True
    assert (await limiter.is_allowed("tenant-abc"))[0] is True
    assert (await limiter.is_allowed("tenant-abc"))[0] is True

    # 4th blocked
    allowed, retry_after = await limiter.is_allowed("tenant-abc")
    assert allowed is False
    assert 1 <= retry_after <= 10

    # Distinct tenant unblocked
    assert (await limiter.is_allowed("tenant-xyz"))[0] is True


@pytest.mark.integration
async def test_api_rate_limiter_returns_429_with_retry_after():
    token = create_access_token({
        "sub": "user-test",
        "org_id": "org-redis-test",
        "role": "CLIENT",
    })

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Exhaust 5-request burst limit on /api/v1/documents
        for _ in range(5):
            res = await client.get(
                "/api/v1/documents",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code == 200

        # Exceeded request must return 429
        exceeded = await client.get(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert exceeded.status_code == 429
        assert "Retry-After" in exceeded.headers