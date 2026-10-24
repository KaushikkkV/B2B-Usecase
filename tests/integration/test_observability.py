import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.integration
async def test_request_id_generated_when_missing():
    """Verify that every request receives an X-Request-ID header if none was sent."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/healthz")
        assert res.status_code == 200
        assert "x-request-id" in res.headers
        assert len(res.headers["x-request-id"]) >= 16


@pytest.mark.integration
async def test_request_id_preserved_when_supplied_by_gateway():
    """Verify that an upstream trace ID is preserved for end-to-end tracing."""
    upstream_id = "trace-req-client-corp-12345"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get(
            "/healthz",
            headers={"X-Request-ID": upstream_id},
        )
        assert res.status_code == 200
        assert res.headers["x-request-id"] == upstream_id