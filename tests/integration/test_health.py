import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.integration
async def test_healthcheck_returns_ok():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")
    
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "b2b-document-vault"}
