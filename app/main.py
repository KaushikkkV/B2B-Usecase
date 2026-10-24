from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.v1.admin import router as admin_router
from app.api.v1.documents import router as doc_router
from app.api.v1.webhooks import router as webhook_router
from app.core.database import AsyncSessionLocal, init_db
from app.core.logging import ObservabilityMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    await init_db()
    yield


app = FastAPI(
    title="Secure B2B Document Vault",
    description="Enterprise cryptographic document pipeline with zero-trust envelope encryption.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(ObservabilityMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(doc_router)
app.include_router(webhook_router)
app.include_router(admin_router)


@app.get("/healthz", tags=["System"])
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "b2b-document-vault"}


@app.get("/readyz", tags=["System"])
async def readiness_check() -> dict[str, str]:
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}
    except Exception as exc:
        return {"status": "unhealthy", "error": str(exc)}