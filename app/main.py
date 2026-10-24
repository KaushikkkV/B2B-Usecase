from fastapi import FastAPI, status

app = FastAPI(
    title="B2B Secure Document Vault",
    version="0.1.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

@app.get("/healthz", status_code=status.HTTP_200_OK, tags=["Health"])
async def healthcheck() -> dict[str, str]:
    return {"status": "ok", "service": "b2b-document-vault"}
