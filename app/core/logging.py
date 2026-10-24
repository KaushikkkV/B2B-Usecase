import json
import logging
import sys
import time
import uuid
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Configure standard logger to output structured JSON to stdout
logger = logging.getLogger("vault.access")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


class ObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.monotonic()

        # 1. Extract upstream trace ID or mint a new UUID4 correlation ID
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = str(uuid.uuid4())

        # Store in request state for downstream handlers
        request.state.request_id = request_id

        # 2. Process downstream request
        response = await call_next(request)

        # 3. Attach X-Request-ID to outgoing response headers
        response.headers["X-Request-ID"] = request_id

        # 4. Emit structured JSON access log
        duration_ms = round((time.monotonic() - start_time) * 1000, 2)
        client_ip = request.client.host if request.client else "unknown"

        log_payload = {
            "timestamp": time.time(),
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "client_ip": client_ip,
        }
        logger.info(json.dumps(log_payload))

        return response