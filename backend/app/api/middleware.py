"""Request correlation and access logging middleware."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import request_id_var

logger = logging.getLogger("app.http")

REQUEST_ID_HEADER = "X-Request-ID"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a correlation id, time the request and log the outcome.

    The request body is never logged: it can contain user credentials and
    security-incident details.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Accept an upstream id only if it is short and safe to echo.
        incoming = request.headers.get(REQUEST_ID_HEADER, "")
        request_id = (
            incoming
            if incoming and len(incoming) <= 64 and incoming.isascii() and incoming.isprintable()
            else uuid.uuid4().hex[:16]
        )
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        try:
            try:
                response = await call_next(request)
            except Exception:
                self.log_result(request, started, 500, failed=True)
                raise
            response.headers[REQUEST_ID_HEADER] = request_id
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("X-Frame-Options", "DENY")
            response.headers.setdefault("Referrer-Policy", "no-referrer")
            if request.url.path.startswith("/api/"):
                response.headers.setdefault("Cache-Control", "no-store")
                response.headers.setdefault("Pragma", "no-cache")
            self.log_result(request, started, response.status_code)
            return response
        finally:
            request_id_var.reset(token)

    @staticmethod
    def log_result(request: Request, started: float, status: int, *, failed: bool = False) -> None:
        duration_ms = (time.perf_counter() - started) * 1000
        # Route templates have bounded cardinality and never expose a user-supplied
        # identifier or query string to the monitoring pipeline.
        path = getattr(request.scope.get("route"), "path", "<unmatched>")
        log = logger.exception if failed else logger.info
        log(
            "http_request method=%s path=%s status=%s duration_ms=%.1f",
            request.method,
            path,
            status,
            duration_ms,
            extra={
                "request_id": request_id_var.get(),
                "method": request.method,
                "route": path,
                "status": status,
                "duration_ms": round(duration_ms, 2),
            },
        )
