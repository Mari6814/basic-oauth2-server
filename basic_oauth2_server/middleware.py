"""HTTP middleware for OAuth server."""

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from basic_oauth2_server.rate_limiter import RateLimiter


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforce rate limiting on OAuth token and authorization endpoints."""

    RATE_LIMITED_PATHS = {"/oauth2/token", "/authorize", "/authorize/confirm"}

    def __init__(self, app: ASGIApp, rate_limiter: RateLimiter | None = None) -> None:
        super().__init__(app)
        self._limiter = rate_limiter or RateLimiter()

    async def dispatch(self, request: Request, call_next) -> Response:
        # Only rate limit specific endpoints
        if request.url.path in self.RATE_LIMITED_PATHS:
            forwarded_for = request.headers.get("x-forwarded-for")
            client_ip = (
                forwarded_for.split(",")[0].strip()
                if forwarded_for
                else (request.client.host if request.client else "unknown")
            )
            if self._limiter.is_rate_limited(client_ip):
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limit_exceeded",
                        "error_description": "Too many requests. Please try again later.",
                    },
                    headers={
                        "Retry-After": str(self._limiter.get_reset_time(client_ip))
                    },
                )
            # Add rate limit headers to response
            response = await call_next(request)
            remaining = self._limiter.get_remaining(client_ip)
            response.headers["X-RateLimit-Limit"] = str(
                self._limiter.requests_per_minute
            )
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(
                self._limiter.get_reset_time(client_ip)
            )
            return response
        return await call_next(request)


class TokenCacheControlMiddleware(BaseHTTPMiddleware):
    """Add cache control headers to token endpoint responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        if request.url.path == "/oauth2/token":
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response
