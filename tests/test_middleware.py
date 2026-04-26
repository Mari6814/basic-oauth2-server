"""Tests for RateLimitMiddleware and TokenCacheControlMiddleware."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from basic_oauth2_server.middleware import (
    RateLimitMiddleware,
    TokenCacheControlMiddleware,
)
from basic_oauth2_server.rate_limiter import RateLimiter


def _make_app_with_rate_limit(requests_per_minute: int = 5) -> FastAPI:
    """Create a minimal app with RateLimitMiddleware for testing."""
    app = FastAPI()
    limiter = RateLimiter(requests_per_minute=requests_per_minute)
    app.add_middleware(RateLimitMiddleware, rate_limiter=limiter)

    @app.get("/oauth2/token")
    async def token():
        return {"ok": True}

    @app.get("/authorize")
    async def authorize():
        return {"ok": True}

    @app.get("/not-rate-limited")
    async def other():
        return {"ok": True}

    return app


def _make_app_with_cache_control() -> FastAPI:
    app = FastAPI()
    app.add_middleware(TokenCacheControlMiddleware)

    @app.post("/oauth2/token")
    async def token():
        return {"ok": True}

    @app.get("/other")
    async def other():
        return {"ok": True}

    return app


@pytest.fixture
def rate_limit_client() -> TestClient:
    return TestClient(_make_app_with_rate_limit(requests_per_minute=5))


@pytest.fixture
def tight_rate_limit_client() -> TestClient:
    return TestClient(_make_app_with_rate_limit(requests_per_minute=1))


@pytest.fixture
def cache_control_client() -> TestClient:
    return TestClient(_make_app_with_cache_control())


class TestRateLimitMiddleware:
    def test_allows_requests_under_limit(self):
        client = TestClient(_make_app_with_rate_limit(requests_per_minute=3))
        for _ in range(3):
            assert client.get("/oauth2/token").status_code == 200

    def test_blocks_over_limit(self, tight_rate_limit_client: TestClient):
        tight_rate_limit_client.get("/oauth2/token")
        response = tight_rate_limit_client.get("/oauth2/token")
        assert response.status_code == 429
        assert response.json()["error"] == "rate_limit_exceeded"

    def test_429_includes_retry_after(self, tight_rate_limit_client: TestClient):
        tight_rate_limit_client.get("/oauth2/token")
        response = tight_rate_limit_client.get("/oauth2/token")
        assert response.status_code == 429
        assert "retry-after" in response.headers

    def test_response_includes_ratelimit_headers(self, rate_limit_client: TestClient):
        response = rate_limit_client.get("/oauth2/token")
        assert response.status_code == 200
        assert response.headers["x-ratelimit-limit"] == "5"
        assert "x-ratelimit-remaining" in response.headers
        assert "x-ratelimit-reset" in response.headers

    def test_remaining_decrements(self, rate_limit_client: TestClient):
        r1 = rate_limit_client.get("/oauth2/token")
        r2 = rate_limit_client.get("/oauth2/token")
        assert int(r1.headers["x-ratelimit-remaining"]) > int(
            r2.headers["x-ratelimit-remaining"]
        )

    def test_not_applied_to_unlisted_paths(self, tight_rate_limit_client: TestClient):
        tight_rate_limit_client.get("/oauth2/token")
        tight_rate_limit_client.get("/oauth2/token")
        assert tight_rate_limit_client.get("/not-rate-limited").status_code == 200
        assert (
            "x-ratelimit-limit"
            not in tight_rate_limit_client.get("/not-rate-limited").headers
        )

    def test_uses_x_forwarded_for(self, tight_rate_limit_client: TestClient):
        tight_rate_limit_client.get(
            "/oauth2/token", headers={"x-forwarded-for": "10.0.0.1"}
        )
        response = tight_rate_limit_client.get(
            "/oauth2/token", headers={"x-forwarded-for": "10.0.0.1"}
        )
        assert response.status_code == 429

    def test_x_forwarded_for_uses_first_ip(self, tight_rate_limit_client: TestClient):
        tight_rate_limit_client.get(
            "/oauth2/token", headers={"x-forwarded-for": "10.0.0.1, 192.168.1.1"}
        )
        response = tight_rate_limit_client.get(
            "/oauth2/token", headers={"x-forwarded-for": "10.0.0.1, 172.16.0.1"}
        )
        assert response.status_code == 429

    def test_authorize_path_is_rate_limited(self, tight_rate_limit_client: TestClient):
        tight_rate_limit_client.get("/authorize")
        assert tight_rate_limit_client.get("/authorize").status_code == 429

    def test_each_app_instance_has_independent_state(self):
        client1 = TestClient(_make_app_with_rate_limit(requests_per_minute=1))
        client2 = TestClient(_make_app_with_rate_limit(requests_per_minute=1))
        client1.get("/oauth2/token")
        assert client1.get("/oauth2/token").status_code == 429
        assert client2.get("/oauth2/token").status_code == 200


class TestTokenCacheControlMiddleware:
    def test_adds_headers_on_token_endpoint(self, cache_control_client: TestClient):
        response = cache_control_client.post("/oauth2/token")
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"

    def test_not_added_to_other_endpoints(self, cache_control_client: TestClient):
        response = cache_control_client.get("/other")
        assert "cache-control" not in response.headers
        assert "pragma" not in response.headers
