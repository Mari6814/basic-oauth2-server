"""Tests for the RateLimiter class."""

import time


from basic_oauth2_server.rate_limiter import RateLimiter


def test_allows_requests_under_limit():
    limiter = RateLimiter(requests_per_minute=5)
    for _ in range(5):
        assert limiter.is_rate_limited("1.2.3.4") is False


def test_blocks_request_over_limit():
    limiter = RateLimiter(requests_per_minute=3)
    for _ in range(3):
        limiter.is_rate_limited("1.2.3.4")
    assert limiter.is_rate_limited("1.2.3.4") is True


def test_different_ips_are_tracked_independently():
    limiter = RateLimiter(requests_per_minute=2)
    limiter.is_rate_limited("1.2.3.4")
    limiter.is_rate_limited("1.2.3.4")
    assert limiter.is_rate_limited("1.2.3.4") is True
    assert limiter.is_rate_limited("9.9.9.9") is False


def test_expired_requests_are_excluded():
    limiter = RateLimiter(requests_per_minute=2, window_size=1)
    limiter.is_rate_limited("1.2.3.4")
    limiter.is_rate_limited("1.2.3.4")
    assert limiter.is_rate_limited("1.2.3.4") is True

    time.sleep(1.1)
    assert limiter.is_rate_limited("1.2.3.4") is False


def test_get_remaining_decrements():
    limiter = RateLimiter(requests_per_minute=5)
    assert limiter.get_remaining("1.2.3.4") == 5
    limiter.is_rate_limited("1.2.3.4")
    assert limiter.get_remaining("1.2.3.4") == 4
    limiter.is_rate_limited("1.2.3.4")
    assert limiter.get_remaining("1.2.3.4") == 3


def test_get_remaining_never_negative():
    limiter = RateLimiter(requests_per_minute=2)
    for _ in range(5):
        limiter.is_rate_limited("1.2.3.4")
    assert limiter.get_remaining("1.2.3.4") == 0


def test_get_remaining_unknown_ip():
    limiter = RateLimiter(requests_per_minute=5)
    assert limiter.get_remaining("5.5.5.5") == 5


def test_get_reset_time_unknown_ip_is_now():
    limiter = RateLimiter(requests_per_minute=5)
    before = int(time.time())
    reset = limiter.get_reset_time("5.5.5.5")
    assert reset >= before


def test_get_reset_time_is_oldest_plus_window():
    limiter = RateLimiter(requests_per_minute=5, window_size=60)
    before = int(time.time())
    limiter.is_rate_limited("1.2.3.4")
    reset = limiter.get_reset_time("1.2.3.4")
    assert before + 60 <= reset <= before + 61


def test_at_capacity_allows_new_ip_through():
    limiter = RateLimiter(requests_per_minute=5, maxsize=2)
    limiter.is_rate_limited("1.1.1.1")
    limiter.is_rate_limited("2.2.2.2")
    # Tracker is full — new IP must be allowed through (not blocked)
    assert limiter.is_rate_limited("3.3.3.3") is False


def test_eviction_frees_slot_for_new_ip():
    limiter = RateLimiter(requests_per_minute=5, window_size=1, maxsize=2)
    limiter.is_rate_limited("1.1.1.1")
    limiter.is_rate_limited("2.2.2.2")

    time.sleep(1.1)  # Both entries expire

    # After eviction, 3.3.3.3 should get a tracker and be allowed
    assert limiter.is_rate_limited("3.3.3.3") is False
    assert "3.3.3.3" in limiter._trackers
