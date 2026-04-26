"""In-memory rate limiter for OAuth endpoints."""

import logging
import time

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    In-memory sliding-window rate limiter.

    Each instance carries its own state, so creating a new instance gives a
    clean slate — no global variables, no cache clearing needed in tests.

    Once the tracker is full (maxsize IPs), new IPs are not tracked and their
    requests are allowed through rather than incorrectly blocking them.
    """

    def __init__(
        self,
        requests_per_minute: int = 20,
        window_size: int = 60,
        maxsize: int = 1000,
    ):
        self.requests_per_minute = requests_per_minute
        self.window_size = window_size
        self.maxsize = maxsize
        self._trackers: dict[str, list[float]] = {}

    def _get_tracker(self, client_ip: str) -> list[float] | None:
        if client_ip in self._trackers:
            return self._trackers[client_ip]
        if len(self._trackers) >= self.maxsize:
            self._evict_expired()
        if len(self._trackers) >= self.maxsize:
            logger.warning(
                "Rate limiter at capacity (%d IPs), skipping %s",
                self.maxsize,
                client_ip,
            )
            return None
        self._trackers[client_ip] = []
        return self._trackers[client_ip]

    def _evict_expired(self) -> None:
        now = time.time()
        expired = [
            ip
            for ip, ts in self._trackers.items()
            if not any(now - t < self.window_size for t in ts)
        ]
        for ip in expired:
            del self._trackers[ip]

    def is_rate_limited(self, client_ip: str) -> bool:
        tracker = self._get_tracker(client_ip)
        if tracker is None:
            return False
        now = time.time()
        tracker[:] = [ts for ts in tracker if now - ts < self.window_size]
        if len(tracker) >= self.requests_per_minute:
            logger.warning(
                "Rate limit exceeded for IP %s: %d requests in %d seconds",
                client_ip,
                len(tracker),
                self.window_size,
            )
            return True
        tracker.append(now)
        return False

    def get_remaining(self, client_ip: str) -> int:
        tracker = self._trackers.get(client_ip, [])
        now = time.time()
        valid = [ts for ts in tracker if now - ts < self.window_size]
        return max(0, self.requests_per_minute - len(valid))

    def get_reset_time(self, client_ip: str) -> int:
        tracker = self._trackers.get(client_ip, [])
        now = time.time()
        valid = [ts for ts in tracker if now - ts < self.window_size]
        if not valid:
            return int(now)
        return int(min(valid) + self.window_size)
