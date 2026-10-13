
"""Redis-backed API rate limiting for SecurePAM."""

import hashlib

import redis.asyncio as redis
from fastapi import Request


class RateLimitUnavailable(Exception):
    """Raised when the rate-limit store cannot be reached."""


class RedisRateLimiter:
    def __init__(self, redis_url: str):
        self._redis = redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )

    async def close(self) -> None:
        await self._redis.aclose()

    async def check(
        self,
        *,
        key: str,
        limit: int,
        window_seconds: int = 60,
    ) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds) atomically."""
        script = """
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then
            redis.call('EXPIRE', KEYS[1], ARGV[1])
        end
        local ttl = redis.call('TTL', KEYS[1])
        return {count, ttl}
        """

        try:
            count, ttl = await self._redis.eval(
                script, 1, key, window_seconds
            )
        except Exception as exc:
            raise RateLimitUnavailable() from exc

        if int(count) <= limit:
            return True, 0

        return False, max(1, int(ttl))


def client_identifier(request: Request) -> str:
    """Identify the direct client without trusting forwarded headers."""
    address = request.client.host if request.client else "unknown"
    return hashlib.sha256(address.encode("utf-8")).hexdigest()[:24]
