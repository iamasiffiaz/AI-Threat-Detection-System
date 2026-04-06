"""
Redis cache service: dashboard caching, rule engine state persistence,
IP reputation scoring, and real-time alert pub/sub.
"""
import json
import logging
from typing import Any, Optional
import redis.asyncio as aioredis
from app.core.config import settings

logger = logging.getLogger(__name__)

_DASHBOARD_TTL = 30          # seconds
_IP_REPUTATION_TTL = 3600    # 1 hour
_RULE_STATE_WINDOW = 3600    # 1 hour rule counters


class CacheService:
    """
    Async Redis wrapper. All methods are safe to call even when Redis is
    unavailable — they degrade silently so the app stays functional.
    """

    def __init__(self):
        self._client: Optional[aioredis.Redis] = None

    async def connect(self):
        try:
            self._client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=3,
            )
            await self._client.ping()
            logger.info("Redis connected successfully")
        except Exception as e:
            logger.warning(f"Redis unavailable ({e}); caching disabled")
            self._client = None

    async def disconnect(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None

    # ------------------------------------------------------------------ #
    #  Generic get / set / delete                                          #
    # ------------------------------------------------------------------ #

    async def get(self, key: str) -> Optional[Any]:
        if not self._client:
            return None
        try:
            value = await self._client.get(key)
            return json.loads(value) if value else None
        except Exception:
            return None

    async def set(self, key: str, value: Any, ttl: int = _DASHBOARD_TTL):
        if not self._client:
            return
        try:
            await self._client.setex(key, ttl, json.dumps(value, default=str))
        except Exception:
            pass

    async def delete(self, key: str):
        if not self._client:
            return
        try:
            await self._client.delete(key)
        except Exception:
            pass

    async def delete_pattern(self, pattern: str):
        if not self._client:
            return
        try:
            keys = await self._client.keys(pattern)
            if keys:
                await self._client.delete(*keys)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Raw key helpers (used by behavioral_profile_service)               #
    # ------------------------------------------------------------------ #

    async def increment(self, key: str, amount: int = 1, ttl: Optional[int] = None) -> int:
        """Increment a raw key by amount; optionally set TTL on first creation."""
        if not self._client:
            return 0
        try:
            pipe = self._client.pipeline()
            if amount == 1:
                await pipe.incr(key)
            else:
                await pipe.incrby(key, amount)
            if ttl:
                await pipe.expire(key, ttl)
            results = await pipe.execute()
            return int(results[0])
        except Exception:
            return 0

    async def get_int(self, key: str) -> int:
        """GET a key and return its value as int (0 if missing)."""
        if not self._client:
            return 0
        try:
            v = await self._client.get(key)
            return int(v) if v else 0
        except Exception:
            return 0

    async def raw_sadd(self, key: str, member: str, ttl: Optional[int] = None) -> int:
        """SADD a member to a set; returns cardinality. Optionally set TTL."""
        if not self._client:
            return 0
        try:
            pipe = self._client.pipeline()
            await pipe.sadd(key, member)
            if ttl:
                await pipe.expire(key, ttl)
            await pipe.scard(key)
            results = await pipe.execute()
            return int(results[-1])
        except Exception:
            return 0

    async def raw_scard(self, key: str) -> int:
        """SCARD — cardinality of a set."""
        if not self._client:
            return 0
        try:
            v = await self._client.scard(key)
            return int(v) if v else 0
        except Exception:
            return 0

    # ------------------------------------------------------------------ #
    #  Dashboard caching helpers                                           #
    # ------------------------------------------------------------------ #

    async def get_dashboard(self, key: str) -> Optional[dict]:
        return await self.get(f"dashboard:{key}")

    async def set_dashboard(self, key: str, data: dict):
        await self.set(f"dashboard:{key}", data, ttl=_DASHBOARD_TTL)

    async def invalidate_dashboard(self):
        await self.delete_pattern("dashboard:*")

    # ------------------------------------------------------------------ #
    #  Rule engine — sliding-window counters backed by Redis               #
    # ------------------------------------------------------------------ #

    async def rule_increment(self, rule: str, ip: str, window_seconds: int) -> int:
        """Increment a per-IP counter for a rule; returns new count."""
        if not self._client:
            return 0
        key = f"rule:{rule}:{ip}"
        try:
            pipe = self._client.pipeline()
            await pipe.incr(key)
            await pipe.expire(key, window_seconds)
            results = await pipe.execute()
            return int(results[0])
        except Exception:
            return 0

    async def rule_get(self, rule: str, ip: str) -> int:
        if not self._client:
            return 0
        try:
            v = await self._client.get(f"rule:{rule}:{ip}")
            return int(v) if v else 0
        except Exception:
            return 0

    async def rule_sadd(self, rule: str, ip: str, member: str, window_seconds: int) -> int:
        """Add a member to a per-IP set; returns cardinality."""
        if not self._client:
            return 0
        key = f"ruleset:{rule}:{ip}"
        try:
            pipe = self._client.pipeline()
            await pipe.sadd(key, member)
            await pipe.expire(key, window_seconds)
            await pipe.scard(key)
            results = await pipe.execute()
            return int(results[2])
        except Exception:
            return 0

    async def rule_scard(self, rule: str, ip: str) -> int:
        if not self._client:
            return 0
        try:
            v = await self._client.scard(f"ruleset:{rule}:{ip}")
            return int(v) if v else 0
        except Exception:
            return 0

    async def is_in_cooldown(self, rule: str, ip: str) -> bool:
        if not self._client:
            return False
        try:
            return await self._client.exists(f"cooldown:{rule}:{ip}") > 0
        except Exception:
            return False

    async def set_cooldown(self, rule: str, ip: str, seconds: int):
        if not self._client:
            return
        try:
            await self._client.setex(f"cooldown:{rule}:{ip}", seconds, "1")
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  IP reputation / threat scoring                                      #
    # ------------------------------------------------------------------ #

    async def get_ip_score(self, ip: str) -> Optional[float]:
        return await self.get(f"ip_score:{ip}")

    async def set_ip_score(self, ip: str, score: float):
        await self.set(f"ip_score:{ip}", score, ttl=_IP_REPUTATION_TTL)

    async def increment_ip_alerts(self, ip: str) -> int:
        """Track how many alerts an IP has triggered (persists 24h)."""
        if not self._client:
            return 0
        key = f"ip_alerts:{ip}"
        try:
            pipe = self._client.pipeline()
            await pipe.incr(key)
            await pipe.expire(key, 86400)
            results = await pipe.execute()
            return int(results[0])
        except Exception:
            return 0

    async def get_ip_alerts(self, ip: str) -> int:
        if not self._client:
            return 0
        try:
            v = await self._client.get(f"ip_alerts:{ip}")
            return int(v) if v else 0
        except Exception:
            return 0

    # ------------------------------------------------------------------ #
    #  Pub/Sub for real-time alert broadcasting                            #
    # ------------------------------------------------------------------ #

    async def publish_alert(self, alert_data: dict):
        if not self._client:
            return
        try:
            await self._client.publish(
                "threat_alerts",
                json.dumps(alert_data, default=str),
            )
        except Exception:
            pass


cache_service = CacheService()
