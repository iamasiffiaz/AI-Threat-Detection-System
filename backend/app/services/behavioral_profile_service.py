"""
Behavioral Profiling Service
==============================
Maintains per-IP and per-user behavioral baselines in Redis.
Detects deviations that indicate anomalous activity even when
individual events don't trigger rule thresholds.

Architecture:
  - Short window  (1h)  : real-time activity counters (INCR / EXPIRE)
  - Long window   (24h) : rolling baseline stored as a JSON snapshot
  - Deviation score     : 0.0 – 1.0 (fed into risk_scoring_service)

Redis key scheme:
  bp:ip:<ip>:1h:*          sliding 1-hour counters
  bp:ip:<ip>:24h:*         24-hour counters
  bp:ip:<ip>:baseline      JSON baseline snapshot (updated every 15 min)
  bp:user:<user>:1h:*      same per username
"""
import json
import logging
import math
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

from app.services.cache_service import cache_service

logger = logging.getLogger(__name__)

_1H  = 3600
_24H = 86400
_BASELINE_TTL = 7 * 86400   # keep baseline for 7 days


@dataclass
class BehaviorProfile:
    # Current window (1h)
    req_count_1h:        int   = 0
    failed_logins_1h:    int   = 0
    unique_ports_1h:     int   = 0
    unique_dests_1h:     int   = 0
    bytes_out_1h:        int   = 0
    alert_count_1h:      int   = 0

    # Current window (24h)
    req_count_24h:       int   = 0
    failed_logins_24h:   int   = 0

    # Baseline (rolling 24h average, sampled every 15 min)
    baseline_req:        float = 0.0
    baseline_failed:     float = 0.0
    baseline_ports:      float = 0.0

    # Derived
    deviation_score:     float = 0.0   # 0.0-1.0
    is_new_source:       bool  = False  # first time seen in >24h window


class BehavioralProfileService:

    # -----------------------------------------------------------------------
    # Update (call on every log ingestion)
    # -----------------------------------------------------------------------

    async def update_ip(self, ip: str, event: Dict[str, Any]) -> BehaviorProfile:
        """
        Increment counters for an IP based on the incoming log event.
        Returns the current BehaviorProfile with deviation score.
        """
        if not cache_service.available:
            return BehaviorProfile()

        event_type   = (event.get("event_type") or "").lower()
        dest_port    = event.get("destination_port") or 0
        dest_ip      = event.get("destination_ip") or ""
        bytes_sent   = int(event.get("bytes_sent") or 0)
        is_failure   = any(t in event_type for t in ("fail", "deny", "reject", "error"))

        prefix_1h  = f"bp:ip:{ip}:1h"
        prefix_24h = f"bp:ip:{ip}:24h"

        # Atomic increment counters
        await cache_service.increment(f"{prefix_1h}:req",    ttl=_1H)
        await cache_service.increment(f"{prefix_24h}:req",   ttl=_24H)

        if is_failure:
            await cache_service.increment(f"{prefix_1h}:fail",  ttl=_1H)
            await cache_service.increment(f"{prefix_24h}:fail", ttl=_24H)

        if dest_port:
            await cache_service.raw_sadd(f"{prefix_1h}:ports", str(dest_port), ttl=_1H)
        if dest_ip:
            await cache_service.raw_sadd(f"{prefix_1h}:dests",  dest_ip, ttl=_1H)
        if bytes_sent > 0:
            await cache_service.increment(f"{prefix_1h}:bytes", amount=bytes_sent, ttl=_1H)

        return await self.get_profile_ip(ip)

    async def update_user(self, username: str, event: Dict[str, Any]):
        """Increment per-user counters."""
        if not username or not cache_service.available:
            return

        event_type = (event.get("event_type") or "").lower()
        is_failure = any(t in event_type for t in ("fail", "deny", "reject"))

        prefix = f"bp:user:{username}:1h"
        await cache_service.increment(f"{prefix}:req",  ttl=_1H)
        if is_failure:
            await cache_service.increment(f"{prefix}:fail", ttl=_1H)

    # -----------------------------------------------------------------------
    # Read profile
    # -----------------------------------------------------------------------

    async def get_profile_ip(self, ip: str) -> BehaviorProfile:
        if not cache_service.available:
            return BehaviorProfile()

        prefix_1h  = f"bp:ip:{ip}:1h"
        prefix_24h = f"bp:ip:{ip}:24h"

        req_1h   = await cache_service.get_int(f"{prefix_1h}:req")
        fail_1h  = await cache_service.get_int(f"{prefix_1h}:fail")
        bytes_1h = await cache_service.get_int(f"{prefix_1h}:bytes")
        req_24h  = await cache_service.get_int(f"{prefix_24h}:req")
        fail_24h = await cache_service.get_int(f"{prefix_24h}:fail")

        ports_1h = await cache_service.raw_scard(f"{prefix_1h}:ports")
        dests_1h = await cache_service.raw_scard(f"{prefix_1h}:dests")

        baseline = await self._load_baseline(ip)
        is_new   = (req_24h or 0) <= 1 and (baseline is None or baseline.get("req", 0) == 0)

        profile = BehaviorProfile(
            req_count_1h=req_1h or 0,
            failed_logins_1h=fail_1h or 0,
            unique_ports_1h=ports_1h or 0,
            unique_dests_1h=dests_1h or 0,
            bytes_out_1h=bytes_1h or 0,
            req_count_24h=req_24h or 0,
            failed_logins_24h=fail_24h or 0,
            baseline_req=float((baseline or {}).get("req", 0)),
            baseline_failed=float((baseline or {}).get("fail", 0)),
            baseline_ports=float((baseline or {}).get("ports", 0)),
            is_new_source=is_new,
        )

        profile.deviation_score = self._compute_deviation(profile)

        # Opportunistically refresh baseline every ~15 min
        await self._maybe_update_baseline(ip, profile)

        return profile

    # -----------------------------------------------------------------------
    # Deviation calculation
    # -----------------------------------------------------------------------

    @staticmethod
    def _compute_deviation(p: BehaviorProfile) -> float:
        """
        Returns 0.0-1.0 deviation score.
        Uses a simple z-score-inspired approach: how many std-deviations
        above the rolling baseline is the current window?
        Falls back to raw thresholds when no baseline exists.
        """
        scores: list[float] = []

        def _rel_deviation(current: float, baseline: float, cap: float = 10.0) -> float:
            """How many times over baseline is current value?"""
            if baseline < 1:
                # No baseline — use absolute thresholds
                return min(current / cap, 1.0)
            ratio = current / baseline
            return min((ratio - 1.0) / 9.0, 1.0) if ratio > 1 else 0.0

        # Request rate deviation
        scores.append(_rel_deviation(p.req_count_1h, p.baseline_req, cap=100))

        # Failed login deviation
        scores.append(_rel_deviation(p.failed_logins_1h, p.baseline_failed, cap=20))

        # Port scan indicator
        scores.append(_rel_deviation(p.unique_ports_1h, p.baseline_ports, cap=15))

        # High data exfiltration flag (> 50 MB in 1h)
        exfil = 1.0 if p.bytes_out_1h > 50 * 1024 * 1024 else p.bytes_out_1h / (50 * 1024 * 1024)
        scores.append(min(exfil, 1.0))

        # New source bump
        if p.is_new_source and p.req_count_1h > 5:
            scores.append(0.4)

        return round(min(sum(scores) / len(scores), 1.0), 3) if scores else 0.0

    # -----------------------------------------------------------------------
    # Baseline persistence
    # -----------------------------------------------------------------------

    async def _load_baseline(self, ip: str) -> Optional[Dict]:
        data = await cache_service.get(f"bp:ip:{ip}:baseline")
        if not data:
            return None
        try:
            return json.loads(data) if isinstance(data, str) else data
        except Exception:
            return None

    async def _maybe_update_baseline(self, ip: str, profile: BehaviorProfile):
        """
        Refresh baseline snapshot if it doesn't exist yet or if the
        last-updated timestamp is older than 15 minutes.
        """
        flag_key = f"bp:ip:{ip}:baseline:updated"
        if await cache_service.get(flag_key):
            return  # Updated recently

        baseline_key = f"bp:ip:{ip}:baseline"
        existing = await self._load_baseline(ip)

        # Exponential moving average: new_baseline = 0.8 * old + 0.2 * current
        alpha = 0.2
        new_baseline = {
            "req":   round((1 - alpha) * float((existing or {}).get("req",   0)) + alpha * profile.req_count_24h,   2),
            "fail":  round((1 - alpha) * float((existing or {}).get("fail",  0)) + alpha * profile.failed_logins_24h, 2),
            "ports": round((1 - alpha) * float((existing or {}).get("ports", 0)) + alpha * profile.unique_ports_1h,  2),
        }

        await cache_service.set(baseline_key, json.dumps(new_baseline), ttl=_BASELINE_TTL)
        await cache_service.set(flag_key,     "1",                      ttl=900)  # 15-min refresh guard


# Singleton
behavioral_profile_service = BehavioralProfileService()
