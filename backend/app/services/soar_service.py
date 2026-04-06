"""
SOAR-lite Service (Security Orchestration, Automation & Response)
===================================================================
Provides automated response capabilities:
  • IP blocking / blacklisting with reason and expiry
  • SOAR playbook recommendations based on attack type
  • Block-hit counter (tracks how many events were blocked for a given IP)
  • Redis hot-set for O(1) block checks at ingestion time
  • REST API endpoints in routers/soar.py

Playbooks are action templates — in production these would trigger SIEM
integrations, firewall rule pushes, or ticketing systems (Jira, ServiceNow).
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.blacklist import IPBlacklist
from app.services.cache_service import cache_service

logger = logging.getLogger(__name__)

_BLACKLIST_REDIS_KEY = "soar:blacklist"          # Redis SET of blocked IPs
_BLACKLIST_REDIS_TTL = 86400 * 7                 # Sync Redis set every 7 days


# ---------------------------------------------------------------------------
# Playbook templates
# ---------------------------------------------------------------------------

_PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "Brute Force": {
        "name": "Brute Force Response",
        "steps": [
            "Block source IP at firewall / WAF",
            "Reset affected account passwords immediately",
            "Enable MFA for targeted accounts",
            "Review authentication logs for successful logins from this IP",
            "Alert account owners via email/SMS",
            "Add IP to threat intelligence blacklist feed",
        ],
        "auto_actions": ["block_ip", "alert_user"],
        "sla_minutes": 30,
        "severity_trigger": "high",
    },
    "Port Scanning": {
        "name": "Port Scan Response",
        "steps": [
            "Block source IP at perimeter firewall",
            "Review exposed service inventory",
            "Check for successful connections on discovered ports",
            "Look for follow-up exploitation attempts",
            "File threat intelligence ticket with attacker IP details",
        ],
        "auto_actions": ["block_ip"],
        "sla_minutes": 60,
        "severity_trigger": "medium",
    },
    "SQL Injection": {
        "name": "SQL Injection Response",
        "steps": [
            "Block source IP immediately",
            "Enable WAF SQL injection rule set",
            "Audit recent database queries for malicious content",
            "Review application logs for successful injection responses",
            "Patch or sanitize vulnerable endpoints",
            "Consider application rollback if data exfiltration detected",
        ],
        "auto_actions": ["block_ip", "escalate"],
        "sla_minutes": 15,
        "severity_trigger": "high",
    },
    "Data Exfiltration": {
        "name": "Data Exfiltration Response",
        "steps": [
            "Block source IP and any related egress connections",
            "Identify which data sets were accessed",
            "Preserve forensic evidence (PCAP, logs)",
            "Invoke data breach notification procedures if PII involved",
            "Isolate affected endpoint / account",
            "Engage legal / compliance team",
            "Report to regulatory body if required",
        ],
        "auto_actions": ["block_ip", "escalate", "preserve_evidence"],
        "sla_minutes": 10,
        "severity_trigger": "critical",
    },
    "C2 Communication": {
        "name": "C2 Beaconing Response",
        "steps": [
            "Block C2 destination IP/domain at firewall and DNS",
            "Isolate compromised endpoint from network",
            "Perform memory forensics on affected host",
            "Identify persistence mechanisms (registry, scheduled tasks)",
            "Hunt for lateral movement from compromised host",
            "Re-image endpoint after forensic collection",
        ],
        "auto_actions": ["block_ip", "isolate_host", "escalate"],
        "sla_minutes": 15,
        "severity_trigger": "critical",
    },
    "DDoS / Flood": {
        "name": "DDoS Mitigation Response",
        "steps": [
            "Enable rate limiting / traffic scrubbing",
            "Activate upstream DDoS protection service if available",
            "Block top source IPs (use geo-blocking if volumetric)",
            "Monitor service availability metrics",
            "Scale infrastructure if needed",
            "Document attack volume and pattern for post-incident report",
        ],
        "auto_actions": ["rate_limit", "block_ip"],
        "sla_minutes": 5,
        "severity_trigger": "high",
    },
    "Remote Code Execution": {
        "name": "RCE Response",
        "steps": [
            "Block source IP immediately",
            "Isolate affected server from network",
            "Preserve process list, open connections, and memory",
            "Identify vulnerability exploited and patch immediately",
            "Check for webshell or backdoor installation",
            "Full forensic investigation before returning to production",
        ],
        "auto_actions": ["block_ip", "isolate_host", "escalate"],
        "sla_minutes": 5,
        "severity_trigger": "critical",
    },
    "Credential Stuffing": {
        "name": "Credential Stuffing Response",
        "steps": [
            "Block source IP / ASN range",
            "Force password reset on accounts with successful login from this IP",
            "Enable CAPTCHA on login endpoint",
            "Implement velocity checks (too many login attempts per IP)",
            "Notify affected users",
            "Consider passwordless / MFA enforcement",
        ],
        "auto_actions": ["block_ip", "alert_user"],
        "sla_minutes": 20,
        "severity_trigger": "high",
    },
    "Unknown / Anomaly": {
        "name": "Generic Anomaly Response",
        "steps": [
            "Review raw logs for context",
            "Check if IP matches known threat intelligence",
            "Monitor for follow-up activity",
            "If anomaly score > 0.8, consider temporary block",
        ],
        "auto_actions": [],
        "sla_minutes": 120,
        "severity_trigger": "medium",
    },
}

_DEFAULT_PLAYBOOK = _PLAYBOOKS["Unknown / Anomaly"]


class SOARService:

    # -----------------------------------------------------------------------
    # Startup: load blacklist into Redis
    # -----------------------------------------------------------------------

    async def sync_blacklist_to_redis(self, db: AsyncSession):
        """Load all active blacklist entries into Redis SET on startup."""
        if not cache_service.available:
            return
        try:
            result = await db.execute(
                select(IPBlacklist.ip_address).where(IPBlacklist.is_active == True)
            )
            ips = [row[0] for row in result.all()]
            if ips:
                client = cache_service._client
                pipe = client.pipeline()
                await pipe.delete(_BLACKLIST_REDIS_KEY)
                await pipe.sadd(_BLACKLIST_REDIS_KEY, *ips)
                await pipe.expire(_BLACKLIST_REDIS_KEY, _BLACKLIST_REDIS_TTL)
                await pipe.execute()
                logger.info("SOAR: synced %d blocked IPs to Redis", len(ips))
        except Exception as exc:
            logger.warning("SOAR blacklist sync failed: %s", exc)

    # -----------------------------------------------------------------------
    # IP check (O(1) via Redis)
    # -----------------------------------------------------------------------

    async def is_blocked(self, ip: str) -> bool:
        if not cache_service.available:
            return False
        try:
            return bool(await cache_service._client.sismember(_BLACKLIST_REDIS_KEY, ip))
        except Exception:
            return False

    # -----------------------------------------------------------------------
    # Block / unblock
    # -----------------------------------------------------------------------

    async def block_ip(
        self,
        ip: str,
        reason: str,
        db: AsyncSession,
        *,
        added_by:    str = "auto",
        risk_score:  Optional[float] = None,
        attack_types: Optional[List[str]] = None,
        rule_names:   Optional[List[str]] = None,
        incident_id:  Optional[int] = None,
        expires_in_hours: Optional[int] = None,
        notes: Optional[str] = None,
    ) -> IPBlacklist:
        """
        Block an IP address.  Idempotent — if already blocked, updates metadata.
        """
        expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
            if expires_in_hours else None
        )

        result = await db.execute(
            select(IPBlacklist).where(IPBlacklist.ip_address == ip)
        )
        entry = result.scalar_one_or_none()

        if entry:
            entry.is_active     = True
            entry.reason        = reason
            entry.risk_score    = risk_score or entry.risk_score
            entry.added_by      = added_by
            entry.expires_at    = expires_at
            if notes:
                entry.notes = notes
        else:
            entry = IPBlacklist(
                ip_address=ip,
                reason=reason,
                attack_types=json.dumps(attack_types or []),
                rule_names=json.dumps(rule_names or []),
                risk_score=risk_score,
                added_by=added_by,
                is_active=True,
                incident_id=incident_id,
                expires_at=expires_at,
                notes=notes,
            )
            db.add(entry)

        await db.commit()
        await db.refresh(entry)

        # Add to Redis hot set
        if cache_service.available:
            try:
                await cache_service._client.sadd(_BLACKLIST_REDIS_KEY, ip)
            except Exception:
                pass

        logger.info("🔒 IP blocked: %s — %s (by %s)", ip, reason, added_by)
        return entry

    async def unblock_ip(self, ip: str, db: AsyncSession) -> bool:
        result = await db.execute(
            select(IPBlacklist).where(IPBlacklist.ip_address == ip)
        )
        entry = result.scalar_one_or_none()
        if not entry:
            return False

        entry.is_active     = False
        entry.unblocked_at  = datetime.now(timezone.utc)
        await db.commit()

        if cache_service.available:
            try:
                await cache_service._client.srem(_BLACKLIST_REDIS_KEY, ip)
            except Exception:
                pass

        logger.info("🔓 IP unblocked: %s", ip)
        return True

    # -----------------------------------------------------------------------
    # Block-hit counter (called at ingestion to count blocked traffic)
    # -----------------------------------------------------------------------

    async def record_block_hit(self, ip: str, db: AsyncSession):
        result = await db.execute(
            select(IPBlacklist).where(IPBlacklist.ip_address == ip, IPBlacklist.is_active == True)
        )
        entry = result.scalar_one_or_none()
        if entry:
            entry.block_hits += 1
            await db.commit()

    # -----------------------------------------------------------------------
    # Playbook resolution
    # -----------------------------------------------------------------------

    @staticmethod
    def get_playbook(attack_type: Optional[str]) -> Dict[str, Any]:
        """Return the most appropriate playbook for an attack type."""
        if not attack_type:
            return _DEFAULT_PLAYBOOK
        # Exact match first
        if attack_type in _PLAYBOOKS:
            return _PLAYBOOKS[attack_type]
        # Partial match
        at_lower = attack_type.lower()
        for key, pb in _PLAYBOOKS.items():
            if key.lower() in at_lower or at_lower in key.lower():
                return pb
        return _DEFAULT_PLAYBOOK

    @staticmethod
    def get_all_playbooks() -> Dict[str, Dict[str, Any]]:
        return _PLAYBOOKS

    # -----------------------------------------------------------------------
    # Auto-response: called from alert_service when risk >= threshold
    # -----------------------------------------------------------------------

    async def auto_respond(
        self, alert_data: Dict[str, Any], db: AsyncSession
    ) -> Optional[str]:
        """
        Run automated response actions based on alert risk score.
        Returns the playbook name that was triggered, or None.
        """
        ip          = alert_data.get("source_ip")
        risk_score  = float(alert_data.get("risk_score") or 0)
        attack_type = alert_data.get("attack_type")
        rule_name   = alert_data.get("rule_name")

        if not ip or risk_score < 85.0:
            return None

        playbook = self.get_playbook(attack_type)
        if "block_ip" in playbook.get("auto_actions", []):
            await self.block_ip(
                ip=ip,
                reason=f"Auto-blocked: {attack_type or rule_name or 'high risk'} (score {risk_score:.1f})",
                db=db,
                added_by="soar_auto",
                risk_score=risk_score,
                attack_types=[attack_type] if attack_type else [],
                rule_names=[rule_name] if rule_name else [],
            )

        return playbook["name"]


# Singleton
soar_service = SOARService()
