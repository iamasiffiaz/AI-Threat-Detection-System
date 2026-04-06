"""
Advanced SIEM Rule Engine — 15 MITRE ATT&CK aligned detection rules.
State is backed by Redis (with in-memory fallback) so counters survive restarts.
"""
import re
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from app.models.alert import AlertSeverity, AlertType
from app.core.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique IDs for each rule
# ---------------------------------------------------------------------------
MITRE_MAP: Dict[str, List[str]] = {
    "brute_force_login":      ["T1110.001", "T1110.003"],  # Password Guessing / Spraying
    "port_scan":              ["T1046"],                    # Network Service Discovery
    "ddos_flood":             ["T1498", "T1499"],           # Network/Endpoint DoS
    "suspicious_port_access": ["T1571"],                    # Non-Standard Port
    "privilege_escalation":   ["T1068", "T1548"],           # Exploitation / Abuse Elevation
    "data_exfiltration":      ["T1041", "T1048"],           # Exfil over C2 / Alt Protocol
    "lateral_movement":       ["T1021", "T1210"],           # Remote Services / Exploit
    "critical_severity_event":["T1190"],                    # Exploit Public-Facing App
    "sql_injection":          ["T1190", "T1059.007"],       # Exploit Public-Facing / SQLi
    "web_attack":             ["T1190", "T1059"],           # Web App Exploit / Script
    "c2_beacon":              ["T1071.001", "T1571"],       # Web C2 / Non-Standard Port
    "dns_tunneling":          ["T1071.004", "T1048.003"],   # DNS C2 / Exfil over DNS
    "credential_stuffing":    ["T1110.004"],                # Credential Stuffing
    "rce_attempt":            ["T1059", "T1203"],           # Command Execution / Client Exploit
    "internal_recon":         ["T1018", "T1046"],           # Remote System Discovery
}

# SQL injection patterns
_SQL_PATTERN = re.compile(
    r"(union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into|"
    r"'\s*(or|and)\s+'?\d|--\s*$|;\s*drop|xp_cmdshell|information_schema)",
    re.IGNORECASE,
)

# Web attack patterns (XSS, path traversal, LFI/RFI, command injection)
_WEB_PATTERN = re.compile(
    r"(<script|javascript:|onerror=|onload=|"           # XSS
    r"\.\./|\.\.\\|%2e%2e|etc/passwd|/etc/shadow|"     # Path traversal
    r"php://|file://|expect://|data://|"                # Wrapper abuse
    r"\bexec\b|\bsystem\b|\bshell_exec\b|\bpassthru\b|" # PHP RCE
    r"cmd\.exe|powershell|/bin/sh|/bin/bash)",           # OS injection
    re.IGNORECASE,
)

# Remote code execution patterns
_RCE_PATTERN = re.compile(
    r"(cmd\.exe|/bin/(bash|sh|zsh)|powershell\.exe|"
    r"wget\s+http|curl\s+http|nc\s+-[elp]|ncat\s+-[elp]|"
    r"python\s+-c|perl\s+-e|ruby\s+-e|java\s+-jar|"
    r"msfvenom|metasploit|reverse.?shell)",
    re.IGNORECASE,
)


@dataclass
class DetectionRule:
    name: str
    description: str
    severity: AlertSeverity
    enabled: bool = True
    cooldown_seconds: int = 300
    mitre_ttps: List[str] = field(default_factory=list)


@dataclass
class RuleMatch:
    rule_name: str
    title: str
    description: str
    severity: AlertSeverity
    source_ip: Optional[str] = None
    log_entry_id: Optional[int] = None
    context: Dict[str, Any] = field(default_factory=dict)


class RuleEngine:
    """
    Async-capable rule engine with Redis-backed state persistence.
    In-memory fallback is used when Redis is unavailable.
    """

    def __init__(self):
        # In-memory fallback state
        self._failed_logins:    Dict[str, List[datetime]] = defaultdict(list)
        self._port_connections: Dict[str, Dict[int, datetime]] = defaultdict(dict)
        self._request_counts:   Dict[str, List[datetime]] = defaultdict(list)
        self._dns_counts:       Dict[str, List[datetime]] = defaultdict(list)
        self._usernames:        Dict[str, set] = defaultdict(set)
        self._alert_cooldowns:  Dict[str, datetime] = {}

        self.rules = self._build_rules()

    def _build_rules(self) -> List[DetectionRule]:
        return [
            DetectionRule("brute_force_login",      "Multiple failed login attempts from same IP",          AlertSeverity.HIGH,     cooldown_seconds=300,  mitre_ttps=MITRE_MAP["brute_force_login"]),
            DetectionRule("port_scan",               "Systematic multi-port probing from same IP",           AlertSeverity.HIGH,     cooldown_seconds=600,  mitre_ttps=MITRE_MAP["port_scan"]),
            DetectionRule("ddos_flood",              "Request flood indicating DDoS",                        AlertSeverity.CRITICAL, cooldown_seconds=120,  mitre_ttps=MITRE_MAP["ddos_flood"]),
            DetectionRule("suspicious_port_access",  "Connection to known backdoor/C2 port",                 AlertSeverity.MEDIUM,   cooldown_seconds=600,  mitre_ttps=MITRE_MAP["suspicious_port_access"]),
            DetectionRule("privilege_escalation",    "Privilege escalation attempt",                         AlertSeverity.CRITICAL, cooldown_seconds=60,   mitre_ttps=MITRE_MAP["privilege_escalation"]),
            DetectionRule("data_exfiltration",       "Abnormally large outbound transfer",                   AlertSeverity.HIGH,     cooldown_seconds=300,  mitre_ttps=MITRE_MAP["data_exfiltration"]),
            DetectionRule("lateral_movement",        "Internal-to-internal scanning or credential reuse",    AlertSeverity.HIGH,     cooldown_seconds=300,  mitre_ttps=MITRE_MAP["lateral_movement"]),
            DetectionRule("critical_severity_event", "Log entry flagged CRITICAL severity",                  AlertSeverity.CRITICAL, cooldown_seconds=60,   mitre_ttps=MITRE_MAP["critical_severity_event"]),
            # ---- Advanced rules ----
            DetectionRule("sql_injection",           "SQL injection pattern detected in log message",        AlertSeverity.CRITICAL, cooldown_seconds=120,  mitre_ttps=MITRE_MAP["sql_injection"]),
            DetectionRule("web_attack",              "Web exploit pattern (XSS / LFI / RFI / traversal)",   AlertSeverity.HIGH,     cooldown_seconds=180,  mitre_ttps=MITRE_MAP["web_attack"]),
            DetectionRule("c2_beacon",               "High-frequency regular connections suggesting C2",     AlertSeverity.CRITICAL, cooldown_seconds=300,  mitre_ttps=MITRE_MAP["c2_beacon"]),
            DetectionRule("dns_tunneling",           "Excessive DNS queries indicating tunneling",           AlertSeverity.HIGH,     cooldown_seconds=600,  mitre_ttps=MITRE_MAP["dns_tunneling"]),
            DetectionRule("credential_stuffing",     "Many distinct usernames tried from same IP",           AlertSeverity.HIGH,     cooldown_seconds=300,  mitre_ttps=MITRE_MAP["credential_stuffing"]),
            DetectionRule("rce_attempt",             "Remote code execution pattern in log message",         AlertSeverity.CRITICAL, cooldown_seconds=60,   mitre_ttps=MITRE_MAP["rce_attempt"]),
            DetectionRule("internal_recon",          "Internal network reconnaissance detected",             AlertSeverity.HIGH,     cooldown_seconds=300,  mitre_ttps=MITRE_MAP["internal_recon"]),
        ]

    # ------------------------------------------------------------------
    # Cooldown helpers (in-memory)
    # ------------------------------------------------------------------

    def _in_cooldown(self, rule: str, ip: str) -> bool:
        key = f"{rule}:{ip}"
        exp = self._alert_cooldowns.get(key)
        return exp is not None and datetime.now(timezone.utc) < exp

    def _set_cooldown(self, rule: str, ip: str, seconds: int):
        self._alert_cooldowns[f"{rule}:{ip}"] = (
            datetime.now(timezone.utc) + timedelta(seconds=seconds)
        )

    def _prune(self, lst: List[datetime], window_minutes: int) -> List[datetime]:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        return [t for t in lst if t > cutoff]

    # ------------------------------------------------------------------
    # Async evaluate — primary entry point
    # ------------------------------------------------------------------

    async def evaluate(self, log: Dict[str, Any]) -> List[RuleMatch]:
        """
        Evaluate all 15 rules against a single log entry.
        Uses Redis counters when available; falls back to in-memory.
        Returns list of matched RuleMatch objects.
        """
        from app.services.cache_service import cache_service

        matches: List[RuleMatch] = []
        now      = datetime.now(timezone.utc)

        src_ip   = str(log.get("source_ip", "unknown"))
        dst_ip   = str(log.get("destination_ip", "") or "")
        dst_port = int(log.get("destination_port") or 0)
        event    = str(log.get("event_type", "")).lower()
        severity = str(log.get("severity",   "info")).lower()
        message  = str(log.get("message",    "") or "")
        bytes_s  = int(log.get("bytes_sent", 0) or 0)
        username = str(log.get("username",   "") or "")
        log_id   = log.get("id")

        use_redis = cache_service.available

        # ---- 1. Brute Force Login ------------------------------------
        if "fail" in event and "login" in event:
            if use_redis:
                count = await cache_service.rule_increment("brute_force", src_ip, 600)
                in_cd = await cache_service.is_in_cooldown("brute_force_login", src_ip)
            else:
                self._failed_logins[src_ip].append(now)
                self._failed_logins[src_ip] = self._prune(self._failed_logins[src_ip], 10)
                count = len(self._failed_logins[src_ip])
                in_cd = self._in_cooldown("brute_force_login", src_ip)

            if count >= settings.FAILED_LOGIN_THRESHOLD and not in_cd:
                matches.append(RuleMatch(
                    rule_name="brute_force_login",
                    title=f"Brute Force Login: {src_ip}",
                    description=f"{src_ip} made {count} failed login attempts in 10 min. TTPs: {', '.join(MITRE_MAP['brute_force_login'])}",
                    severity=AlertSeverity.HIGH, source_ip=src_ip, log_entry_id=log_id,
                    context={"failed_attempts": count, "mitre_ttps": MITRE_MAP["brute_force_login"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("brute_force_login", src_ip, 300)
                else:
                    self._set_cooldown("brute_force_login", src_ip, 300)

        # ---- 2. Port Scan -------------------------------------------
        if dst_port > 0:
            if use_redis:
                unique_ports = await cache_service.rule_sadd("portscan", src_ip, str(dst_port), 600)
                in_cd = await cache_service.is_in_cooldown("port_scan", src_ip)
            else:
                self._port_connections[src_ip][dst_port] = now
                unique_ports = sum(
                    1 for p, t in self._port_connections[src_ip].items()
                    if (now - t).total_seconds() < 600
                )
                in_cd = self._in_cooldown("port_scan", src_ip)

            if unique_ports >= settings.PORT_SCAN_THRESHOLD and not in_cd:
                matches.append(RuleMatch(
                    rule_name="port_scan",
                    title=f"Port Scan: {src_ip}",
                    description=f"{src_ip} hit {unique_ports} unique ports in 10 min. MITRE: {', '.join(MITRE_MAP['port_scan'])}",
                    severity=AlertSeverity.HIGH, source_ip=src_ip, log_entry_id=log_id,
                    context={"unique_ports": unique_ports, "mitre_ttps": MITRE_MAP["port_scan"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("port_scan", src_ip, 600)
                else:
                    self._set_cooldown("port_scan", src_ip, 600)

        # ---- 3. DDoS Flood -------------------------------------------
        if use_redis:
            rps = await cache_service.rule_increment("ddos", src_ip, 60)
            in_cd = await cache_service.is_in_cooldown("ddos_flood", src_ip)
        else:
            self._request_counts[src_ip].append(now)
            self._request_counts[src_ip] = self._prune(self._request_counts[src_ip], 1)
            rps = len(self._request_counts[src_ip])
            in_cd = self._in_cooldown("ddos_flood", src_ip)

        if rps >= 200 and not in_cd:
            matches.append(RuleMatch(
                rule_name="ddos_flood",
                title=f"DDoS Flood: {src_ip}",
                description=f"{src_ip} sent {rps} requests/min. MITRE: {', '.join(MITRE_MAP['ddos_flood'])}",
                severity=AlertSeverity.CRITICAL, source_ip=src_ip, log_entry_id=log_id,
                context={"requests_per_minute": rps, "mitre_ttps": MITRE_MAP["ddos_flood"]},
            ))
            if use_redis:
                await cache_service.set_cooldown("ddos_flood", src_ip, 120)
            else:
                self._set_cooldown("ddos_flood", src_ip, 120)

        # ---- 4. Suspicious Port Access ------------------------------
        HIGH_RISK = {4444, 1337, 31337, 6666, 6667, 8888, 9001, 4899, 1080, 5554}
        if dst_port in HIGH_RISK:
            in_cd = (
                await cache_service.is_in_cooldown("suspicious_port_access", src_ip)
                if use_redis else self._in_cooldown("suspicious_port_access", src_ip)
            )
            if not in_cd:
                matches.append(RuleMatch(
                    rule_name="suspicious_port_access",
                    title=f"Suspicious Port: {src_ip} → {dst_port}",
                    description=f"Connection to known backdoor/C2 port {dst_port}. MITRE: {', '.join(MITRE_MAP['suspicious_port_access'])}",
                    severity=AlertSeverity.MEDIUM, source_ip=src_ip, log_entry_id=log_id,
                    context={"port": dst_port, "mitre_ttps": MITRE_MAP["suspicious_port_access"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("suspicious_port_access", src_ip, 600)
                else:
                    self._set_cooldown("suspicious_port_access", src_ip, 600)

        # ---- 5. Privilege Escalation --------------------------------
        PRIV_KEYWORDS = {"privilege", "escalat", "sudo", "root_access", "admin_access", "setuid", "sudoers"}
        if any(k in event for k in PRIV_KEYWORDS):
            in_cd = (
                await cache_service.is_in_cooldown("privilege_escalation", src_ip)
                if use_redis else self._in_cooldown("privilege_escalation", src_ip)
            )
            if not in_cd:
                matches.append(RuleMatch(
                    rule_name="privilege_escalation",
                    title=f"Privilege Escalation: {src_ip}",
                    description=f"Event '{log.get('event_type')}' from {src_ip}. MITRE: {', '.join(MITRE_MAP['privilege_escalation'])}",
                    severity=AlertSeverity.CRITICAL, source_ip=src_ip, log_entry_id=log_id,
                    context={"event_type": log.get("event_type"), "mitre_ttps": MITRE_MAP["privilege_escalation"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("privilege_escalation", src_ip, 60)
                else:
                    self._set_cooldown("privilege_escalation", src_ip, 60)

        # ---- 6. Data Exfiltration -----------------------------------
        if bytes_s > 50_000_000:
            in_cd = (
                await cache_service.is_in_cooldown("data_exfiltration", src_ip)
                if use_redis else self._in_cooldown("data_exfiltration", src_ip)
            )
            if not in_cd:
                mb = bytes_s / 1_000_000
                matches.append(RuleMatch(
                    rule_name="data_exfiltration",
                    title=f"Data Exfiltration: {src_ip}",
                    description=f"Large outbound transfer of {mb:.1f} MB from {src_ip}. MITRE: {', '.join(MITRE_MAP['data_exfiltration'])}",
                    severity=AlertSeverity.HIGH, source_ip=src_ip, log_entry_id=log_id,
                    context={"bytes_sent": bytes_s, "mb_sent": round(mb, 2), "mitre_ttps": MITRE_MAP["data_exfiltration"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("data_exfiltration", src_ip, 300)
                else:
                    self._set_cooldown("data_exfiltration", src_ip, 300)

        # ---- 7. Lateral Movement ------------------------------------
        try:
            import ipaddress as _ip
            src_private = _ip.ip_address(src_ip).is_private if src_ip else False
            dst_private = _ip.ip_address(dst_ip).is_private if dst_ip else False
        except ValueError:
            src_private = dst_private = False

        if src_private and dst_private and dst_port in {22, 135, 139, 445, 3389, 5985, 5986}:
            in_cd = (
                await cache_service.is_in_cooldown("lateral_movement", src_ip)
                if use_redis else self._in_cooldown("lateral_movement", src_ip)
            )
            if not in_cd:
                matches.append(RuleMatch(
                    rule_name="lateral_movement",
                    title=f"Lateral Movement: {src_ip} → {dst_ip}:{dst_port}",
                    description=f"Internal host {src_ip} connecting to admin port {dst_port} on {dst_ip}. MITRE: {', '.join(MITRE_MAP['lateral_movement'])}",
                    severity=AlertSeverity.HIGH, source_ip=src_ip, log_entry_id=log_id,
                    context={"dst_ip": dst_ip, "dst_port": dst_port, "mitre_ttps": MITRE_MAP["lateral_movement"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("lateral_movement", src_ip, 300)
                else:
                    self._set_cooldown("lateral_movement", src_ip, 300)

        # ---- 8. Critical Severity Event -----------------------------
        if severity == "critical":
            in_cd = (
                await cache_service.is_in_cooldown("critical_severity_event", src_ip)
                if use_redis else self._in_cooldown("critical_severity_event", src_ip)
            )
            if not in_cd:
                matches.append(RuleMatch(
                    rule_name="critical_severity_event",
                    title=f"Critical Event: {log.get('event_type')}",
                    description=f"CRITICAL severity from {src_ip}: {message[:200]}",
                    severity=AlertSeverity.CRITICAL, source_ip=src_ip, log_entry_id=log_id,
                    context={"message": message[:200], "mitre_ttps": MITRE_MAP["critical_severity_event"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("critical_severity_event", src_ip, 60)
                else:
                    self._set_cooldown("critical_severity_event", src_ip, 60)

        # ---- 9. SQL Injection ----------------------------------------
        combined_text = f"{event} {message}"
        if _SQL_PATTERN.search(combined_text):
            in_cd = (
                await cache_service.is_in_cooldown("sql_injection", src_ip)
                if use_redis else self._in_cooldown("sql_injection", src_ip)
            )
            if not in_cd:
                matches.append(RuleMatch(
                    rule_name="sql_injection",
                    title=f"SQL Injection Attempt: {src_ip}",
                    description=f"SQL injection pattern in request from {src_ip}. MITRE: {', '.join(MITRE_MAP['sql_injection'])}",
                    severity=AlertSeverity.CRITICAL, source_ip=src_ip, log_entry_id=log_id,
                    context={"snippet": combined_text[:300], "mitre_ttps": MITRE_MAP["sql_injection"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("sql_injection", src_ip, 120)
                else:
                    self._set_cooldown("sql_injection", src_ip, 120)

        # ---- 10. Web Attack (XSS / LFI / Path Traversal) -----------
        if _WEB_PATTERN.search(combined_text):
            in_cd = (
                await cache_service.is_in_cooldown("web_attack", src_ip)
                if use_redis else self._in_cooldown("web_attack", src_ip)
            )
            if not in_cd:
                matches.append(RuleMatch(
                    rule_name="web_attack",
                    title=f"Web Attack: {src_ip}",
                    description=f"Web exploit pattern (XSS/LFI/RFI/traversal) from {src_ip}. MITRE: {', '.join(MITRE_MAP['web_attack'])}",
                    severity=AlertSeverity.HIGH, source_ip=src_ip, log_entry_id=log_id,
                    context={"snippet": combined_text[:300], "mitre_ttps": MITRE_MAP["web_attack"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("web_attack", src_ip, 180)
                else:
                    self._set_cooldown("web_attack", src_ip, 180)

        # ---- 11. C2 Beacon (high-freq short-interval connections) ---
        if use_redis:
            beacon_count = await cache_service.rule_increment("c2_beacon", src_ip, 300)
            in_cd = await cache_service.is_in_cooldown("c2_beacon", src_ip)
        else:
            in_cd = self._in_cooldown("c2_beacon", src_ip)
            beacon_count = 0  # no in-memory beacon tracking

        if beacon_count >= 50 and not in_cd:
            matches.append(RuleMatch(
                rule_name="c2_beacon",
                title=f"C2 Beacon Pattern: {src_ip}",
                description=f"{src_ip} made {beacon_count} connections in 5 min suggesting C2 beaconing. MITRE: {', '.join(MITRE_MAP['c2_beacon'])}",
                severity=AlertSeverity.CRITICAL, source_ip=src_ip, log_entry_id=log_id,
                context={"connections_5min": beacon_count, "mitre_ttps": MITRE_MAP["c2_beacon"]},
            ))
            if use_redis:
                await cache_service.set_cooldown("c2_beacon", src_ip, 300)

        # ---- 12. DNS Tunneling --------------------------------------
        if dst_port in {53, 853}:
            if use_redis:
                dns_count = await cache_service.rule_increment("dns_tunnel", src_ip, 600)
                in_cd = await cache_service.is_in_cooldown("dns_tunneling", src_ip)
            else:
                self._dns_counts[src_ip].append(now)
                self._dns_counts[src_ip] = self._prune(self._dns_counts[src_ip], 10)
                dns_count = len(self._dns_counts[src_ip])
                in_cd = self._in_cooldown("dns_tunneling", src_ip)

            if dns_count >= 100 and not in_cd:
                matches.append(RuleMatch(
                    rule_name="dns_tunneling",
                    title=f"DNS Tunneling: {src_ip}",
                    description=f"{src_ip} sent {dns_count} DNS queries in 10 min — possible data tunneling. MITRE: {', '.join(MITRE_MAP['dns_tunneling'])}",
                    severity=AlertSeverity.HIGH, source_ip=src_ip, log_entry_id=log_id,
                    context={"dns_queries_10min": dns_count, "mitre_ttps": MITRE_MAP["dns_tunneling"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("dns_tunneling", src_ip, 600)
                else:
                    self._set_cooldown("dns_tunneling", src_ip, 600)

        # ---- 13. Credential Stuffing --------------------------------
        if username and "login" in event:
            if use_redis:
                unique_users = await cache_service.rule_sadd("cred_stuff", src_ip, username, 600)
                in_cd = await cache_service.is_in_cooldown("credential_stuffing", src_ip)
            else:
                self._usernames[src_ip].add(username)
                unique_users = len(self._usernames[src_ip])
                in_cd = self._in_cooldown("credential_stuffing", src_ip)

            if unique_users >= 10 and not in_cd:
                matches.append(RuleMatch(
                    rule_name="credential_stuffing",
                    title=f"Credential Stuffing: {src_ip}",
                    description=f"{src_ip} tried {unique_users} distinct usernames — credential stuffing attack. MITRE: {', '.join(MITRE_MAP['credential_stuffing'])}",
                    severity=AlertSeverity.HIGH, source_ip=src_ip, log_entry_id=log_id,
                    context={"unique_usernames": unique_users, "mitre_ttps": MITRE_MAP["credential_stuffing"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("credential_stuffing", src_ip, 300)
                else:
                    self._set_cooldown("credential_stuffing", src_ip, 300)

        # ---- 14. RCE Attempt ----------------------------------------
        if _RCE_PATTERN.search(combined_text):
            in_cd = (
                await cache_service.is_in_cooldown("rce_attempt", src_ip)
                if use_redis else self._in_cooldown("rce_attempt", src_ip)
            )
            if not in_cd:
                matches.append(RuleMatch(
                    rule_name="rce_attempt",
                    title=f"RCE Attempt: {src_ip}",
                    description=f"Remote code execution pattern detected from {src_ip}. MITRE: {', '.join(MITRE_MAP['rce_attempt'])}",
                    severity=AlertSeverity.CRITICAL, source_ip=src_ip, log_entry_id=log_id,
                    context={"snippet": combined_text[:300], "mitre_ttps": MITRE_MAP["rce_attempt"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("rce_attempt", src_ip, 60)
                else:
                    self._set_cooldown("rce_attempt", src_ip, 60)

        # ---- 15. Internal Recon -------------------------------------
        if src_private and ("scan" in event or "probe" in event or "discovery" in event):
            if use_redis:
                recon_ports = await cache_service.rule_sadd("int_recon", src_ip, str(dst_port), 600)
                in_cd = await cache_service.is_in_cooldown("internal_recon", src_ip)
            else:
                recon_ports = 0
                in_cd = self._in_cooldown("internal_recon", src_ip)

            if recon_ports >= 15 and not in_cd:
                matches.append(RuleMatch(
                    rule_name="internal_recon",
                    title=f"Internal Recon: {src_ip}",
                    description=f"Internal host {src_ip} scanning {recon_ports} ports — network reconnaissance. MITRE: {', '.join(MITRE_MAP['internal_recon'])}",
                    severity=AlertSeverity.HIGH, source_ip=src_ip, log_entry_id=log_id,
                    context={"ports_scanned": recon_ports, "mitre_ttps": MITRE_MAP["internal_recon"]},
                ))
                if use_redis:
                    await cache_service.set_cooldown("internal_recon", src_ip, 300)
                else:
                    self._set_cooldown("internal_recon", src_ip, 300)

        if matches:
            logger.debug(f"Rule engine: {len(matches)} match(es) for {src_ip}: {[m.rule_name for m in matches]}")

        return matches


rule_engine = RuleEngine()
