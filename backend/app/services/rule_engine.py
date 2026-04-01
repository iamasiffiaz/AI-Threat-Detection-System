"""
SIEM-style Rule Engine for signature-based threat detection.
Rules are evaluated against incoming log entries to generate alerts.
"""
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from app.models.alert import AlertSeverity, AlertType
from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class DetectionRule:
    """Defines a single detection rule with evaluation logic."""
    name: str
    description: str
    severity: AlertSeverity
    enabled: bool = True
    cooldown_seconds: int = 300


@dataclass
class RuleMatch:
    """Result of a rule evaluation that matched."""
    rule_name: str
    title: str
    description: str
    severity: AlertSeverity
    source_ip: Optional[str] = None
    log_entry_id: Optional[int] = None
    context: Dict[str, Any] = field(default_factory=dict)


class RuleEngine:
    """
    Stateful rule engine that maintains per-IP counters and sliding window
    statistics to detect behavioral patterns indicating attacks.
    """

    def __init__(self):
        # Per-IP event trackers: {ip: [timestamps]}
        self._failed_logins: Dict[str, List[datetime]] = defaultdict(list)
        self._port_connections: Dict[str, Dict[int, List[datetime]]] = defaultdict(lambda: defaultdict(list))
        self._request_counts: Dict[str, List[datetime]] = defaultdict(list)
        self._alert_cooldowns: Dict[str, datetime] = {}

        self.rules: List[DetectionRule] = self._load_default_rules()

    def _load_default_rules(self) -> List[DetectionRule]:
        return [
            DetectionRule(
                name="brute_force_login",
                description="Multiple failed login attempts from same source IP",
                severity=AlertSeverity.HIGH,
                cooldown_seconds=300,
            ),
            DetectionRule(
                name="port_scan",
                description="Scanning multiple ports from same source IP",
                severity=AlertSeverity.HIGH,
                cooldown_seconds=600,
            ),
            DetectionRule(
                name="ddos_flood",
                description="Excessive request rate from single IP (potential DDoS)",
                severity=AlertSeverity.CRITICAL,
                cooldown_seconds=120,
            ),
            DetectionRule(
                name="suspicious_port_access",
                description="Connection to known malicious/unusual port",
                severity=AlertSeverity.MEDIUM,
                cooldown_seconds=600,
            ),
            DetectionRule(
                name="privilege_escalation",
                description="Privilege escalation event detected",
                severity=AlertSeverity.CRITICAL,
                cooldown_seconds=60,
            ),
            DetectionRule(
                name="data_exfiltration",
                description="Large outbound data transfer detected",
                severity=AlertSeverity.HIGH,
                cooldown_seconds=300,
            ),
            DetectionRule(
                name="lateral_movement",
                description="Internal-to-internal scanning or connection pattern",
                severity=AlertSeverity.HIGH,
                cooldown_seconds=300,
            ),
            DetectionRule(
                name="critical_severity_event",
                description="Log entry with critical severity level",
                severity=AlertSeverity.CRITICAL,
                cooldown_seconds=60,
            ),
        ]

    def _is_in_cooldown(self, rule_name: str, source_ip: str) -> bool:
        """Check if an alert for this rule+IP is still in cooldown."""
        key = f"{rule_name}:{source_ip}"
        if key in self._alert_cooldowns:
            cooldown_until = self._alert_cooldowns[key]
            if datetime.now(timezone.utc) < cooldown_until:
                return True
        return False

    def _set_cooldown(self, rule_name: str, source_ip: str, seconds: int):
        """Set cooldown for a rule+IP combination."""
        key = f"{rule_name}:{source_ip}"
        self._alert_cooldowns[key] = datetime.now(timezone.utc) + timedelta(seconds=seconds)

    def _prune_old_events(self, event_list: List[datetime], window_minutes: int = 10) -> List[datetime]:
        """Remove events older than the specified window."""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        return [ts for ts in event_list if ts > cutoff]

    def evaluate(self, log: Dict[str, Any]) -> List[RuleMatch]:
        """
        Evaluate all rules against a single log entry.
        Returns a list of matched rules (may be empty).
        """
        matches: List[RuleMatch] = []
        now = datetime.now(timezone.utc)

        src_ip = str(log.get("source_ip", "unknown"))
        dst_port = int(log.get("destination_port") or 0)
        event_type = str(log.get("event_type", "")).lower()
        severity = str(log.get("severity", "info")).lower()
        bytes_sent = int(log.get("bytes_sent") or 0)
        dst_ip = str(log.get("destination_ip", ""))

        log_id = log.get("id")

        # --- Rule 1: Brute Force Login ---
        if "fail" in event_type and "login" in event_type:
            self._failed_logins[src_ip].append(now)
            self._failed_logins[src_ip] = self._prune_old_events(self._failed_logins[src_ip], 10)

            count = len(self._failed_logins[src_ip])
            if count >= settings.FAILED_LOGIN_THRESHOLD and not self._is_in_cooldown("brute_force_login", src_ip):
                matches.append(RuleMatch(
                    rule_name="brute_force_login",
                    title=f"Brute Force Login Detected: {src_ip}",
                    description=f"IP {src_ip} made {count} failed login attempts in the last 10 minutes.",
                    severity=AlertSeverity.HIGH,
                    source_ip=src_ip,
                    log_entry_id=log_id,
                    context={"failed_attempts": count, "window_minutes": 10},
                ))
                self._set_cooldown("brute_force_login", src_ip, 300)

        # --- Rule 2: Port Scan Detection ---
        if dst_port > 0:
            self._port_connections[src_ip][dst_port].append(now)
            unique_ports = {
                p for p, times in self._port_connections[src_ip].items()
                if times and (now - times[-1]).total_seconds() < 600
            }
            if len(unique_ports) >= settings.PORT_SCAN_THRESHOLD and not self._is_in_cooldown("port_scan", src_ip):
                matches.append(RuleMatch(
                    rule_name="port_scan",
                    title=f"Port Scan Detected: {src_ip}",
                    description=f"IP {src_ip} connected to {len(unique_ports)} unique ports in the last 10 minutes.",
                    severity=AlertSeverity.HIGH,
                    source_ip=src_ip,
                    log_entry_id=log_id,
                    context={"unique_ports": len(unique_ports), "sample_ports": list(unique_ports)[:10]},
                ))
                self._set_cooldown("port_scan", src_ip, 600)

        # --- Rule 3: DDoS / Request Flood ---
        self._request_counts[src_ip].append(now)
        self._request_counts[src_ip] = self._prune_old_events(self._request_counts[src_ip], 1)
        req_per_min = len(self._request_counts[src_ip])

        if req_per_min >= 200 and not self._is_in_cooldown("ddos_flood", src_ip):
            matches.append(RuleMatch(
                rule_name="ddos_flood",
                title=f"DDoS Flood Detected: {src_ip}",
                description=f"IP {src_ip} sent {req_per_min} requests in the last minute.",
                severity=AlertSeverity.CRITICAL,
                source_ip=src_ip,
                log_entry_id=log_id,
                context={"requests_per_minute": req_per_min},
            ))
            self._set_cooldown("ddos_flood", src_ip, 120)

        # --- Rule 4: Suspicious Port Access ---
        VERY_SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 6668, 8888}
        if dst_port in VERY_SUSPICIOUS_PORTS and not self._is_in_cooldown("suspicious_port_access", src_ip):
            matches.append(RuleMatch(
                rule_name="suspicious_port_access",
                title=f"Suspicious Port Access: {src_ip} -> port {dst_port}",
                description=f"Connection to commonly used backdoor/C2 port {dst_port} from {src_ip}.",
                severity=AlertSeverity.MEDIUM,
                source_ip=src_ip,
                log_entry_id=log_id,
                context={"port": dst_port},
            ))
            self._set_cooldown("suspicious_port_access", src_ip, 600)

        # --- Rule 5: Privilege Escalation ---
        if any(kw in event_type for kw in ["privilege", "escalat", "sudo", "root", "admin_access"]):
            if not self._is_in_cooldown("privilege_escalation", src_ip):
                matches.append(RuleMatch(
                    rule_name="privilege_escalation",
                    title=f"Privilege Escalation Attempt: {src_ip}",
                    description=f"Potential privilege escalation detected: event '{log.get('event_type')}'",
                    severity=AlertSeverity.CRITICAL,
                    source_ip=src_ip,
                    log_entry_id=log_id,
                    context={"event_type": log.get("event_type")},
                ))
                self._set_cooldown("privilege_escalation", src_ip, 60)

        # --- Rule 6: Data Exfiltration ---
        if bytes_sent > 50_000_000 and not self._is_in_cooldown("data_exfiltration", src_ip):
            mb_sent = bytes_sent / 1_000_000
            matches.append(RuleMatch(
                rule_name="data_exfiltration",
                title=f"Potential Data Exfiltration: {src_ip}",
                description=f"Large outbound transfer of {mb_sent:.1f} MB from {src_ip}.",
                severity=AlertSeverity.HIGH,
                source_ip=src_ip,
                log_entry_id=log_id,
                context={"bytes_sent": bytes_sent, "mb_sent": mb_sent},
            ))
            self._set_cooldown("data_exfiltration", src_ip, 300)

        # --- Rule 7: Critical Severity Event ---
        if severity == "critical" and not self._is_in_cooldown("critical_severity_event", src_ip):
            matches.append(RuleMatch(
                rule_name="critical_severity_event",
                title=f"Critical Event Detected: {log.get('event_type')}",
                description=f"Log entry with CRITICAL severity from {src_ip}: {log.get('message', 'No details')}",
                severity=AlertSeverity.CRITICAL,
                source_ip=src_ip,
                log_entry_id=log_id,
                context={"message": log.get("message")},
            ))
            self._set_cooldown("critical_severity_event", src_ip, 60)

        return matches


# Application-scoped singleton
rule_engine = RuleEngine()
