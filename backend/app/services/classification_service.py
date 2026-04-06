"""
Attack Classification Service
================================
Classifies security events into one of 10 attack categories using a
multi-signal decision tree:

  Signal priority (highest → lowest):
    1. Rule engine match (explicit rule name → direct mapping)
    2. ML pattern (anomaly score + feature hints from event data)
    3. Behavioral signals (scan patterns, exfil volume, failure rates)
    4. Heuristic fallback

Returns:
  attack_type       : str   (one of the 10 categories below)
  confidence_score  : float (0.0 – 1.0)
  reasoning         : str   (human-readable explanation)
"""
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Attack categories (align with MITRE ATT&CK tactical categories)
# ---------------------------------------------------------------------------

class AttackType:
    BRUTE_FORCE         = "Brute Force"
    PORT_SCAN           = "Port Scanning"
    DDOS                = "DDoS / Flood"
    SUSPICIOUS_LOGIN    = "Suspicious Login"
    DATA_EXFILTRATION   = "Data Exfiltration"
    SQL_INJECTION       = "SQL Injection"
    WEB_ATTACK          = "Web Application Attack"
    C2_COMMUNICATION    = "C2 Communication"
    DNS_TUNNELING       = "DNS Tunneling"
    RCE                 = "Remote Code Execution"
    CREDENTIAL_STUFFING = "Credential Stuffing"
    INTERNAL_RECON      = "Internal Reconnaissance"
    LATERAL_MOVEMENT    = "Lateral Movement"
    UNKNOWN             = "Unknown / Anomaly"


# ---------------------------------------------------------------------------
# Rule name → attack type mapping (matches rule_engine.py rule IDs)
# ---------------------------------------------------------------------------
_RULE_TYPE_MAP: dict[str, tuple[str, float]] = {
    # (attack_type, base_confidence)
    "brute_force":          (AttackType.BRUTE_FORCE,         0.92),
    "ssh_brute_force":      (AttackType.BRUTE_FORCE,         0.95),
    "port_scan":            (AttackType.PORT_SCAN,           0.90),
    "syn_flood":            (AttackType.DDOS,                0.88),
    "ddos":                 (AttackType.DDOS,                0.90),
    "suspicious_login":     (AttackType.SUSPICIOUS_LOGIN,    0.85),
    "geo_anomaly":          (AttackType.SUSPICIOUS_LOGIN,    0.75),
    "data_exfil":           (AttackType.DATA_EXFILTRATION,   0.88),
    "large_transfer":       (AttackType.DATA_EXFILTRATION,   0.80),
    "sql_injection":        (AttackType.SQL_INJECTION,       0.93),
    "web_attack":           (AttackType.WEB_ATTACK,          0.88),
    "xss":                  (AttackType.WEB_ATTACK,          0.87),
    "c2_beacon":            (AttackType.C2_COMMUNICATION,    0.85),
    "c2_communication":     (AttackType.C2_COMMUNICATION,    0.87),
    "dns_tunneling":        (AttackType.DNS_TUNNELING,       0.82),
    "credential_stuffing":  (AttackType.CREDENTIAL_STUFFING, 0.88),
    "rce_attempt":          (AttackType.RCE,                 0.90),
    "remote_code_execution":(AttackType.RCE,                 0.92),
    "internal_recon":       (AttackType.INTERNAL_RECON,      0.85),
    "lateral_movement":     (AttackType.LATERAL_MOVEMENT,    0.85),
}

# Event type keywords → attack type hints
_EVENT_HINTS: list[tuple[re.Pattern, str, float]] = [
    (re.compile(r"brute.?force|login.fail|auth.fail", re.I), AttackType.BRUTE_FORCE,         0.70),
    (re.compile(r"port.?scan|nmap|masscan",            re.I), AttackType.PORT_SCAN,           0.75),
    (re.compile(r"sql.?inject|sqli|union.select",      re.I), AttackType.SQL_INJECTION,       0.80),
    (re.compile(r"xss|cross.?site|script.?inject",     re.I), AttackType.WEB_ATTACK,          0.75),
    (re.compile(r"exfil|data.?leak|lfi|rfi|path.?trav",re.I), AttackType.DATA_EXFILTRATION,  0.72),
    (re.compile(r"beacon|c2|command.?control",         re.I), AttackType.C2_COMMUNICATION,   0.70),
    (re.compile(r"dns.tunnel|iodine|dnscat",           re.I), AttackType.DNS_TUNNELING,       0.78),
    (re.compile(r"rce|remote.?exec|shell.?upload|eval\(", re.I), AttackType.RCE,             0.80),
    (re.compile(r"flood|syn.?flood|udp.?flood|icmp.?flood", re.I), AttackType.DDOS,          0.75),
    (re.compile(r"lateral|smb|psexec|wmi.?exec",       re.I), AttackType.LATERAL_MOVEMENT,   0.72),
    (re.compile(r"recon|discovery|sweep|ping.?scan",   re.I), AttackType.INTERNAL_RECON,     0.70),
    (re.compile(r"credential.?stuff|account.?takeover", re.I), AttackType.CREDENTIAL_STUFFING, 0.75),
]


@dataclass
class ClassificationResult:
    attack_type:      str
    confidence_score: float  # 0.0-1.0
    reasoning:        str


class ClassificationService:
    """
    Multi-signal attack classifier.
    Called after rule evaluation and anomaly detection.
    """

    def classify(
        self,
        *,
        rule_name:      Optional[str]  = None,
        event_type:     Optional[str]  = None,
        message:        Optional[str]  = None,
        raw_log:        Optional[str]  = None,
        anomaly_score:  float          = 0.0,
        behavior_score: float          = 0.0,
        unique_ports:   int            = 0,
        bytes_out:      int            = 0,
        failed_logins:  int            = 0,
        is_known_bad:   bool           = False,
    ) -> ClassificationResult:

        # ------------------------------------------------------------------
        # 1. Rule match — highest confidence
        # ------------------------------------------------------------------
        if rule_name:
            key = rule_name.lower().strip()
            if key in _RULE_TYPE_MAP:
                atype, conf = _RULE_TYPE_MAP[key]
                conf = min(conf + (0.05 if is_known_bad else 0.0), 1.0)
                return ClassificationResult(
                    attack_type=atype,
                    confidence_score=round(conf, 3),
                    reasoning=f"Direct rule match: {rule_name}",
                )

        # ------------------------------------------------------------------
        # 2. Event/message text scanning
        # ------------------------------------------------------------------
        combined_text = " ".join(filter(None, [event_type, message, raw_log]))
        for pattern, atype, base_conf in _EVENT_HINTS:
            if pattern.search(combined_text):
                # Boost confidence from ML / behavior signals
                conf = base_conf
                if anomaly_score > 0.6:
                    conf = min(conf + 0.10, 1.0)
                if is_known_bad:
                    conf = min(conf + 0.08, 1.0)
                return ClassificationResult(
                    attack_type=atype,
                    confidence_score=round(conf, 3),
                    reasoning=f"Keyword match in event text ({atype})",
                )

        # ------------------------------------------------------------------
        # 3. Behavioral heuristics
        # ------------------------------------------------------------------
        if unique_ports >= 10:
            return ClassificationResult(
                attack_type=AttackType.PORT_SCAN,
                confidence_score=round(min(0.60 + unique_ports / 100, 0.92), 3),
                reasoning=f"High unique port count ({unique_ports}) suggests port scanning",
            )

        if failed_logins >= 5:
            return ClassificationResult(
                attack_type=AttackType.BRUTE_FORCE,
                confidence_score=round(min(0.55 + failed_logins / 50, 0.90), 3),
                reasoning=f"Elevated failed logins ({failed_logins}) indicate brute force",
            )

        if bytes_out > 10 * 1024 * 1024:  # > 10 MB
            return ClassificationResult(
                attack_type=AttackType.DATA_EXFILTRATION,
                confidence_score=round(min(0.55 + bytes_out / (1024 * 1024 * 100), 0.85), 3),
                reasoning=f"Large outbound transfer ({bytes_out // 1024} KB) suggests exfiltration",
            )

        # ------------------------------------------------------------------
        # 4. Anomaly-only fallback
        # ------------------------------------------------------------------
        if anomaly_score > 0.7:
            return ClassificationResult(
                attack_type=AttackType.UNKNOWN,
                confidence_score=round(0.40 + anomaly_score * 0.30, 3),
                reasoning=f"High anomaly score ({anomaly_score:.3f}) without matching pattern",
            )

        if behavior_score > 0.6:
            return ClassificationResult(
                attack_type=AttackType.UNKNOWN,
                confidence_score=round(0.35 + behavior_score * 0.25, 3),
                reasoning=f"Behavioral deviation ({behavior_score:.3f}) exceeds threshold",
            )

        return ClassificationResult(
            attack_type=AttackType.UNKNOWN,
            confidence_score=0.20,
            reasoning="No clear attack pattern identified",
        )


# Singleton
classification_service = ClassificationService()
