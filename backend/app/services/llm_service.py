"""
Advanced LLM Service: MITRE ATT&CK kill-chain analysis via Ollama (gemma3:12b).
Produces structured threat intelligence with confidence scoring, kill-chain
phase mapping, and actionable remediation steps.
"""
import httpx
import json
import logging
from typing import Dict, Any, List, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Advanced prompt — instructs the model to reason through the full kill chain
# ---------------------------------------------------------------------------
ADVANCED_THREAT_PROMPT = """You are a Tier-3 SOC analyst and threat intelligence specialist.
Perform a complete kill-chain analysis of the following security event.

=== SECURITY EVENT ===
{context}

=== BEHAVIORAL CONTEXT (last 60 min from same IP) ===
{behavior}

=== RELATED RECENT ALERTS ===
{related_alerts}

Respond with ONLY valid JSON matching this exact schema — no markdown, no extra text:
{{
  "threat_summary": "One-sentence executive summary of the threat",
  "explanation": "2-4 sentences explaining what the anomaly indicates, how it works, and why it is dangerous",
  "attack_type": "Primary attack category (e.g. Brute Force, SQL Injection, C2 Beaconing, Data Exfiltration, Lateral Movement, RCE, DDoS, Credential Stuffing, DNS Tunneling, Web Exploit)",
  "kill_chain_phase": "Reconnaissance | Weaponization | Delivery | Exploitation | Installation | C2 | Actions on Objectives",
  "mitre_ttps": ["T1xxx — Technique Name", "..."],
  "threat_actor_profile": "APT group, script kiddie, insider threat, or automated scanner — based on the behavioral pattern",
  "confidence": "Critical | High | Medium | Low",
  "risk_score": 0,
  "indicators_of_compromise": ["IOC description 1", "..."],
  "mitigation_steps": [
    "Immediate: specific action to take right now",
    "Short-term: action to take within 24h",
    "Long-term: hardening or architectural recommendation"
  ],
  "investigation_queries": [
    "SQL/log query or command to investigate further",
    "..."
  ],
  "false_positive_likelihood": "High | Medium | Low",
  "references": ["CVE-XXXX-XXXXX or threat intelligence reference"]
}}

Risk score must be an integer 0-100 (100 = critical confirmed breach).
TTPs must use real MITRE ATT&CK IDs."""


class LLMService:
    """
    Advanced threat analysis service using Ollama (gemma3:12b).
    Includes MITRE ATT&CK kill chain mapping, behavioral context,
    and structured risk scoring.
    """

    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL
        self.model    = settings.OLLAMA_MODEL
        self.timeout  = settings.OLLAMA_TIMEOUT

    async def _call_ollama(self, prompt: str) -> Optional[str]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model":  self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.05,   # near-deterministic for security analysis
                        "top_p":       0.9,
                        "num_predict": 2048,
                    },
                },
            )
            resp.raise_for_status()
            return resp.json().get("response", "")

    async def analyze_threat(
        self,
        anomaly_data:   Dict[str, Any],
        log_data:       Optional[Dict[str, Any]] = None,
        behavior_data:  Optional[Dict[str, Any]] = None,
        related_alerts: Optional[List[str]]      = None,
    ) -> Dict[str, Any]:
        """
        Generate a full MITRE ATT&CK kill-chain threat analysis.
        Falls back to a rich rule-based analysis when Ollama is unavailable.
        """
        # Build event context
        ctx: List[str] = []
        if log_data:
            for label, key in [
                ("Source IP",        "source_ip"),
                ("Destination IP",   "destination_ip"),
                ("Destination Port", "destination_port"),
                ("Source Port",      "source_port"),
                ("Protocol",         "protocol"),
                ("Event Type",       "event_type"),
                ("Severity",         "severity"),
                ("Username",         "username"),
                ("Bytes Sent",       "bytes_sent"),
                ("Bytes Received",   "bytes_received"),
                ("Duration (ms)",    "duration_ms"),
            ]:
                val = log_data.get(key)
                if val is not None and val != "":
                    ctx.append(f"{label}: {val}")
            if log_data.get("message"):
                ctx.append(f"Log Message: {log_data['message'][:500]}")

        score = anomaly_data.get("anomaly_score", 0)
        ctx.append(f"ML Anomaly Score: {score:.3f} (threshold: 0.6)")
        if anomaly_data.get("rule_name"):
            ctx.append(f"Triggered Rule: {anomaly_data['rule_name']}")
        if anomaly_data.get("description"):
            ctx.append(f"Alert Description: {anomaly_data['description'][:300]}")
        if anomaly_data.get("context"):
            for k, v in anomaly_data["context"].items():
                if k != "mitre_ttps":
                    ctx.append(f"{k.replace('_', ' ').title()}: {v}")
            ttps = anomaly_data["context"].get("mitre_ttps", [])
            if ttps:
                ctx.append(f"Detected MITRE TTPs: {', '.join(ttps)}")

        # Build behavioral context
        if behavior_data:
            beh_lines = [
                f"  - Requests/min: {behavior_data.get('requests_per_minute', 0)}",
                f"  - Failed logins: {behavior_data.get('failed_logins', 0)}",
                f"  - Unique ports scanned: {behavior_data.get('unique_ports_count', 0)}",
                f"  - Unique destinations: {behavior_data.get('unique_destinations', 0)}",
                f"  - Total data transferred: {behavior_data.get('total_bytes_mb', 0)} MB",
                f"  - Critical events: {behavior_data.get('critical_events', 0)}",
                f"  - Unique usernames tried: {behavior_data.get('unique_usernames', 0)}",
            ]
            beh_str = "\n".join(beh_lines)
        else:
            beh_str = "No behavioral history available for this IP."

        alerts_str = (
            "\n".join(f"  - {a}" for a in (related_alerts or []))
            or "No related alerts in the last hour."
        )

        prompt = ADVANCED_THREAT_PROMPT.format(
            context="\n".join(ctx),
            behavior=beh_str,
            related_alerts=alerts_str,
        )

        try:
            raw = await self._call_ollama(prompt)
            if raw:
                start = raw.find("{")
                end   = raw.rfind("}") + 1
                if start >= 0 and end > start:
                    parsed = json.loads(raw[start:end])
                    return {
                        "explanation":             parsed.get("explanation", "LLM analysis completed"),
                        "threat_summary":          parsed.get("threat_summary", ""),
                        "attack_type":             parsed.get("attack_type", "Unknown"),
                        "kill_chain_phase":        parsed.get("kill_chain_phase", "Unknown"),
                        "mitre_ttps":              parsed.get("mitre_ttps", []),
                        "threat_actor_profile":    parsed.get("threat_actor_profile", ""),
                        "confidence":              parsed.get("confidence", "Low"),
                        "risk_score":              int(parsed.get("risk_score", 0)),
                        "indicators_of_compromise":parsed.get("indicators_of_compromise", []),
                        "mitigation_steps":        parsed.get("mitigation_steps", []),
                        "investigation_queries":   parsed.get("investigation_queries", []),
                        "false_positive_likelihood":parsed.get("false_positive_likelihood", "Medium"),
                        "references":              parsed.get("references", []),
                        "source":                  "ollama",
                        "model":                   self.model,
                    }

        except httpx.ConnectError:
            logger.warning("Ollama unavailable; using advanced fallback analysis")
        except httpx.TimeoutException:
            logger.warning("Ollama timed out; using advanced fallback analysis")
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"LLM response parse error: {e}")
        except Exception as e:
            logger.error(f"LLM unexpected error: {e}")

        return self._advanced_fallback(anomaly_data, log_data, behavior_data)

    # ------------------------------------------------------------------
    # Rich rule-based fallback (used when Ollama is down)
    # ------------------------------------------------------------------

    _RULE_INTEL: Dict[str, Dict[str, Any]] = {
        "brute_force_login": {
            "attack_type":      "Brute Force Authentication Attack",
            "kill_chain_phase": "Exploitation",
            "mitre_ttps":       ["T1110.001 — Password Guessing", "T1110.003 — Password Spraying"],
            "confidence":       "High",
            "risk_score":       72,
            "explanation": (
                "Multiple failed authentication attempts from a single source IP indicate an "
                "automated brute-force or password-spraying attack targeting user accounts. "
                "The attacker is systematically testing credentials to gain unauthorized access. "
                "Successful authentication would give the attacker a foothold in the environment."
            ),
            "mitigation_steps": [
                "Immediate: Block source IP at the perimeter firewall",
                "Short-term: Enable account lockout after 5 failed attempts and alert on lockouts",
                "Long-term: Deploy MFA on all authentication endpoints and implement adaptive authentication",
            ],
            "investigation_queries": [
                "SELECT * FROM log_entries WHERE source_ip='<IP>' AND event_type LIKE '%fail%' ORDER BY timestamp DESC LIMIT 100",
                "Check if any accounts were successfully authenticated after the failed attempts",
            ],
        },
        "port_scan": {
            "attack_type":      "Network Reconnaissance / Port Scanning",
            "kill_chain_phase": "Reconnaissance",
            "mitre_ttps":       ["T1046 — Network Service Discovery"],
            "confidence":       "High",
            "risk_score":       55,
            "explanation": (
                "Systematic connection attempts across multiple ports from a single IP indicate "
                "network reconnaissance — a precursor to targeted exploitation. "
                "The attacker is mapping open services to identify vulnerable targets. "
                "This is often followed by exploitation attempts against discovered services."
            ),
            "mitigation_steps": [
                "Immediate: Block source IP at perimeter and enable IDS scan detection",
                "Short-term: Review firewall rules to minimize exposed attack surface",
                "Long-term: Implement network segmentation and deploy a honeypot",
            ],
            "investigation_queries": [
                "SELECT destination_port, COUNT(*) as c FROM log_entries WHERE source_ip='<IP>' GROUP BY destination_port ORDER BY c DESC",
                "Check for subsequent exploitation attempts from this IP",
            ],
        },
        "sql_injection": {
            "attack_type":      "SQL Injection",
            "kill_chain_phase": "Exploitation",
            "mitre_ttps":       ["T1190 — Exploit Public-Facing Application", "T1059.007 — JavaScript/SQLi"],
            "confidence":       "High",
            "risk_score":       88,
            "explanation": (
                "SQL injection patterns detected in the request indicate an attempt to manipulate "
                "backend database queries. If successful, the attacker could extract sensitive data, "
                "bypass authentication, or execute OS commands via the database. "
                "This is one of the most critical web application vulnerabilities (OWASP Top 10)."
            ),
            "mitigation_steps": [
                "Immediate: Block source IP and review WAF rules for SQL injection patterns",
                "Short-term: Audit all database queries for parameterization; enable WAF SQL injection ruleset",
                "Long-term: Implement parameterized queries / ORM throughout the codebase and run DAST scans",
            ],
            "investigation_queries": [
                "Check web application logs for successful SQL injection responses (unusual data in responses)",
                "Review database audit logs for anomalous SELECT/UNION/DROP operations",
            ],
        },
        "c2_beacon": {
            "attack_type":      "Command and Control Beaconing",
            "kill_chain_phase": "C2",
            "mitre_ttps":       ["T1071.001 — Web Protocols C2", "T1571 — Non-Standard Port"],
            "confidence":       "High",
            "risk_score":       85,
            "explanation": (
                "High-frequency regular connections from a single IP to the same destination "
                "suggest a compromised host beacon communicating with a C2 server. "
                "C2 beaconing allows an attacker to maintain persistent access and issue commands. "
                "The regular interval pattern is characteristic of automated malware check-ins."
            ),
            "mitigation_steps": [
                "Immediate: Isolate the source host from the network immediately",
                "Short-term: Run endpoint forensics; capture network traffic for C2 protocol analysis",
                "Long-term: Deploy DNS/HTTP proxy with threat intel filtering and behavioral analysis",
            ],
            "investigation_queries": [
                "Analyze beacon interval regularity: SELECT timestamp FROM log_entries WHERE source_ip='<IP>' ORDER BY timestamp",
                "Check if destination IP is in threat intelligence feeds",
            ],
        },
        "rce_attempt": {
            "attack_type":      "Remote Code Execution Attempt",
            "kill_chain_phase": "Exploitation",
            "mitre_ttps":       ["T1059 — Command and Scripting Interpreter", "T1203 — Exploitation for Client Execution"],
            "confidence":       "Critical",
            "risk_score":       95,
            "explanation": (
                "Remote code execution patterns detected indicate an active exploitation attempt. "
                "If successful, the attacker gains the ability to execute arbitrary code on the server, "
                "leading to full system compromise, data theft, ransomware deployment, or persistent backdoors. "
                "This is the highest severity web application threat."
            ),
            "mitigation_steps": [
                "Immediate: Block source IP and take affected system offline for forensic analysis",
                "Short-term: Review all processes spawned by the web server; check for new accounts or scheduled tasks",
                "Long-term: Deploy application-layer WAF, harden server configurations, implement least-privilege execution",
            ],
            "investigation_queries": [
                "Check web server process tree for unexpected child processes",
                "Review /var/log/auth.log and web server error logs for successful exploit indicators",
            ],
        },
        "data_exfiltration": {
            "attack_type":      "Data Exfiltration",
            "kill_chain_phase": "Actions on Objectives",
            "mitre_ttps":       ["T1041 — Exfiltration Over C2 Channel", "T1048 — Exfiltration Over Alt Protocol"],
            "confidence":       "High",
            "risk_score":       82,
            "explanation": (
                "Abnormally large outbound data transfer detected from an internal host. "
                "This pattern is consistent with data exfiltration — a threat actor or malicious insider "
                "copying sensitive data to an external location. "
                "Immediate containment is required to prevent further data loss."
            ),
            "mitigation_steps": [
                "Immediate: Block outbound connections from source host; preserve network captures as evidence",
                "Short-term: Identify what data was transferred; notify data protection officer if PII involved",
                "Long-term: Implement DLP solution and egress filtering with data classification",
            ],
            "investigation_queries": [
                "SELECT * FROM log_entries WHERE source_ip='<IP>' AND bytes_sent > 1000000 ORDER BY timestamp DESC",
                "Identify destination IP geolocation and threat intelligence classification",
            ],
        },
    }

    def _advanced_fallback(
        self,
        anomaly_data:  Dict[str, Any],
        log_data:      Optional[Dict[str, Any]],
        behavior_data: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        rule = anomaly_data.get("rule_name", "")
        score = float(anomaly_data.get("anomaly_score") or 0)
        intel = self._RULE_INTEL.get(rule, {})

        # Dynamic risk score: boost by anomaly score and behavioral severity
        base_risk = intel.get("risk_score", 40)
        if behavior_data:
            if behavior_data.get("failed_logins", 0) > 20:
                base_risk = min(base_risk + 10, 100)
            if behavior_data.get("unique_ports_count", 0) > 50:
                base_risk = min(base_risk + 10, 100)
            if behavior_data.get("total_bytes_mb", 0) > 100:
                base_risk = min(base_risk + 15, 100)
        base_risk = min(base_risk + int(score * 20), 100)

        src_ip = (log_data or {}).get("source_ip", "unknown")

        return {
            "explanation":             intel.get("explanation",
                f"Anomalous behavior detected (ML score: {score:.3f}) from {src_ip}. "
                "Behavioral pattern warrants immediate investigation by the security team."),
            "threat_summary":          f"{intel.get('attack_type', 'Suspicious Activity')} from {src_ip}",
            "attack_type":             intel.get("attack_type", "Suspicious Activity"),
            "kill_chain_phase":        intel.get("kill_chain_phase", "Unknown"),
            "mitre_ttps":              intel.get("mitre_ttps", []),
            "threat_actor_profile":    "Automated scanner or opportunistic attacker",
            "confidence":              intel.get("confidence", "High" if score > 0.8 else "Medium" if score > 0.6 else "Low"),
            "risk_score":              base_risk,
            "indicators_of_compromise":[f"Source IP: {src_ip}", f"Anomaly score: {score:.3f}"],
            "mitigation_steps":        intel.get("mitigation_steps", [
                "Immediate: Investigate source IP and recent activity in all logs",
                "Short-term: Review related log entries and check for lateral movement",
                "Long-term: Consider blocking this IP range and escalating to the security team",
            ]),
            "investigation_queries":   intel.get("investigation_queries", [
                f"SELECT * FROM log_entries WHERE source_ip='{src_ip}' ORDER BY timestamp DESC LIMIT 100",
            ]),
            "false_positive_likelihood": "Low" if score > 0.8 else "Medium",
            "references":              [],
            "source":                  "fallback",
            "model":                   "rule-based",
        }

    async def check_availability(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(f"{self.base_url}/api/tags")
                if r.status_code == 200:
                    models = [m["name"] for m in r.json().get("models", [])]
                    if self.model in models:
                        return True
                    logger.warning(f"Model '{self.model}' not found in Ollama. Available: {models}")
                    return False
                return False
        except Exception:
            return False


llm_service = LLMService()
