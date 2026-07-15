"""
MITRE ATT&CK mapping service — defensive technique mapping for alerts/incidents.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mitre_mapping import MitreMapping
from app.models.alert import Alert
from app.models.incident import Incident


# Internal mapping database (common defensive detections)
MITRE_RULES: List[Dict[str, Any]] = [
    {
        "patterns": [r"brute.?force", r"failed.?login", r"credential.?stuff", r"password.?spray"],
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "confidence": 90,
        "severity_weight": 80,
    },
    {
        "patterns": [r"powershell", r"pwsh", r"encoded.?command", r"invoke-expression"],
        "tactic": "Execution",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "confidence": 88,
        "severity_weight": 75,
    },
    {
        "patterns": [r"cmd\.exe", r"command.?line", r"wscript", r"cscript"],
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "confidence": 75,
        "severity_weight": 65,
    },
    {
        "patterns": [r"outbound", r"c2", r"beacon", r"command.?and.?control", r"suspicious.?domain"],
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "confidence": 85,
        "severity_weight": 85,
    },
    {
        "patterns": [r"privilege.?escalat", r"uac.?bypass", r"getsystem", r"token.?impersonat"],
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "confidence": 82,
        "severity_weight": 88,
    },
    {
        "patterns": [r"exfil", r"data.?transfer", r"large.?upload", r"unusual.?outbound.?traffic"],
        "tactic": "Exfiltration",
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "confidence": 87,
        "severity_weight": 90,
    },
    {
        "patterns": [r"malware", r"hash.?match", r"trojan", r"ransomware", r"virus"],
        "tactic": "Execution",
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "confidence": 80,
        "severity_weight": 85,
        "extra": {"tactic2": "Defense Evasion", "technique_id2": "T1027", "name2": "Obfuscated Files or Information"},
    },
    {
        "patterns": [r"port.?scan", r"recon", r"nmap", r"network.?scan"],
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "confidence": 78,
        "severity_weight": 55,
    },
    {
        "patterns": [r"lateral.?movement", r"smb", r"psexec", r"remote.?desktop", r"rdp"],
        "tactic": "Lateral Movement",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "confidence": 84,
        "severity_weight": 82,
    },
    {
        "patterns": [r"sql.?injection", r"xss", r"web.?attack", r"path.?traversal"],
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "confidence": 86,
        "severity_weight": 80,
    },
    {
        "patterns": [r"phishing", r"spear.?phish", r"malicious.?email"],
        "tactic": "Initial Access",
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "confidence": 83,
        "severity_weight": 70,
    },
    {
        "patterns": [r"dns.?tunnel", r"dns.?exfil"],
        "tactic": "Exfiltration",
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "confidence": 80,
        "severity_weight": 78,
    },
    {
        "patterns": [r"persist", r"scheduled.?task", r"registry.?run", r"startup.?folder"],
        "tactic": "Persistence",
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "confidence": 77,
        "severity_weight": 72,
    },
    {
        "patterns": [r"anomaly", r"unusual.?traffic", r"behavioral"],
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "confidence": 55,
        "severity_weight": 50,
    },
]

IOC_MITRE_HINTS = {
    "file_hash": ("Execution", "T1204", "User Execution", 70),
    "domain": ("Command and Control", "T1071", "Application Layer Protocol", 65),
    "url": ("Command and Control", "T1071", "Application Layer Protocol", 65),
    "ip": ("Command and Control", "T1071", "Application Layer Protocol", 60),
    "email": ("Initial Access", "T1566", "Phishing", 70),
    "cve": ("Initial Access", "T1190", "Exploit Public-Facing Application", 75),
    "malware_family": ("Execution", "T1204", "User Execution", 80),
}


class MitreMappingService:

    def _text_blob(self, alert_data: Dict[str, Any]) -> str:
        parts = [
            str(alert_data.get("title") or ""),
            str(alert_data.get("description") or ""),
            str(alert_data.get("attack_type") or ""),
            str(alert_data.get("rule_name") or ""),
            str(alert_data.get("alert_type") or ""),
        ]
        return " ".join(parts).lower()

    def map_alert_to_mitre(self, alert_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        blob = self._text_blob(alert_data)
        mappings: List[Dict[str, Any]] = []
        seen = set()

        for rule in MITRE_RULES:
            if any(re.search(p, blob) for p in rule["patterns"]):
                key = rule["technique_id"]
                if key not in seen:
                    seen.add(key)
                    mappings.append({
                        "tactic": rule["tactic"],
                        "technique_id": rule["technique_id"],
                        "technique_name": rule["technique_name"],
                        "confidence": float(rule["confidence"]),
                        "reasoning": f"Matched detection patterns related to {rule['technique_name']}",
                        "severity_weight": rule.get("severity_weight", 50),
                    })
                extra = rule.get("extra")
                if extra and extra["technique_id2"] not in seen:
                    seen.add(extra["technique_id2"])
                    mappings.append({
                        "tactic": extra["tactic2"],
                        "technique_id": extra["technique_id2"],
                        "technique_name": extra["name2"],
                        "confidence": float(rule["confidence"]) - 5,
                        "reasoning": f"Secondary mapping for {rule['technique_name']}",
                        "severity_weight": rule.get("severity_weight", 50) - 5,
                    })

        if not mappings:
            mappings.append({
                "tactic": "Discovery",
                "technique_id": "T1082",
                "technique_name": "System Information Discovery",
                "confidence": 40.0,
                "reasoning": "Default low-confidence mapping for unclassified alert",
                "severity_weight": 35,
            })
        return mappings

    def map_iocs_to_mitre(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        mappings = []
        seen = set()
        for ioc in iocs:
            itype = ioc.get("ioc_type") or "unknown"
            hint = IOC_MITRE_HINTS.get(itype)
            if not hint:
                continue
            tactic, tid, tname, conf = hint
            if tid in seen:
                continue
            seen.add(tid)
            mappings.append({
                "tactic": tactic,
                "technique_id": tid,
                "technique_name": tname,
                "confidence": float(conf),
                "reasoning": f"IOC type '{itype}' commonly associated with {tname}",
            })
        return mappings

    async def persist_mappings(
        self,
        db: AsyncSession,
        mappings: List[Dict[str, Any]],
        alert_id: Optional[int] = None,
        incident_id: Optional[int] = None,
    ) -> List[MitreMapping]:
        rows = []
        for m in mappings:
            row = MitreMapping(
                alert_id=alert_id,
                incident_id=incident_id,
                tactic=m["tactic"],
                technique_id=m["technique_id"],
                technique_name=m["technique_name"],
                confidence=m.get("confidence", 70),
                reasoning=m.get("reasoning"),
            )
            db.add(row)
            rows.append(row)
        await db.flush()
        return rows

    async def get_mitre_tactics_summary(
        self, db: AsyncSession, incident_id: int
    ) -> Dict[str, Any]:
        result = await db.execute(
            select(MitreMapping).where(MitreMapping.incident_id == incident_id)
        )
        rows = result.scalars().all()
        tactics: Dict[str, int] = {}
        techniques = []
        for r in rows:
            tactics[r.tactic] = tactics.get(r.tactic, 0) + 1
            techniques.append({
                "id": r.id,
                "tactic": r.tactic,
                "technique_id": r.technique_id,
                "technique_name": r.technique_name,
                "confidence": r.confidence,
                "reasoning": r.reasoning,
            })
        return {
            "incident_id": incident_id,
            "tactic_distribution": tactics,
            "techniques": techniques,
            "total_mappings": len(rows),
        }

    def generate_mitre_recommendations(self, mitre_mappings: List[Dict[str, Any]]) -> List[str]:
        recs = []
        tactics = {m.get("tactic") for m in mitre_mappings}
        if "Credential Access" in tactics:
            recs.append("Enforce MFA, reset impacted credentials, and review failed login telemetry.")
        if "Execution" in tactics:
            recs.append("Isolate affected endpoints and review script/command execution logs.")
        if "Command and Control" in tactics:
            recs.append("Block suspicious domains/IPs at the perimeter and hunt for related beacons.")
        if "Exfiltration" in tactics:
            recs.append("Review outbound data transfers and tighten DLP / egress controls.")
        if "Privilege Escalation" in tactics:
            recs.append("Audit privileged accounts and revoke unnecessary elevation rights.")
        if "Lateral Movement" in tactics:
            recs.append("Segment networks and review remote service authentication events.")
        if not recs:
            recs.append("Continue monitoring and enrich with additional telemetry before containment.")
        return recs


mitre_mapping_service = MitreMappingService()
