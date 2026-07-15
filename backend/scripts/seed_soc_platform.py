"""
Seed realistic SOC Platform 2.0 demo data.
Usage (from backend/):
  python -m app.scripts.seed_soc_platform
or:
  python scripts/seed_soc_platform.py
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Allow running as standalone script
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from sqlalchemy import select, func

from app.core.database import AsyncSessionLocal, create_tables
from app.core.security import hash_password
from app.models.user import User, UserRole
from app.models.alert import Alert, AlertSeverity, AlertStatus, AlertType
from app.models.incident import Incident, IncidentStatus, IncidentSeverity
from app.models.threat_feed import ThreatFeedItem, IOCType, ThreatFeedSeverity
from app.models.extracted_ioc import ExtractedIOC
from app.models.mitre_mapping import MitreMapping
from app.models.analyst_note import AnalystNote, NoteType
from app.models.incident_timeline import IncidentTimelineEvent
from app.models.incident_report import IncidentReport
from app.models.platform_settings import PlatformSettings


NOW = datetime.now(timezone.utc)

INCIDENT_TEMPLATES = [
    ("Suspicious login brute force activity", "multiple failed logins from unknown IPs targeting VPN gateway", IncidentSeverity.HIGH, 82),
    ("Malware hash detected in endpoint telemetry", "SHA256 matched known Emotet loader on finance workstation", IncidentSeverity.CRITICAL, 94),
    ("Unusual outbound traffic to suspicious domain", "beaconing every 60s to malware-c2.evil.example", IncidentSeverity.HIGH, 88),
    ("Data exfiltration pattern detected", "large encrypted uploads to rare ASN during off-hours", IncidentSeverity.CRITICAL, 96),
    ("Repeated failed login attempts from unknown IP", "credential stuffing against O365 SSO portal", IncidentSeverity.MEDIUM, 68),
    ("Suspicious PowerShell execution alert", "encoded PowerShell with Invoke-Expression on jump host", IncidentSeverity.HIGH, 85),
    ("Payment system API traffic anomaly", "ML anomaly on payment API rate and destination mix", IncidentSeverity.HIGH, 79),
    ("Credential stuffing attempt", "distributed auth failures across user corpus", IncidentSeverity.MEDIUM, 72),
    ("DNS tunneling suspicion", "long subdomain queries to rare TLD", IncidentSeverity.HIGH, 81),
    ("Lateral movement via SMB", "admin share access from unexpected subnet", IncidentSeverity.CRITICAL, 91),
]

ALERT_TITLES = [
    "Brute force login detected",
    "Suspicious PowerShell command",
    "Unusual outbound connection",
    "Privilege escalation signal",
    "Data exfiltration pattern",
    "Malware hash match",
    "Suspicious domain beaconing",
    "Port scan detected",
    "SQL injection attempt",
    "Credential stuffing attempt",
    "DNS tunneling indicator",
    "Lateral movement SMB",
    "Geo-anomaly login",
    "C2 beacon pattern",
    "Ransomware note artifact",
]

IOC_SAMPLES = [
    (IOCType.IP, "185.220.101.45", "tor_exit", ThreatFeedSeverity.HIGH),
    (IOCType.IP, "45.33.32.156", "scanner", ThreatFeedSeverity.MEDIUM),
    (IOCType.IP, "91.219.237.188", "c2", ThreatFeedSeverity.CRITICAL),
    (IOCType.DOMAIN, "malware-c2.evil.example", "c2", ThreatFeedSeverity.CRITICAL),
    (IOCType.DOMAIN, "update-cdn.phish.example", "phishing", ThreatFeedSeverity.HIGH),
    (IOCType.URL, "http://phish.example/login", "phishing", ThreatFeedSeverity.HIGH),
    (IOCType.FILE_HASH, "44d88612fea8a8f36de82e1278abb02f", "malware", ThreatFeedSeverity.HIGH),
    (IOCType.FILE_HASH, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sample", ThreatFeedSeverity.MEDIUM),
    (IOCType.EMAIL, "attacker@evil.example", "phishing", ThreatFeedSeverity.MEDIUM),
    (IOCType.CVE, "CVE-2024-21762", "vuln", ThreatFeedSeverity.CRITICAL),
    (IOCType.MALWARE_FAMILY, "lockbit", "ransomware", ThreatFeedSeverity.CRITICAL),
    (IOCType.THREAT_ACTOR, "apt29", "apt", ThreatFeedSeverity.HIGH),
]

MITRE_SAMPLES = [
    ("Credential Access", "T1110", "Brute Force", 90),
    ("Execution", "T1059.001", "PowerShell", 88),
    ("Command and Control", "T1071", "Application Layer Protocol", 85),
    ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", 82),
    ("Exfiltration", "T1041", "Exfiltration Over C2 Channel", 87),
    ("Discovery", "T1046", "Network Service Discovery", 78),
    ("Lateral Movement", "T1021", "Remote Services", 84),
    ("Initial Access", "T1190", "Exploit Public-Facing Application", 86),
]


async def seed():
    await create_tables()
    async with AsyncSessionLocal() as db:
        existing_feeds = (await db.execute(select(func.count(ThreatFeedItem.id)))).scalar() or 0
        force = os.environ.get("FORCE_SEED", "").lower() in ("1", "true", "yes")
        if existing_feeds >= 50 and not force:
            print("Seed data already present — skipping (threat feeds >= 50). Set FORCE_SEED=1 to force.")
            return

        # Users
        users_spec = [
            ("admin", "admin@soc.local", "Admin User", UserRole.ADMIN, "Admin1234!"),
            ("analyst1", "analyst1@soc.local", "Alex Rivera", UserRole.SOC_ANALYST, "Analyst123!"),
            ("analyst2", "analyst2@soc.local", "Sam Chen", UserRole.SOC_ANALYST, "Analyst123!"),
            ("manager1", "manager@soc.local", "Jordan Lee", UserRole.SOC_MANAGER, "Manager123!"),
            ("intel1", "intel@soc.local", "Taylor Kim", UserRole.THREAT_INTEL_ANALYST, "Intel123!"),
            ("exec1", "exec@soc.local", "Morgan Blake", UserRole.EXECUTIVE_VIEWER, "Exec123!"),
        ]
        for username, email, full_name, role, password in users_spec:
            exists = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
            if not exists:
                db.add(User(
                    username=username,
                    email=email,
                    full_name=full_name,
                    role=role,
                    hashed_password=hash_password(password),
                    is_active=True,
                ))
        await db.flush()
        print("Users seeded")

        # Settings
        if not (await db.execute(select(PlatformSettings).limit(1))).scalar_one_or_none():
            db.add(PlatformSettings(
                organization_name="CyberGuard SOC",
                default_role="soc_analyst",
                ai_provider="ollama",
                threat_feed_refresh_interval=30,
                severity_threshold=40,
            ))

        # Threat feeds (~100)
        for i in range(100):
            base = IOC_SAMPLES[i % len(IOC_SAMPLES)]
            itype, value, category, sev = base
            suffix = f"-{i}" if i >= len(IOC_SAMPLES) and itype in (IOCType.IP, IOCType.DOMAIN) else ""
            v = value
            if itype == IOCType.IP and i >= len(IOC_SAMPLES):
                v = f"203.0.{i % 255}.{(i * 7) % 255}"
            elif itype == IOCType.DOMAIN and i >= len(IOC_SAMPLES):
                v = f"ioc{i}.threatlab.example"
            db.add(ThreatFeedItem(
                ioc_value=v + (suffix if itype not in (IOCType.IP, IOCType.DOMAIN) and i >= len(IOC_SAMPLES) else ""),
                ioc_type=itype,
                source=random.choice(["mock_external_feed", "manual", "csv_import", "json_import", "osint_lab"]),
                confidence_score=round(random.uniform(55, 98), 1),
                threat_category=category,
                first_seen=NOW - timedelta(days=random.randint(1, 40)),
                last_seen=NOW - timedelta(hours=random.randint(1, 72)),
                tags=json.dumps(random.sample(["c2", "malware", "phishing", "apt", "ransomware", "scanner"], k=2)),
                description=f"Seed IOC {i}: {category}",
                severity=sev,
                is_active=random.random() > 0.08,
            ))
        await db.flush()
        print("Threat feeds seeded")

        # Incidents (10)
        incidents = []
        for idx, (title, desc, sev, risk) in enumerate(INCIDENT_TEMPLATES):
            status = [
                IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED,
                IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING,
                IncidentStatus.OPEN, IncidentStatus.CONTAINED, IncidentStatus.INVESTIGATING,
                IncidentStatus.OPEN, IncidentStatus.FALSE_POSITIVE,
            ][idx]
            inc = Incident(
                title=title,
                description=desc,
                severity=sev,
                status=status,
                risk_score=float(risk),
                alert_count=0,
                source_ip=f"185.220.101.{10 + idx}",
                attack_types=json.dumps(["credential_access", "execution", "c2"][idx % 3:]),
                assigned_to=random.choice(["analyst1", "analyst2", "manager1"]),
                affected_assets=json.dumps([f"host-{idx}.corp.local", f"svc-{idx}"]),
                related_iocs=json.dumps([IOC_SAMPLES[idx % len(IOC_SAMPLES)][1]]),
                business_impact=random.choice(["Low", "Medium", "High", "Critical"]),
                first_seen=NOW - timedelta(days=idx + 1, hours=3),
                last_seen=NOW - timedelta(hours=idx),
                llm_summary=f"Automated summary for {title}",
            )
            db.add(inc)
            incidents.append(inc)
        await db.flush()
        print("Incidents seeded")

        # Alerts (50)
        alerts = []
        for i in range(50):
            sev = random.choice(list(AlertSeverity))
            risk = {"low": random.uniform(10, 39), "medium": random.uniform(40, 69),
                    "high": random.uniform(70, 89), "critical": random.uniform(90, 100)}[sev.value]
            inc = incidents[i % len(incidents)]
            alert = Alert(
                title=ALERT_TITLES[i % len(ALERT_TITLES)],
                description=f"Seeded alert {i}: correlated activity around {inc.title}",
                severity=sev,
                alert_type=random.choice(list(AlertType)),
                status=random.choice([AlertStatus.OPEN, AlertStatus.INVESTIGATING, AlertStatus.RESOLVED]),
                source_ip=f"203.0.113.{(i % 200) + 1}",
                rule_name=random.choice(["brute_force", "powershell", "c2_beacon", "data_exfil", "port_scan", None]),
                anomaly_score=round(random.uniform(0.4, 0.99), 3),
                risk_score=round(risk, 1),
                incident_id=inc.id,
                attack_type=random.choice(["brute_force", "malware", "exfil", "c2", "recon"]),
                severity_reason=f"Hybrid score {risk:.1f} from ML + SIEM + TI",
                recommended_action="Investigate and contain if confirmed",
                scoring_factors=json.dumps({"ml_anomaly": 12, "siem_rule": 14, "threat_feed_ioc": 10, "total": round(risk, 1)}),
                triggered_at=NOW - timedelta(hours=random.randint(1, 200)),
            )
            db.add(alert)
            alerts.append(alert)
            inc.alert_count = (inc.alert_count or 0) + 1
        await db.flush()
        print("Alerts seeded")

        # Extracted IOCs (40)
        for i in range(40):
            itype, value, _, _ = IOC_SAMPLES[i % len(IOC_SAMPLES)]
            db.add(ExtractedIOC(
                ioc_value=value if i < len(IOC_SAMPLES) else f"{value}-{i}",
                ioc_type=itype.value,
                source_text=f"Extracted from seeded alert context #{i}",
                source_context=random.choice(["alert", "incident", "manual"]),
                alert_id=alerts[i % len(alerts)].id,
                incident_id=incidents[i % len(incidents)].id,
                feed_match=i % 3 != 0,
                confidence=round(random.uniform(60, 95), 1),
            ))
        await db.flush()

        # MITRE mappings (30)
        for i in range(30):
            tactic, tid, tname, conf = MITRE_SAMPLES[i % len(MITRE_SAMPLES)]
            db.add(MitreMapping(
                alert_id=alerts[i % len(alerts)].id,
                incident_id=incidents[i % len(incidents)].id,
                tactic=tactic,
                technique_id=tid,
                technique_name=tname,
                confidence=float(conf - (i % 5)),
                reasoning=f"Seed mapping for {tname}",
            ))
        await db.flush()

        # Analyst notes (15)
        for i in range(15):
            db.add(AnalystNote(
                alert_id=alerts[i % len(alerts)].id if i % 2 == 0 else None,
                incident_id=incidents[i % len(incidents)].id,
                analyst_name=random.choice(["Alex Rivera", "Sam Chen", "Jordan Lee"]),
                note_text=f"Seed note {i}: reviewed telemetry and correlated with threat feeds.",
                note_type=random.choice(list(NoteType)),
            ))
        await db.flush()

        # Timeline events (100)
        event_types = [
            "first_suspicious_event", "ioc_match", "alert_generated", "mitre_mapping",
            "analyst_note", "severity_updated", "status_changed", "report_generated",
        ]
        for i in range(100):
            inc = incidents[i % len(incidents)]
            et = event_types[i % len(event_types)]
            db.add(IncidentTimelineEvent(
                incident_id=inc.id,
                event_type=et,
                title=f"{et.replace('_', ' ').title()} #{i}",
                description=f"Seeded timeline event {i} for incident {inc.id}",
                timestamp=NOW - timedelta(hours=100 - i),
                source=random.choice(["system", "alert_engine", "analyst", "mitre_engine", "report_service"]),
                severity=random.choice(["low", "medium", "high", "critical"]),
                related_alert_id=alerts[i % len(alerts)].id if i % 2 == 0 else None,
            ))
        await db.flush()

        # Reports (8) with executive-ready content
        for i in range(8):
            inc = incidents[i]
            payload = {
                "incident_id": inc.id,
                "incident_title": inc.title,
                "severity": inc.severity.value,
                "risk_score": inc.risk_score,
                "status": inc.status.value,
                "executive_summary": (
                    f"SOC investigation for '{inc.title}' is underway with assessed risk "
                    f"{inc.severity.value.upper()} ({inc.risk_score:.0f}/100). "
                    "Leadership posture: support containment of confirmed threats and track report status."
                ),
                "technical_summary": inc.description or inc.title,
                "likely_impact": inc.business_impact or "Potential unauthorized access or service disruption.",
                "recommended_actions": [
                    "Validate IOCs against threat feeds",
                    "Contain confirmed malicious activity",
                    "Document analyst notes and escalate if scope expands",
                ],
                "timeline_summary": f"Seeded timeline spanning correlated detections for incident {inc.id}.",
                "iocs": [{"ioc_type": IOC_SAMPLES[i % len(IOC_SAMPLES)][0].value, "ioc_value": IOC_SAMPLES[i % len(IOC_SAMPLES)][1], "feed_match": True}],
                "mitre_mappings": [
                    {"tactic": MITRE_SAMPLES[i % len(MITRE_SAMPLES)][0], "technique_id": MITRE_SAMPLES[i % len(MITRE_SAMPLES)][1], "technique_name": MITRE_SAMPLES[i % len(MITRE_SAMPLES)][2], "confidence": MITRE_SAMPLES[i % len(MITRE_SAMPLES)][3]}
                ],
                "generated_date": NOW.isoformat(),
                "generated_by": "seed_script",
            }
            db.add(IncidentReport(
                incident_id=inc.id,
                title=inc.title,
                severity=inc.severity.value,
                risk_score=inc.risk_score,
                report_json=json.dumps(payload),
                generated_by="seed_script",
            ))

        await db.commit()
        print("SOC Platform 2.0 seed complete.")
        print("Demo logins: admin/Admin1234! | analyst1/Analyst123! | manager1/Manager123!")


if __name__ == "__main__":
    asyncio.run(seed())
