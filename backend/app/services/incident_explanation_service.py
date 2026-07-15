"""
LLM-based incident/alert explanation service (defensive only).
Produces structured analyst + executive content. Falls back to realistic
mock explanations when no LLM API is available.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def _severity_playbook(severity: str) -> List[str]:
    s = (severity or "medium").lower()
    if s == "critical":
        return [
            "Activate high-severity incident bridge and assign an incident commander",
            "Contain confirmed malicious hosts/accounts immediately after validation",
            "Block confirmed IOCs at perimeter and endpoint controls",
            "Preserve forensic evidence before remediation",
            "Prepare executive status update within one hour",
        ]
    if s == "high":
        return [
            "Begin focused investigation within one hour",
            "Validate IOCs against threat feeds and historical FP patterns",
            "Contain impacted assets if confidence remains high",
            "Escalate to SOC Manager if scope expands",
            "Document all actions in analyst notes",
        ]
    if s == "medium":
        return [
            "Queue for analyst review within the current shift",
            "Enrich with threat intelligence and MITRE mapping",
            "Confirm business impact of affected assets",
            "Monitor for related detections",
            "Close only after corroboration is complete",
        ]
    return [
        "Monitor and document as informational unless corroborating signals appear",
        "Re-score if additional IOCs or MITRE mappings are found",
        "Suppress only after confirming benign pattern",
    ]


def _context_from_title(title: str) -> Dict[str, str]:
    t = (title or "").lower()
    if "brute" in t or "credential" in t or "login" in t:
        return {
            "pattern": "credential abuse / authentication anomalies",
            "why": "Credential stuffing or brute-force activity can lead to account takeover and lateral movement if successful authentications occur.",
            "impact": "Compromised user accounts, privilege misuse, and potential access to business applications or VPN resources.",
        }
    if "powershell" in t or "script" in t or "execution" in t:
        return {
            "pattern": "suspicious script / command execution",
            "why": "Abnormal script execution is commonly used for discovery, defense evasion, and post-exploitation tooling.",
            "impact": "Endpoint integrity risk, possible privilege escalation, and follow-on payload execution.",
        }
    if "exfil" in t or "outbound" in t or "data" in t:
        return {
            "pattern": "potential data movement / unusual egress",
            "why": "Unexpected outbound transfers may indicate data staging or exfiltration over approved protocols.",
            "impact": "Sensitive data exposure, regulatory risk, and intellectual property loss.",
        }
    if "malware" in t or "hash" in t or "ransomware" in t:
        return {
            "pattern": "malware indicator detection",
            "why": "Hash or family matches suggest known-bad software may be present on an endpoint and should be verified quickly.",
            "impact": "Host compromise, encryption risk, or credential dumping depending on the family.",
        }
    if "beacon" in t or "c2" in t or "domain" in t:
        return {
            "pattern": "possible command-and-control communication",
            "why": "Periodic or rare-domain outbound connections can indicate beaconing to attacker-controlled infrastructure.",
            "impact": "Remote control of hosts, secondary payload delivery, and sustained dwell time.",
        }
    return {
        "pattern": "correlated security anomalies",
        "why": "Combined ML and rule signals suggest activity that warrants structured investigation before containment.",
        "impact": "Service disruption, unauthorized access, or undetected follow-on activity if left uninvestigated.",
    }


class IncidentExplanationService:
    """Defensive incident/alert explanation generator."""

    SYSTEM_PROMPT = (
        "You are a senior SOC analyst assistant. Produce defensive, incident-response focused "
        "explanations only. Cover what happened, why it matters, affected assets, IOCs, MITRE "
        "tactics/techniques, risk, likely impact, containment steps, and an investigation checklist. "
        "Never provide offensive exploitation steps, malware creation guidance, credential theft "
        "instructions, or bypass techniques."
    )

    def generate_mock_explanation(
        self,
        *,
        title: str,
        severity: str = "medium",
        risk_score: float = 50,
        assets: Optional[List[str]] = None,
        iocs: Optional[List[Dict[str, Any]]] = None,
        mitre_mappings: Optional[List[Dict[str, Any]]] = None,
        timeline_summary: str = "",
        entity: str = "alert",
    ) -> Dict[str, Any]:
        assets = assets or ["unknown-host"]
        iocs = iocs or []
        mitre_mappings = mitre_mappings or []
        ctx = _context_from_title(title)

        ioc_lines = (
            "\n".join(f"- {i.get('ioc_type')}: `{i.get('ioc_value')}`" for i in iocs[:12])
            or "- No IOCs extracted yet — run IOC extraction on alert/incident text"
        )
        mitre_lines = (
            "\n".join(
                f"- {m.get('tactic')} / {m.get('technique_id')} — {m.get('technique_name')} "
                f"(confidence {m.get('confidence', 'n/a')})"
                for m in mitre_mappings[:10]
            )
            or "- Pending MITRE ATT&CK mapping"
        )

        what = (
            f"Telemetry and detection logic identified '{title}' as {ctx['pattern']}. "
            f"This {entity} is currently scored {severity.upper()} with composite risk "
            f"{risk_score:.1f}/100 after hybrid severity evaluation (ML anomaly, SIEM rules, "
            f"threat-feed IOC matches, MITRE tactic weight, and asset context)."
        )
        why = ctx["why"] + " Rapid structured triage reduces dwell time and business disruption."
        impact = ctx["impact"]
        containment = _severity_playbook(severity)
        checklist = [
            "Confirm affected users/assets and business criticality",
            "Extract and enrich IOCs against active threat feeds",
            "Map activity to MITRE ATT&CK tactics and techniques",
            "Reconstruct timeline and identify gaps in visibility",
            "Document analyst observations, actions, and escalations",
            "Contain only after validation; preserve evidence",
            "Publish executive report once status is Contained or Resolved",
        ]
        executive = (
            f"SOC investigation for '{title}' is underway. Current assessed risk is "
            f"{severity.upper()} ({risk_score:.0f}/100). Assets in preliminary scope: "
            f"{', '.join(str(a) for a in assets[:5])}. "
            "Recommended leadership posture: support containment of confirmed threats, "
            "review business impact, and track report-ready status from the SOC."
        )
        analyst_recs = [
            "Prefer defensive containment and evidence preservation over destructive remediations until scope is clear",
            "Correlate related alerts into the parent incident before closing individual detections",
            "Use severity re-score after new IOC or MITRE evidence is added",
        ]

        full_text = (
            f"## What Happened\n{what}\n\n"
            f"## Why It Matters\n{why}\n\n"
            f"## Affected Assets\n" + "\n".join(f"- {a}" for a in assets) + "\n\n"
            f"## IOCs\n{ioc_lines}\n\n"
            f"## MITRE ATT&CK\n{mitre_lines}\n\n"
            f"## Risk\n{severity.upper()} ({risk_score:.1f}/100)\n\n"
            f"## Likely Impact\n{impact}\n\n"
            f"## Containment Steps\n" + "\n".join(f"- {c}" for c in containment) + "\n\n"
            f"## Investigation Checklist\n" + "\n".join(f"- {c}" for c in checklist) + "\n\n"
            f"## Executive Summary\n{executive}"
        )

        return {
            "what_happened": what,
            "why_it_matters": why,
            "affected_assets_users": assets,
            "iocs_involved": ioc_lines,
            "mitre_tactics_techniques": mitre_lines,
            "risk_level": severity,
            "risk_score": risk_score,
            "likely_impact": impact,
            "recommended_containment_steps": containment,
            "investigation_checklist": checklist,
            "analyst_recommendations": analyst_recs,
            "executive_summary": executive,
            "timeline_summary": timeline_summary or "Timeline pending reconstruction.",
            "source": "mock_explanation_engine",
            "prompt_profile": "defensive_soc_incident_response",
            "system_prompt_excerpt": self.SYSTEM_PROMPT[:180] + "…",
            "full_text": full_text,
        }

    async def explain_alert(
        self,
        alert: Any,
        iocs: Optional[List[Dict[str, Any]]] = None,
        mitre_mappings: Optional[List[Dict[str, Any]]] = None,
        timeline: Optional[str] = None,
        llm_available: bool = False,
    ) -> Dict[str, Any]:
        base = self.generate_mock_explanation(
            title=getattr(alert, "title", "Security Alert"),
            severity=getattr(getattr(alert, "severity", None), "value", None)
            or str(getattr(alert, "severity", "medium")),
            risk_score=float(getattr(alert, "risk_score", None) or 50),
            assets=[getattr(alert, "source_ip", None) or "unknown-source"],
            iocs=iocs,
            mitre_mappings=mitre_mappings,
            timeline_summary=timeline or "",
            entity="alert",
        )
        if getattr(alert, "llm_explanation", None):
            base["existing_llm_explanation"] = alert.llm_explanation
            base["full_text"] = (
                "## Existing LLM Analysis\n"
                + alert.llm_explanation
                + "\n\n---\n\n"
                + base["full_text"]
            )
        base["llm_available"] = llm_available
        return base

    async def explain_incident(
        self,
        incident: Any,
        alerts: Optional[List[Any]] = None,
        iocs: Optional[List[Dict[str, Any]]] = None,
        mitre_mappings: Optional[List[Dict[str, Any]]] = None,
        timeline: Optional[str] = None,
        llm_available: bool = False,
    ) -> Dict[str, Any]:
        assets: List[str] = []
        if getattr(incident, "source_ip", None):
            assets.append(str(incident.source_ip))
        if getattr(incident, "affected_assets", None):
            assets.append(str(incident.affected_assets)[:200])
        if not assets:
            assets = ["multiple-assets"]

        explanation = self.generate_mock_explanation(
            title=getattr(incident, "title", "Security Incident"),
            severity=getattr(getattr(incident, "severity", None), "value", None) or "medium",
            risk_score=float(getattr(incident, "risk_score", None) or 50),
            assets=assets,
            iocs=iocs,
            mitre_mappings=mitre_mappings,
            timeline_summary=timeline or "",
            entity="incident",
        )
        explanation["related_alert_count"] = len(alerts or [])
        explanation["llm_available"] = llm_available
        if getattr(incident, "llm_summary", None):
            explanation["existing_llm_summary"] = incident.llm_summary
        return explanation

    def generate_executive_summary(self, incident: Any, explanation: Optional[Dict] = None) -> str:
        if explanation and explanation.get("executive_summary"):
            return str(explanation["executive_summary"])
        return (
            f"Incident '{getattr(incident, 'title', 'N/A')}' is currently "
            f"{getattr(getattr(incident, 'status', None), 'value', 'open')} with "
            f"severity {getattr(getattr(incident, 'severity', None), 'value', 'medium')} "
            f"and risk score {getattr(incident, 'risk_score', 0)}. "
            "SOC recommends continued investigation and containment of confirmed indicators."
        )

    def generate_analyst_recommendations(
        self, incident: Any, mitre_mappings: Optional[List] = None
    ) -> List[str]:
        recs = [
            "Document all investigative steps in analyst notes",
            "Re-score severity after IOC enrichment",
            "Align response actions to mapped MITRE techniques",
            "Generate PDF incident report for stakeholders after containment",
        ]
        severity = getattr(getattr(incident, "severity", None), "value", "") or ""
        if severity in ("high", "critical"):
            recs.insert(0, "Escalate to SOC Manager and activate high-severity playbook")
        if mitre_mappings:
            recs.append("Review MITRE recommendations for tactic-specific containment controls")
        return recs


incident_explanation_service = IncidentExplanationService()
