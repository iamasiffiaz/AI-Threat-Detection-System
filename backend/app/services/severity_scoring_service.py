"""
Advanced hybrid alert severity scoring for SOC Platform 2.0.

Severity bands:
  Low: 1–39 | Medium: 40–69 | High: 70–89 | Critical: 90–100
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

from app.models.alert import AlertSeverity


TACTIC_SEVERITY = {
    "Initial Access": 70,
    "Execution": 75,
    "Persistence": 72,
    "Privilege Escalation": 88,
    "Defense Evasion": 70,
    "Credential Access": 82,
    "Discovery": 45,
    "Lateral Movement": 85,
    "Collection": 70,
    "Command and Control": 86,
    "Exfiltration": 92,
    "Impact": 95,
}


@dataclass
class SeverityResult:
    risk_score: float
    severity: str
    severity_reason: str
    recommended_action: str
    scoring_factors: Dict[str, Any]


class SeverityScoringService:

    def classify_severity(self, score: float) -> str:
        s = max(1.0, min(100.0, float(score)))
        if s >= 90:
            return AlertSeverity.CRITICAL.value
        if s >= 70:
            return AlertSeverity.HIGH.value
        if s >= 40:
            return AlertSeverity.MEDIUM.value
        return AlertSeverity.LOW.value

    def calculate_risk_score(
        self,
        *,
        ml_anomaly_score: float = 0.0,
        siem_rule_match: bool = False,
        rule_weight: float = 0.5,
        threat_feed_match: bool = False,
        ioc_confidence: float = 0.0,
        asset_criticality: float = 0.5,
        user_risk_profile: float = 0.3,
        mitre_tactic_severity: float = 50.0,
        event_frequency: float = 0.2,
        business_impact: float = 0.4,
        historical_false_positives: float = 0.1,
    ) -> Dict[str, float]:
        factors = {
            "ml_anomaly": round(min(ml_anomaly_score, 1.0) * 20.0, 2),
            "siem_rule": round((rule_weight if siem_rule_match else 0.0) * 18.0, 2),
            "threat_feed_ioc": round((15.0 if threat_feed_match else 0.0) * min(ioc_confidence / 100.0 or 0.7, 1.0), 2),
            "ioc_confidence": round(min(ioc_confidence / 100.0, 1.0) * 8.0, 2),
            "asset_criticality": round(min(asset_criticality, 1.0) * 10.0, 2),
            "user_risk": round(min(user_risk_profile, 1.0) * 7.0, 2),
            "mitre_tactic": round(min(mitre_tactic_severity / 100.0, 1.0) * 12.0, 2),
            "event_frequency": round(min(event_frequency, 1.0) * 5.0, 2),
            "business_impact": round(min(business_impact, 1.0) * 5.0, 2),
        }
        # Reduce score when historical FP rate is high
        fp_penalty = round(min(historical_false_positives, 1.0) * 10.0, 2)
        factors["false_positive_penalty"] = -fp_penalty
        total = max(1.0, min(100.0, sum(factors.values())))
        factors["total"] = round(total, 2)
        return factors

    def explain_severity_reasoning(self, factors: Dict[str, float], severity: str) -> str:
        contributors = sorted(
            ((k, v) for k, v in factors.items() if k != "total" and v > 0),
            key=lambda x: x[1],
            reverse=True,
        )[:4]
        parts = [f"{k.replace('_', ' ')} (+{v:.1f})" for k, v in contributors]
        penalty = factors.get("false_positive_penalty", 0)
        msg = f"Classified as {severity.upper()} (score {factors.get('total', 0):.1f}) based on: " + ", ".join(parts)
        if penalty:
            msg += f"; adjusted by FP history ({penalty:.1f})"
        return msg

    def recommend_response_action(self, severity: str, alert_type: Optional[str] = None) -> str:
        actions = {
            "critical": "Immediate containment: isolate host/block IOC, escalate to on-call, begin full incident workflow.",
            "high": "Prioritize investigation within 1 hour; validate IOCs, map MITRE techniques, notify SOC Manager.",
            "medium": "Queue for analyst review; enrich with threat feeds and confirm asset impact within shift.",
            "low": "Monitor and document; close as informational if no corroborating signals within 24h.",
        }
        base = actions.get((severity or "low").lower(), actions["low"])
        if alert_type and "exfil" in alert_type.lower():
            base += " Review outbound transfers and enable enhanced egress logging."
        return base

    def calculate_alert_severity(
        self,
        alert: Any,
        iocs: Optional[List[Dict[str, Any]]] = None,
        mitre_mappings: Optional[List[Dict[str, Any]]] = None,
        asset_context: Optional[Dict[str, Any]] = None,
    ) -> SeverityResult:
        iocs = iocs or []
        mitre_mappings = mitre_mappings or []
        asset_context = asset_context or {}

        ml = float(getattr(alert, "anomaly_score", None) or asset_context.get("ml_anomaly_score") or 0.0)
        if ml > 1.0:
            ml = ml / 100.0

        rule_name = getattr(alert, "rule_name", None) or ""
        siem = bool(rule_name) or (getattr(alert, "alert_type", None) and str(getattr(alert, "alert_type")).lower() in ("rule_based", "hybrid"))
        feed_match = any(i.get("feed_match") for i in iocs)
        ioc_conf = max([float(i.get("feed_confidence") or i.get("confidence") or 0) for i in iocs], default=0.0)

        mitre_sev = 50.0
        if mitre_mappings:
            mitre_sev = max(
                TACTIC_SEVERITY.get(m.get("tactic"), 50) for m in mitre_mappings
            )

        factors = self.calculate_risk_score(
            ml_anomaly_score=ml,
            siem_rule_match=siem,
            rule_weight=0.8 if siem else 0.0,
            threat_feed_match=feed_match,
            ioc_confidence=ioc_conf,
            asset_criticality=float(asset_context.get("asset_criticality", 0.5)),
            user_risk_profile=float(asset_context.get("user_risk_profile", 0.3)),
            mitre_tactic_severity=mitre_sev,
            event_frequency=float(asset_context.get("event_frequency", 0.25)),
            business_impact=float(asset_context.get("business_impact", 0.4)),
            historical_false_positives=float(asset_context.get("historical_false_positives", 0.1)),
        )

        severity = self.classify_severity(factors["total"])
        reason = self.explain_severity_reasoning(factors, severity)
        action = self.recommend_response_action(
            severity,
            str(getattr(alert, "attack_type", None) or getattr(alert, "title", "") or ""),
        )
        return SeverityResult(
            risk_score=factors["total"],
            severity=severity,
            severity_reason=reason,
            recommended_action=action,
            scoring_factors=factors,
        )

    def to_alert_fields(self, result: SeverityResult) -> Dict[str, Any]:
        return {
            "risk_score": result.risk_score,
            "severity": result.severity,
            "severity_reason": result.severity_reason,
            "recommended_action": result.recommended_action,
            "scoring_factors": json.dumps(result.scoring_factors),
        }


severity_scoring_service = SeverityScoringService()
