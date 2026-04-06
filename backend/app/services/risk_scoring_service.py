"""
Risk Scoring Service
======================
Replaces binary severity with a dynamic 0–100 composite risk score.

Formula (max 100 points):
  ┌──────────────────────────────────┬──────────────┐
  │ Signal                           │ Max points   │
  ├──────────────────────────────────┼──────────────┤
  │ ML anomaly score                 │     25       │
  │ Rule matches (count × weight)    │     25       │
  │ Threat intelligence reputation   │     20       │
  │ Behavioral deviation             │     15       │
  │ Known-bad IP bonus               │      5       │
  │ Classification confidence        │      5       │
  │ Alert history for this IP        │      5       │
  └──────────────────────────────────┴──────────────┘

Severity thresholds:
  0  – 25  → Low
  26 – 50  → Medium
  51 – 75  → High
  76 – 100 → Critical
"""
from dataclasses import dataclass
from typing import List, Optional

from app.models.alert import AlertSeverity


# ---------------------------------------------------------------------------
# Weights for multi-rule matches
# ---------------------------------------------------------------------------
_RULE_SEVERITY_WEIGHTS = {
    # Rule name                        → weight (0-5)
    "brute_force":          4,
    "ssh_brute_force":      5,
    "port_scan":            3,
    "syn_flood":            4,
    "data_exfil":           5,
    "sql_injection":        5,
    "rce_attempt":          5,
    "c2_beacon":            5,
    "dns_tunneling":        4,
    "credential_stuffing":  4,
    "lateral_movement":     5,
    "web_attack":           3,
    "suspicious_login":     3,
    "internal_recon":       3,
    "geo_anomaly":          2,
}
_DEFAULT_RULE_WEIGHT = 2


@dataclass
class RiskScoreResult:
    risk_score:  float         # 0.0-100.0
    severity:    AlertSeverity
    breakdown:   dict          # per-signal contribution (for audit trail)


class RiskScoringService:

    def compute(
        self,
        *,
        anomaly_score:        float = 0.0,   # 0-1 from IsolationForest/LOF
        rule_names:           List[str] = (),
        threat_reputation:    float = 0.0,   # 0-100 from TI service
        behavior_score:       float = 0.0,   # 0-1 from behavioral profiler
        is_known_bad_ip:      bool  = False,
        classification_conf:  float = 0.0,   # 0-1 from classification service
        ip_alert_count:       int   = 0,     # alerts triggered by this IP in 24h
    ) -> RiskScoreResult:

        breakdown: dict = {}

        # 1. ML anomaly score  (0 → 25 pts)
        ml_pts = round(min(anomaly_score, 1.0) * 25.0, 2)
        breakdown["ml_anomaly"] = ml_pts

        # 2. Rule match score  (0 → 25 pts)
        total_rule_weight = sum(
            _RULE_SEVERITY_WEIGHTS.get(r.lower(), _DEFAULT_RULE_WEIGHT)
            for r in rule_names
        )
        rule_pts = round(min(total_rule_weight / 20.0, 1.0) * 25.0, 2)
        breakdown["rule_matches"] = rule_pts

        # 3. Threat intelligence  (0 → 20 pts)
        ti_pts = round(min(threat_reputation / 100.0, 1.0) * 20.0, 2)
        breakdown["threat_intel"] = ti_pts

        # 4. Behavioral deviation  (0 → 15 pts)
        beh_pts = round(min(behavior_score, 1.0) * 15.0, 2)
        breakdown["behavioral"] = beh_pts

        # 5. Known-bad IP bonus  (0 or 5 pts)
        bad_ip_pts = 5.0 if is_known_bad_ip else 0.0
        breakdown["known_bad_ip"] = bad_ip_pts

        # 6. Classification confidence  (0 → 5 pts)
        class_pts = round(min(classification_conf, 1.0) * 5.0, 2)
        breakdown["classification_conf"] = class_pts

        # 7. Alert history  (0 → 5 pts; scales with repeat offender behaviour)
        hist_pts = round(min(ip_alert_count / 20.0, 1.0) * 5.0, 2)
        breakdown["alert_history"] = hist_pts

        total = round(ml_pts + rule_pts + ti_pts + beh_pts + bad_ip_pts + class_pts + hist_pts, 2)
        total = min(total, 100.0)
        breakdown["total"] = total

        return RiskScoreResult(
            risk_score=total,
            severity=self._to_severity(total),
            breakdown=breakdown,
        )

    @staticmethod
    def _to_severity(score: float) -> AlertSeverity:
        if score >= 76:
            return AlertSeverity.CRITICAL
        if score >= 51:
            return AlertSeverity.HIGH
        if score >= 26:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    @staticmethod
    def score_to_severity(score: float) -> AlertSeverity:
        """Static helper for use without instantiating the service."""
        if score >= 76:
            return AlertSeverity.CRITICAL
        if score >= 51:
            return AlertSeverity.HIGH
        if score >= 26:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW


# Singleton
risk_scoring_service = RiskScoringService()
