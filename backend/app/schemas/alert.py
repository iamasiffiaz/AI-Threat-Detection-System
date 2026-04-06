"""
Pydantic schemas for security alerts.
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from app.models.alert import AlertSeverity, AlertStatus, AlertType


class AlertResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: AlertSeverity
    alert_type: AlertType
    status: AlertStatus
    source_ip: Optional[str]
    rule_name: Optional[str]
    anomaly_score: Optional[float]
    llm_explanation: Optional[str]
    attack_type: Optional[str]
    mitigation_steps: Optional[str]
    log_entry_id: Optional[int]

    # Enterprise SOC fields
    risk_score:               Optional[float] = None
    incident_id:              Optional[int]   = None
    geo_country:              Optional[str]   = None
    geo_city:                 Optional[str]   = None
    threat_reputation:        Optional[float] = None
    is_known_bad_ip:          Optional[bool]  = None
    kill_chain_phase:         Optional[str]   = None
    mitre_ttps:               Optional[str]   = None
    false_positive_likelihood: Optional[str]  = None
    behavior_score:           Optional[float] = None

    triggered_at: datetime
    resolved_at: Optional[datetime]

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    llm_explanation: Optional[str] = None
    attack_type: Optional[str] = None
    mitigation_steps: Optional[str] = None


class AlertCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: str
    severity: AlertSeverity
    alert_type: AlertType = AlertType.RULE_BASED
    source_ip: Optional[str] = None
    rule_name: Optional[str] = None
    anomaly_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    log_entry_id: Optional[int] = None


class AlertSummary(BaseModel):
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    alerts_last_24h: int
    by_type: dict
    by_status: dict
    recent_alerts: List[AlertResponse]
