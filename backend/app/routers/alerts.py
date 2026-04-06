"""
Alerts router: retrieve, update, and analyze security alerts.
"""
import asyncio
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from datetime import datetime
from app.core.database import get_db
from app.core.dependencies import get_current_active_user, require_analyst_or_admin
from app.models.user import User
from app.models.alert import Alert, AlertSeverity, AlertStatus, AlertType
from app.models.log_entry import LogEntry
from app.schemas.alert import AlertResponse, AlertUpdate, AlertSummary
from app.services.alert_service import alert_service
from app.services.llm_service import llm_service
from app.services.rule_engine import RuleMatch

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get("", response_model=dict)
async def get_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[AlertSeverity] = None,
    status: Optional[AlertStatus] = None,
    alert_type: Optional[AlertType] = None,
    source_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Retrieve paginated security alerts with filters."""
    alerts, total = await alert_service.get_alerts(
        db=db,
        page=page,
        page_size=page_size,
        severity=severity,
        status=status,
        alert_type=alert_type,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
    )
    return {
        "items": [AlertResponse.model_validate(a) for a in alerts],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/summary", response_model=AlertSummary)
async def get_alert_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get alert summary statistics for the dashboard."""
    return await alert_service.get_summary(db)


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a single alert by ID."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    updates: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    """Update alert status, explanation, or mitigation steps."""
    updated = await alert_service.update_alert(
        db, alert_id, updates.model_dump(exclude_none=True)
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    return updated


@router.post("/{alert_id}/analyze", response_model=dict)
async def analyze_alert_with_llm(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    """
    Trigger LLM analysis for a specific alert.
    Generates detailed threat explanation, attack type, and mitigation steps.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    log_dict = None
    if alert.log_entry_id:
        log_result = await db.execute(
            select(LogEntry).where(LogEntry.id == alert.log_entry_id)
        )
        log = log_result.scalar_one_or_none()
        if log:
            log_dict = {
                "source_ip": log.source_ip,
                "destination_ip": log.destination_ip,
                "destination_port": log.destination_port,
                "protocol": log.protocol.value if log.protocol else None,
                "event_type": log.event_type,
                "severity": log.severity.value if log.severity else None,
                "message": log.message,
            }

    analysis = await llm_service.analyze_threat(
        anomaly_data={
            "rule_name": alert.rule_name,
            "anomaly_score": alert.anomaly_score or 0,
            "description": alert.description,
        },
        log_data=log_dict,
    )

    # Persist the analysis
    await alert_service.update_alert(db, alert_id, {
        "llm_explanation": analysis.get("explanation"),
        "attack_type": analysis.get("attack_type"),
        "mitigation_steps": "\n".join(
            f"• {s}" for s in analysis.get("mitigation_steps", [])
        ),
    })

    return analysis


@router.post("/reanalyze-all", response_model=dict)
async def reanalyze_all_alerts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
):
    """
    Re-trigger LLM analysis for all alerts that have fallback/missing explanations.
    Runs enrichment as background tasks and returns immediately.
    """
    result = await db.execute(select(Alert))
    alerts = result.scalars().all()

    queued = 0
    for alert in alerts:
        if not alert.llm_explanation or "Manual investigation recommended" in (alert.llm_explanation or ""):
            log_dict = None
            if alert.log_entry_id:
                log_result = await db.execute(
                    select(LogEntry).where(LogEntry.id == alert.log_entry_id)
                )
                log = log_result.scalar_one_or_none()
                if log:
                    log_dict = {
                        "source_ip": log.source_ip,
                        "destination_ip": log.destination_ip,
                        "destination_port": log.destination_port,
                        "protocol": log.protocol.value if log.protocol else None,
                        "event_type": log.event_type,
                        "severity": log.severity.value if log.severity else None,
                        "message": log.message,
                    }

            asyncio.create_task(
                alert_service._enrich_alert_with_llm(
                    alert.id,
                    RuleMatch(
                        rule_name=alert.rule_name or "unknown",
                        title=alert.title,
                        description=alert.description,
                        severity=alert.severity,
                        source_ip=alert.source_ip,
                        context={"anomaly_score": alert.anomaly_score or 0},
                    ),
                    log_dict,
                )
            )
            queued += 1

    return {
        "queued": queued,
        "total": len(alerts),
        "message": f"Re-analysis queued for {queued} alert(s). Results will appear shortly.",
    }
