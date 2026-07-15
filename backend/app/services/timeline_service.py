"""
Incident timeline reconstruction service.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from sqlalchemy import select, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident_timeline import IncidentTimelineEvent
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.analyst_note import AnalystNote
from app.models.mitre_mapping import MitreMapping
from app.models.extracted_ioc import ExtractedIOC
from app.models.incident_report import IncidentReport


class TimelineService:

    async def add_timeline_event(
        self,
        db: AsyncSession,
        incident_id: int,
        event_type: str,
        title: str,
        description: str = "",
        source: str = "system",
        severity: Optional[str] = None,
        related_alert_id: Optional[int] = None,
        related_ioc_id: Optional[int] = None,
        timestamp: Optional[datetime] = None,
    ) -> IncidentTimelineEvent:
        event = IncidentTimelineEvent(
            incident_id=incident_id,
            event_type=event_type,
            title=title,
            description=description,
            source=source,
            severity=severity,
            related_alert_id=related_alert_id,
            related_ioc_id=related_ioc_id,
            timestamp=timestamp or datetime.now(timezone.utc),
        )
        db.add(event)
        await db.flush()
        return event

    def sort_timeline_events(
        self, events: List[IncidentTimelineEvent]
    ) -> List[IncidentTimelineEvent]:
        return sorted(events, key=lambda e: e.timestamp or datetime.min.replace(tzinfo=timezone.utc))

    def detect_timeline_gaps(
        self, events: List[IncidentTimelineEvent], gap_hours: float = 6.0
    ) -> List[Dict[str, Any]]:
        sorted_events = self.sort_timeline_events(events)
        gaps = []
        for a, b in zip(sorted_events, sorted_events[1:]):
            if not a.timestamp or not b.timestamp:
                continue
            delta = b.timestamp - a.timestamp
            if delta >= timedelta(hours=gap_hours):
                gaps.append({
                    "after_event_id": a.id,
                    "before_event_id": b.id,
                    "gap_hours": round(delta.total_seconds() / 3600, 2),
                    "message": f"Activity gap of {delta.total_seconds()/3600:.1f}h between '{a.title}' and '{b.title}'",
                })
        return gaps

    def summarize_timeline(self, events: List[IncidentTimelineEvent]) -> str:
        if not events:
            return "No timeline events recorded yet."
        sorted_events = self.sort_timeline_events(events)
        first = sorted_events[0]
        last = sorted_events[-1]
        types = {}
        for e in sorted_events:
            types[e.event_type] = types.get(e.event_type, 0) + 1
        type_parts = ", ".join(f"{k}: {v}" for k, v in sorted(types.items()))
        return (
            f"Timeline spans {len(sorted_events)} events from "
            f"{first.timestamp.isoformat() if first.timestamp else 'unknown'} "
            f"({first.title}) to "
            f"{last.timestamp.isoformat() if last.timestamp else 'unknown'} "
            f"({last.title}). Event mix — {type_parts}."
        )

    async def reconstruct_incident_timeline(
        self, db: AsyncSession, incident_id: int
    ) -> Dict[str, Any]:
        incident = (
            await db.execute(select(Incident).where(Incident.id == incident_id))
        ).scalar_one_or_none()
        if not incident:
            return {"error": "Incident not found"}

        # Existing stored events
        existing = (
            await db.execute(
                select(IncidentTimelineEvent).where(
                    IncidentTimelineEvent.incident_id == incident_id
                )
            )
        ).scalars().all()

        if len(existing) < 2:
            # Bootstrap reconstruction from related entities
            await self.add_timeline_event(
                db, incident_id,
                event_type="first_suspicious_event",
                title="First suspicious activity observed",
                description=incident.description or incident.title,
                source="correlation_engine",
                severity=incident.severity.value if incident.severity else None,
                timestamp=incident.first_seen,
            )

            alerts = (
                await db.execute(
                    select(Alert).where(Alert.incident_id == incident_id).order_by(asc(Alert.triggered_at))
                )
            ).scalars().all()
            for a in alerts:
                await self.add_timeline_event(
                    db, incident_id,
                    event_type="alert_generated",
                    title=f"Alert generated: {a.title}",
                    description=a.description[:500] if a.description else "",
                    source="alert_engine",
                    severity=a.severity.value if a.severity else None,
                    related_alert_id=a.id,
                    timestamp=a.triggered_at,
                )

            iocs = (
                await db.execute(
                    select(ExtractedIOC).where(ExtractedIOC.incident_id == incident_id)
                )
            ).scalars().all()
            for ioc in iocs[:20]:
                await self.add_timeline_event(
                    db, incident_id,
                    event_type="ioc_match",
                    title=f"IOC identified: {ioc.ioc_type} — {ioc.ioc_value}",
                    description=ioc.source_text or "",
                    source="ioc_extraction",
                    related_ioc_id=ioc.id,
                    timestamp=ioc.created_at,
                )

            mappings = (
                await db.execute(
                    select(MitreMapping).where(MitreMapping.incident_id == incident_id)
                )
            ).scalars().all()
            for m in mappings:
                await self.add_timeline_event(
                    db, incident_id,
                    event_type="mitre_mapping",
                    title=f"MITRE mapped: {m.technique_id} {m.technique_name}",
                    description=m.reasoning or m.tactic,
                    source="mitre_engine",
                    timestamp=m.created_at,
                )

            notes = (
                await db.execute(
                    select(AnalystNote).where(AnalystNote.incident_id == incident_id)
                )
            ).scalars().all()
            for n in notes:
                await self.add_timeline_event(
                    db, incident_id,
                    event_type="analyst_note",
                    title=f"Analyst note ({n.note_type.value}): {n.analyst_name}",
                    description=n.note_text[:500],
                    source="analyst",
                    timestamp=n.created_at,
                )

            reports = (
                await db.execute(
                    select(IncidentReport).where(IncidentReport.incident_id == incident_id)
                )
            ).scalars().all()
            for r in reports:
                await self.add_timeline_event(
                    db, incident_id,
                    event_type="report_generated",
                    title=f"Report generated: {r.title}",
                    description=f"Severity {r.severity}, risk {r.risk_score}",
                    source="report_service",
                    timestamp=r.created_at,
                )

            await self.add_timeline_event(
                db, incident_id,
                event_type="status_changed",
                title=f"Incident status: {incident.status.value}",
                description=f"Current status is {incident.status.value}",
                source="incident_management",
                severity=incident.severity.value if incident.severity else None,
                timestamp=incident.last_seen,
            )
            await db.commit()

        events = (
            await db.execute(
                select(IncidentTimelineEvent)
                .where(IncidentTimelineEvent.incident_id == incident_id)
                .order_by(asc(IncidentTimelineEvent.timestamp))
            )
        ).scalars().all()

        event_dicts = [
            {
                "id": e.id,
                "incident_id": e.incident_id,
                "event_type": e.event_type,
                "title": e.title,
                "description": e.description,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "source": e.source,
                "severity": e.severity,
                "related_alert_id": e.related_alert_id,
                "related_ioc_id": e.related_ioc_id,
            }
            for e in events
        ]
        return {
            "incident_id": incident_id,
            "events": event_dicts,
            "gaps": self.detect_timeline_gaps(list(events)),
            "summary": self.summarize_timeline(list(events)),
            "total": len(event_dicts),
        }


timeline_service = TimelineService()
