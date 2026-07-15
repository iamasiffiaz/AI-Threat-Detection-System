"""
Incident report generation — JSON + PDF (reportlab when available).
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.alert import Alert
from app.models.analyst_note import AnalystNote
from app.models.mitre_mapping import MitreMapping
from app.models.extracted_ioc import ExtractedIOC
from app.models.incident_report import IncidentReport
from app.models.incident_timeline import IncidentTimelineEvent
from app.services.incident_explanation_service import incident_explanation_service
from app.services.timeline_service import timeline_service

logger = logging.getLogger(__name__)

REPORTS_DIR = Path(__file__).resolve().parents[2] / "data" / "reports"


class ReportService:

    def _ensure_dir(self) -> Path:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        return REPORTS_DIR

    async def build_report_data(
        self,
        db: AsyncSession,
        incident_id: int,
        generated_by: str = "system",
    ) -> Dict[str, Any]:
        incident = (
            await db.execute(select(Incident).where(Incident.id == incident_id))
        ).scalar_one_or_none()
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        alerts = (
            await db.execute(select(Alert).where(Alert.incident_id == incident_id))
        ).scalars().all()
        notes = (
            await db.execute(select(AnalystNote).where(AnalystNote.incident_id == incident_id))
        ).scalars().all()
        mappings = (
            await db.execute(select(MitreMapping).where(MitreMapping.incident_id == incident_id))
        ).scalars().all()
        iocs = (
            await db.execute(select(ExtractedIOC).where(ExtractedIOC.incident_id == incident_id))
        ).scalars().all()
        timeline = await timeline_service.reconstruct_incident_timeline(db, incident_id)

        ioc_dicts = [
            {"ioc_type": i.ioc_type, "ioc_value": i.ioc_value, "feed_match": i.feed_match}
            for i in iocs
        ]
        mitre_dicts = [
            {
                "tactic": m.tactic,
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "confidence": m.confidence,
            }
            for m in mappings
        ]
        explanation = await incident_explanation_service.explain_incident(
            incident,
            alerts=list(alerts),
            iocs=ioc_dicts,
            mitre_mappings=mitre_dicts,
            timeline=timeline.get("summary"),
        )

        data = {
            "incident_id": incident.id,
            "incident_title": incident.title,
            "severity": incident.severity.value if incident.severity else None,
            "risk_score": incident.risk_score,
            "status": incident.status.value if incident.status else None,
            "assigned_analyst": incident.assigned_to,
            "affected_assets": incident.affected_assets or incident.source_ip,
            "executive_summary": explanation.get("executive_summary"),
            "technical_summary": explanation.get("what_happened"),
            "why_it_matters": explanation.get("why_it_matters"),
            "likely_impact": explanation.get("likely_impact"),
            "recommended_actions": explanation.get("recommended_containment_steps"),
            "investigation_checklist": explanation.get("investigation_checklist"),
            "timeline": timeline.get("events", []),
            "timeline_summary": timeline.get("summary"),
            "iocs": ioc_dicts,
            "mitre_mappings": mitre_dicts,
            "related_alerts": [
                {
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity.value if a.severity else None,
                    "risk_score": a.risk_score,
                }
                for a in alerts
            ],
            "analyst_notes": [
                {
                    "analyst_name": n.analyst_name,
                    "note_type": n.note_type.value,
                    "note_text": n.note_text,
                    "created_at": n.created_at.isoformat() if n.created_at else None,
                }
                for n in notes
            ],
            "generated_by": generated_by,
            "generated_date": datetime.now(timezone.utc).isoformat(),
        }
        return data

    def _render_pdf(self, report_id: int, data: Dict[str, Any]) -> Optional[str]:
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
        except ImportError:
            logger.warning("reportlab not installed — storing HTML fallback only")
            return self._render_html(report_id, data)

        path = self._ensure_dir() / f"incident_report_{report_id}.pdf"
        doc = SimpleDocTemplate(str(path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        def add(title: str, body: str):
            story.append(Paragraph(title, styles["Heading2"]))
            story.append(Paragraph((body or "N/A").replace("\n", "<br/>"), styles["BodyText"]))
            story.append(Spacer(1, 0.15 * inch))

        story.append(Paragraph("AI Threat Intelligence SOC Platform 2.0 — Incident Report", styles["Title"]))
        story.append(Spacer(1, 0.2 * inch))
        add("Incident", f"{data.get('incident_title')} (ID {data.get('incident_id')})")
        add("Severity / Risk", f"{data.get('severity')} / {data.get('risk_score')}")
        add("Status", str(data.get("status")))
        add("Executive Summary", str(data.get("executive_summary")))
        add("Technical Summary", str(data.get("technical_summary")))
        add("Timeline Summary", str(data.get("timeline_summary")))
        add("IOCs", json.dumps(data.get("iocs", []), indent=2))
        add("MITRE Mappings", json.dumps(data.get("mitre_mappings", []), indent=2))
        add("Recommended Actions", "\n".join(data.get("recommended_actions") or []))
        add("Generated", str(data.get("generated_date")))
        doc.build(story)
        return str(path)

    def _render_html(self, report_id: int, data: Dict[str, Any]) -> str:
        path = self._ensure_dir() / f"incident_report_{report_id}.html"
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Incident Report {report_id}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#020617;color:#E5E7EB;padding:32px;}}
h1{{color:#06B6D4}} h2{{color:#2563EB;border-bottom:1px solid #334155;padding-bottom:4px}}
.card{{background:#111827;border:1px solid #334155;border-radius:8px;padding:16px;margin:12px 0}}
pre{{white-space:pre-wrap;background:#0F172A;padding:12px;border-radius:6px}}
</style></head><body>
<h1>SOC Incident Report</h1>
<div class="card"><h2>{data.get('incident_title')}</h2>
<p>Severity: {data.get('severity')} | Risk: {data.get('risk_score')} | Status: {data.get('status')}</p>
<p>Generated: {data.get('generated_date')}</p></div>
<div class="card"><h2>Executive Summary</h2><p>{data.get('executive_summary')}</p></div>
<div class="card"><h2>Technical Summary</h2><p>{data.get('technical_summary')}</p></div>
<div class="card"><h2>Timeline</h2><pre>{data.get('timeline_summary')}</pre></div>
<div class="card"><h2>IOCs</h2><pre>{json.dumps(data.get('iocs'), indent=2)}</pre></div>
<div class="card"><h2>MITRE</h2><pre>{json.dumps(data.get('mitre_mappings'), indent=2)}</pre></div>
</body></html>"""
        path.write_text(html, encoding="utf-8")
        return str(path)

    async def generate_report(
        self,
        db: AsyncSession,
        incident_id: int,
        generated_by: str = "system",
    ) -> IncidentReport:
        data = await self.build_report_data(db, incident_id, generated_by)
        report = IncidentReport(
            incident_id=incident_id,
            title=data["incident_title"],
            severity=data.get("severity"),
            risk_score=data.get("risk_score"),
            report_json=json.dumps(data),
            generated_by=generated_by,
        )
        db.add(report)
        await db.flush()

        pdf_path = self._render_pdf(report.id, data)
        report.pdf_path = pdf_path
        await db.commit()
        await db.refresh(report)

        from app.services.timeline_service import timeline_service as ts
        await ts.add_timeline_event(
            db, incident_id,
            event_type="report_generated",
            title=f"Incident report #{report.id} generated",
            description=f"Generated by {generated_by}",
            source="report_service",
            severity=data.get("severity"),
        )
        await db.commit()
        return report


report_service = ReportService()
