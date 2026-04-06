"""
AI SOC Assistant router — chat-style interface powered by the LLM.

Analysts can ask natural language questions about specific alerts,
incidents, or general threat scenarios. The assistant uses full
context from our database to provide grounded, specific answers.

Endpoints:
  POST /api/v1/soc-assistant/ask                Ask a free-form question
  POST /api/v1/soc-assistant/explain/{alert_id} "Explain this alert"
  POST /api/v1/soc-assistant/advise/{alert_id}  "What should I do?"
  POST /api/v1/soc-assistant/incident/{id}      Incident summary
"""
import json
import logging
from typing import Optional, List, AsyncGenerator

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user
from app.core.config import settings
from app.models.user import User
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.log_entry import LogEntry

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/soc-assistant", tags=["soc-assistant"])

_OLLAMA_TIMEOUT = 120.0   # LLM can be slow


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AskRequest(BaseModel):
    question:   str
    context:    Optional[str]  = None   # optional extra context
    alert_ids:  Optional[List[int]] = None


class SOCResponse(BaseModel):
    answer:           str
    sources_used:     List[str]
    confidence:       str
    recommended_actions: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# LLM helper
# ---------------------------------------------------------------------------

async def _call_llm(prompt: str) -> str:
    """Send prompt to Ollama and return the full response text (non-streaming)."""
    try:
        async with httpx.AsyncClient(timeout=_OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{settings.OLLAMA_BASE_URL}/api/generate",
                json={
                    "model":  settings.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 1024},
                },
            )
            if resp.status_code == 200:
                return resp.json().get("response", "")
    except Exception as exc:
        logger.warning("SOC assistant LLM call failed: %s", exc)
    return ""


async def _stream_llm(prompt: str) -> AsyncGenerator[str, None]:
    """Stream Ollama response token by token as an async generator."""
    try:
        async with httpx.AsyncClient(timeout=_OLLAMA_TIMEOUT) as client:
            async with client.stream(
                "POST",
                f"{settings.OLLAMA_BASE_URL}/api/generate",
                json={
                    "model":  settings.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": True,
                    "options": {"temperature": 0.3, "num_predict": 2048},
                },
            ) as response:
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("response", "")
                        if token:
                            yield token
                        if chunk.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue
    except Exception as exc:
        logger.warning("SOC assistant stream failed: %s", exc)
        yield "\n\n⚠ Stream interrupted. Please check Ollama is running."


async def _sse_stream(prompt: str) -> AsyncGenerator[str, None]:
    """
    Wrap _stream_llm into Server-Sent Events format.
    Each token is sent as:  data: <token>\n\n
    Completion signal:       data: [DONE]\n\n
    Newlines inside tokens are escaped as \\n so SSE framing isn't broken.
    """
    try:
        async for token in _stream_llm(prompt):
            # Escape literal newlines so SSE line boundaries stay intact
            escaped = token.replace("\\", "\\\\").replace("\n", "\\n")
            yield f"data: {escaped}\n\n"
    except Exception as exc:
        yield f"data: ⚠ {str(exc)}\n\n"
    finally:
        yield "data: [DONE]\n\n"


_SSE_HEADERS = {
    "Cache-Control":    "no-cache",
    "X-Accel-Buffering": "no",      # disable nginx/proxy buffering
    "Connection":       "keep-alive",
}


def _build_alert_context(alert: Alert, logs: list) -> str:
    """Build a text description of alert context for the LLM prompt."""
    parts = [
        f"Alert ID: {alert.id}",
        f"Title: {alert.title}",
        f"Severity: {alert.severity.value.upper()}",
        f"Status: {alert.status.value}",
        f"Source IP: {alert.source_ip}",
        f"Attack Type: {alert.attack_type or 'Unknown'}",
        f"Rule Matched: {alert.rule_name or 'None'}",
        f"Risk Score: {alert.risk_score or 'N/A'}/100",
        f"Anomaly Score: {alert.anomaly_score or 'N/A'}",
        f"Kill Chain Phase: {alert.kill_chain_phase or 'N/A'}",
        f"MITRE TTPs: {alert.mitre_ttps or 'N/A'}",
        f"Geo Country: {alert.geo_country or 'Unknown'}",
        f"Threat Reputation: {alert.threat_reputation or 0}/100",
        f"Known Bad IP: {alert.is_known_bad_ip}",
        f"Triggered At: {alert.triggered_at}",
    ]
    if logs:
        parts.append(f"\nRelated Log Entries ({len(logs)} recent):")
        for log in logs[:5]:
            parts.append(
                f"  - [{log.timestamp}] {log.event_type} | "
                f"proto={log.protocol.value if log.protocol else '?'} | "
                f"dst_port={log.destination_port} | "
                f"msg={log.message or ''}"
            )
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/ask", response_model=SOCResponse)
async def ask(
    request: AskRequest,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """
    Free-form question to the SOC AI assistant.
    Optionally pass alert_ids for grounded context.
    """
    alert_context = ""
    sources = ["user_question"]

    if request.alert_ids:
        for aid in request.alert_ids[:3]:
            a_result = await db.execute(select(Alert).where(Alert.id == aid))
            alert = a_result.scalar_one_or_none()
            if alert:
                alert_context += f"\n\n--- Alert {aid} ---\n"
                alert_context += _build_alert_context(alert, [])
                sources.append(f"alert_{aid}")

    system_context = request.context or ""
    if alert_context:
        system_context += "\n\nContext from security alerts:\n" + alert_context

    prompt = f"""You are an expert SOC (Security Operations Center) analyst with 15+ years of experience in threat detection, incident response, and digital forensics.

{f"Context:{chr(10)}{system_context}" if system_context else ""}

Analyst Question:
{request.question}

Instructions:
- Be specific and actionable in your response
- If context is available, reference specific details
- Provide clear, prioritized recommendations
- Use MITRE ATT&CK framework terminology where relevant
- Be concise but comprehensive

Answer:"""

    llm_response = await _call_llm(prompt)

    if not llm_response:
        llm_response = (
            "The AI assistant is currently unavailable. "
            "Please consult the alert details, MITRE ATT&CK framework, "
            "and your organization's runbooks for guidance."
        )

    return SOCResponse(
        answer=llm_response,
        sources_used=sources,
        confidence="high" if alert_context else "medium",
    )


@router.post("/explain/{alert_id}", response_model=SOCResponse)
async def explain_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """
    'Explain this alert' — detailed LLM explanation with full context.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Fetch related logs
    log_result = await db.execute(
        select(LogEntry)
        .where(LogEntry.source_ip == alert.source_ip)
        .order_by(LogEntry.timestamp.desc())
        .limit(10)
    ) if alert.source_ip else None
    logs = log_result.scalars().all() if log_result else []

    context = _build_alert_context(alert, logs)

    prompt = f"""You are a senior SOC analyst. Explain the following security alert in plain English that a junior analyst can understand.

{context}

Explain:
1. What is happening (in plain English)
2. Why this is flagged as {alert.severity.value.upper()} severity
3. What the attacker is likely trying to accomplish
4. What evidence supports this conclusion
5. How confident you are and why

Be specific to this alert — do NOT give generic advice."""

    answer = await _call_llm(prompt)
    if not answer:
        answer = alert.llm_explanation or f"Alert '{alert.title}' from {alert.source_ip} with {alert.severity.value} severity. Risk score: {alert.risk_score}."

    return SOCResponse(
        answer=answer,
        sources_used=["alert", "logs", "threat_intel"],
        confidence="high",
    )


@router.post("/advise/{alert_id}", response_model=SOCResponse)
async def advise_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """
    'What should I do?' — actionable response recommendations.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    from app.services.soar_service import soar_service
    playbook = soar_service.get_playbook(alert.attack_type)

    context = _build_alert_context(alert, [])
    playbook_steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(playbook.get("steps", [])))

    prompt = f"""You are a senior SOC incident responder. An analyst needs specific action guidance.

{context}

Standard Playbook for {alert.attack_type or 'this attack type'}:
{playbook_steps}

Provide a PRIORITIZED action plan:
1. Immediate actions (next 5 minutes)
2. Short-term actions (next 30 minutes)
3. Investigation steps
4. Preventive measures

Make your recommendations specific to the details of THIS alert.
Reference the source IP {alert.source_ip}, severity {alert.severity.value}, and risk score {alert.risk_score}."""

    answer = await _call_llm(prompt)
    if not answer:
        answer = f"Recommended playbook: {playbook['name']}\n\nSteps:\n" + playbook_steps

    return SOCResponse(
        answer=answer,
        sources_used=["alert", "playbook", "threat_intel"],
        confidence="high",
        recommended_actions=playbook.get("steps", []),
    )


@router.post("/incident/{incident_id}", response_model=SOCResponse)
async def incident_summary(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """AI-generated incident summary with timeline and recommended next steps."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Get related alerts
    alerts_result = await db.execute(
        select(Alert).where(Alert.incident_id == incident_id)
        .order_by(Alert.triggered_at).limit(20)
    )
    alerts = alerts_result.scalars().all()

    alert_summary = "\n".join(
        f"  - [{a.triggered_at}] {a.title} (severity={a.severity.value}, "
        f"rule={a.rule_name}, risk={a.risk_score})"
        for a in alerts
    )

    def _try_parse(v):
        try:
            return json.loads(v) if v else []
        except Exception:
            return []

    prompt = f"""You are a SOC team lead. Provide an executive summary for the following security incident.

Incident Details:
  ID:          {incident.id}
  Title:       {incident.title}
  Severity:    {incident.severity.value.upper()}
  Status:      {incident.status.value}
  Source IP:   {incident.source_ip}
  Country:     {incident.geo_country or 'Unknown'}
  Risk Score:  {incident.risk_score}/100
  Alert Count: {incident.alert_count}
  Attack Types: {', '.join(_try_parse(incident.attack_types))}
  MITRE TTPs:  {incident.mitre_ttps or 'Unknown'}
  First Seen:  {incident.first_seen}
  Last Seen:   {incident.last_seen}

Alert Timeline:
{alert_summary or "No alerts linked"}

Provide:
1. Executive summary (3-4 sentences)
2. Attack progression timeline
3. Business impact assessment
4. Immediate containment priorities
5. Recommended escalation path"""

    answer = await _call_llm(prompt)
    if not answer:
        answer = (
            f"Incident #{incident_id}: {incident.title}\n"
            f"Severity: {incident.severity.value.upper()} | "
            f"Status: {incident.status.value} | "
            f"Risk: {incident.risk_score}/100\n"
            f"{incident.alert_count} alerts from {incident.source_ip}"
        )

    return SOCResponse(
        answer=answer,
        sources_used=["incident", "alerts"],
        confidence="high",
    )


# ---------------------------------------------------------------------------
# Streaming endpoints  (SSE — text/event-stream)
# ---------------------------------------------------------------------------

@router.post("/stream/ask")
async def stream_ask(
    request: AskRequest,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Stream a free-form answer token by token via SSE."""
    alert_context = ""
    if request.alert_ids:
        for aid in request.alert_ids[:3]:
            a_result = await db.execute(select(Alert).where(Alert.id == aid))
            alert = a_result.scalar_one_or_none()
            if alert:
                alert_context += f"\n\n--- Alert {aid} ---\n"
                alert_context += _build_alert_context(alert, [])

    system_context = (request.context or "") + (
        "\n\nContext from security alerts:\n" + alert_context if alert_context else ""
    )

    prompt = f"""You are an expert SOC analyst with 15+ years of experience in threat detection, incident response, and digital forensics.

{f"Context:{chr(10)}{system_context}" if system_context else ""}

Analyst Question:
{request.question}

Instructions:
- Be specific and actionable
- Reference specific details from context if available
- Use MITRE ATT&CK framework terminology where relevant
- Be concise but comprehensive

Answer:"""

    return StreamingResponse(_sse_stream(prompt), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/stream/explain/{alert_id}")
async def stream_explain_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Stream a plain-English alert explanation token by token via SSE."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    log_result = await db.execute(
        select(LogEntry)
        .where(LogEntry.source_ip == alert.source_ip)
        .order_by(LogEntry.timestamp.desc())
        .limit(10)
    ) if alert.source_ip else None
    logs = log_result.scalars().all() if log_result else []
    context = _build_alert_context(alert, logs)

    prompt = f"""You are a senior SOC analyst. Explain the following security alert in plain English that a junior analyst can understand.

{context}

Explain:
1. What is happening (in plain English)
2. Why this is flagged as {alert.severity.value.upper()} severity
3. What the attacker is likely trying to accomplish
4. What evidence supports this conclusion
5. How confident you are and why

Be specific to this alert — do NOT give generic advice."""

    return StreamingResponse(_sse_stream(prompt), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/stream/advise/{alert_id}")
async def stream_advise_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Stream an action plan for an alert token by token via SSE."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    from app.services.soar_service import soar_service
    playbook = soar_service.get_playbook(alert.attack_type)
    context  = _build_alert_context(alert, [])
    playbook_steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(playbook.get("steps", [])))

    prompt = f"""You are a senior SOC incident responder. An analyst needs specific action guidance.

{context}

Standard Playbook for {alert.attack_type or 'this attack type'}:
{playbook_steps}

Provide a PRIORITIZED action plan:
1. Immediate actions (next 5 minutes)
2. Short-term actions (next 30 minutes)
3. Investigation steps
4. Preventive measures

Make recommendations specific to THIS alert — source IP {alert.source_ip}, severity {alert.severity.value}, risk score {alert.risk_score}."""

    return StreamingResponse(_sse_stream(prompt), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/stream/incident/{incident_id}")
async def stream_incident_summary(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Stream an incident executive summary token by token via SSE."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts_result = await db.execute(
        select(Alert).where(Alert.incident_id == incident_id)
        .order_by(Alert.triggered_at).limit(20)
    )
    alerts = alerts_result.scalars().all()
    alert_summary = "\n".join(
        f"  - [{a.triggered_at}] {a.title} (severity={a.severity.value}, risk={a.risk_score})"
        for a in alerts
    )

    def _try_parse(v):
        try: return json.loads(v) if v else []
        except Exception: return []

    prompt = f"""You are a SOC team lead. Provide an executive summary for the following security incident.

Incident Details:
  ID:          {incident.id}
  Title:       {incident.title}
  Severity:    {incident.severity.value.upper()}
  Status:      {incident.status.value}
  Source IP:   {incident.source_ip}
  Country:     {incident.geo_country or 'Unknown'}
  Risk Score:  {incident.risk_score}/100
  Alert Count: {incident.alert_count}
  Attack Types: {', '.join(_try_parse(incident.attack_types))}
  MITRE TTPs:  {incident.mitre_ttps or 'Unknown'}
  First Seen:  {incident.first_seen}
  Last Seen:   {incident.last_seen}

Alert Timeline:
{alert_summary or "No alerts linked"}

Provide:
1. Executive summary (3-4 sentences)
2. Attack progression timeline
3. Business impact assessment
4. Immediate containment priorities
5. Recommended escalation path"""

    return StreamingResponse(_sse_stream(prompt), media_type="text/event-stream", headers=_SSE_HEADERS)
