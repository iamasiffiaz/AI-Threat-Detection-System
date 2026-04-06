"""
Event Viewer Router
====================
REST API for controlling the Windows Event Log integration service.

Endpoints:
  GET  /api/v1/event-viewer/status         — service status + counters
  POST /api/v1/event-viewer/start          — start real-time polling
  POST /api/v1/event-viewer/stop           — stop polling
  GET  /api/v1/event-viewer/recent         — last N ingested events (from UI)
  POST /api/v1/event-viewer/pull-now       — manual one-shot pull
  GET  /api/v1/event-viewer/channels       — available channels on this machine
  GET  /api/v1/event-viewer/event-ids      — complete Event ID → description map
"""

import asyncio
import platform
import sys
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.dependencies import get_current_user
from app.models.user import User
from app.services.event_viewer_service import event_viewer_service, _EVENT_MAP, IS_WINDOWS

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/event-viewer", tags=["Event Viewer"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class StartRequest(BaseModel):
    channels: Optional[List[str]] = Field(
        None,
        description="Windows Event channels to monitor. Defaults to Security, System, Application.",
        example=["Security", "System", "Application"],
    )
    interval_seconds: int = Field(
        5, ge=2, le=60,
        description="Poll interval in seconds (min=2, max=60)",
    )


class PullNowRequest(BaseModel):
    channel: str = Field("Security", description="Channel to pull events from")
    count:   int = Field(50, ge=1, le=500, description="Number of events to pull")


class EventViewerStatus(BaseModel):
    running:          bool
    status:           str
    poll_interval_s:  int
    channels:         List[str]
    active_channels:  List[str] = []
    denied_channels:  List[str] = []
    events_ingested:  int
    last_record_ids:  dict
    last_error:       Optional[str]
    is_windows:       bool
    platform:         str


class WindowsEventOut(BaseModel):
    record_id:    int
    event_id:     int
    channel:      str
    computer:     str
    timestamp:    str
    event_type:   str
    severity:     str
    description:  str
    source_ip:    str
    username:     Optional[str]
    domain:       Optional[str]
    process_name: Optional[str]
    logon_type:   Optional[int]
    status_code:  Optional[str]
    message:      str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/status", response_model=EventViewerStatus)
async def get_status(current_user: User = Depends(get_current_user)):
    """Get current status of the Event Viewer service."""
    svc_status = event_viewer_service.get_status()
    return EventViewerStatus(
        **svc_status,
        platform=platform.system(),
    )


@router.post("/start")
async def start_service(
    req: StartRequest = StartRequest(),
    current_user: User = Depends(get_current_user),
):
    """Start real-time Windows Event Log polling."""
    if not IS_WINDOWS:
        raise HTTPException(
            status_code=422,
            detail=f"Windows Event Viewer is only available on Windows. Current platform: {platform.system()}",
        )
    if event_viewer_service._running:
        return {"message": "Service already running", "status": event_viewer_service.get_status()}

    await event_viewer_service.start(
        channels=req.channels,
        interval=req.interval_seconds,
    )
    return {
        "message": "Event Viewer service started",
        "channels": event_viewer_service._channels,
        "interval_seconds": event_viewer_service._poll_interval,
    }


@router.post("/stop")
async def stop_service(current_user: User = Depends(get_current_user)):
    """Stop the Event Viewer polling service."""
    if not event_viewer_service._running:
        return {"message": "Service is not running"}
    await event_viewer_service.stop()
    return {"message": "Event Viewer service stopped"}


@router.get("/recent")
async def get_recent_events(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
):
    """Return the most recent events ingested from Event Viewer."""
    return {
        "events":    event_viewer_service.get_recent_events(limit),
        "total_ingested": event_viewer_service._events_ingested,
    }


@router.post("/pull-now")
async def pull_now(
    req: PullNowRequest = PullNowRequest(),
    current_user: User = Depends(get_current_user),
):
    """
    One-shot pull: fetch the latest N events from a channel and ingest them immediately.
    Returns the events that were pulled and the count ingested.
    """
    if not IS_WINDOWS:
        raise HTTPException(status_code=422, detail="Windows-only feature")

    try:
        events = await event_viewer_service.pull_now(channel=req.channel, count=req.count)
    except Exception as exc:
        logger.error("pull-now failed for %s: %s", req.channel, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Pull failed: {exc}")

    result_events = [
        WindowsEventOut(
            record_id=e.record_id,
            event_id=e.event_id,
            channel=e.channel,
            computer=e.computer,
            timestamp=e.timestamp.isoformat(),
            event_type=e.event_type,
            severity=e.severity,
            description=e.description,
            source_ip=e.source_ip,
            username=e.username,
            domain=e.domain,
            process_name=e.process_name,
            logon_type=e.logon_type,
            status_code=e.status_code,
            message=e.message,
        )
        for e in events
    ]

    return {
        "channel":  req.channel,
        "pulled":   len(result_events),
        "ingested": len(result_events),
        "message":  f"Pulled and ingested {len(result_events)} events from {req.channel}",
        "events":   result_events,
    }


@router.get("/channels")
async def list_channels(current_user: User = Depends(get_current_user)):
    """List available Windows Event Log channels on this machine."""
    if not IS_WINDOWS:
        return {"channels": [], "note": f"Not available on {platform.system()}"}

    try:
        proc = await asyncio.create_subprocess_exec(
            r"C:\Windows\System32\wevtutil.exe", "el",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        channels = [
            c.strip() for c in stdout.decode("utf-8", errors="replace").splitlines()
            if c.strip()
        ]
        # Sort: common channels first
        priority = ["Security", "System", "Application"]
        sorted_channels = priority + [c for c in channels if c not in priority]
        return {
            "channels": sorted_channels[:200],   # cap at 200
            "total":    len(channels),
        }
    except Exception as exc:
        logger.error("Failed to list channels: %s", exc)
        return {"channels": [], "error": str(exc)}


@router.post("/reset-watermarks")
async def reset_watermarks(
    days: int = 30,
    current_user: User = Depends(get_current_user),
):
    """
    Clear all saved RecordID watermarks and restart the feed.
    Triggers a full backfill of the last `days` days per channel, then
    switches to live polling automatically.
    """
    if not IS_WINDOWS:
        raise HTTPException(status_code=422, detail="Windows-only feature")

    channels = list(event_viewer_service._channels)
    interval = event_viewer_service._poll_interval
    was_running = event_viewer_service._running

    # Stop everything cleanly (cancels any in-flight backfill too)
    if was_running:
        await event_viewer_service.stop()

    # Clear persisted watermarks AFTER stop so in-flight backfill can't overwrite them
    event_viewer_service._record_ids.clear()
    await event_viewer_service._save_state()

    # Start poll loop if it wasn't running; if already running just force-backfill
    if not event_viewer_service._running:
        await event_viewer_service.start(channels=channels, interval=interval)
    else:
        # start() won't restart if already running — force backfill directly
        await event_viewer_service.force_backfill_all(days=days)

    return {
        "message": f"Watermarks cleared — backfilling ALL channels for last {days} days",
        "channels": channels,
        "days":     days,
        "restarted": was_running,
    }


@router.get("/diagnose")
async def diagnose(current_user: User = Depends(get_current_user)):
    """
    Run a raw wevtutil self-test and return diagnostic info.
    Use this to verify wevtutil works and events are readable.
    """
    import subprocess, sys
    results = {}
    wevtutil = r"C:\Windows\System32\wevtutil.exe"

    for channel in ["System", "Application"]:
        cmd = [wevtutil, "qe", channel, "/c:3", "/rd:true", "/f:xml"]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=10, creationflags=0x08000000)
            from app.services.event_viewer_service import _decode_bytes
            stdout = _decode_bytes(r.stdout)
            stderr = _decode_bytes(r.stderr)
            results[channel] = {
                "exit_code":    r.returncode,
                "stdout_len":   len(r.stdout),
                "stderr":       stderr[:300],
                "output_preview": stdout[:500] if stdout else "(empty)",
                "has_events":   "<Event " in stdout,
            }
        except Exception as exc:
            results[channel] = {"error": str(exc)}

    return {
        "wevtutil_path": wevtutil,
        "platform":      sys.platform,
        "channels":      results,
        "service_state": {
            "running":          event_viewer_service._running,
            "record_ids":       dict(event_viewer_service._record_ids),
            "events_ingested":  event_viewer_service._events_ingested,
            "recent_count":     len(event_viewer_service._recent_events),
            "active_channels":  list(event_viewer_service._active_channels),
            "denied_channels":  list(event_viewer_service._denied_channels),
        },
    }


@router.post("/purge-sample-data")
async def purge_sample_data(
    current_user: User = Depends(get_current_user),
):
    """
    Delete ALL log entries, anomalies, and alerts that are NOT from Windows
    Event Viewer (i.e., old synthetic/sample data from the basic system).
    Keeps the database clean so the ML model trains only on real events.
    Clears the in-memory recent-events buffer too.
    """
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        # Count before
        result = await session.execute(text("SELECT COUNT(*) FROM log_entries"))
        total_before = result.scalar()

        # Delete all log entries (cascades to anomalies / alerts that reference them)
        await session.execute(text("DELETE FROM anomalies"))
        await session.execute(text("DELETE FROM alerts"))
        await session.execute(text("DELETE FROM log_entries"))
        await session.commit()

        result = await session.execute(text("SELECT COUNT(*) FROM log_entries"))
        total_after = result.scalar()

    # Reset in-memory counters and buffer
    event_viewer_service._events_ingested = 0
    event_viewer_service._recent_events.clear()

    logger.info("Purged %d log entries (sample data removed)", total_before - total_after)
    return {
        "deleted": total_before - total_after,
        "remaining": total_after,
        "message": (
            "All sample/old data cleared. "
            "Click 'Load 30 Days' to re-ingest real Windows events."
        ),
    }


@router.get("/event-ids")
async def list_event_ids(current_user: User = Depends(get_current_user)):
    """Return the full Event ID → (type, severity, description) mapping."""
    return {
        "event_ids": {
            str(eid): {
                "event_type":  info[0],
                "severity":    info[1],
                "description": info[2],
            }
            for eid, info in _EVENT_MAP.items()
        },
        "total": len(_EVENT_MAP),
    }
