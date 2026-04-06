"""
Windows Event Viewer Service
==============================
Reads real-time security events from the Windows Event Log and feeds them
directly into the AI Threat Detection pipeline.

Architecture:
  - Uses wevtutil.exe (built-in Windows tool) via asyncio subprocess — no extra libs needed
  - Tracks last processed EventRecordID per channel in Redis (falls back to file)
  - Polls configurable channels every N seconds
  - Maps 40+ Windows Event IDs to structured LogEntryCreate objects
  - Feeds into log_service.ingest_bulk() → full ML + rule + TI + SOAR pipeline

Monitored Event Channels:
  Security  — logons, failures, account changes, privilege use
  System    — service installs, crashes
  Application — application errors

Requires: Uvicorn must run with sufficient privileges to read Security channel.
  Run as Administrator OR grant read access: wevtutil sl Security /ca:"..."
"""

import asyncio
import concurrent.futures
import logging
import platform
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Thread pool for running wevtutil synchronously without blocking the event loop
_wevtutil_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=3, thread_name_prefix="wevtutil"
)

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"


def _decode_bytes(data: bytes) -> str:
    """Decode wevtutil output — handles UTF-16 LE (BOM or bare) and UTF-8."""
    if not data:
        return ""
    # UTF-16 LE BOM
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    # Bare UTF-16 LE: every other byte is 0x00 for ASCII content
    if len(data) >= 4 and data[1] == 0 and data[3] == 0:
        try:
            return data.decode("utf-16-le", errors="replace")
        except Exception:
            pass
    # Default: UTF-8 (wevtutil /f:xml on most modern Windows)
    return data.decode("utf-8", errors="replace")
_WEVTUTIL  = r"C:\Windows\System32\wevtutil.exe"
_STATE_FILE = Path(__file__).parent.parent.parent / "event_viewer_state.json"

# ---------------------------------------------------------------------------
# Event ID → (event_type, default_severity, description)
# ---------------------------------------------------------------------------

_EVENT_MAP: Dict[int, Tuple[str, str, str]] = {
    # ── Authentication ──────────────────────────────────────────────────────
    4624: ("login_success",                 "info",     "Successful logon"),
    4625: ("login_failed",                  "high",     "Failed logon attempt"),
    4634: ("logoff",                        "info",     "Account logoff"),
    4647: ("user_initiated_logoff",         "info",     "User-initiated logoff"),
    4648: ("explicit_credential_logon",     "medium",   "Logon using explicit credentials"),
    4675: ("sid_filtered",                  "medium",   "SIDs were filtered"),
    4769: ("kerberos_service_ticket",       "info",     "Kerberos service ticket"),
    4771: ("kerberos_preauthentication",    "medium",   "Kerberos pre-auth failure"),
    4776: ("credential_validation",         "medium",   "Credential validation attempt"),
    4778: ("session_reconnect",             "info",     "Session reconnected"),
    4779: ("session_disconnect",            "info",     "Session disconnected"),
    # ── Account lockout ─────────────────────────────────────────────────────
    4740: ("account_lockout",               "critical", "User account locked out"),
    4767: ("account_unlocked",              "medium",   "User account unlocked"),
    # ── Account management ──────────────────────────────────────────────────
    4720: ("user_account_created",          "high",     "New user account created"),
    4722: ("user_account_enabled",          "medium",   "User account enabled"),
    4723: ("password_change_attempt",       "medium",   "Password change attempted"),
    4724: ("password_reset_attempt",        "high",     "Password reset attempted"),
    4725: ("user_account_disabled",         "medium",   "User account disabled"),
    4726: ("user_account_deleted",          "high",     "User account deleted"),
    4727: ("global_group_created",          "medium",   "Security-enabled global group created"),
    4728: ("global_group_member_added",     "medium",   "Member added to security group"),
    4729: ("global_group_member_removed",   "medium",   "Member removed from security group"),
    4731: ("local_group_created",           "medium",   "Security-enabled local group created"),
    4732: ("local_group_member_added",      "high",     "Member added to local security group"),
    4733: ("local_group_member_removed",    "medium",   "Member removed from local group"),
    4738: ("user_account_changed",          "medium",   "User account changed"),
    4756: ("universal_group_member_added",  "medium",   "Member added to universal group"),
    # ── Privilege use ───────────────────────────────────────────────────────
    4672: ("special_privilege_logon",       "medium",   "Special privileges assigned to logon"),
    4673: ("privileged_service_called",     "medium",   "Privileged service called"),
    4674: ("privileged_object_operation",   "medium",   "Privileged object operation"),
    # ── Process & task ──────────────────────────────────────────────────────
    4688: ("process_created",               "info",     "New process created"),
    4689: ("process_terminated",            "info",     "Process exited"),
    4698: ("scheduled_task_created",        "high",     "Scheduled task created"),
    4699: ("scheduled_task_deleted",        "medium",   "Scheduled task deleted"),
    4700: ("scheduled_task_enabled",        "medium",   "Scheduled task enabled"),
    4701: ("scheduled_task_disabled",       "medium",   "Scheduled task disabled"),
    4702: ("scheduled_task_updated",        "medium",   "Scheduled task updated"),
    # ── Service installs ────────────────────────────────────────────────────
    4697: ("service_installed",             "critical", "Service installed in system"),
    7045: ("new_service_installed",         "critical", "New service installed"),
    7034: ("service_crashed",               "high",     "Service terminated unexpectedly"),
    7036: ("service_state_change",          "info",     "Service state changed"),
    7040: ("service_start_type_changed",    "medium",   "Service start type changed"),
    # ── Audit & policy ──────────────────────────────────────────────────────
    4719: ("audit_policy_changed",          "critical", "System audit policy changed"),
    4907: ("audit_settings_changed",        "high",     "Auditing settings changed"),
    4904: ("security_event_source_added",   "high",     "Security event source added"),
    4905: ("security_event_source_removed", "high",     "Security event source removed"),
    # ── Firewall ────────────────────────────────────────────────────────────
    4946: ("firewall_rule_added",           "high",     "Windows Firewall rule added"),
    4947: ("firewall_rule_modified",        "high",     "Windows Firewall rule modified"),
    4948: ("firewall_rule_deleted",         "medium",   "Windows Firewall rule deleted"),
    4950: ("firewall_setting_changed",      "medium",   "Windows Firewall setting changed"),
    # ── Network ─────────────────────────────────────────────────────────────
    5156: ("network_connection",            "info",     "Windows Filtering Platform allowed connection"),
    5157: ("network_connection_blocked",    "medium",   "Windows Filtering Platform blocked connection"),
    5158: ("bind_allowed",                  "info",     "WFP bind permitted"),
    5447: ("wfp_filter_changed",            "high",     "WFP filter changed"),
    # ── Remote Desktop / RDP ────────────────────────────────────────────────
    4821: ("rdp_connection_refused",        "medium",   "RDP connection refused"),
    1149: ("rdp_user_authenticated",        "medium",   "RDP user authentication"),
    # ── PowerShell ──────────────────────────────────────────────────────────
    4103: ("powershell_pipeline",           "medium",   "PowerShell pipeline executed"),
    4104: ("powershell_script_block",       "high",     "PowerShell script block logged"),
}

# Severity name → Severity enum value
_SEVERITY_NORM = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
}

# Channels to monitor
# Channels that work without special permissions
_DEFAULT_CHANNELS = [
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
]

# Security channel needs SeSecurityPrivilege — added only when explicitly requested
# or when the backend detects it can read it successfully
_ELEVATED_CHANNELS = ["Security"]

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


# ---------------------------------------------------------------------------
# Parsed event dataclass
# ---------------------------------------------------------------------------

@dataclass
class WindowsEvent:
    record_id:     int
    event_id:      int
    channel:       str
    computer:      str
    timestamp:     datetime
    event_type:    str
    severity:      str
    description:   str
    source_ip:     str
    username:      Optional[str]
    domain:        Optional[str]
    process_name:  Optional[str]
    logon_type:    Optional[int]
    status_code:   Optional[str]
    message:       str
    raw_xml:       str
    data:          Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class EventViewerService:
    """
    Polls Windows Event Log channels and ingests events into the SOC platform.
    """

    def __init__(self):
        self._running:         bool       = False
        self._task:            Optional[asyncio.Task] = None
        self._backfill_task:   Optional[asyncio.Task] = None  # tracked separately so stop() cancels it
        self._snapshot_task:   Optional[asyncio.Task] = None  # periodic 5-min safety-net pull
        self._poll_interval:   int        = 5        # seconds
        self._channels:        List[str]  = _DEFAULT_CHANNELS
        self._record_ids:      Dict[str, int] = {}   # channel → last processed RecordID
        self._events_ingested: int        = 0
        self._events_per_poll: int        = 200      # max events per channel per poll
        self._last_error:      Optional[str] = None
        self._status_msg:      str        = "Stopped"
        self._recent_events:   List[dict] = []       # last 200 events for the UI
        self._elevation_warned: set       = set()    # channels already warned about elevation
        self._denied_channels:  set       = set()    # channels blocked by permissions
        self._active_channels:  set       = set()    # channels confirmed working

    # -----------------------------------------------------------------------
    # Public control
    # -----------------------------------------------------------------------

    async def start(self, channels: Optional[List[str]] = None, interval: int = 5):
        if not IS_WINDOWS:
            logger.warning("EventViewerService: Windows-only — skipping on %s", platform.system())
            self._status_msg = f"Not supported on {platform.system()}"
            return

        if self._running:
            logger.info("EventViewerService already running")
            return

        if channels:
            self._channels = channels

        self._poll_interval = max(interval, 2)
        self._running = True
        self._status_msg = "Starting…"
        self._last_error = None
        self._elevation_warned.clear()
        self._denied_channels.clear()
        self._active_channels.clear()

        # Load persisted state
        await self._load_state()

        # ── Wevtutil self-test ──────────────────────────────────────────────────
        # Fetch 1 event from System so we know wevtutil works before starting loops
        test_out = await self._run_wevtutil("System", "*", count=1)
        if test_out:
            logger.info("EventViewer self-test OK — wevtutil returned %d chars from System", len(test_out))
        else:
            logger.warning(
                "EventViewer self-test FAILED — wevtutil returned nothing for System. "
                "Check that wevtutil.exe exists and the backend has read access to event logs."
            )
        # ────────────────────────────────────────────────────────────────────────

        # Start the poll loop immediately so the service responds
        self._task = asyncio.create_task(self._poll_loop(), name="event_viewer_poll")
        # Periodic snapshot every 5 minutes as a safety-net and to keep live feed fresh
        self._snapshot_task = asyncio.create_task(
            self._snapshot_loop(interval_minutes=5), name="event_viewer_snapshot"
        )
        # Populate the live feed from DB so it shows events immediately after restart
        asyncio.create_task(self._refresh_recent_from_db(), name="event_viewer_db_refresh")
        logger.info("EventViewerService started (channels=%s, interval=%ds)", self._channels, self._poll_interval)

        # Backfill fresh channels in background — does NOT block start() returning
        fresh_channels = [ch for ch in self._channels if ch not in self._record_ids]
        if fresh_channels:
            logger.info("EventViewer: scheduling 30-day backfill for: %s", fresh_channels)
            self._backfill_task = asyncio.create_task(
                self._run_backfill(fresh_channels, days=30),
                name="event_viewer_backfill",
            )
        else:
            logger.info(
                "EventViewer: all channels have watermarks — live polling only. "
                "Click 'Load 30 Days' to force a full re-backfill."
            )

    async def stop(self):
        self._running = False
        # Cancel backfill first — prevents it writing stale watermarks after stop()
        if self._backfill_task and not self._backfill_task.done():
            self._backfill_task.cancel()
            try:
                await self._backfill_task
            except asyncio.CancelledError:
                pass
            self._backfill_task = None
        if self._snapshot_task and not self._snapshot_task.done():
            self._snapshot_task.cancel()
            try:
                await self._snapshot_task
            except asyncio.CancelledError:
                pass
            self._snapshot_task = None
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._save_state()
        self._status_msg = "Stopped"
        logger.info("EventViewerService stopped")

    def get_status(self) -> dict:
        return {
            "running":          self._running,
            "status":           self._status_msg,
            "poll_interval_s":  self._poll_interval,
            "channels":         self._channels,
            "active_channels":  list(self._active_channels),
            "denied_channels":  list(self._denied_channels),
            "events_ingested":  self._events_ingested,
            "last_record_ids":  self._record_ids,
            "last_error":       self._last_error,
            "is_windows":       IS_WINDOWS,
        }

    def get_recent_events(self, limit: int = 50) -> List[dict]:
        return self._recent_events[-limit:]

    # -----------------------------------------------------------------------
    # Polling loop
    # -----------------------------------------------------------------------

    async def _poll_loop(self):
        self._status_msg = "Polling"
        while self._running:
            try:
                total = 0
                for channel in self._channels:
                    count = await self._poll_channel(channel)
                    total += count

                if total > 0:
                    logger.info("EventViewer: ingested %d events this poll", total)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._last_error = str(exc)
                logger.error("EventViewer poll error: %s", exc, exc_info=True)

            await asyncio.sleep(self._poll_interval)

    async def _poll_channel(self, channel: str) -> int:
        last_id = self._record_ids.get(channel, 0)

        # XPath query: events after last RecordID
        # No spaces in XPath — spaces cause list2cmdline to wrap the arg in
        # double-quotes which wevtutil treats as literal characters and rejects
        query = f"*[System[(EventRecordID>{last_id})]]"

        xml_output = await self._run_wevtutil(channel, query)
        if not xml_output:
            return 0

        events = self._parse_xml(xml_output, channel)
        if not events:
            return 0

        # Successful read — mark channel as active, clear any denied flag
        self._active_channels.add(channel)
        self._denied_channels.discard(channel)
        self._elevation_warned.discard(channel)

        # Update RecordID watermark
        max_rid = max(e.record_id for e in events)
        self._record_ids[channel] = max_rid
        await self._save_state()

        # Convert and ingest
        await self._ingest_events(events)
        return len(events)

    # -----------------------------------------------------------------------
    # wevtutil runner
    # -----------------------------------------------------------------------

    async def _run_wevtutil(
        self, channel: str, query: str, count: int = 200
    ) -> Optional[str]:
        """
        Call wevtutil.exe via a thread-pool executor (avoids Proactor event loop
        subprocess issues on Windows) and return raw XML string.
        """
        cmd = [
            _WEVTUTIL, "qe", channel,
            f"/c:{count}",
            "/rd:true",         # newest first (we reverse after parsing)
            "/f:xml",
            f"/q:{query}",
        ]

        def _run() -> Optional[str]:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=30,
                    creationflags=0x08000000,   # CREATE_NO_WINDOW — no console popup
                )
                stderr_bytes = result.stderr
                stdout_bytes = result.stdout

                if result.returncode != 0:
                    err = _decode_bytes(stderr_bytes)
                    out = _decode_bytes(stdout_bytes)
                    if "access is denied" in err.lower() or "access is denied" in out.lower():
                        self._denied_channels.add(channel)
                        if channel not in self._elevation_warned:
                            self._elevation_warned.add(channel)
                            logger.warning(
                                "EventViewer: '%s' requires elevated privileges — skipping.",
                                channel,
                            )
                    else:
                        logger.warning(
                            "wevtutil [%s] exit=%d stderr=%r stdout_len=%d",
                            channel, result.returncode, err[:300], len(stdout_bytes),
                        )
                    return None

                raw = _decode_bytes(stdout_bytes).strip()
                if raw:
                    logger.debug("wevtutil [%s] OK — %d chars", channel, len(raw))
                else:
                    logger.debug("wevtutil [%s] OK — empty output (0 events)", channel)
                return raw if raw else None

            except FileNotFoundError:
                self._last_error = "wevtutil.exe not found"
                logger.error("wevtutil.exe not found at %s", _WEVTUTIL)
                return None
            except subprocess.TimeoutExpired:
                logger.warning("wevtutil timeout for channel %s", channel)
                return None
            except Exception as exc:
                logger.warning("wevtutil error [%s]: %s", channel, exc)
                return None

        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(_wevtutil_executor, _run),
                timeout=20.0,
            )
        except asyncio.TimeoutError:
            logger.warning("wevtutil executor timeout for channel %s", channel)
            return None

    async def _snapshot_loop(self, interval_minutes: int = 5):
        """
        Every `interval_minutes`, pull the last interval+1 minutes of events from
        all channels. This acts as a safety net for any events missed by the
        watermark-based poll loop, and keeps the live feed visibly active.
        """
        interval_secs = interval_minutes * 60
        await asyncio.sleep(interval_secs)   # first snapshot after one full interval
        while self._running:
            logger.info("EventViewer: scheduled %d-min snapshot pull", interval_minutes)
            total = 0
            for channel in self._channels:
                if not self._running:
                    break
                if channel in self._denied_channels:
                    continue
                # Pull the most recent events — count covers ~1 event/sec × interval
                xml_output = await self._run_wevtutil(channel, "*", count=min(interval_minutes * 60, 1000))
                if xml_output:
                    events = self._parse_xml(xml_output, channel)
                    # Only ingest events we haven't seen (RecordID > current watermark)
                    watermark = self._record_ids.get(channel, 0)
                    new_events = [e for e in events if e.record_id > watermark]
                    if new_events:
                        await self._ingest_events(new_events)
                        max_rid = max(e.record_id for e in new_events)
                        self._record_ids[channel] = max_rid
                        total += len(new_events)
                        logger.info("EventViewer snapshot [%s]: +%d new events", channel, len(new_events))
            if total:
                await self._save_state()
                logger.info("EventViewer snapshot complete — %d new events total", total)
            else:
                logger.debug("EventViewer snapshot: no new events across all channels")
            await asyncio.sleep(interval_secs)

    async def _refresh_recent_from_db(self):
        """
        On startup, populate _recent_events from the DB so the Live Feed
        shows real events immediately (not empty after backend restart).
        """
        try:
            from app.core.database import AsyncSessionLocal
            from sqlalchemy import select, desc
            from app.models.log_entry import LogEntry

            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(LogEntry)
                    .order_by(desc(LogEntry.ingested_at))
                    .limit(200)
                )
                entries = result.scalars().all()

            for e in reversed(entries):   # oldest first
                self._recent_events.append({
                    "record_id":  None,
                    "event_id":   None,
                    "channel":    "DB",
                    "timestamp":  e.timestamp.isoformat() if e.timestamp else None,
                    "event_type": e.event_type,
                    "severity":   e.severity.value if hasattr(e.severity, "value") else str(e.severity),
                    "source_ip":  e.source_ip,
                    "username":   e.username,
                    "message":    (e.message or "")[:200],
                })

            if len(self._recent_events) > 200:
                self._recent_events = self._recent_events[-200:]

            if entries:
                logger.info("EventViewer: pre-loaded %d recent events from DB into live feed", len(entries))
        except Exception as exc:
            logger.debug("_refresh_recent_from_db failed: %s", exc)

    async def force_backfill_all(self, days: int = 30):
        """Cancel any running backfill and start a fresh one for ALL channels."""
        if self._backfill_task and not self._backfill_task.done():
            self._backfill_task.cancel()
            try:
                await self._backfill_task
            except asyncio.CancelledError:
                pass
        # Clear watermarks in memory so _run_backfill writes fresh ones
        self._record_ids.clear()
        logger.info("EventViewer: force-backfill ALL channels for last %d days", days)
        self._backfill_task = asyncio.create_task(
            self._run_backfill(list(self._channels), days=days),
            name="event_viewer_backfill",
        )

    async def _run_backfill(self, channels: list, days: int = 30):
        """Background task: sequentially backfill each channel then save state."""
        self._status_msg = f"Backfilling {len(channels)} channel(s)…"
        for channel in channels:
            if not self._running:
                break
            await self._backfill_channel(channel, days=days)
        await self._save_state()
        self._status_msg = "Running"
        logger.info("EventViewer: background backfill complete for %s", channels)

    async def _backfill_channel(self, channel: str, days: int = 30):
        """
        Pull the most recent events for a channel (up to 5000), ingest them, then
        set the watermark so live polling takes over from that point.
        Uses a simple '*' query for maximum compatibility — wevtutil /rd:true returns
        newest-first, so the first 5000 events cover the last ~30 days on most machines.
        """
        logger.info("EventViewer backfill: %s — fetching up to 5000 recent events", channel)

        # Simple '*' query is the most reliable — no XPath date math that wevtutil
        # sometimes rejects with cryptic errors
        xml_output = await self._run_wevtutil(channel, "*", count=5000)
        if not xml_output:
            # Channel inaccessible — set watermark to 0 so live polling tries again later
            self._record_ids[channel] = 0
            await self._save_state()
            return

        events = self._parse_xml(xml_output, channel)
        if not events:
            self._record_ids[channel] = 0
            await self._save_state()
            return

        total = len(events)
        max_rid = max(e.record_id for e in events)

        # Save watermark immediately so live polling starts from here even if
        # ingestion is interrupted
        self._record_ids[channel] = max_rid
        await self._save_state()

        # Ingest in batches of 500 so we don't block the event loop too long
        BATCH = 500
        ingested = 0
        for i in range(0, total, BATCH):
            batch = events[i : i + BATCH]
            await self._ingest_events(batch)
            ingested += len(batch)
            logger.info(
                "EventViewer backfill: %s — ingested %d / %d events…",
                channel, ingested, total,
            )
            # Yield control between batches so the event loop stays responsive
            await asyncio.sleep(0)

        logger.info(
            "EventViewer backfill complete: %s — %d events over last %d days (watermark=%d)",
            channel, total, days, max_rid,
        )

    async def _get_current_max_record_id(self, channel: str) -> int:
        """Get the highest RecordID currently in the channel (for bootstrapping)."""
        xml_output = await self._run_wevtutil(channel, "*", count=1)
        if not xml_output:
            return 0
        events = self._parse_xml(xml_output, channel)
        if events:
            return events[0].record_id
        return 0

    # -----------------------------------------------------------------------
    # XML parsing
    # -----------------------------------------------------------------------

    def _parse_xml(self, xml_text: str, channel: str) -> List[WindowsEvent]:
        """Parse wevtutil XML output into WindowsEvent objects."""
        events: List[WindowsEvent] = []

        if not xml_text:
            return events

        # wevtutil prepends an XML declaration to its output:
        #   <?xml version="1.0" encoding="UTF-16"?>
        # Placing that declaration inside a wrapper element makes invalid XML,
        # so strip ALL processing instructions / declarations before wrapping.
        cleaned = re.sub(r'<\?xml[^?]*\?>', '', xml_text).strip()

        # wevtutil outputs individual <Event> elements without a root wrapper.
        # Wrap them so we can parse as a single document.
        # Declare the Windows Event namespace on the root so child lookups work.
        wrapped = (
            '<Events xmlns:e="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'{cleaned}'
            '</Events>'
        )

        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError as exc:
            logger.debug("Bulk XML parse failed (%s), trying per-event fallback: %s", channel, exc)
            # Fallback: split on <Event and parse each chunk individually
            for chunk in re.split(r'(?=<Event[\s>])', cleaned):
                chunk = chunk.strip()
                if not chunk:
                    continue
                try:
                    ev = ET.fromstring(chunk)
                    parsed = self._parse_single_event(ev, channel)
                    if parsed:
                        events.append(parsed)
                except ET.ParseError:
                    pass
            events.reverse()
            logger.debug("Per-event fallback parsed %d events from %s", len(events), channel)
            return events

        # Find <Event> elements — they may be namespaced or plain depending on wevtutil version
        found = root.findall("Event") or root.findall(
            "{http://schemas.microsoft.com/win/2004/08/events/event}Event"
        )
        for ev_elem in found:
            parsed = self._parse_single_event(ev_elem, channel)
            if parsed:
                events.append(parsed)

        # Reverse so we process oldest → newest (wevtutil /rd:true returns newest first)
        events.reverse()
        logger.debug("Parsed %d events from %s", len(events), channel)
        return events

    def _parse_single_event(
        self, ev: ET.Element, channel: str
    ) -> Optional[WindowsEvent]:
        """Extract fields from a single <Event> XML element."""
        try:
            ns = {"e": _NS}

            def find(path: str) -> Optional[ET.Element]:
                return ev.find(path, ns)

            def text(path: str) -> str:
                el = find(path)
                return (el.text or "").strip() if el is not None else ""

            sys_el = find("e:System")
            if sys_el is None:
                return None

            event_id   = int(text("e:System/e:EventID") or "0")
            record_id  = int(text("e:System/e:EventRecordID") or "0")
            computer   = text("e:System/e:Computer")
            ts_str     = (find("e:System/e:TimeCreated") or ET.Element("")).get("SystemTime", "")
            channel_el = text("e:System/e:Channel")

            # Parse timestamp
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00").rstrip("0").rstrip(".") + "Z"
                                            if "." in ts_str and not ts_str.endswith("Z")
                                            else ts_str.replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now(timezone.utc)

            # EventData extraction
            data: Dict[str, str] = {}
            for data_el in ev.findall(".//e:EventData/e:Data", ns):
                name  = data_el.get("Name", "")
                value = (data_el.text or "").strip()
                if name and value and value != "-":
                    data[name] = value

            # Also handle <UserData> elements
            for ud_el in ev.findall(".//e:UserData//*", ns):
                name = ud_el.tag.split("}")[-1]   # strip namespace
                if ud_el.text and ud_el.text.strip():
                    data[name] = ud_el.text.strip()

            # Map event ID
            mapped = _EVENT_MAP.get(event_id)
            event_type  = mapped[0] if mapped else f"event_{event_id}"
            severity    = mapped[1] if mapped else "info"
            description = mapped[2] if mapped else f"Windows Event {event_id}"

            # Extract IP (multiple field names used across event IDs)
            source_ip = (
                data.get("IpAddress") or
                data.get("SourceAddress") or
                data.get("ClientAddress") or
                data.get("Workstation") or   # sometimes FQDN
                data.get("WorkstationName") or
                ""
            ).strip().rstrip(".")

            # Sanitise IP — if it's a hostname not an IP, use 0.0.0.0
            if source_ip and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+$", source_ip):
                source_ip = "0.0.0.0"
            if not source_ip or source_ip in ("::1", "127.0.0.1", "LOCAL", "-"):
                source_ip = "127.0.0.1"

            # Username
            username = (
                data.get("TargetUserName") or
                data.get("SubjectUserName") or
                data.get("AccountName") or
                data.get("UserName") or
                ""
            ).strip()
            if username in ("-", "$", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                username = None

            domain = (
                data.get("TargetDomainName") or
                data.get("SubjectDomainName") or
                ""
            ).strip() or None

            # Process name
            process_name = (
                data.get("NewProcessName") or
                data.get("ProcessName") or
                ""
            ) or None

            # Logon type
            logon_type_str = data.get("LogonType", "")
            logon_type = int(logon_type_str) if logon_type_str.isdigit() else None

            # Status code (for failed logons)
            status_code = data.get("Status") or data.get("SubStatus")

            # Build human-readable message
            parts = [f"[{channel_el or channel}] EventID={event_id}: {description}"]
            if username:
                parts.append(f"User: {username}" + (f"\\{domain}" if domain else ""))
            if source_ip and source_ip != "127.0.0.1":
                parts.append(f"From: {source_ip}")
            if logon_type:
                logon_names = {2:"Interactive", 3:"Network", 4:"Batch", 5:"Service", 7:"Unlock",
                               8:"NetworkCleartext", 9:"NewCredentials", 10:"RemoteInteractive", 11:"CachedInteractive"}
                parts.append(f"Logon: {logon_names.get(logon_type, str(logon_type))}")
            if status_code:
                parts.append(f"Status: {status_code}")
            if process_name:
                parts.append(f"Process: {process_name}")

            message = " | ".join(parts)

            # Build raw XML (truncated)
            raw_xml = ET.tostring(ev, encoding="unicode")[:2000]

            return WindowsEvent(
                record_id=record_id,
                event_id=event_id,
                channel=channel_el or channel,
                computer=computer,
                timestamp=ts,
                event_type=event_type,
                severity=severity,
                description=description,
                source_ip=source_ip,
                username=username,
                domain=domain,
                process_name=process_name,
                logon_type=logon_type,
                status_code=status_code,
                message=message,
                raw_xml=raw_xml,
                data=data,
            )

        except Exception as exc:
            logger.debug("Failed to parse event: %s", exc)
            return None

    # -----------------------------------------------------------------------
    # Ingestion
    # -----------------------------------------------------------------------

    async def _ingest_events(self, events: List[WindowsEvent]):
        """Convert WindowsEvent objects to LogEntryCreate and ingest."""
        from app.schemas.log_entry import LogEntryCreate
        from app.models.log_entry import Protocol, Severity
        from app.services.log_service import log_service
        from app.core.database import AsyncSessionLocal

        def _map_severity(sev: str):
            return Severity(sev) if sev in Severity.__members__.values() else Severity.INFO

        def _map_protocol(ev: WindowsEvent) -> Protocol:
            # Network events often specify protocol in data
            proto = ev.data.get("Protocol", "").upper()
            if proto in ("TCP", "6"):   return Protocol.TCP
            if proto in ("UDP", "17"):  return Protocol.UDP
            if proto in ("ICMP", "1"):  return Protocol.ICMP
            return Protocol.OTHER

        log_entries = []
        for ev in events:
            try:
                # Destination port from network events
                dst_port = None
                dst_port_str = ev.data.get("DestPort") or ev.data.get("DestinationPort") or ""
                if dst_port_str.isdigit():
                    dst_port = int(dst_port_str)

                src_port = None
                src_port_str = ev.data.get("SourcePort") or ""
                if src_port_str.isdigit():
                    src_port = int(src_port_str)

                entry = LogEntryCreate(
                    timestamp=ev.timestamp,
                    source_ip=ev.source_ip,
                    destination_ip=None,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol=_map_protocol(ev),
                    event_type=ev.event_type,
                    severity=_map_severity(ev.severity),
                    message=ev.message,
                    raw_log=ev.raw_xml[:1000],
                    username=ev.username,
                )
                log_entries.append(entry)

            except Exception as exc:
                logger.debug("Failed to convert event %d: %s", ev.event_id, exc)

        if not log_entries:
            return

        try:
            async with AsyncSessionLocal() as session:
                result = await log_service.ingest_bulk(session, log_entries)
                ingested = result.get("ingested", 0)
                self._events_ingested += ingested

                # Keep recent events for the UI (last 100)
                for ev in events[-ingested:]:
                    self._recent_events.append({
                        "record_id":  ev.record_id,
                        "event_id":   ev.event_id,
                        "channel":    ev.channel,
                        "timestamp":  ev.timestamp.isoformat(),
                        "event_type": ev.event_type,
                        "severity":   ev.severity,
                        "source_ip":  ev.source_ip,
                        "username":   ev.username,
                        "message":    ev.message[:200],
                    })

                # Trim to last 200 entries
                if len(self._recent_events) > 200:
                    self._recent_events = self._recent_events[-200:]

                logger.info(
                    "EventViewer: ingested %d/%d events (alerts=%d, anomalies=%d)",
                    ingested, len(log_entries),
                    result.get("alerts_created", 0),
                    result.get("anomalies_detected", 0),
                )
        except Exception as exc:
            self._last_error = str(exc)
            logger.error("EventViewer ingestion error: %s", exc, exc_info=True)

    # -----------------------------------------------------------------------
    # Manual pull (for the "pull now" endpoint)
    # -----------------------------------------------------------------------

    async def pull_now(
        self, channel: str = "Security", count: int = 50
    ) -> List[WindowsEvent]:
        """Pull the most recent N events from a channel, ingest them, and return the list."""
        xml_output = await self._run_wevtutil(channel, "*", count=count)
        if not xml_output:
            return []
        events = self._parse_xml(xml_output, channel)
        if events:
            await self._ingest_events(events)   # save to DB + fire detection pipeline
            logger.info("EventViewer manual pull: %s → %d events ingested", channel, len(events))
        return events

    # -----------------------------------------------------------------------
    # State persistence (Redis preferred, file fallback)
    # -----------------------------------------------------------------------

    async def _save_state(self):
        import json
        from app.services.cache_service import cache_service

        state = {ch: rid for ch, rid in self._record_ids.items()}
        try:
            if cache_service.available:
                await cache_service.set("evtviewer:state", state, ttl=86400 * 30)
                return
        except Exception:
            pass
        # File fallback
        try:
            _STATE_FILE.write_text(json.dumps(state))
        except Exception:
            pass

    async def _load_state(self):
        import json
        from app.services.cache_service import cache_service

        try:
            if cache_service.available:
                data = await cache_service.get("evtviewer:state")
                if data and isinstance(data, dict):
                    self._record_ids = {k: int(v) for k, v in data.items()}
                    logger.info("EventViewer: loaded state from Redis (%d channels)", len(self._record_ids))
                    return
        except Exception:
            pass
        # File fallback
        try:
            if _STATE_FILE.exists():
                data = json.loads(_STATE_FILE.read_text())
                self._record_ids = {k: int(v) for k, v in data.items()}
                logger.info("EventViewer: loaded state from file (%d channels)", len(self._record_ids))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

event_viewer_service = EventViewerService()
