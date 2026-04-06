"""
Log Service: handles log ingestion, storage, querying, and statistics.
Coordinates with the ML model, rule engine, threat intel, and behavioral profiling.
"""
import asyncio
import csv
import json
import io
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, AsyncIterator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc, text
from app.models.log_entry import LogEntry, Severity, Protocol
from app.models.anomaly import Anomaly
from app.schemas.log_entry import LogEntryCreate, LogStatistics
from app.services.rule_engine import rule_engine
from app.services.alert_service import alert_service
from app.services.behavioral_profile_service import behavioral_profile_service
from app.services.soar_service import soar_service
from app.services.cache_service import cache_service
from app.ml.model_manager import model_manager
from app.core.config import settings

logger = logging.getLogger(__name__)


class LogService:
    """Handles all log ingestion, parsing, storage, and retrieval operations."""

    async def ingest_single(
        self,
        db: AsyncSession,
        log_data: LogEntryCreate,
    ) -> tuple[LogEntry, Optional[float]]:
        """
        Ingest a single log entry:
        1. Store in database
        2. Score with ML model
        3. Evaluate against rule engine
        4. Create alerts if necessary
        Returns (log_entry, anomaly_score).
        """
        log_entry = LogEntry(**log_data.model_dump())
        db.add(log_entry)
        await db.flush()  # Get ID

        log_dict = self._log_to_dict(log_entry)

        # Behavioral profile update (fast Redis ops, non-blocking)
        profile = await behavioral_profile_service.update_ip(log_entry.source_ip, log_dict)
        if log_entry.username:
            await behavioral_profile_service.update_user(log_entry.username, log_dict)

        # Quick blacklist check — mark log entry if source IP is blocked
        if await soar_service.is_blocked(log_entry.source_ip):
            log_entry.is_blacklisted = True
            await soar_service.record_block_hit(log_entry.source_ip, db)

        # ML anomaly scoring
        anomaly_score = await model_manager.score_log(log_dict)

        # Store anomaly record if above threshold
        if anomaly_score >= settings.ANOMALY_THRESHOLD:
            anomaly = Anomaly(
                log_entry_id=log_entry.id,
                anomaly_score=anomaly_score,
                model_name="EnsembleAnomalyDetector",
                source_ip=log_entry.source_ip,
                event_type=log_entry.event_type,
                feature_vector=log_dict,
            )
            db.add(anomaly)

            await alert_service.create_from_anomaly(
                db=db,
                anomaly_score=anomaly_score,
                log_dict=log_dict,
                log_entry_id=log_entry.id,
            )

        # Rule-based evaluation (now async with Redis state)
        rule_matches = await rule_engine.evaluate(log_dict)
        for match in rule_matches:
            match.log_entry_id = log_entry.id
            await alert_service.create_from_rule_match(db=db, match=match, log_dict=log_dict)

        model_manager.notify_ingested(1)

        await db.commit()
        await db.refresh(log_entry)

        # Async TI enrichment for the log entry (non-blocking background task)
        asyncio.create_task(self._enrich_log_with_ti(log_entry.id, log_entry.source_ip))

        return log_entry, anomaly_score

    async def ingest_bulk(
        self,
        db: AsyncSession,
        logs_data: List[LogEntryCreate],
    ) -> Dict[str, Any]:
        """
        Bulk ingest log entries with batch ML scoring.
        More efficient than individual ingestion for large batches.
        """
        log_entries = []
        for log_data in logs_data:
            entry = LogEntry(**log_data.model_dump())
            db.add(entry)
            log_entries.append(entry)

        await db.flush()

        log_dicts = [self._log_to_dict(e) for e in log_entries]

        # Batch ML scoring
        scores = await model_manager.score_bulk(log_dicts)

        alerts_created = 0
        anomalies_created = 0

        for entry, log_dict, score in zip(log_entries, log_dicts, scores):
            log_dict["id"] = entry.id

            # Update behavioral profiles (Redis, fast)
            await behavioral_profile_service.update_ip(entry.source_ip, log_dict)
            if entry.username:
                await behavioral_profile_service.update_user(entry.username, log_dict)

            # Blacklist check
            if await soar_service.is_blocked(entry.source_ip):
                entry.is_blacklisted = True

            if score >= settings.ANOMALY_THRESHOLD:
                anomaly = Anomaly(
                    log_entry_id=entry.id,
                    anomaly_score=score,
                    model_name="EnsembleAnomalyDetector",
                    source_ip=entry.source_ip,
                    event_type=entry.event_type,
                )
                db.add(anomaly)
                anomalies_created += 1

            # Rule evaluation (async, Redis-backed)
            matches = await rule_engine.evaluate(log_dict)
            for match in matches:
                match.log_entry_id = entry.id
                await alert_service.create_from_rule_match(db=db, match=match, log_dict=log_dict)
                alerts_created += 1

        await db.commit()
        model_manager.notify_ingested(len(log_entries))

        # Trigger background retraining if threshold reached (use fresh session)
        if model_manager.should_retrain():
            asyncio.create_task(model_manager._safe_retrain())

        # Invalidate cached dashboard stats
        await cache_service.invalidate_dashboard()

        return {
            "ingested":           len(log_entries),
            "anomalies_detected": anomalies_created,
            "alerts_created":     alerts_created,
        }

    async def parse_and_ingest_file(
        self,
        db: AsyncSession,
        file_content: bytes,
        filename: str,
    ) -> Dict[str, Any]:
        """
        Parse an uploaded file (CSV, JSON, syslog) and ingest all log entries.
        Supports CSV, JSON array, and newline-delimited JSON formats.
        """
        filename_lower = filename.lower()
        logs_data: List[LogEntryCreate] = []

        try:
            if filename_lower.endswith(".csv"):
                logs_data = self._parse_csv(file_content)
            elif filename_lower.endswith(".json"):
                logs_data = self._parse_json(file_content)
            elif filename_lower.endswith((".log", ".txt")):
                logs_data = self._parse_syslog(file_content)
            else:
                raise ValueError(f"Unsupported file format: {filename}")
        except Exception as e:
            raise ValueError(f"Failed to parse file '{filename}': {e}")

        if not logs_data:
            return {"ingested": 0, "message": "No valid log entries found in file"}

        return await self.ingest_bulk(db, logs_data)

    def _parse_csv(self, content: bytes) -> List[LogEntryCreate]:
        """Parse CSV log file into LogEntryCreate objects."""
        text = content.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        logs = []
        for row in reader:
            try:
                logs.append(self._dict_to_log_entry(row))
            except Exception as e:
                logger.debug(f"Skipping CSV row: {e}")
        return logs

    def _parse_json(self, content: bytes) -> List[LogEntryCreate]:
        """Parse JSON log file (array or newline-delimited)."""
        text = content.decode("utf-8", errors="replace").strip()
        logs = []
        try:
            data = json.loads(text)
            if isinstance(data, list):
                for item in data:
                    try:
                        logs.append(self._dict_to_log_entry(item))
                    except Exception:
                        pass
            elif isinstance(data, dict):
                logs.append(self._dict_to_log_entry(data))
        except json.JSONDecodeError:
            # Try newline-delimited JSON
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        item = json.loads(line)
                        logs.append(self._dict_to_log_entry(item))
                    except Exception:
                        pass
        return logs

    def _parse_syslog(self, content: bytes) -> List[LogEntryCreate]:
        """Parse basic syslog format into structured log entries."""
        text = content.decode("utf-8", errors="replace")
        logs = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                # Basic syslog parsing: extract timestamp and message
                parts = line.split(" ", 4)
                timestamp = datetime.now(timezone.utc)
                src_ip = "127.0.0.1"

                # Try to extract timestamp from first 3 tokens (syslog format)
                if len(parts) >= 3:
                    try:
                        ts_str = " ".join(parts[:3])
                        timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(
                            year=datetime.now().year, tzinfo=timezone.utc
                        )
                    except ValueError:
                        pass

                # Extract IP-like strings from the message
                import re
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                if ips:
                    src_ip = ips[0]

                logs.append(LogEntryCreate(
                    timestamp=timestamp,
                    source_ip=src_ip,
                    event_type="syslog_event",
                    severity=Severity.INFO,
                    message=line[:500],
                    raw_log=line[:1000],
                ))
            except Exception:
                pass
        return logs

    def _dict_to_log_entry(self, data: dict) -> LogEntryCreate:
        """Convert a raw dict to LogEntryCreate, handling various field name formats."""
        # Normalize common field name variations
        def get(keys, default=None):
            for k in keys:
                v = data.get(k) or data.get(k.lower()) or data.get(k.upper())
                if v is not None and v != "":
                    return v
            return default

        timestamp_raw = get(["timestamp", "ts", "time", "date", "@timestamp"])
        if timestamp_raw:
            if isinstance(timestamp_raw, (int, float)):
                timestamp = datetime.fromtimestamp(timestamp_raw, tz=timezone.utc)
            else:
                try:
                    timestamp = datetime.fromisoformat(str(timestamp_raw).replace("Z", "+00:00"))
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        return LogEntryCreate(
            timestamp=timestamp,
            source_ip=str(get(["source_ip", "src_ip", "src", "srcip", "client_ip"], "0.0.0.0")),
            destination_ip=get(["destination_ip", "dst_ip", "dst", "dstip", "server_ip"]),
            source_port=self._safe_int(get(["source_port", "src_port", "sport"])),
            destination_port=self._safe_int(get(["destination_port", "dst_port", "dport", "port"])),
            protocol=self._normalize_protocol(get(["protocol", "proto"], "OTHER")),
            event_type=str(get(["event_type", "event", "type", "action", "category"], "unknown")),
            severity=self._normalize_severity(get(["severity", "level", "priority"], "info")),
            message=get(["message", "msg", "description", "details"]),
            raw_log=str(data)[:1000],
            bytes_sent=self._safe_int(get(["bytes_sent", "bytes_out", "out_bytes"])),
            bytes_received=self._safe_int(get(["bytes_received", "bytes_in", "in_bytes"])),
            duration_ms=self._safe_float(get(["duration_ms", "duration", "elapsed"])),
            username=get(["username", "user", "user_name"]),
            country_code=get(["country_code", "country", "geo_country"]),
        )

    def _safe_int(self, value) -> Optional[int]:
        try:
            return int(value) if value is not None else None
        except (ValueError, TypeError):
            return None

    def _safe_float(self, value) -> Optional[float]:
        try:
            return float(value) if value is not None else None
        except (ValueError, TypeError):
            return None

    def _normalize_protocol(self, value) -> Protocol:
        mapping = {
            "tcp": Protocol.TCP, "udp": Protocol.UDP, "icmp": Protocol.ICMP,
            "http": Protocol.HTTP, "https": Protocol.HTTPS, "dns": Protocol.DNS,
            "ftp": Protocol.FTP, "ssh": Protocol.SSH,
        }
        return mapping.get(str(value).lower(), Protocol.OTHER)

    def _normalize_severity(self, value) -> Severity:
        mapping = {
            "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
            "high": Severity.HIGH, "critical": Severity.CRITICAL,
            "warning": Severity.MEDIUM, "warn": Severity.MEDIUM, "error": Severity.HIGH,
            "debug": Severity.INFO, "notice": Severity.LOW,
        }
        return mapping.get(str(value).lower(), Severity.INFO)

    def _log_to_dict(self, log: LogEntry) -> dict:
        """Convert SQLAlchemy LogEntry to a plain dict for ML/rule processing."""
        return {
            "id": log.id,
            "timestamp": log.timestamp,
            "source_ip": log.source_ip,
            "destination_ip": log.destination_ip,
            "source_port": log.source_port,
            "destination_port": log.destination_port,
            "protocol": log.protocol.value if log.protocol else "OTHER",
            "event_type": log.event_type,
            "severity": log.severity.value if log.severity else "info",
            "message": log.message,
            "bytes_sent": log.bytes_sent,
            "bytes_received": log.bytes_received,
            "duration_ms": log.duration_ms,
            "username": log.username,
        }

    async def get_logs(
        self,
        db: AsyncSession,
        page: int = 1,
        page_size: int = 50,
        severity: Optional[Severity] = None,
        source_ip: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> tuple[List[LogEntry], int]:
        """Paginated log retrieval with filtering."""
        filters = []
        if severity:
            filters.append(LogEntry.severity == severity)
        if source_ip:
            filters.append(LogEntry.source_ip == source_ip)
        if event_type:
            filters.append(LogEntry.event_type.ilike(f"%{event_type}%"))
        if start_time:
            filters.append(LogEntry.timestamp >= start_time)
        if end_time:
            filters.append(LogEntry.timestamp <= end_time)

        base_query = select(LogEntry)
        count_query = select(func.count(LogEntry.id))

        if filters:
            base_query = base_query.where(and_(*filters))
            count_query = count_query.where(and_(*filters))

        total = (await db.execute(count_query)).scalar() or 0
        logs = (
            await db.execute(
                base_query.order_by(desc(LogEntry.timestamp))
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).scalars().all()

        return list(logs), total

    async def get_statistics(self, db: AsyncSession) -> LogStatistics:
        """Compute dashboard statistics for log data."""
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(hours=24)

        total = (await db.execute(select(func.count(LogEntry.id)))).scalar() or 0
        last_hour = (
            await db.execute(
                select(func.count(LogEntry.id)).where(LogEntry.ingested_at >= hour_ago)
            )
        ).scalar() or 0
        last_24h = (
            await db.execute(
                select(func.count(LogEntry.id)).where(LogEntry.ingested_at >= day_ago)
            )
        ).scalar() or 0

        # Top source IPs
        top_ips_result = await db.execute(
            select(LogEntry.source_ip, func.count(LogEntry.id).label("count"))
            .where(LogEntry.timestamp >= day_ago)
            .group_by(LogEntry.source_ip)
            .order_by(desc("count"))
            .limit(10)
        )
        top_ips = [{"ip": row[0], "count": row[1]} for row in top_ips_result]

        # Events by severity
        severity_result = await db.execute(
            select(LogEntry.severity, func.count(LogEntry.id).label("count"))
            .group_by(LogEntry.severity)
        )
        by_severity = {str(row[0].value): row[1] for row in severity_result}

        # Events by protocol
        protocol_result = await db.execute(
            select(LogEntry.protocol, func.count(LogEntry.id).label("count"))
            .group_by(LogEntry.protocol)
        )
        by_protocol = {str(row[0].value): row[1] for row in protocol_result}

        # Traffic timeline (hourly buckets for last 24h)
        timeline_result = await db.execute(
            text("""
                SELECT
                    date_trunc('hour', timestamp) as hour,
                    COUNT(*) as count
                FROM log_entries
                WHERE timestamp >= :day_ago
                GROUP BY hour
                ORDER BY hour
            """),
            {"day_ago": day_ago},
        )
        timeline = [
            {"timestamp": row[0].isoformat(), "count": row[1]}
            for row in timeline_result
        ]

        return LogStatistics(
            total_logs=total,
            logs_last_hour=last_hour,
            logs_last_24h=last_24h,
            top_source_ips=top_ips,
            events_by_severity=by_severity,
            events_by_protocol=by_protocol,
            traffic_timeline=timeline,
        )

    async def generate_sample_logs(
        self, db: AsyncSession, count: int = 100
    ) -> Dict[str, Any]:
        """Generate synthetic log data for testing and demo purposes."""
        import random
        from datetime import timedelta

        sample_ips = [
            "192.168.1.100", "192.168.1.101", "10.0.0.5", "10.0.0.12",
            "203.0.113.45", "198.51.100.23", "185.220.101.5", "45.33.32.156",
        ]
        event_types = [
            "login_success", "login_failed", "file_access", "network_connection",
            "port_scan", "ssh_brute_force", "web_request", "dns_query",
            "firewall_block", "privilege_escalation",
        ]
        protocols = list(Protocol)
        severities = list(Severity)

        now = datetime.now(timezone.utc)
        logs = []

        for i in range(count):
            offset = timedelta(seconds=random.randint(0, 86400))
            severity_weights = [0.4, 0.3, 0.15, 0.1, 0.05]

            logs.append(LogEntryCreate(
                timestamp=now - offset,
                source_ip=random.choice(sample_ips),
                destination_ip=f"10.0.0.{random.randint(1, 254)}",
                source_port=random.randint(1024, 65535),
                destination_port=random.choice([22, 80, 443, 3306, 5432, 8080, 3389, 445]),
                protocol=random.choice(protocols),
                event_type=random.choice(event_types),
                severity=random.choices(severities, weights=severity_weights)[0],
                message=f"Sample event {i+1} - {random.choice(event_types)}",
                bytes_sent=random.randint(100, 1_000_000),
                bytes_received=random.randint(100, 500_000),
                duration_ms=random.uniform(1, 5000),
            ))

        return await self.ingest_bulk(db, logs)


    async def _enrich_log_with_ti(self, log_id: int, source_ip: str):
        """
        Background task: fetch TI data and write geo/reputation fields to the log entry.
        Uses its own DB session to avoid session-lifetime issues.
        """
        try:
            from app.core.database import AsyncSessionLocal
            from app.services.threat_intel_service import threat_intel_service

            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(LogEntry).where(LogEntry.id == log_id)
                )
                entry = result.scalar_one_or_none()
                if not entry:
                    return

                ti = await threat_intel_service.lookup(source_ip, session)
                entry.country_code      = ti.country_code or entry.country_code
                entry.geo_city          = ti.city
                entry.geo_isp           = ti.isp
                entry.geo_asn           = ti.asn
                entry.latitude          = ti.latitude or None
                entry.longitude         = ti.longitude or None
                entry.threat_reputation = ti.reputation_score
                entry.is_known_bad_ip   = ti.is_known_bad

                await session.commit()
        except Exception as exc:
            logger.debug("TI enrichment for log %d failed: %s", log_id, exc)


log_service = LogService()
