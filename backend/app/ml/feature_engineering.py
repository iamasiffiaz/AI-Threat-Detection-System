"""
Feature engineering pipeline for anomaly detection.
Extracts statistical and behavioral features from raw log entries.
"""
import numpy as np
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import ipaddress
import logging

logger = logging.getLogger(__name__)

# Well-known suspicious ports (common attack vectors)
SUSPICIOUS_PORTS = {
    22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 1521,
    3306, 3389, 4444, 5432, 5900, 6379, 8080, 8443, 9200, 27017
}

STANDARD_PORTS = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995}


class FeatureEngineer:
    """
    Transforms normalized log entries into numerical feature vectors
    suitable for ML anomaly detection models.
    """

    FEATURE_NAMES = [
        "hour_of_day",
        "day_of_week",
        "is_weekend",
        "dest_port",
        "is_suspicious_port",
        "is_standard_port",
        "high_port",
        "bytes_sent_log",
        "bytes_received_log",
        "bytes_ratio",
        "duration_log",
        "is_internal_src",
        "is_internal_dst",
        "is_cross_network",
        "protocol_encoded",
        "severity_encoded",
        "event_type_encoded",
        "failed_login_flag",
        "scan_flag",
        "large_transfer_flag",
    ]

    PROTOCOL_MAP = {
        "TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3,
        "HTTPS": 4, "DNS": 5, "FTP": 6, "SSH": 7, "OTHER": 8
    }

    SEVERITY_MAP = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    EVENT_TYPE_MAP: Dict[str, int] = {}
    _event_type_counter = 0

    def _encode_event_type(self, event_type: str) -> int:
        """Encode event type string to integer with memoization."""
        event_lower = event_type.lower()
        if event_lower not in self.EVENT_TYPE_MAP:
            self.EVENT_TYPE_MAP[event_lower] = self._event_type_counter
            self.__class__._event_type_counter += 1
        return self.EVENT_TYPE_MAP[event_lower]

    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if an IP address belongs to a private/internal range."""
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False

    def extract_features(self, log: Dict[str, Any]) -> np.ndarray:
        """
        Extract a fixed-length numerical feature vector from a single log entry.
        Returns a numpy array of shape (n_features,).
        """
        timestamp = log.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        hour = timestamp.hour if timestamp else 12
        dow = timestamp.weekday() if timestamp else 0
        is_weekend = 1 if dow >= 5 else 0

        src_ip = str(log.get("source_ip", ""))
        dst_ip = str(log.get("destination_ip", ""))
        dest_port = int(log.get("destination_port") or 0)

        is_suspicious = 1 if dest_port in SUSPICIOUS_PORTS else 0
        is_standard = 1 if dest_port in STANDARD_PORTS else 0
        high_port = 1 if dest_port > 49151 else 0

        bytes_sent = float(log.get("bytes_sent") or 0)
        bytes_recv = float(log.get("bytes_received") or 0)
        bytes_sent_log = np.log1p(bytes_sent)
        bytes_recv_log = np.log1p(bytes_recv)
        bytes_ratio = bytes_sent / (bytes_recv + 1.0)

        duration = float(log.get("duration_ms") or 0)
        duration_log = np.log1p(duration)

        is_internal_src = 1 if self._is_private_ip(src_ip) else 0
        is_internal_dst = 1 if self._is_private_ip(dst_ip) else 0
        is_cross_network = 1 if is_internal_src != is_internal_dst else 0

        protocol = str(log.get("protocol", "OTHER")).upper()
        protocol_enc = self.PROTOCOL_MAP.get(protocol, 8)

        severity = str(log.get("severity", "info")).lower()
        severity_enc = self.SEVERITY_MAP.get(severity, 0)

        event_type = str(log.get("event_type", "unknown"))
        event_enc = self._encode_event_type(event_type)

        event_lower = event_type.lower()
        failed_login = 1 if "fail" in event_lower and "login" in event_lower else 0
        scan_flag = 1 if "scan" in event_lower or "probe" in event_lower else 0
        large_transfer = 1 if bytes_sent > 10_000_000 or bytes_recv > 10_000_000 else 0

        return np.array([
            hour, dow, is_weekend,
            dest_port, is_suspicious, is_standard, high_port,
            bytes_sent_log, bytes_recv_log, bytes_ratio, duration_log,
            is_internal_src, is_internal_dst, is_cross_network,
            protocol_enc, severity_enc, event_enc,
            failed_login, scan_flag, large_transfer,
        ], dtype=np.float64)

    def extract_bulk_features(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        """Extract features from multiple log entries, returning a 2D array."""
        if not logs:
            return np.empty((0, len(self.FEATURE_NAMES)))
        features = [self.extract_features(log) for log in logs]
        return np.vstack(features)

    def compute_ip_behavior_features(
        self,
        logs: List[Dict[str, Any]],
        window_minutes: int = 60,
    ) -> Dict[str, Dict[str, float]]:
        """
        Compute per-IP behavioral statistics over a sliding time window.
        Returns a dict mapping source_ip -> behavioral metrics.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        ip_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "total_requests": 0,
            "failed_logins": 0,
            "unique_ports": set(),
            "unique_destinations": set(),
            "total_bytes": 0,
            "events": [],
        })

        for log in logs:
            ts = log.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts)
            if ts and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            if ts and ts < cutoff:
                continue

            src = str(log.get("source_ip", "unknown"))
            stats = ip_stats[src]
            stats["total_requests"] += 1

            event = str(log.get("event_type", "")).lower()
            if "fail" in event and "login" in event:
                stats["failed_logins"] += 1

            port = log.get("destination_port")
            if port:
                stats["unique_ports"].add(port)

            dst = log.get("destination_ip")
            if dst:
                stats["unique_destinations"].add(dst)

            stats["total_bytes"] += (
                (log.get("bytes_sent") or 0) + (log.get("bytes_received") or 0)
            )

        # Convert sets to counts for serialization
        result = {}
        for ip, stats in ip_stats.items():
            result[ip] = {
                "total_requests": stats["total_requests"],
                "failed_logins": stats["failed_logins"],
                "unique_ports_count": len(stats["unique_ports"]),
                "unique_destinations_count": len(stats["unique_destinations"]),
                "total_bytes": stats["total_bytes"],
                "requests_per_minute": stats["total_requests"] / max(window_minutes, 1),
            }

        return result
