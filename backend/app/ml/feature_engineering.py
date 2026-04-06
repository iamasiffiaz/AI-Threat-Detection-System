"""
Advanced feature engineering pipeline for anomaly detection.
Extracts 35 statistical, behavioral, and network-topology features
from normalized log entries.
"""
import numpy as np
import math
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import ipaddress
import logging

logger = logging.getLogger(__name__)

SUSPICIOUS_PORTS = {
    22, 23, 25, 53, 80, 135, 139, 443, 445, 512, 513, 514,
    1433, 1521, 3306, 3389, 4444, 5432, 5900, 6379, 8080, 8443,
    9200, 27017, 1337, 31337, 6666, 6667, 8888, 9001,
}
STANDARD_PORTS  = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995}
ADMIN_PORTS     = {22, 23, 3389, 5900, 5800, 2222, 2323}
DB_PORTS        = {3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984}
DNS_PORTS       = {53, 853}
HIGH_RISK_PORTS = {4444, 1337, 31337, 6666, 6667, 8888, 9001, 4899, 1080}


class FeatureEngineer:
    """
    Transforms normalized log entries into 35-dimensional feature vectors
    suitable for ensemble anomaly detection (IsolationForest + LOF).
    """

    FEATURE_NAMES = [
        # --- Temporal (5) ---
        "hour_of_day",
        "day_of_week",
        "is_weekend",
        "is_night_hours",          # 00:00-06:00
        "is_business_hours",       # 08:00-18:00 weekday

        # --- Port features (8) ---
        "dest_port",
        "dest_port_normalized",    # 0-1 scaled
        "is_suspicious_port",
        "is_standard_port",
        "is_admin_port",
        "is_db_port",
        "is_dns_port",
        "is_high_risk_port",

        # --- Payload / traffic (6) ---
        "bytes_sent_log",
        "bytes_received_log",
        "bytes_total_log",
        "bytes_ratio",             # sent / (recv+1)
        "data_asymmetry",          # |sent-recv| / (sent+recv+1)
        "duration_log",

        # --- Network topology (8) ---
        "is_internal_src",
        "is_internal_dst",
        "is_cross_network",
        "is_external_to_internal", # external attacking internal
        "is_internal_to_internal",
        "is_same_subnet",          # src and dst same /24
        "src_is_loopback",
        "src_is_broadcast_range",

        # --- Protocol / event encoding (4) ---
        "protocol_encoded",
        "severity_encoded",
        "event_type_encoded",
        "event_severity_product",  # combined signal

        # --- Behavioral flags (4) ---
        "failed_login_flag",
        "scan_flag",
        "large_transfer_flag",
        "high_port_flag",          # dest > 49151 (ephemeral)
    ]

    PROTOCOL_MAP = {
        "TCP": 1, "UDP": 2, "ICMP": 3, "HTTP": 4,
        "HTTPS": 5, "DNS": 6, "FTP": 7, "SSH": 8, "OTHER": 0,
    }
    SEVERITY_MAP = {
        "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
    }

    # Class-level memoization so feature IDs are consistent within a process
    EVENT_TYPE_MAP: Dict[str, int] = {}
    _event_type_counter = 0

    def _encode_event_type(self, event_type: str) -> int:
        key = event_type.lower()
        if key not in self.EVENT_TYPE_MAP:
            self.__class__.EVENT_TYPE_MAP[key] = self.__class__._event_type_counter
            self.__class__._event_type_counter += 1
        return self.EVENT_TYPE_MAP[key]

    def _is_private(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _is_loopback(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_loopback
        except ValueError:
            return False

    def _same_subnet_24(self, ip1: str, ip2: str) -> bool:
        try:
            n1 = ipaddress.ip_network(f"{ip1}/24", strict=False)
            return ipaddress.ip_address(ip2) in n1
        except ValueError:
            return False

    def extract_features(self, log: Dict[str, Any]) -> np.ndarray:
        """
        Extract a 35-dimensional feature vector from a single log entry.
        All values are finite floats suitable for sklearn estimators.
        """
        # ---- Timestamp ------------------------------------------------
        ts = log.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except ValueError:
                ts = None
        hour      = int(ts.hour)      if ts else 12
        dow       = int(ts.weekday()) if ts else 0
        is_wkend  = 1 if dow >= 5 else 0
        is_night  = 1 if hour < 6 else 0
        is_biz    = 1 if (8 <= hour <= 18 and dow < 5) else 0

        # ---- Ports ----------------------------------------------------
        src_ip   = str(log.get("source_ip", ""))
        dst_ip   = str(log.get("destination_ip", "") or "")
        dst_port = int(log.get("destination_port") or 0)

        p_susp   = 1 if dst_port in SUSPICIOUS_PORTS else 0
        p_std    = 1 if dst_port in STANDARD_PORTS   else 0
        p_admin  = 1 if dst_port in ADMIN_PORTS      else 0
        p_db     = 1 if dst_port in DB_PORTS         else 0
        p_dns    = 1 if dst_port in DNS_PORTS        else 0
        p_hisk   = 1 if dst_port in HIGH_RISK_PORTS  else 0
        p_norm   = min(dst_port / 65535.0, 1.0)

        # ---- Payload --------------------------------------------------
        sent     = float(log.get("bytes_sent")     or 0)
        recv     = float(log.get("bytes_received") or 0)
        total    = sent + recv
        b_sent   = math.log1p(sent)
        b_recv   = math.log1p(recv)
        b_total  = math.log1p(total)
        b_ratio  = sent / (recv + 1.0)
        b_asym   = abs(sent - recv) / (total + 1.0)
        dur      = float(log.get("duration_ms") or 0)
        d_log    = math.log1p(dur)

        # ---- Network topology ----------------------------------------
        is_int_src = 1 if self._is_private(src_ip) else 0
        is_int_dst = 1 if (dst_ip and self._is_private(dst_ip)) else 0
        is_cross   = 1 if is_int_src != is_int_dst else 0
        is_ext2int = 1 if (not is_int_src and is_int_dst) else 0
        is_int2int = 1 if (is_int_src and is_int_dst) else 0
        is_same_sn = 1 if (dst_ip and self._same_subnet_24(src_ip, dst_ip)) else 0
        is_loop    = 1 if self._is_loopback(src_ip) else 0
        is_bcast   = 1 if src_ip.endswith(".255") else 0

        # ---- Protocol / event encoding --------------------------------
        proto      = str(log.get("protocol", "OTHER")).upper()
        proto_enc  = self.PROTOCOL_MAP.get(proto, 0)
        sev        = str(log.get("severity", "info")).lower()
        sev_enc    = self.SEVERITY_MAP.get(sev, 0)
        evt        = str(log.get("event_type", "unknown"))
        evt_enc    = self._encode_event_type(evt)
        sev_evt    = float(sev_enc * (evt_enc % 10 + 1))  # combined signal

        # ---- Behavioral flags ----------------------------------------
        evt_low        = evt.lower()
        failed_login   = 1 if ("fail" in evt_low and "login" in evt_low) else 0
        scan_flag      = 1 if ("scan" in evt_low or "probe" in evt_low or "recon" in evt_low) else 0
        large_transfer = 1 if (sent > 10_000_000 or recv > 10_000_000) else 0
        high_port_flag = 1 if dst_port > 49151 else 0

        vec = np.array([
            # temporal
            hour, dow, is_wkend, is_night, is_biz,
            # ports
            dst_port, p_norm, p_susp, p_std, p_admin, p_db, p_dns, p_hisk,
            # payload
            b_sent, b_recv, b_total, b_ratio, b_asym, d_log,
            # topology
            is_int_src, is_int_dst, is_cross, is_ext2int, is_int2int,
            is_same_sn, is_loop, is_bcast,
            # encoding
            proto_enc, sev_enc, evt_enc, sev_evt,
            # flags
            failed_login, scan_flag, large_transfer, high_port_flag,
        ], dtype=np.float64)

        return np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)

    def extract_bulk_features(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        """Extract features from multiple log entries → 2D array (N, 35)."""
        if not logs:
            return np.empty((0, len(self.FEATURE_NAMES)))
        return np.vstack([self.extract_features(log) for log in logs])

    def compute_ip_behavior_features(
        self,
        logs: List[Dict[str, Any]],
        window_minutes: int = 60,
    ) -> Dict[str, Dict[str, float]]:
        """
        Compute per-IP behavioral statistics over a sliding time window.
        Returns ip → metrics dict (used by the rule engine and LLM enrichment).
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "total_requests":   0,
            "failed_logins":    0,
            "unique_ports":     set(),
            "unique_dsts":      set(),
            "unique_usernames": set(),
            "total_bytes":      0,
            "critical_events":  0,
            "scan_events":      0,
        })

        for log in logs:
            ts = log.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except ValueError:
                    ts = None
            if ts:
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < cutoff:
                    continue

            src  = str(log.get("source_ip", "unknown"))
            s    = stats[src]
            s["total_requests"] += 1

            evt = str(log.get("event_type", "")).lower()
            if "fail" in evt and "login" in evt:
                s["failed_logins"] += 1
            if "scan" in evt or "probe" in evt:
                s["scan_events"] += 1
            if str(log.get("severity", "")).lower() == "critical":
                s["critical_events"] += 1

            port = log.get("destination_port")
            if port:
                s["unique_ports"].add(int(port))

            dst = log.get("destination_ip")
            if dst:
                s["unique_dsts"].add(str(dst))

            user = log.get("username")
            if user:
                s["unique_usernames"].add(str(user))

            s["total_bytes"] += (
                (log.get("bytes_sent") or 0) + (log.get("bytes_received") or 0)
            )

        result = {}
        for ip, s in stats.items():
            result[ip] = {
                "total_requests":          s["total_requests"],
                "failed_logins":           s["failed_logins"],
                "unique_ports_count":      len(s["unique_ports"]),
                "unique_destinations":     len(s["unique_dsts"]),
                "unique_usernames":        len(s["unique_usernames"]),
                "total_bytes_mb":          round(s["total_bytes"] / 1_000_000, 3),
                "critical_events":         s["critical_events"],
                "scan_events":             s["scan_events"],
                "requests_per_minute":     round(s["total_requests"] / max(window_minutes, 1), 2),
            }
        return result
