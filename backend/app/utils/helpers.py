"""
Utility helpers: IP validation, report generation, common transformations.
"""
import csv
import io
import json
import ipaddress
from typing import List, Dict, Any, Optional
from datetime import datetime


def is_valid_ip(ip: str) -> bool:
    """Validate an IPv4 or IPv6 address string."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/RFC1918 range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def generate_csv_report(data: List[Dict[str, Any]], filename_prefix: str = "report") -> bytes:
    """Generate a CSV report from a list of dictionaries."""
    if not data:
        return b""

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=data[0].keys())
    writer.writeheader()
    writer.writerows(data)
    return output.getvalue().encode("utf-8")


def generate_json_report(data: List[Dict[str, Any]]) -> bytes:
    """Generate a JSON report with metadata."""
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_records": len(data),
        "data": data,
    }
    return json.dumps(report, indent=2, default=str).encode("utf-8")


def truncate_string(s: str, max_length: int = 255) -> str:
    """Truncate a string to max_length, appending ellipsis if needed."""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."


def sanitize_ip(ip: str) -> str:
    """Sanitize and validate an IP address, returning '0.0.0.0' if invalid."""
    if is_valid_ip(ip):
        return ip
    return "0.0.0.0"


def parse_port_range(port_spec: str) -> List[int]:
    """Parse a port specification like '80,443,8000-8100' into a list of ports."""
    ports = []
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            try:
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.append(int(part))
            except ValueError:
                pass
    return [p for p in ports if 0 <= p <= 65535]
