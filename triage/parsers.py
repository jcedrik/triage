"""Parse alert files into Alert objects."""

from __future__ import annotations

import json
from datetime import datetime

from .models import Alert, Severity


def _parse_ts(value: str) -> datetime:
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_json(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("expected a JSON array of alert objects")

    alerts = []
    for i, obj in enumerate(data):
        try:
            alerts.append(Alert(
                timestamp=_parse_ts(obj["timestamp"]),
                source_host=obj["host"],
                signature=obj["signature"],
                severity=Severity.from_str(obj["severity"]),
                technique_id=obj.get("technique_id", ""),
                category=obj.get("category", ""),
                src_ip=obj.get("src_ip", ""),
                dst_ip=obj.get("dst_ip", ""),
                raw=obj.get("raw", ""),
            ))
        except (KeyError, ValueError) as e:
            raise ValueError(f"bad alert at index {i}: {e}") from e
    return alerts
