"""Parse alert files into Alert objects."""

from __future__ import annotations

import json
from datetime import datetime

from .models import Alert, Severity


def _parse_ts(value: str) -> datetime:
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return datetime.fromisoformat(value)


def parse_json(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    alerts = []
    for obj in data:
        alerts.append(Alert(
            timestamp=_parse_ts(obj["timestamp"]),
            source_host=obj["host"],
            signature=obj["signature"],
            severity=Severity.from_str(obj["severity"]),
            technique_id=obj.get("technique_id", ""),
        ))
    return alerts
