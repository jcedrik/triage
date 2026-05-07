"""Input parsers: normalize different alert sources into Alert objects.

A SOC ingests from many tools, each with its own format. We support two here:

  - triage JSON: the engine's native format, a list of alert objects.
  - generic CSV: a common denominator for exports from other tools.

Both normalize into the same Alert type so everything downstream is
source-agnostic. Adding a new source means adding one parser here and nothing
else changes.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime

from .models import Alert, Severity


def _parse_ts(value: str) -> datetime:
    """Accept ISO 8601, with or without timezone. Fall back to now-ish parsing
    errors loudly so bad data doesn't silently distort the timeline."""
    value = value.strip()
    # Common formats we tolerate.
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    # Last resort: ISO parser (handles offsets like +00:00).
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_json(path: str) -> list[Alert]:
    """Parse the native JSON format: a list of alert objects.

    Each object: timestamp, host, signature, severity, and optionally
    technique_id, category, src_ip, dst_ip, raw.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("expected a JSON array of alert objects")

    alerts: list[Alert] = []
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


def parse_csv(path: str) -> list[Alert]:
    """Parse a generic CSV export.

    Expected columns (header row required): timestamp, host, signature,
    severity, technique_id, category, src_ip, dst_ip. Missing optional columns
    are tolerated.
    """
    alerts: list[Alert] = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {"timestamp", "host", "signature", "severity"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV missing required columns: {sorted(missing)}")
        for i, row in enumerate(reader):
            try:
                alerts.append(Alert(
                    timestamp=_parse_ts(row["timestamp"]),
                    source_host=row["host"],
                    signature=row["signature"],
                    severity=Severity.from_str(row["severity"]),
                    technique_id=row.get("technique_id", "") or "",
                    category=row.get("category", "") or "",
                    src_ip=row.get("src_ip", "") or "",
                    dst_ip=row.get("dst_ip", "") or "",
                ))
            except (KeyError, ValueError) as e:
                raise ValueError(f"bad row {i + 2}: {e}") from e  # +2: header+0index
    return alerts


def load(path: str) -> list[Alert]:
    """Dispatch on file extension."""
    if path.endswith(".json"):
        return parse_json(path)
    if path.endswith(".csv"):
        return parse_csv(path)
    raise ValueError("unsupported input; use .json or .csv")
