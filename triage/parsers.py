"""Input parsers: normalize different alert sources into Alert objects.

A SOC ingests from many tools, each with its own format. We support two here:

  - triage JSON: the engine's native format, a list of alert objects.
  - generic CSV: a common denominator for exports from other tools.
  - Suricata EVE: the newline-delimited eve.json that Suricata writes,
    filtered to event_type == "alert". This is what a lab actually produces.

Both normalize into the same Alert type so everything downstream is
source-agnostic. Adding a new source means adding one parser here and nothing
else changes.
"""

from __future__ import annotations

import csv
import json
import re
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


# Suricata severity is 1 (highest) to 4. Map onto our scale.
_SURICATA_SEVERITY = {1: Severity.CRITICAL, 2: Severity.HIGH, 3: Severity.MEDIUM, 4: Severity.LOW}

# Suricata rule metadata often carries ATT&CK ids as
# metadata: mitre_technique_id T1190, mitre_tactic_id TA0001
# ET Open rules use "mitre_technique_id" in the rule metadata field.

_MITRE_IN_METADATA = re.compile(r"mitre_technique_id\s*[:=]?\s*(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_MITRE_IN_SIG = re.compile(r"\b(T\d{4})(?:\.\d{3})?\b")


def parse_suricata_eve(path: str) -> list[Alert]:
    """Parse Suricata's eve.json (one JSON object per line).

    Only event_type == "alert" records become alerts. The host is dest_ip
    (the asset being attacked) unless a `host` field is present. The
    technique id is read from the rule metadata when the rule carries one
    (ET Open and Sigma-derived rules do), otherwise from the signature text.
    """
    alerts: list[Alert] = []
    with open(path, "r", encoding="utf-8") as f:
        for n, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError as e:
                raise ValueError(f"bad JSON on line {n}: {e}") from e
            if ev.get("event_type") != "alert":
                continue
            al = ev.get("alert", {})
            meta = al.get("metadata") or {}
            technique = ""
            # metadata is usually {"mitre_technique_id": ["T1190"], ...}
            for key in ("mitre_technique_id", "mitre_technique"):
                v = meta.get(key)
                if v:
                    technique = v[0] if isinstance(v, list) else str(v)
                    break
            if not technique:
                m = _MITRE_IN_METADATA.search(json.dumps(meta)) or _MITRE_IN_SIG.search(al.get("signature", ""))
                technique = m.group(1) if m else ""
            technique = technique.split(".")[0] if technique else ""  # sub-techniques roll up
            alerts.append(Alert(
                timestamp=_parse_ts(ev["timestamp"]),
                source_host=ev.get("host") or ev.get("dest_ip", "unknown"),
                signature=al.get("signature", "unknown signature"),
                severity=_SURICATA_SEVERITY.get(int(al.get("severity", 3)), Severity.MEDIUM),
                technique_id=technique,
                category=al.get("category", ""),
                src_ip=ev.get("src_ip", ""),
                dst_ip=ev.get("dest_ip", ""),
                raw=line[:500],
            ))
    return alerts


def load(path: str, fmt: str = "auto") -> list[Alert]:
    """Dispatch on --format, or sniff the file when fmt is "auto"."""
    if fmt == "auto":
        if path.endswith(".csv"):
            fmt = "csv"
        elif path.endswith((".eve", ".eve.json")) or "eve" in path.rsplit("/", 1)[-1]:
            fmt = "suricata"
        elif path.endswith(".json"):
            with open(path, "r", encoding="utf-8") as f:
                head = f.read(2048).lstrip()
            fmt = "suricata" if head.startswith("{") and '"event_type"' in head else "json"
        else:
            raise ValueError("unsupported input; use .json, .csv or Suricata eve.json (or pass --format)")
    if fmt == "json":
        return parse_json(path)
    if fmt == "csv":
        return parse_csv(path)
    if fmt == "suricata":
        return parse_suricata_eve(path)
    raise ValueError(f"unknown format: {fmt}")
