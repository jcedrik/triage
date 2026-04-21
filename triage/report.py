"""Render incidents to the terminal."""

from __future__ import annotations

import sys

from .models import Incident, Severity
from . import mitre

_COLORS = {
    Severity.CRITICAL: "\033[95m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def render_terminal(incidents: list, total_alerts: int) -> str:
    color = sys.stdout.isatty()

    def c(text, code):
        return f"{code}{text}{_RESET}" if color else text

    lines = []
    lines.append(c(f"triage - {total_alerts} alerts -> "
                   f"{len(incidents)} incident(s)", _BOLD))
    lines.append("")

    ranked = sorted(incidents, key=lambda i: i.risk_score, reverse=True)
    for inc in ranked:
        tag = c(f"[{inc.severity.label().upper()}]", _COLORS[inc.severity])
        lines.append(f"{tag} {inc.incident_id}  host={inc.host}  "
                     f"risk={inc.risk_score}/100  alerts={len(inc.alerts)}")
        lines.append("")
    return "\n".join(lines)
