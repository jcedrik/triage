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
    lines.append(c(f"triage - {total_alerts} alerts correlated into "
                   f"{len(incidents)} incident(s)", _BOLD))
    lines.append("")

    ranked = sorted(incidents, key=lambda i: i.risk_score, reverse=True)
    for inc in ranked:
        tag = c(f"[{inc.severity.label().upper()}]", _COLORS[inc.severity])
        lines.append(f"{tag} {inc.incident_id}  host={inc.host}  "
                     f"risk={inc.risk_score}/100  alerts={len(inc.alerts)}")
        if inc.tactics:
            chain = " -> ".join(sorted(inc.tactics))
            lines.append(f"   kill chain: {chain}")
        lines.append(f"   window: {inc.first_seen():%Y-%m-%d %H:%M} "
                     f"to {inc.last_seen():%H:%M}")
        for a in sorted(inc.alerts, key=lambda x: x.severity, reverse=True)[:3]:
            tech = f" [{a.technique_id}]" if a.technique_id else ""
            lines.append(f"     - {a.severity.label():8s} {a.signature}{tech}")
        if len(inc.alerts) > 3:
            lines.append(f"     ... and {len(inc.alerts) - 3} more")
        lines.append("")
    return "\n".join(lines)
