"""Reporters: render correlated incidents three ways.

  - terminal: a ranked, colored summary for an analyst at a console.
  - json: machine-readable, for piping into other tooling or storage.
  - html: a self-contained dashboard with a MITRE tactic overview, meant to
    be opened in a browser or embedded in a report.

Each reporter takes the same list of scored incidents, so the analysis is done
once and presented many ways.
"""

from __future__ import annotations

import json
import sys

from .models import Incident, Severity
from . import mitre

# ---- terminal ----

_COLORS = {
    Severity.CRITICAL: "\033[95m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def render_terminal(incidents: list[Incident], total_alerts: int) -> str:
    color = sys.stdout.isatty()

    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines = []
    lines.append(c(
        f"triage - {total_alerts} alerts correlated into "
        f"{len(incidents)} incident(s)", _BOLD))
    lines.append("")

    ranked = sorted(incidents, key=lambda i: i.risk_score, reverse=True)
    for inc in ranked:
        tag = c(f"[{inc.severity.label().upper()}]",
                _COLORS[inc.severity])
        lines.append(
            f"{tag} {inc.incident_id}  host={inc.host}  "
            f"risk={inc.risk_score}/100  alerts={len(inc.alerts)}")
        if inc.tactics:
            chain = " -> ".join(mitre.sort_tactics(inc.tactics))
            lines.append(f"   kill chain: {chain}")
        lines.append(
            f"   window: {inc.first_seen():%Y-%m-%d %H:%M} "
            f"to {inc.last_seen():%H:%M}")
        # show the top alerts in the incident
        for a in sorted(inc.alerts, key=lambda x: x.severity, reverse=True)[:3]:
            tech = f" [{a.technique_id}]" if a.technique_id else ""
            lines.append(
                f"     - {a.severity.label():8s} {a.signature}{tech}")
        if len(inc.alerts) > 3:
            lines.append(f"     ... and {len(inc.alerts) - 3} more")
        lines.append("")

    return "\n".join(lines)


# ---- json ----

def render_json(incidents: list[Incident], total_alerts: int) -> str:
    ranked = sorted(incidents, key=lambda i: i.risk_score, reverse=True)
    payload = {
        "total_alerts": total_alerts,
        "incident_count": len(incidents),
        "incidents": [inc.to_dict() for inc in ranked],
    }
    return json.dumps(payload, indent=2)


# ---- html dashboard ----

def render_html(incidents: list[Incident], total_alerts: int) -> str:
    ranked = sorted(incidents, key=lambda i: i.risk_score, reverse=True)

    sev_class = {
        Severity.CRITICAL: "crit", Severity.HIGH: "high",
        Severity.MEDIUM: "med", Severity.LOW: "low", Severity.INFO: "info",
    }

    # Which tactics appear anywhere, for the kill-chain overview strip.
    all_tactics = set()
    for inc in incidents:
        all_tactics |= inc.tactics

    tactic_cells = ""
    for tac in mitre.TACTIC_ORDER:
        active = tac in all_tactics
        cls = "tac active" if active else "tac"
        tactic_cells += f'<div class="{cls}">{tac}</div>'

    rows = ""
    for inc in ranked:
        chain = " &rarr; ".join(mitre.sort_tactics(inc.tactics)) or "&mdash;"
        techs = ", ".join(
            f"{t} ({mitre.technique_name(t)})"
            for t in sorted(inc.techniques)) or "&mdash;"
        alert_items = "".join(
            f"<li><span class='sev {sev_class[a.severity]}'>"
            f"{a.severity.label()}</span> {_esc(a.signature)}"
            f"{(' [' + a.technique_id + ']') if a.technique_id else ''}</li>"
            for a in sorted(inc.alerts, key=lambda x: x.severity, reverse=True))
        rows += f"""
        <div class="incident {sev_class[inc.severity]}">
          <div class="inc-head">
            <span class="inc-id">{inc.incident_id}</span>
            <span class="badge {sev_class[inc.severity]}">
              {inc.severity.label()} &middot; risk {inc.risk_score}/100</span>
          </div>
          <div class="inc-meta">
            host <b>{_esc(inc.host)}</b> &middot; {len(inc.alerts)} alerts
            &middot; {inc.first_seen():%Y-%m-%d %H:%M}&ndash;{inc.last_seen():%H:%M}
          </div>
          <div class="chain">{chain}</div>
          <div class="techs">{techs}</div>
          <ul class="alerts">{alert_items}</ul>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>triage dashboard</title>
<style>
  :root {{
    --bg:#0d0f12; --panel:#14171c; --line:#232830; --text:#e6e8ea;
    --muted:#8a929c; --crit:#c586c0; --high:#ff5c5c; --med:#e6c14b;
    --low:#5b9bd5; --info:#6b7280; --accent:#4ec9b0;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text);
    font-family:'JetBrains Mono',ui-monospace,'SF Mono',monospace;
    padding:32px; }}
  h1 {{ font-size:20px; margin:0 0 4px; letter-spacing:1px; }}
  .sub {{ color:var(--muted); font-size:13px; margin-bottom:24px; }}
  .killchain {{ display:flex; flex-wrap:wrap; gap:4px; margin-bottom:28px; }}
  .tac {{ font-size:11px; padding:6px 8px; border:1px solid var(--line);
    border-radius:4px; color:var(--muted); }}
  .tac.active {{ color:var(--bg); background:var(--accent);
    border-color:var(--accent); font-weight:600; }}
  .incident {{ background:var(--panel); border:1px solid var(--line);
    border-left:3px solid var(--info); border-radius:6px;
    padding:16px 18px; margin-bottom:14px; }}
  .incident.crit {{ border-left-color:var(--crit); }}
  .incident.high {{ border-left-color:var(--high); }}
  .incident.med {{ border-left-color:var(--med); }}
  .incident.low {{ border-left-color:var(--low); }}
  .inc-head {{ display:flex; justify-content:space-between;
    align-items:center; }}
  .inc-id {{ font-size:15px; font-weight:600; }}
  .badge {{ font-size:11px; padding:4px 8px; border-radius:4px;
    background:var(--line); }}
  .badge.crit {{ color:var(--crit); }} .badge.high {{ color:var(--high); }}
  .badge.med {{ color:var(--med); }} .badge.low {{ color:var(--low); }}
  .inc-meta {{ color:var(--muted); font-size:12px; margin:6px 0; }}
  .chain {{ font-size:13px; color:var(--accent); margin:8px 0 4px; }}
  .techs {{ font-size:11px; color:var(--muted); margin-bottom:8px; }}
  .alerts {{ list-style:none; padding:0; margin:0; }}
  .alerts li {{ font-size:12px; padding:3px 0;
    border-top:1px solid var(--line); }}
  .sev {{ display:inline-block; width:64px; font-weight:600; }}
  .sev.crit {{ color:var(--crit); }} .sev.high {{ color:var(--high); }}
  .sev.med {{ color:var(--med); }} .sev.low {{ color:var(--low); }}
  .sev.info {{ color:var(--info); }}
</style></head><body>
  <h1>triage</h1>
  <div class="sub">{total_alerts} alerts correlated into {len(incidents)} incidents &middot; ranked by risk</div>
  <div class="killchain">{tactic_cells}</div>
  {rows}
</body></html>"""


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;"))
