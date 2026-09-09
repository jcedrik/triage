"""Command-line entry point for triage.

Usage:
    triage <alerts.json|alerts.csv> [--window MIN] [--json OUT] [--html OUT]

Reads alerts, correlates them into incidents, scores and ranks them, and by
default prints a terminal summary. Optionally writes a JSON report and/or an
HTML dashboard.

Exit codes:
    0  ran successfully, no critical incidents
    1  ran successfully, at least one CRITICAL incident found
    2  usage / runtime error
"""

from __future__ import annotations

import argparse
import sys

from . import report
from .correlator import Correlator
from .models import Severity
from .parsers import load
from .scorer import score_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="triage",
        description="Correlate security alerts into ranked incidents.")
    p.add_argument("input", help="alerts file (.json or .csv)")
    p.add_argument("--window", type=int, default=30,
                   help="correlation window in minutes (default: 30)")
    p.add_argument("--json", metavar="FILE",
                   help="write JSON report to FILE")
    p.add_argument("--html", metavar="FILE",
                   help="write HTML dashboard to FILE")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the terminal summary")
    p.add_argument("--format", choices=["auto", "json", "csv", "suricata"], default="auto",
                   help="input format (default: auto-detect; suricata = eve.json)")
    p.add_argument("--pivot-src-ip", action="store_true",
                   help="merge incidents across hosts that share an external source IP")
    p.add_argument("--kql", metavar="FILE",
                   help="write Microsoft Sentinel KQL hunting queries for each incident to FILE")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        alerts = load(args.input, fmt=args.format)
    except (OSError, ValueError) as e:
        print(f"triage: {e}", file=sys.stderr)
        return 2

    incidents = Correlator(window_minutes=args.window, pivot_src_ip=args.pivot_src_ip).correlate(alerts)
    score_all(incidents)

    if not args.quiet:
        print(report.render_terminal(incidents, len(alerts)))

    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                f.write(report.render_json(incidents, len(alerts)))
            print(f"triage: JSON report written to {args.json}",
                  file=sys.stderr)
        except OSError as e:
            print(f"triage: cannot write JSON: {e}", file=sys.stderr)
            return 2

    if args.html:
        try:
            with open(args.html, "w", encoding="utf-8") as f:
                f.write(report.render_html(incidents, len(alerts)))
            print(f"triage: HTML dashboard written to {args.html}",
                  file=sys.stderr)
        except OSError as e:
            print(f"triage: cannot write HTML: {e}", file=sys.stderr)
            return 2

    if args.kql:
        try:
            with open(args.kql, "w", encoding="utf-8") as f:
                f.write(report.render_kql(incidents))
            print(f"triage: KQL queries written to {args.kql}", file=sys.stderr)
        except OSError as e:
            print(f"triage: cannot write KQL: {e}", file=sys.stderr)
            return 2

    has_critical = any(i.severity == Severity.CRITICAL for i in incidents)
    return 1 if has_critical else 0


if __name__ == "__main__":
    raise SystemExit(main())
