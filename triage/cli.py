"""CLI entry point for triage."""

from __future__ import annotations

import argparse

from .parsers import load
from .correlator import Correlator
from .scorer import score_all
from .models import Severity
from . import report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="triage")
    p.add_argument("input")
    p.add_argument("--window", type=int, default=30)
    p.add_argument("--json", metavar="FILE")
    p.add_argument("--html", metavar="FILE")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    alerts = load(args.input)
    incidents = Correlator(window_minutes=args.window).correlate(alerts)
    score_all(incidents)

    if not args.quiet:
        print(report.render_terminal(incidents, len(alerts)))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(report.render_json(incidents, len(alerts)))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(report.render_html(incidents, len(alerts)))

    has_critical = any(i.severity == Severity.CRITICAL for i in incidents)
    return 1 if has_critical else 0


if __name__ == "__main__":
    raise SystemExit(main())
