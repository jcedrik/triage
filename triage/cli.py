"""CLI entry point."""

from __future__ import annotations

import argparse

from .parsers import parse_json
from .correlator import Correlator
from .scorer import score_all
from . import report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="triage")
    p.add_argument("input")
    p.add_argument("--window", type=int, default=30)
    args = p.parse_args(argv)

    alerts = parse_json(args.input)
    incidents = Correlator(window_minutes=args.window).correlate(alerts)
    score_all(incidents)
    print(report.render_terminal(incidents, len(alerts)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
