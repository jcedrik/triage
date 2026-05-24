# triage

A small SOC engine that takes a pile of security alerts and turns it into a short list of incidents worth actually looking at, ranked by risk and mapped to MITRE ATT&CK.

The idea came from my Purple Team lab work. When you run detections across network and endpoint telemetry, you don't get "an attack happened", you get hundreds of individual alerts, most of them noise or the same thing firing over and over. The hard part isn't detecting stuff, it's figuring out which of those alerts belong together and which ones matter. That grouping and ranking step is what triage does.

## What it does

You give it alerts (JSON or CSV), and it:

- groups alerts that hit the same host around the same time into one incident
- pulls out the MITRE techniques in each incident so you can see how far the attack got along the kill chain
- gives each incident a risk score from 0 to 100 and ranks them
- prints a summary, and can also write a JSON report and an HTML dashboard

In the sample, 8 raw alerts become 3 incidents, and the one that's actually bad (a web server that got scanned, then SQL injected, then dropped a web shell, then had creds dumped and data pulled out) ends up at the top with a risk of 100. The two minor ones stay separate and low.

## Running it

```bash
pip install -e .
triage samples/alerts.json
```

To also get the dashboard:

```bash
triage samples/alerts.json --html dashboard.html
```

Then open dashboard.html in a browser. There's a CSV sample too if you want to see the other input format:

```bash
triage samples/alerts.csv
```

Options: `--window` sets how many minutes apart alerts can be and still count as the same incident (default 30), `--json FILE` and `--html FILE` write reports, `--quiet` skips the terminal output. It exits with code 1 if anything critical showed up, so you could wire it into a pipeline.

## Alert format

JSON is a list of objects. Only timestamp, host, signature and severity are required, the rest are optional:

```json
{
  "timestamp": "2026-06-13T02:15:11",
  "host": "web-01",
  "signature": "SQL injection attempt",
  "severity": "high",
  "technique_id": "T1190"
}
```

CSV uses the same fields as columns. The technique_id is a MITRE id like T1190. If you leave it out the alert still gets correlated, you just won't see it on the kill chain.

## How the correlation works

Grouping is by host and time window. Within one host, alerts keep joining the same incident until there's a quiet gap longer than the window, then a new incident starts. It's the simplest approach that actually works, and it's what cuts the alert count down.

The risk score isn't a black box, I wanted to be able to explain any number it produces. It's built from the worst single alert in the incident, plus a bonus for each extra ATT&CK tactic present (an incident that spans execution, credential access and exfiltration is way worse than three port scans), plus a small capped bonus for volume. The weights are in scorer.py with comments.

The MITRE mapping in mitre.py is a curated subset of the enterprise techniques, not the whole framework, enough to make the kill-chain view meaningful.

## Layout

Each piece is its own file so I could test them separately:

- models.py: the Alert and Incident types
- parsers.py: reads JSON and CSV into alerts
- correlator.py: groups alerts into incidents
- scorer.py: risk scoring
- mitre.py: technique to tactic mapping
- report.py: terminal, JSON and HTML output
- cli.py: ties it together

## Tests

```bash
pip install -e ".[dev]"
pytest
```

12 tests. They cover the correlation logic (grouping, splitting on a time gap, keeping hosts separate), the scoring (multi-stage incidents scoring higher, the cap at 100), the MITRE lookup, and the parsers rejecting bad input.

## Things I'd add next

Right now correlation is host plus time. The obvious next step is correlating across hosts by shared IP or by technique chains, which would catch lateral movement that the current version treats as separate incidents. A streaming mode for continuous input and more ATT&CK coverage would come after that.

## License

MIT
