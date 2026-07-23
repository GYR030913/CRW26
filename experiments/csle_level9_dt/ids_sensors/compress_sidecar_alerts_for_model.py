#!/usr/bin/env python3
"""Create compact chronological IDS-alert model input from sidecar replay logs."""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path


LINE_RE = re.compile(
    r"^(?P<md>\d{2}/\d{2})-(?P<hms>\d{2}:\d{2}:\d{2})(?:\.(?P<usec>\d+))?\s+"
    r"\[\*\*\]\s+\[1:(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.*?)\s+\[\*\*\]\s+"
    r"\[Classification:\s+(?P<cls>.*?)\]\s+\[Priority:\s+(?P<pri>\d+)\]\s+"
    r"\{(?P<proto>[^}]+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)"
)


DEFAULT_INCLUDE_SIDS = {
    "9100002",  # SSH connection
    "9100003",  # SSH brute force
    "9100004",  # SambaCry
    "9100005",  # SMB
    "9100006",  # NetBIOS
    "9100007",  # DVWA SQLi
    "9100008",  # credential disclosure
    "9100009",  # Elasticsearch CVE
    "9100010",  # reverse shell/backdoor-like
    "9100011",
    "9100012",
    "9100013",
    "9100014",
    "9100015",
    "9100016",
    "9100017",
    "9100018",
    "9100021",
    "9100024",
    "9100025",
    "9100026",
    "9100027",
}


def parse_alert(line: str, year: int) -> dict[str, str] | None:
    match = LINE_RE.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    usec = (data.get("usec") or "0")[:6].ljust(6, "0")
    dt = datetime.strptime(f"{year}/{data['md']} {data['hms']}.{usec}", "%Y/%m/%d %H:%M:%S.%f")
    data["dt"] = dt
    data["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S,%f")[:23]
    return data


def flow_key(alert: dict[str, str]) -> tuple[str, str, str, str, str]:
    dst_host = alert["dst"].rsplit(":", 1)[0]
    dst_port = alert["dst"].rsplit(":", 1)[1] if ":" in alert["dst"] else ""
    src_host = alert["src"].rsplit(":", 1)[0]
    return (alert["sid"], alert["msg"], src_host, dst_host, dst_port)


def format_alert(alert: dict[str, str]) -> str:
    return (
        f"{alert['timestamp']} [    INFO] Alert: [pri={alert['pri']} cls={alert['cls']}] "
        f"{{{alert['proto']}}} {alert['src']} -> {alert['dst']} "
        f"[1:{alert['sid']}:{alert['rev']}] {alert['msg']}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Compress sidecar replay Snort alerts for model input.")
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--year", type=int, default=2026)
    parser.add_argument("--max-per-flow", type=int, default=6)
    parser.add_argument("--include-default-rules", action="store_true")
    args = parser.parse_args()

    replay_dir = Path(args.session_dir) / "snort_replay"
    alerts = []
    for path in sorted(replay_dir.glob("*_fast.log")):
        source = path.name.removesuffix("_fast.log")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            alert = parse_alert(line, args.year)
            if not alert:
                continue
            alert["source"] = source
            if not args.include_default_rules and alert["sid"] not in DEFAULT_INCLUDE_SIDS:
                continue
            alerts.append(alert)

    alerts.sort(key=lambda item: item["dt"])
    counts: dict[tuple[str, str, str, str, str], int] = defaultdict(int)
    selected = []
    for alert in alerts:
        key = flow_key(alert)
        counts[key] += 1
        if counts[key] <= args.max_per_flow:
            selected.append(alert)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["Compressed IDS alerts:"]
    lines.extend(format_alert(alert) for alert in selected)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"raw_sidecar_alerts={len(alerts)}")
    print(f"compressed_alerts={len(selected)}")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
