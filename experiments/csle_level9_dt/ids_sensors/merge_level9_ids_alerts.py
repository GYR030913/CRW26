#!/usr/bin/env python3
"""Merge router Snort alerts with passive IDS replay alerts."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def run(cmd: list[str], timeout: int = 60) -> dict[str, Any]:
    proc = subprocess.run(
        cmd,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return {"cmd": cmd, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def collect_router_fast_log(router_container: str, out_path: Path) -> dict[str, Any]:
    result = run(["docker", "exec", router_container, "bash", "-lc", "cat /var/snort/fast.log 2>/dev/null || true"])
    out_path.write_text(result["stdout"], encoding="utf-8")
    return result


def tagged_lines(source: str, path: Path) -> list[str]:
    if not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            lines.append(f"[{source}] {line}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge level9 IDS fast alerts.")
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--execution-id", type=int, required=True)
    parser.add_argument("--router-container", default=None)
    args = parser.parse_args()

    session_dir = Path(args.session_dir)
    replay_dir = session_dir / "snort_replay"
    merged_path = session_dir / "merged_ids_fast.log"
    summary_path = session_dir / "merged_ids_summary.json"
    router_container = args.router_container or f"csle_router_2_1-level9-{args.execution_id}"
    router_fast = session_dir / "router_fast.log"
    router_result = collect_router_fast_log(router_container, router_fast)

    all_lines = tagged_lines("router", router_fast)
    sources = [{"source": "router", "path": str(router_fast), "lines": len(all_lines)}]
    for fast_log in sorted(replay_dir.glob("*_fast.log")):
        source = fast_log.name.removesuffix("_fast.log")
        lines = tagged_lines(source, fast_log)
        all_lines.extend(lines)
        sources.append({"source": source, "path": str(fast_log), "lines": len(lines)})

    merged_path.write_text("\n".join(all_lines) + ("\n" if all_lines else ""), encoding="utf-8")
    summary = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "execution_id": args.execution_id,
        "router_container": router_container,
        "router_collect": router_result,
        "merged_log": str(merged_path),
        "sources": sources,
        "total_lines": len(all_lines),
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"merged_lines={len(all_lines)}")
    print(merged_path)
    print(summary_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
