#!/usr/bin/env python3
"""Run candidate DT16 attack commands from a generated attack plan.

This runner intentionally executes only the concrete commands present in the
input JSON. It does not call CSLE static sequences or helper exploit scripts by
itself.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLAN = (
    REPO_ROOT
    / "experiments"
    / "csle_level9_dt"
    / "artifacts"
    / "model_outputs"
    / "codex_no_helper_dt16_experienced_attack_plan.json"
)
DEFAULT_OUT_DIR = (
    REPO_ROOT
    / "experiments"
    / "csle_level9_dt"
    / "artifacts"
    / "model_outputs"
)


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run_docker_command(container: str, command: str, timeout: int) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    proc = subprocess.run(
        ["docker", "exec", container, "bash", "-lc", command],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return {
        "container": container,
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "started_at_utc": started.isoformat(),
        "ended_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run generated CSLE level9 DT attack commands.")
    parser.add_argument("--plan-file", default=str(DEFAULT_PLAN))
    parser.add_argument("--out-file", default=None)
    parser.add_argument("--timeout-per-command", type=int, default=180)
    parser.add_argument(
        "--section",
        default="attack_commands",
        choices=["attack_commands", "discovery_commands"],
        help="Plan section to execute. Default intentionally excludes discovery.",
    )
    args = parser.parse_args()

    plan_path = Path(args.plan_file)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    commands = plan.get(args.section, [])
    if not isinstance(commands, list):
        raise TypeError(f"{args.section} must be a list")

    results = []
    print(f"running {len(commands)} commands from {plan_path}", flush=True)
    for idx, item in enumerate(commands, start=1):
        container = item["container"]
        command = item["command"]
        phase = item.get("phase", f"command {idx}")
        print(f"--- COMMAND {idx}/{len(commands)}: {phase} ---", flush=True)
        result = run_docker_command(container, command, args.timeout_per_command)
        result["index"] = idx
        result["phase"] = phase
        result["description"] = item.get("description")
        result["expected_alert_or_state"] = item.get("expected_alert_or_state")
        result["risk"] = item.get("risk")
        result["needs_manual_review"] = item.get("needs_manual_review")
        results.append(result)
        print(f"returncode={result['returncode']}", flush=True)

    output = {
        "kind": "csle_level9_generated_attack_command_run",
        "plan_file": str(plan_path),
        "section": args.section,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command_count": len(results),
        "results": results,
    }
    out_file = Path(args.out_file) if args.out_file else DEFAULT_OUT_DIR / f"codex_no_helper_dt16_attack_run_{timestamp()}.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
