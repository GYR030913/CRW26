#!/usr/bin/env python3
"""Export a high-level and command-level ground-truth attack record."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STEP_RE = re.compile(r"^--- STEP (\d+)/(\d+) ---$")
COMMAND_MARKERS = (
    "Running NMAP scan",
    "Sql injeciton cmd:",
    "SQL injection cmd:",
    "CVE-2015-1427 cmd:",
    "Sambacry",
    "samba_exploit",
    "shellshock",
    "CVE-2010-0426",
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_ip_text(value: Any) -> Any:
    if isinstance(value, str):
        return re.sub(r"\b(?:15|16)\.9\.", "X.9.", value)
    if isinstance(value, list):
        return [normalize_ip_text(v) for v in value]
    if isinstance(value, dict):
        return {k: normalize_ip_text(v) for k, v in value.items()}
    return value


def compromised_delta(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> list[dict[str, Any]]:
    before_keys = {json.dumps(normalize_ip_text(machine), sort_keys=True) for machine in before}
    return [
        machine for machine in after
        if json.dumps(normalize_ip_text(machine), sort_keys=True) not in before_keys
    ]


def extract_terminal_commands(path: Path | None) -> dict[int, list[str]]:
    if path is None or not path.exists():
        return {}
    commands_by_step: dict[int, list[str]] = {}
    current_step: int | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.rstrip()
        match = STEP_RE.match(line)
        if match:
            current_step = int(match.group(1))
            commands_by_step.setdefault(current_step, [])
            continue
        if current_step is None:
            continue
        if any(marker in line for marker in COMMAND_MARKERS):
            commands_by_step.setdefault(current_step, []).append(line)
    return commands_by_step


def build_record(report: dict[str, Any], terminal_commands: dict[int, list[str]]) -> dict[str, Any]:
    high_level_steps = []
    command_level_steps = []

    for step in report.get("steps", []):
        action = step.get("action", {})
        step_no = step.get("step")
        before = step.get("compromised_or_credentialed_before", [])
        after = step.get("compromised_or_credentialed_after", [])
        delta = compromised_delta(before, after)

        high_level_steps.append(
            {
                "step": step_no,
                "status": step.get("status"),
                "error_phase": step.get("error_phase"),
                "action_name": action.get("name"),
                "action_id": action.get("id"),
                "action_type": action.get("type"),
                "action_index": action.get("index"),
                "target_ips": action.get("ips", []),
                "target_ips_normalized": normalize_ip_text(action.get("ips", [])),
                "description": action.get("descr"),
                "vulnerability": action.get("vulnerability"),
                "outcome": action.get("action_outcome"),
                "new_or_changed_compromised_state": delta,
                "new_or_changed_compromised_state_normalized": normalize_ip_text(delta),
            }
        )

        command_level_steps.append(
            {
                "step": step_no,
                "action_name": action.get("name"),
                "target_ips": action.get("ips", []),
                "command_templates_from_action": action.get("cmds", []),
                "terminal_command_lines": terminal_commands.get(int(step_no), []) if step_no is not None else [],
                "terminal_command_lines_normalized": normalize_ip_text(
                    terminal_commands.get(int(step_no), []) if step_no is not None else []
                ),
            }
        )

    return {
        "schema_version": "level9-attack-ground-truth/v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": {
            "emulation_name": report.get("emulation_name"),
            "execution_id": report.get("execution_id"),
            "sequence": report.get("sequence"),
            "agent_ip": report.get("agent_ip"),
        },
        "purpose": (
            "Ground-truth record for comparing a fine-tuned model's predicted attack "
            "sequence/tactics/techniques against the actually executed CSLE level9 sequence."
        ),
        "high_level_attack": high_level_steps,
        "command_level_attack": command_level_steps,
        "final_compromised_state": report.get("final_compromised_state", []),
        "final_compromised_state_normalized": normalize_ip_text(report.get("final_compromised_state", [])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Export level9 attack ground truth.")
    parser.add_argument("--attack-report", required=True)
    parser.add_argument("--terminal-log")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    report_path = Path(args.attack_report)
    terminal_path = Path(args.terminal_log) if args.terminal_log else None
    out_path = Path(args.out)

    report = load_json(report_path)
    terminal_commands = extract_terminal_commands(terminal_path)
    record = build_record(report, terminal_commands)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
