#!/usr/bin/env python3
"""Adapt predicted core level9 attacks into a CSLE executable sequence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "model_outputs" / "attack_plans"

PIVOT_CREATING_ACTIONS = {
    "SAMBACRY_EXPLOIT",
    "DVWA_SQL_INJECTION",
    "CVE_2015_1427_EXPLOIT",
    "TELNET_SAME_USER_PASS_DICTIONARY",
    "FTP_SAME_USER_PASS_DICTIONARY",
    "SHELLSHOCK_EXPLOIT",
    "CVE_2015_3306_EXPLOIT",
    "CVE_2016_10033_EXPLOIT",
}

LOGIN_AFTER_ACTIONS = PIVOT_CREATING_ACTIONS | {
    "SSH_SAME_USER_PASS_DICTIONARY",
    "CVE_2010_0426_PRIV_ESC",
    "CVE_2015_5602_PRIV_ESC",
}

DISCOVERY_BEFORE_ACTIONS = {
    "SAMBACRY_EXPLOIT",
    "SSH_SAME_USER_PASS_DICTIONARY",
    "DVWA_SQL_INJECTION",
    "CVE_2015_1427_EXPLOIT",
    "SHELLSHOCK_EXPLOIT",
    "CVE_2015_3306_EXPLOIT",
    "CVE_2016_10033_EXPLOIT",
}

TARGETS = {
    "SAMBACRY_EXPLOIT": "samba",
    "SSH_SAME_USER_PASS_DICTIONARY": "ssh",
    "CVE_2010_0426_PRIV_ESC": "ssh",
    "DVWA_SQL_INJECTION": "dvwa",
    "CVE_2015_1427_EXPLOIT": "elasticsearch",
    "TELNET_SAME_USER_PASS_DICTIONARY": "samba",
    "FTP_SAME_USER_PASS_DICTIONARY": "dvwa",
    "SHELLSHOCK_EXPLOIT": "dvwa",
    "CVE_2015_3306_EXPLOIT": "ftp",
    "CVE_2016_10033_EXPLOIT": "mail",
    "CVE_2015_5602_PRIV_ESC": "ssh",
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def action_item(action: str, target: str, reason: str) -> dict[str, str]:
    return {"action": action, "target": target, "reason": reason}


def append_unique_consecutive(actions: list[dict[str, str]], item: dict[str, str]) -> None:
    if actions and actions[-1]["action"] == item["action"] and actions[-1]["target"] == item["target"]:
        return
    actions.append(item)


def load_core_attacks(data: dict[str, Any]) -> list[dict[str, str]]:
    if isinstance(data.get("selected_core_plan"), dict):
        raw = data["selected_core_plan"].get("core_attacks", [])
    else:
        raw = data.get("core_attacks", data.get("actions", []))
    attacks: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        action = str(item.get("action", item.get("attack", ""))).strip().upper()
        target = str(item.get("target") or TARGETS.get(action, "")).strip().lower()
        reason = str(item.get("reason", "")).strip()
        if action:
            attacks.append({"action": action, "target": target, "reason": reason})
    return attacks


def adapt(core_attacks: list[dict[str, str]], *, include_final_scan: bool) -> dict[str, Any]:
    actions: list[dict[str, str]] = []
    saw_login = False
    saw_tools_since_login = False
    pivot_available = False

    for attack in core_attacks:
        core_action = attack["action"]
        target = attack["target"] or TARGETS.get(core_action, "")
        reason = attack.get("reason", "")

        if core_action in DISCOVERY_BEFORE_ACTIONS:
            append_unique_consecutive(
                actions,
                action_item(
                    "PING_SCAN",
                    "all",
                    f"Adapter-added support action before {core_action} to refresh CSLE reachable-host state.",
                ),
            )

        if pivot_available and not saw_tools_since_login and core_action not in {"CVE_2010_0426_PRIV_ESC", "CVE_2015_5602_PRIV_ESC"}:
            append_unique_consecutive(
                actions,
                action_item(
                    "INSTALL_TOOLS",
                    "all",
                    f"Adapter-added support action before {core_action} because a compromised host may be used as a pivot.",
                ),
            )
            saw_tools_since_login = True

        append_unique_consecutive(
            actions,
            action_item(core_action, target, reason or "Core attack predicted by checkpoint-850."),
        )

        if core_action in LOGIN_AFTER_ACTIONS:
            append_unique_consecutive(
                actions,
                action_item(
                    "SERVICE_LOGIN",
                    "all",
                    f"Adapter-added CSLE runtime support action after {core_action} to update credentials, logged_in/root, and active connections.",
                ),
            )
            saw_login = True
            saw_tools_since_login = False

        if core_action in PIVOT_CREATING_ACTIONS or (
            core_action == "SSH_SAME_USER_PASS_DICTIONARY" and saw_login
        ):
            pivot_available = True

    if include_final_scan:
        append_unique_consecutive(
            actions,
            action_item("PING_SCAN", "all", "Adapter-added final reachability scan after inferred core attack sequence."),
        )

    return {
        "schema_version": 1,
        "sequence_name": "adapted_core_attack_csle_sequence",
        "prediction_basis": "Core attacks predicted by checkpoint-850; support actions added deterministically by adapter.",
        "execution_model": (
            "Run this sequence through run_predicted_csle_action_sequence.py so CSLE performs "
            "attacker_transition/defender_transition, credential insertion, service login, root detection, "
            "and final attacker-state updates."
        ),
        "actions": actions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-plan-file", type=Path, required=True)
    parser.add_argument(
        "--output-file",
        type=Path,
        default=DEFAULT_OUTPUT_DIR / "adapted_core_attack_csle_sequence.json",
    )
    parser.add_argument("--no-final-scan", action="store_true")
    args = parser.parse_args()

    data = read_json(args.core_plan_file)
    core_attacks = load_core_attacks(data)
    if not core_attacks:
        raise SystemExit(f"no core attacks found in {args.core_plan_file}")
    plan = adapt(core_attacks, include_final_scan=not args.no_final_scan)
    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    args.output_file.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"core_attacks={len(core_attacks)}")
    print(f"adapted_actions={len(plan['actions'])}")
    print(args.output_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
