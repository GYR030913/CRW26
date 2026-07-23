"""Run one CSLE level9 static attacker sequence and save observations.

Example:
    CSLE_HOME=/path/to/csle /path/to/csle/.venv/bin/python \
      experiments/csle_level9_dt/run_static_sequence_once.py \
      --execution-id 15 --sequence novice
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ARTIFACT_DIR = Path(__file__).resolve().with_name("artifacts")


def add_csle_paths() -> None:
    csle_root = REPO_ROOT / "external" / "csle"
    paths = [
        csle_root / "simulation-system" / "libs" / "csle-common" / "src",
        csle_root / "simulation-system" / "libs" / "csle-attacker" / "src",
        csle_root / "simulation-system" / "libs" / "csle-defender" / "src",
        csle_root / "simulation-system" / "libs" / "csle-collector" / "src",
        csle_root / "simulation-system" / "libs" / "csle-base" / "src",
        csle_root / "simulation-system" / "libs" / "csle-ryu" / "src",
    ]
    for path in paths:
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def default_output_path(execution_id: int, sequence: str) -> Path:
    return DEFAULT_ARTIFACT_DIR / f"level9_{execution_id}_{sequence}_{timestamp()}.json"


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(json_safe(k)): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    if hasattr(value, "to_dict"):
        return json_safe(value.to_dict())
    if hasattr(value, "name") and hasattr(value, "value"):
        return value.name
    if hasattr(value, "__dict__"):
        return json_safe(value.__dict__)
    return value


def credential_to_dict(credential: Any) -> dict[str, Any]:
    return {
        "username": getattr(credential, "username", None),
        "password": getattr(credential, "pw", None),
        "port": getattr(credential, "port", None),
        "protocol": str(getattr(credential, "protocol", "")),
        "service": getattr(credential, "service", None),
        "root": getattr(credential, "root", None),
    }


def compromised_or_credentialed_machines(state: Any) -> list[dict[str, Any]]:
    machines = []
    attacker_obs = state.attacker_obs_state
    for machine in attacker_obs.machines:
        credentials = [
            credential_to_dict(credential)
            for credential in getattr(machine, "shell_access_credentials", [])
        ]
        backdoor_credentials = [
            credential_to_dict(credential)
            for credential in getattr(machine, "backdoor_credentials", [])
        ]
        flags = [json_safe(flag) for flag in getattr(machine, "flags_found", set())]
        logged_in = bool(getattr(machine, "logged_in", False))
        root = bool(getattr(machine, "root", False))
        if credentials or backdoor_credentials or flags or logged_in or root:
            machines.append(
                {
                    "index": getattr(machine, "index", None),
                    "ips": sorted(getattr(machine, "ips", [])),
                    "credentials": credentials,
                    "backdoor_credentials": backdoor_credentials,
                    "logged_in": logged_in,
                    "root": root,
                    "flags": flags,
                    "shell_access": bool(getattr(machine, "shell_access", False)),
                    "logged_in_services": list(getattr(machine, "logged_in_services", [])),
                    "root_services": list(getattr(machine, "root_services", [])),
                }
            )
    return machines


def machine_index_map(state: Any) -> list[dict[str, Any]]:
    machines = []
    for list_position, machine in enumerate(state.attacker_obs_state.machines):
        machines.append(
            {
                "list_position": list_position,
                "machine_index": getattr(machine, "index", None),
                "ips": sorted(getattr(machine, "ips", [])),
                "logged_in": bool(getattr(machine, "logged_in", False)),
                "root": bool(getattr(machine, "root", False)),
                "shell_access": bool(getattr(machine, "shell_access", False)),
                "credentials": [
                    credential_to_dict(credential)
                    for credential in getattr(machine, "shell_access_credentials", [])
                ],
                "backdoor_credentials": [
                    credential_to_dict(credential)
                    for credential in getattr(machine, "backdoor_credentials", [])
                ],
                "cve_vulns": [
                    json_safe(vuln)
                    for vuln in getattr(machine, "cve_vulns", [])
                ],
                "osvdb_vulns": [
                    json_safe(vuln)
                    for vuln in getattr(machine, "osvdb_vulns", [])
                ],
                "logged_in_services": list(getattr(machine, "logged_in_services", [])),
                "root_services": list(getattr(machine, "root_services", [])),
            }
        )
    return machines


def action_to_dict(action: Any) -> dict[str, Any]:
    return {
        "id": json_safe(action.id),
        "name": action.name,
        "type": json_safe(action.type),
        "index": action.index,
        "ips": list(action.ips),
        "cmds": list(action.cmds),
        "descr": action.descr,
        "vulnerability": json_safe(action.vulnerability),
        "action_outcome": json_safe(action.action_outcome),
        "backdoor": action.backdoor,
    }


def run_sequence(
    execution_id: int,
    emulation_name: str,
    sequence: str,
    continue_on_error: bool = False,
) -> dict[str, Any]:
    add_csle_paths()

    import csle_common.constants.constants as constants  # pylint: disable=import-outside-toplevel
    from csle_attacker.attacker import Attacker  # pylint: disable=import-outside-toplevel
    from csle_common.dao.emulation_action.defender.emulation_defender_stopping_actions import (  # pylint: disable=import-outside-toplevel
        EmulationDefenderStoppingActions,
    )
    from csle_common.dao.emulation_config.emulation_env_state import EmulationEnvState  # pylint: disable=import-outside-toplevel
    from csle_common.metastore.metastore_facade import MetastoreFacade  # pylint: disable=import-outside-toplevel
    from csle_defender.defender import Defender  # pylint: disable=import-outside-toplevel

    sequence_key_map = {
        "novice": constants.STATIC_ATTACKERS.NOVICE,
        "experienced": constants.STATIC_ATTACKERS.EXPERIENCED,
        "expert": constants.STATIC_ATTACKERS.EXPERT,
    }
    sequence_key = sequence_key_map[sequence]

    execution = MetastoreFacade.get_emulation_execution(
        ip_first_octet=execution_id,
        emulation_name=emulation_name,
    )
    if execution is None:
        raise RuntimeError(f"Execution not found: {emulation_name} id={execution_id}")

    env_config = execution.emulation_env_config
    actions = env_config.static_attacker_sequences[sequence_key]
    state = EmulationEnvState(emulation_env_config=env_config)
    steps: list[dict[str, Any]] = []

    print(f"=== CSLE LEVEL9 STATIC SEQUENCE: {sequence} ===", flush=True)
    print(f"emulation={emulation_name} execution_id={execution_id}", flush=True)
    print(f"agent_ip={env_config.containers_config.agent_ip}", flush=True)
    print(f"steps={len(actions)}", flush=True)

    for step_idx, original_action in enumerate(actions, start=1):
        action = copy.deepcopy(original_action)
        machine_index_map_before = machine_index_map(state)
        before = compromised_or_credentialed_machines(state)
        print(f"\n--- STEP {step_idx}/{len(actions)} ---", flush=True)
        print(
            f"action={action.name} id={json_safe(action.id)} "
            f"type={json_safe(action.type)} index={action.index}",
            flush=True,
        )
        print(
            "machine_index_map_before="
            + json.dumps(machine_index_map_before, indent=2, sort_keys=True),
            flush=True,
        )
        target_resolution_error = None
        target_resolution_traceback = None
        try:
            action.ips = state.attacker_obs_state.get_action_ips(
                a=action,
                emulation_env_config=env_config,
            )
        except Exception as exc:  # noqa: BLE001 - record index-resolution failures.
            target_resolution_error = repr(exc)
            target_resolution_traceback = traceback.format_exc()
            print(f"target_resolution_status=error error={target_resolution_error}", flush=True)
            print(target_resolution_traceback, flush=True)
        print(f"target_ips={action.ips}", flush=True)

        if target_resolution_error is not None:
            step_record = {
                "step": step_idx,
                "status": "error",
                "error": target_resolution_error,
                "error_traceback": target_resolution_traceback,
                "error_phase": "target_resolution",
                "action": action_to_dict(action),
                "machine_index_map_before": machine_index_map_before,
                "observed_machine_count": len(state.attacker_obs_state.machines),
                "compromised_or_credentialed_before": before,
                "compromised_or_credentialed_after": before,
            }
            steps.append(step_record)
            print("status=error", flush=True)
            print(f"observed_machines={step_record['observed_machine_count']}", flush=True)
            print(
                "compromised_or_credentialed="
                + json.dumps(before, indent=2, sort_keys=True),
                flush=True,
            )
            if not continue_on_error:
                break
            continue

        status = "success"
        error = None
        error_traceback = None
        try:
            state = Attacker.attacker_transition(s=state, attacker_action=action)
            defender_action = EmulationDefenderStoppingActions.CONTINUE(index=-1)
            state = Defender.defender_transition(
                s=state,
                defender_action=defender_action,
                attacker_action=action,
            )
        except Exception as exc:  # noqa: BLE001 - preserve exact failure in report.
            status = "error"
            error = repr(exc)
            error_traceback = traceback.format_exc()
            print(f"status=error error={error}", flush=True)
            print(error_traceback, flush=True)

        after = compromised_or_credentialed_machines(state)
        step_record = {
            "step": step_idx,
            "status": status,
            "error": error,
            "error_traceback": error_traceback,
            "error_phase": "attacker_transition" if status == "error" else None,
            "action": action_to_dict(action),
            "machine_index_map_before": machine_index_map_before,
            "observed_machine_count": len(state.attacker_obs_state.machines),
            "compromised_or_credentialed_before": before,
            "compromised_or_credentialed_after": after,
        }
        steps.append(step_record)
        print(f"status={status}", flush=True)
        print(f"observed_machines={step_record['observed_machine_count']}", flush=True)
        print(
            "compromised_or_credentialed="
            + json.dumps(after, indent=2, sort_keys=True),
            flush=True,
        )
        if status == "error" and not continue_on_error:
            break

    final_state = compromised_or_credentialed_machines(state)
    return {
        "schema_version": 1,
        "created_at_utc": timestamp(),
        "emulation_name": emulation_name,
        "execution_id": execution_id,
        "sequence": sequence,
        "agent_ip": env_config.containers_config.agent_ip,
        "steps": steps,
        "final_compromised_state": final_state,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execution-id", type=int, required=True)
    parser.add_argument("--sequence", choices=["novice", "experienced", "expert"], required=True)
    parser.add_argument("--emulation-name", default="csle-level9-0.10.0")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Record a step error and continue executing later actions.",
    )
    args = parser.parse_args()

    output = args.output or default_output_path(args.execution_id, args.sequence)
    output.parent.mkdir(parents=True, exist_ok=True)

    report = run_sequence(
        execution_id=args.execution_id,
        emulation_name=args.emulation_name,
        sequence=args.sequence,
        continue_on_error=args.continue_on_error,
    )
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\n=== FINAL SUMMARY ===", flush=True)
    print(json.dumps(report["final_compromised_state"], indent=2, sort_keys=True), flush=True)
    print(f"wrote {output}", flush=True)


if __name__ == "__main__":
    main()
