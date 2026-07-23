"""Run a predicted CSLE attacker action sequence through the CSLE runtime.

The input plan is intentionally high-level: it names CSLE action types and
semantic targets such as "samba", "ssh", "dvwa", and "elasticsearch".
This runner resolves those targets against the current attacker observation
state before each step, then executes the real CSLE transition logic.

Example:
    CSLE_HOME=/home/yu3194924316/llm-recovery-dt/external/csle \
    /home/yu3194924316/llm-recovery-dt/external/csle/.venv/bin/python \
      experiments/csle_level9_dt/run_predicted_csle_action_sequence.py \
      --execution-id 16 \
      --plan-file experiments/csle_level9_dt/artifacts/model_outputs/codex_predicted_csle_action_sequence_from_checkpoint850.json
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import traceback
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ARTIFACT_DIR = Path(__file__).resolve().with_name("artifacts")

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_static_sequence_once import (  # noqa: E402
    action_to_dict,
    add_csle_paths,
    compromised_or_credentialed_machines,
    json_safe,
    machine_index_map,
    timestamp,
)


TargetResolver = Callable[[Any, str, int], int]


def default_output_path(execution_id: int, sequence_name: str) -> Path:
    safe_name = "".join(char if char.isalnum() or char in "-_" else "_" for char in sequence_name)
    return DEFAULT_ARTIFACT_DIR / f"level9_{execution_id}_{safe_name}_{timestamp()}.json"


def load_plan(plan_file: Path) -> dict[str, Any]:
    plan = json.loads(plan_file.read_text(encoding="utf-8"))
    if not isinstance(plan, dict):
        raise ValueError("Plan must be a JSON object")
    actions = plan.get("actions")
    if not isinstance(actions, list) or not actions:
        raise ValueError("Plan must contain a non-empty actions list")
    for idx, action in enumerate(actions, start=1):
        if not isinstance(action, dict):
            raise ValueError(f"Plan action {idx} must be a JSON object")
        if not action.get("action"):
            raise ValueError(f"Plan action {idx} is missing action")
    return plan


def candidate_ips_for_target(target: str, execution_id: int) -> list[str]:
    prefix = f"{execution_id}.9"
    target_key = target.strip().lower().replace("-", "_").replace(" ", "_")
    target_map = {
        "samba": [f"{prefix}.2.3", f"{prefix}.4.3", f"{prefix}.253.3"],
        "sambacry": [f"{prefix}.2.3", f"{prefix}.4.3", f"{prefix}.253.3"],
        "ssh": [f"{prefix}.2.78", f"{prefix}.3.78", f"{prefix}.253.78"],
        "ssh_server": [f"{prefix}.2.78", f"{prefix}.3.78", f"{prefix}.253.78"],
        "dvwa": [f"{prefix}.4.74", f"{prefix}.5.74", f"{prefix}.253.74"],
        "sql": [f"{prefix}.4.74", f"{prefix}.5.74", f"{prefix}.253.74"],
        "sql_injection": [f"{prefix}.4.74", f"{prefix}.5.74", f"{prefix}.253.74"],
        "elasticsearch": [f"{prefix}.5.62", f"{prefix}.6.62", f"{prefix}.7.62", f"{prefix}.253.62"],
        "cve_2015_1427": [f"{prefix}.5.62", f"{prefix}.6.62", f"{prefix}.7.62", f"{prefix}.253.62"],
    }
    if target_key in target_map:
        return target_map[target_key]
    if target_key.count(".") == 3:
        return [target_key]
    return []


def resolve_target_index(state: Any, target: str, execution_id: int) -> tuple[int, dict[str, Any]]:
    target_key = target.strip().lower()
    if target_key in {"all", "subnets", "network", "*"}:
        return -1, {"target": target, "mode": "all"}

    candidates = candidate_ips_for_target(target, execution_id)
    if not candidates:
        raise ValueError(f"Unknown target: {target}")

    machines = state.attacker_obs_state.machines
    for position, machine in enumerate(machines):
        machine_ips = set(getattr(machine, "ips", []))
        matched = sorted(machine_ips.intersection(candidates))
        if matched:
            return position, {
                "target": target,
                "mode": "exact_ip",
                "candidate_ips": candidates,
                "matched_ips": matched,
                "resolved_machine_ips": sorted(machine_ips),
            }

    candidate_last_octets = {ip.split(".")[-1] for ip in candidates}
    for position, machine in enumerate(machines):
        machine_ips = set(getattr(machine, "ips", []))
        matched = sorted(ip for ip in machine_ips if ip.split(".")[-1] in candidate_last_octets)
        if matched:
            return position, {
                "target": target,
                "mode": "last_octet_fallback",
                "candidate_ips": candidates,
                "matched_ips": matched,
                "resolved_machine_ips": sorted(machine_ips),
            }

    raise ValueError(
        f"Could not resolve target={target} candidate_ips={candidates} "
        f"observed_machines={len(machines)}"
    )


def build_action(action_name: str, index: int, env_config: Any) -> Any:
    add_csle_paths()

    from csle_common.dao.emulation_action.attacker.emulation_attacker_network_service_actions import (  # pylint: disable=import-outside-toplevel
        EmulationAttackerNetworkServiceActions,
    )
    from csle_common.dao.emulation_action.attacker.emulation_attacker_nmap_actions import (  # pylint: disable=import-outside-toplevel
        EmulationAttackerNMAPActions,
    )
    from csle_common.dao.emulation_action.attacker.emulation_attacker_shell_actions import (  # pylint: disable=import-outside-toplevel
        EmulationAttackerShellActions,
    )

    subnet_masks = env_config.topology_config.subnetwork_masks if index == -1 else None
    name = action_name.strip().upper()
    factories: dict[str, Callable[[], Any]] = {
        "PING_SCAN": lambda: EmulationAttackerNMAPActions.PING_SCAN(index=index, ips=subnet_masks),
        "TCP_SYN_STEALTH_SCAN": lambda: EmulationAttackerNMAPActions.TCP_SYN_STEALTH_SCAN(
            index=index, ips=subnet_masks
        ),
        "VULSCAN": lambda: EmulationAttackerNMAPActions.VULSCAN(index=index, ips=subnet_masks),
        "NMAP_VULNERS": lambda: EmulationAttackerNMAPActions.NMAP_VULNERS(index=index, ips=subnet_masks),
        "SSH_SAME_USER_PASS_DICTIONARY": lambda: EmulationAttackerNMAPActions.SSH_SAME_USER_PASS_DICTIONARY(
            index=index, ips=subnet_masks
        ),
        "TELNET_SAME_USER_PASS_DICTIONARY": lambda: EmulationAttackerNMAPActions.TELNET_SAME_USER_PASS_DICTIONARY(
            index=index, ips=subnet_masks
        ),
        "FTP_SAME_USER_PASS_DICTIONARY": lambda: EmulationAttackerNMAPActions.FTP_SAME_USER_PASS_DICTIONARY(
            index=index, ips=subnet_masks
        ),
        "SERVICE_LOGIN": lambda: EmulationAttackerNetworkServiceActions.SERVICE_LOGIN(index=index),
        "INSTALL_TOOLS": lambda: EmulationAttackerShellActions.INSTALL_TOOLS(index=index),
        "SSH_BACKDOOR": lambda: EmulationAttackerShellActions.SSH_BACKDOOR(index=index),
        "SAMBACRY_EXPLOIT": lambda: EmulationAttackerShellActions.SAMBACRY_EXPLOIT(index=index),
        "SHELLSHOCK_EXPLOIT": lambda: EmulationAttackerShellActions.SHELLSHOCK_EXPLOIT(index=index),
        "DVWA_SQL_INJECTION": lambda: EmulationAttackerShellActions.DVWA_SQL_INJECTION(index=index),
        "CVE_2015_3306_EXPLOIT": lambda: EmulationAttackerShellActions.CVE_2015_3306_EXPLOIT(index=index),
        "CVE_2015_1427_EXPLOIT": lambda: EmulationAttackerShellActions.CVE_2015_1427_EXPLOIT(index=index),
        "CVE_2016_10033_EXPLOIT": lambda: EmulationAttackerShellActions.CVE_2016_10033_EXPLOIT(index=index),
        "CVE_2010_0426_PRIV_ESC": lambda: EmulationAttackerShellActions.CVE_2010_0426_PRIV_ESC(index=index),
        "CVE_2015_5602_PRIV_ESC": lambda: EmulationAttackerShellActions.CVE_2015_5602_PRIV_ESC(index=index),
    }
    if name not in factories:
        raise ValueError(f"Unsupported action: {action_name}")
    return factories[name]()


def run_predicted_sequence(
    execution_id: int,
    emulation_name: str,
    plan_file: Path,
    continue_on_error: bool = False,
) -> dict[str, Any]:
    add_csle_paths()

    from csle_attacker.attacker import Attacker  # pylint: disable=import-outside-toplevel
    from csle_common.dao.emulation_action.defender.emulation_defender_stopping_actions import (  # pylint: disable=import-outside-toplevel
        EmulationDefenderStoppingActions,
    )
    from csle_common.dao.emulation_config.emulation_env_state import EmulationEnvState  # pylint: disable=import-outside-toplevel
    from csle_common.metastore.metastore_facade import MetastoreFacade  # pylint: disable=import-outside-toplevel
    from csle_defender.defender import Defender  # pylint: disable=import-outside-toplevel

    plan = load_plan(plan_file)
    sequence_name = plan.get("sequence_name", plan_file.stem)

    execution = MetastoreFacade.get_emulation_execution(
        ip_first_octet=execution_id,
        emulation_name=emulation_name,
    )
    if execution is None:
        raise RuntimeError(f"Execution not found: {emulation_name} id={execution_id}")

    env_config = execution.emulation_env_config
    state = EmulationEnvState(emulation_env_config=env_config)
    plan_actions = plan["actions"]
    steps: list[dict[str, Any]] = []

    print(f"=== CSLE LEVEL9 PREDICTED ACTION SEQUENCE: {sequence_name} ===", flush=True)
    print(f"emulation={emulation_name} execution_id={execution_id}", flush=True)
    print(f"agent_ip={env_config.containers_config.agent_ip}", flush=True)
    print(f"steps={len(plan_actions)}", flush=True)

    for step_idx, predicted in enumerate(plan_actions, start=1):
        machine_index_map_before = machine_index_map(state)
        before = compromised_or_credentialed_machines(state)
        action_name = str(predicted["action"])
        target = str(predicted.get("target", "all"))

        print(f"\n--- STEP {step_idx}/{len(plan_actions)} ---", flush=True)
        print(f"predicted_action={action_name} target={target}", flush=True)
        print(
            "machine_index_map_before="
            + json.dumps(machine_index_map_before, indent=2, sort_keys=True),
            flush=True,
        )

        action = None
        resolution = None
        status = "success"
        error = None
        error_traceback = None
        error_phase = None
        after = before

        try:
            resolved_index, resolution = resolve_target_index(state, target, execution_id)
            action = build_action(action_name, resolved_index, env_config)
            action.ips = state.attacker_obs_state.get_action_ips(
                a=action,
                emulation_env_config=env_config,
            )
            print(
                f"resolved_index={resolved_index} resolution="
                + json.dumps(resolution, sort_keys=True),
                flush=True,
            )
            print(
                f"action={action.name} id={json_safe(action.id)} "
                f"type={json_safe(action.type)} index={action.index}",
                flush=True,
            )
            print(f"target_ips={action.ips}", flush=True)
        except Exception as exc:  # noqa: BLE001 - preserve exact failure.
            status = "error"
            error = repr(exc)
            error_traceback = traceback.format_exc()
            error_phase = "target_resolution_or_action_build"
            print(f"status=error error={error}", flush=True)
            print(error_traceback, flush=True)

        if status == "success":
            try:
                state = Attacker.attacker_transition(s=state, attacker_action=action)
                defender_action = EmulationDefenderStoppingActions.CONTINUE(index=-1)
                state = Defender.defender_transition(
                    s=state,
                    defender_action=defender_action,
                    attacker_action=action,
                )
            except Exception as exc:  # noqa: BLE001 - preserve exact runtime failure.
                status = "error"
                error = repr(exc)
                error_traceback = traceback.format_exc()
                error_phase = "attacker_transition"
                print(f"status=error error={error}", flush=True)
                print(error_traceback, flush=True)

        after = compromised_or_credentialed_machines(state)
        step_record = {
            "step": step_idx,
            "status": status,
            "error": error,
            "error_traceback": error_traceback,
            "error_phase": error_phase,
            "predicted_action": copy.deepcopy(predicted),
            "target_resolution": resolution,
            "action": action_to_dict(action) if action is not None else None,
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
        "kind": "csle_predicted_action_sequence_run",
        "emulation_name": emulation_name,
        "execution_id": execution_id,
        "sequence": sequence_name,
        "plan_file": str(plan_file),
        "plan": plan,
        "agent_ip": env_config.containers_config.agent_ip,
        "steps": steps,
        "final_compromised_state": final_state,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execution-id", type=int, required=True)
    parser.add_argument("--plan-file", type=Path, required=True)
    parser.add_argument("--emulation-name", default="csle-level9-0.10.0")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Record a step error and continue executing later predicted actions.",
    )
    args = parser.parse_args()

    plan = load_plan(args.plan_file)
    sequence_name = plan.get("sequence_name", args.plan_file.stem)
    output = args.output or default_output_path(args.execution_id, sequence_name)
    output.parent.mkdir(parents=True, exist_ok=True)

    report = run_predicted_sequence(
        execution_id=args.execution_id,
        emulation_name=args.emulation_name,
        plan_file=args.plan_file,
        continue_on_error=args.continue_on_error,
    )
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\n=== FINAL SUMMARY ===", flush=True)
    print(json.dumps(report["final_compromised_state"], indent=2, sort_keys=True), flush=True)
    print(f"wrote {output}", flush=True)


if __name__ == "__main__":
    main()
