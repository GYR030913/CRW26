#!/usr/bin/env python3
"""Evaluate an externally executed attack with CSLE's service-login logic.

This script does not execute an attack. It injects candidate credentials into a
fresh CSLE attacker observation state, calls CSLE's native NETWORK_SERVICE_LOGIN
transition, and reports logged_in/root using the same connection and sudo checks
used by CSLE static attacker sequences.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CREDENTIALS = (
    REPO_ROOT
    / "experiments"
    / "csle_level9_dt"
    / "artifacts"
    / "model_inputs"
    / "experienced"
    / "candidate_credentials_level9_experienced_dt16.json"
)
DEFAULT_OUT_DIR = (
    REPO_ROOT
    / "experiments"
    / "csle_level9_dt"
    / "artifacts"
    / "model_outputs"
)


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
    for machine in state.attacker_obs_state.machines:
        credentials = [
            credential_to_dict(credential)
            for credential in getattr(machine, "shell_access_credentials", [])
        ]
        backdoor_credentials = [
            credential_to_dict(credential)
            for credential in getattr(machine, "backdoor_credentials", [])
        ]
        logged_in = bool(getattr(machine, "logged_in", False))
        root = bool(getattr(machine, "root", False))
        if credentials or backdoor_credentials or logged_in or root:
            machines.append(
                {
                    "index": getattr(machine, "index", None),
                    "ips": sorted(getattr(machine, "ips", [])),
                    "credentials": credentials,
                    "backdoor_credentials": backdoor_credentials,
                    "logged_in": logged_in,
                    "root": root,
                    "flags": [json_safe(flag) for flag in getattr(machine, "flags_found", set())],
                    "shell_access": bool(getattr(machine, "shell_access", False)),
                    "logged_in_services": list(getattr(machine, "logged_in_services", [])),
                    "root_services": list(getattr(machine, "root_services", [])),
                    "reachable": sorted(getattr(machine, "reachable", set())),
                }
            )
    return machines


def service_to_constants(service: str, constants: Any) -> tuple[str, int]:
    normalized = service.lower()
    if normalized == constants.SSH.SERVICE_NAME:
        return constants.SSH.SERVICE_NAME, constants.SSH.DEFAULT_PORT
    if normalized == constants.TELNET.SERVICE_NAME:
        return constants.TELNET.SERVICE_NAME, constants.TELNET.DEFAULT_PORT
    if normalized == constants.FTP.SERVICE_NAME:
        return constants.FTP.SERVICE_NAME, constants.FTP.DEFAULT_PORT
    raise ValueError(f"Unsupported service for CSLE service login: {service}")


def load_candidate_credentials(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "machines" not in data or not isinstance(data["machines"], list):
        raise ValueError("candidate credentials file must contain a machines list")
    return data


def build_state_with_candidates(env_config: Any, candidates: dict[str, Any]) -> Any:
    import csle_common.constants.constants as constants  # pylint: disable=import-outside-toplevel
    from csle_common.dao.emulation_config.credential import Credential  # pylint: disable=import-outside-toplevel
    from csle_common.dao.emulation_config.emulation_env_state import EmulationEnvState  # pylint: disable=import-outside-toplevel
    from csle_common.dao.emulation_config.transport_protocol import TransportProtocol  # pylint: disable=import-outside-toplevel
    from csle_common.dao.emulation_observation.attacker.emulation_attacker_machine_observation_state import (  # pylint: disable=import-outside-toplevel
        EmulationAttackerMachineObservationState,
    )

    state = EmulationEnvState(emulation_env_config=env_config)
    state.attacker_obs_state.agent_reachable = set(candidates.get("agent_reachable", []))
    machines = []
    for item in candidates["machines"]:
        ips = item.get("ips", [])
        if not ips:
            raise ValueError(f"candidate machine missing ips: {item}")
        machine = EmulationAttackerMachineObservationState(ips=ips)
        machine.shell_access = True
        machine.untried_credentials = True
        machine.reachable = set(item.get("reachable", []))
        for cred_item in item.get("credentials", []):
            service_name, default_port = service_to_constants(cred_item["service"], constants)
            credential = Credential(
                username=cred_item["username"],
                pw=cred_item["password"],
                port=int(cred_item.get("port", default_port)),
                protocol=TransportProtocol.TCP,
                service=service_name,
                root=bool(cred_item.get("root", False)),
            )
            machine.shell_access_credentials.append(credential)
            if cred_item.get("kind") == "backdoor":
                machine.backdoor_credentials.append(copy.deepcopy(credential))
                machine.backdoor_tried = True
                machine.backdoor_installed = True
        machines.append(machine)
    state.attacker_obs_state.machines = machines
    return state


def evaluate_with_csle_service_login(
    execution_id: int,
    emulation_name: str,
    candidate_credentials: Path,
) -> dict[str, Any]:
    add_csle_paths()

    from csle_attacker.attacker import Attacker  # pylint: disable=import-outside-toplevel
    from csle_common.dao.emulation_action.attacker.emulation_attacker_network_service_actions import (  # pylint: disable=import-outside-toplevel
        EmulationAttackerNetworkServiceActions,
    )
    from csle_common.dao.emulation_action.defender.emulation_defender_stopping_actions import (  # pylint: disable=import-outside-toplevel
        EmulationDefenderStoppingActions,
    )
    from csle_common.metastore.metastore_facade import MetastoreFacade  # pylint: disable=import-outside-toplevel
    from csle_defender.defender import Defender  # pylint: disable=import-outside-toplevel

    execution = MetastoreFacade.get_emulation_execution(
        ip_first_octet=execution_id,
        emulation_name=emulation_name,
    )
    if execution is None:
        raise RuntimeError(f"Execution not found: {emulation_name} id={execution_id}")

    candidates = load_candidate_credentials(candidate_credentials)
    state = build_state_with_candidates(execution.emulation_env_config, candidates)
    before = compromised_or_credentialed_machines(state)

    action = EmulationAttackerNetworkServiceActions.SERVICE_LOGIN(index=-1)
    state = Attacker.attacker_transition(s=state, attacker_action=action)
    defender_action = EmulationDefenderStoppingActions.CONTINUE(index=-1)
    state = Defender.defender_transition(
        s=state,
        defender_action=defender_action,
        attacker_action=action,
    )
    after = compromised_or_credentialed_machines(state)

    return {
        "schema_version": 1,
        "kind": "csle_service_login_evaluation",
        "created_at_utc": timestamp(),
        "emulation_name": emulation_name,
        "execution_id": execution_id,
        "agent_ip": execution.emulation_env_config.containers_config.agent_ip,
        "candidate_credentials_file": str(candidate_credentials),
        "candidate_state_before_service_login": before,
        "final_compromised_state": after,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execution-id", type=int, required=True)
    parser.add_argument("--emulation-name", default="csle-level9-0.10.0")
    parser.add_argument("--candidate-credentials", type=Path, default=DEFAULT_CREDENTIALS)
    parser.add_argument("--out-file", type=Path)
    args = parser.parse_args()

    output = args.out_file or (
        DEFAULT_OUT_DIR / f"csle_login_evaluation_execution{args.execution_id}_{timestamp()}.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    report = evaluate_with_csle_service_login(
        execution_id=args.execution_id,
        emulation_name=args.emulation_name,
        candidate_credentials=args.candidate_credentials,
    )
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("=== CSLE SERVICE LOGIN EVALUATION SUMMARY ===", flush=True)
    print(json.dumps(report["final_compromised_state"], indent=2, sort_keys=True), flush=True)
    print(f"wrote {output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
