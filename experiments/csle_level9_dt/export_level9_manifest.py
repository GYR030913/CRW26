"""Export a CSLE level9 manifest for the level9-specific digital twin.

The manifest is derived from the upstream CSLE level9 config. It preserves
CSLE's address template (`<EXECUTION_ID>.9.x.x`) so the same DT description can
be resolved for any concrete execution first octet.
"""

from __future__ import annotations

import argparse
import enum
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
CSLE_ROOT = REPO_ROOT / "external" / "csle"
LEVEL9_ENV_DIR = CSLE_ROOT / "emulation-system" / "envs" / "0.10.0" / "level_9"
DEFAULT_OUTPUT = Path(__file__).resolve().with_name("level9_manifest.json")


def add_csle_paths() -> None:
    """Make the local CSLE level9 config importable."""
    for path in (LEVEL9_ENV_DIR,):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def jsonable(value: Any) -> Any:
    """Convert CSLE DAO objects, enums, sets, and tuples into JSON values."""
    if isinstance(value, enum.Enum):
        return value.name
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(jsonable(k)): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(item) for item in value]
    if hasattr(value, "to_dict"):
        return jsonable(value.to_dict())
    if hasattr(value, "__dict__"):
        return jsonable(value.__dict__)
    return value


def action_to_dict(action: Any) -> dict[str, Any]:
    """Serialize one CSLE attacker action with stable, readable enum values."""
    return {
        "id": jsonable(action.id),
        "name": action.name,
        "type": jsonable(action.type),
        "index": action.index,
        "ips": jsonable(action.ips),
        "cmds": jsonable(action.cmds),
        "alt_cmds": jsonable(action.alt_cmds),
        "descr": action.descr,
        "vulnerability": jsonable(action.vulnerability),
        "action_outcome": jsonable(action.action_outcome),
        "backdoor": action.backdoor,
    }


def build_manifest(network_id: int, level: int, version: str, name: str) -> dict[str, Any]:
    """Build a manifest from the upstream CSLE level9 config."""
    add_csle_paths()
    import config as level9_config  # pylint: disable=import-error,import-outside-toplevel

    cfg = level9_config.default_config(
        name=name,
        network_id=network_id,
        level=level,
        version=version,
    )
    static_sequences = {
        sequence_name: [action_to_dict(action) for action in actions]
        for sequence_name, actions in cfg.static_attacker_sequences.items()
    }
    return {
        "source": "csle-level9",
        "source_config": str(LEVEL9_ENV_DIR / "config.py"),
        "name": cfg.name,
        "version": cfg.version,
        "level": cfg.level,
        "network_id": network_id,
        "execution_id_placeholder": "<EXECUTION_ID>",
        "agent_ip_template": cfg.containers_config.agent_ip,
        "router_ip_template": cfg.containers_config.router_ip,
        "subnetwork_masks": jsonable(cfg.topology_config.subnetwork_masks),
        "containers": jsonable(cfg.containers_config.containers),
        "topology_nodes": jsonable(cfg.topology_config.node_configs),
        "services": jsonable(cfg.services_config.services_configs),
        "users": jsonable(cfg.users_config.users_configs),
        "vulnerabilities": jsonable(cfg.vuln_config.node_vulnerability_configs),
        "flags": jsonable(cfg.flags_config.node_flag_configs),
        "static_attacker_sequences": static_sequences,
        "counts": {
            "containers": len(cfg.containers_config.containers),
            "topology_nodes": len(cfg.topology_config.node_configs),
            "services": len(cfg.services_config.services_configs),
            "users": len(cfg.users_config.users_configs),
            "vulnerabilities": len(cfg.vuln_config.node_vulnerability_configs),
            "flags": len(cfg.flags_config.node_flag_configs),
            "static_attacker_sequences": {
                key: len(value) for key, value in static_sequences.items()
            },
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network-id", type=int, default=9)
    parser.add_argument("--level", type=int, default=9)
    parser.add_argument("--version", default="0.10.0")
    parser.add_argument("--name", default="csle-level9-0.10.0")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    manifest = build_manifest(
        network_id=args.network_id,
        level=args.level,
        version=args.version,
        name=args.name,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {args.output}")
    print(json.dumps(manifest["counts"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
