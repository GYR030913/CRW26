#!/usr/bin/env python3
"""Shared helpers for CSLE level9 service-level rollback tools."""

from __future__ import annotations

import json
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BASELINE_ROOT = REPO_ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "recovery_baselines"

CORE_CONTAINERS = [
    "csle_samba_2_1-level9-{execution_id}",
    "csle_ssh_1_1-level9-{execution_id}",
    "csle_sql_injection_1_1-level9-{execution_id}",
    "csle_cve_2015_1427_1_1-level9-{execution_id}",
]

BASE_RESTORE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d",
    "/home",
    "/root/.ssh",
    "/etc/samba",
    "/var/lib/samba",
]

WEB_RESTORE_PATHS = [
    "/var/www",
    "/etc/apache2",
    "/etc/nginx",
]

ELASTICSEARCH_RESTORE_PATHS = [
    "/etc/elasticsearch",
]

ELASTICSEARCH_DATA_PATHS = [
    "/var/lib/elasticsearch",
]

BROAD_AUDIT_PATHS = [
    "/etc",
    "/home",
    "/root",
    "/var/www",
    "/var/lib/samba",
    "/var/spool/cron",
]

SERVICES_BY_CONTAINER_PREFIX = {
    "csle_samba_2_1": ["ssh", "smbd"],
    "csle_ssh_1_1": ["ssh"],
    "csle_sql_injection_1_1": ["ssh", "apache2", "nginx"],
    "csle_cve_2015_1427_1_1": ["ssh", "elasticsearch"],
}


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run(cmd: list[str], timeout: int = 120) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    proc = subprocess.run(
        cmd,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "started_at_utc": started.isoformat(),
        "ended_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - started_monotonic, 3),
    }


def docker_exec(container: str, shell_cmd: str, timeout: int = 120) -> dict[str, Any]:
    return run(["docker", "exec", container, "bash", "-lc", shell_cmd], timeout=timeout)


def docker_cp(src: str, dst: str, timeout: int = 120) -> dict[str, Any]:
    return run(["docker", "cp", src, dst], timeout=timeout)


def container_name(template_or_name: str, execution_id: int) -> str:
    return template_or_name.format(execution_id=execution_id)


def default_containers(execution_id: int) -> list[str]:
    return [container_name(template, execution_id) for template in CORE_CONTAINERS]


def services_for_container(container: str) -> list[str]:
    for prefix, services in SERVICES_BY_CONTAINER_PREFIX.items():
        if container.startswith(prefix):
            return services
    return ["ssh"]


def build_restore_paths(
    *,
    include_web: bool = False,
    include_elasticsearch_config: bool = False,
    include_elasticsearch_data: bool = False,
) -> list[str]:
    paths = list(BASE_RESTORE_PATHS)
    if include_web:
        paths.extend(WEB_RESTORE_PATHS)
    if include_elasticsearch_config:
        paths.extend(ELASTICSEARCH_RESTORE_PATHS)
    if include_elasticsearch_data:
        paths.extend(ELASTICSEARCH_DATA_PATHS)
    return sorted(dict.fromkeys(paths))


def build_audit_paths(
    *,
    restore_paths: list[str],
    include_elasticsearch_data: bool = False,
) -> list[str]:
    paths = [*BROAD_AUDIT_PATHS, *restore_paths]
    if include_elasticsearch_data:
        paths.extend(ELASTICSEARCH_DATA_PATHS)
    return sorted(dict.fromkeys(paths))


def shell_array(values: list[str]) -> str:
    return " ".join(shlex.quote(value) for value in values)


def read_manifest(path: Path) -> dict[str, Any]:
    return json.loads((path / "manifest.json").read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def is_under(path: str, roots: list[str]) -> bool:
    normalized = path.rstrip("/")
    for root in roots:
        root_norm = root.rstrip("/")
        if normalized == root_norm or normalized.startswith(root_norm + "/"):
            return True
    return False


def parse_hashes(text: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        digest, file_path = parts
        hashes[file_path.strip()] = digest
    return hashes


def parse_inventory(text: str) -> dict[str, str]:
    inventory: dict[str, str] = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        inventory[fields[1]] = line
    return inventory


def collect_inventory_cmd(paths: list[str]) -> str:
    path_args = shell_array(paths)
    return (
        "set +e; "
        f"for p in {path_args}; do "
        "  if [ -e \"$p\" ]; then "
        "    find \"$p\" -xdev \\( -type f -o -type l -o -type d \\) "
        "      -printf '%y\\t%p\\t%s\\t%T@\\t%m\\t%u\\t%g\\n' 2>/dev/null; "
        "  fi; "
        "done | sort"
    )


def collect_hashes_cmd(paths: list[str]) -> str:
    path_args = shell_array(paths)
    return (
        "set +e; tmp=$(mktemp); "
        f"for p in {path_args}; do "
        "  if [ -e \"$p\" ]; then find \"$p\" -xdev -type f -print 2>/dev/null >> \"$tmp\"; fi; "
        "done; "
        "sort -u \"$tmp\" | xargs -r sha256sum 2>/dev/null; "
        "rm -f \"$tmp\""
    )
