#!/usr/bin/env python3
"""Restore a CSLE level9 service-level rollback baseline."""

from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import (
    collect_inventory_cmd,
    docker_cp,
    docker_exec,
    parse_inventory,
    read_manifest,
    services_for_container,
    shell_array,
    write_json,
)


def cleanup_extra_restore_scope_paths(item: dict[str, Any], baseline_dir: Path) -> dict[str, Any]:
    """Remove paths created after the baseline inside the restore scope."""
    container = item["container"]
    container_dir = baseline_dir / container
    restore_paths = item.get("paths_restored", [])
    baseline_inventory_path = container_dir / "restore_inventory.txt"
    if not restore_paths or not baseline_inventory_path.exists():
        return {"skipped": "missing restore paths or baseline restore inventory"}

    baseline_inventory = parse_inventory(
        baseline_inventory_path.read_text(encoding="utf-8", errors="replace")
    )
    current_inventory_result = docker_exec(container, collect_inventory_cmd(restore_paths), timeout=600)
    current_inventory = parse_inventory(current_inventory_result["stdout"])
    extra_paths = sorted(set(current_inventory) - set(baseline_inventory), key=lambda value: value.count("/"), reverse=True)
    if not extra_paths:
        return {
            "extra_path_count": 0,
            "current_inventory": current_inventory_result,
            "remove_extra_paths": {"skipped": "no extra paths"},
        }

    remove_result = docker_exec(
        container,
        "rm -rf -- " + shell_array(extra_paths),
        timeout=600,
    )
    return {
        "extra_path_count": len(extra_paths),
        "extra_paths": extra_paths,
        "current_inventory": current_inventory_result,
        "remove_extra_paths": remove_result,
    }


def restore_container(item: dict[str, Any], baseline_dir: Path, restart_services: bool) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    container = item["container"]
    container_dir = baseline_dir / container
    local_tar = container_dir / "files.tar.gz"
    remote_tar = "/tmp/csle_recovery_baseline_restore.tar.gz"
    remote_iptables = "/tmp/csle_recovery_baseline_iptables.rules"

    cleanup_recovery_evidence = docker_exec(
        container,
        "rm -rf /tmp/recovery_evidence; "
        "rm -f /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-",
        timeout=60,
    )
    cleanup_extra_paths = cleanup_extra_restore_scope_paths(item, baseline_dir)
    copy_tar = docker_cp(str(local_tar), f"{container}:{remote_tar}", timeout=600)
    restore_files = docker_exec(
        container,
        f"tar -xzf {remote_tar} -C / --same-owner --numeric-owner 2>/tmp/csle_recovery_restore_tar.stderr; "
        "rc=$?; cat /tmp/csle_recovery_restore_tar.stderr >&2; "
        f"rm -f {remote_tar} /tmp/csle_recovery_restore_tar.stderr; "
        "exit $rc",
        timeout=900,
    )

    iptables_path = container_dir / "iptables.rules"
    if iptables_path.exists() and iptables_path.stat().st_size > 0:
        copy_iptables = docker_cp(str(iptables_path), f"{container}:{remote_iptables}", timeout=60)
        restore_iptables = docker_exec(
            container,
            f"iptables-restore < {remote_iptables} 2>/tmp/csle_recovery_iptables.stderr; "
            "rc=$?; cat /tmp/csle_recovery_iptables.stderr >&2; "
            f"rm -f {remote_iptables} /tmp/csle_recovery_iptables.stderr; "
            "exit $rc",
            timeout=120,
        )
    else:
        copy_iptables = {"skipped": "empty iptables baseline"}
        restore_iptables = {"skipped": "empty iptables baseline"}

    service_results = []
    if restart_services:
        for service in item.get("services") or services_for_container(container):
            service_results.append(
                docker_exec(container, f"service {service} restart 2>/dev/null || true", timeout=120)
            )

    return {
        "container": container,
        "started_at_utc": started_at.isoformat(),
        "ended_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - started_monotonic, 3),
        "cleanup_recovery_evidence": cleanup_recovery_evidence,
        "cleanup_extra_paths": cleanup_extra_paths,
        "copy_tar": copy_tar,
        "restore_files": restore_files,
        "copy_iptables": copy_iptables,
        "restore_iptables": restore_iptables,
        "service_restarts": service_results,
    }


def main() -> int:
    started_at = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    parser = argparse.ArgumentParser(description="Restore a CSLE level9 service-level rollback baseline.")
    parser.add_argument("--baseline-dir", required=True)
    parser.add_argument("--no-restart-services", action="store_true")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    baseline_dir = Path(args.baseline_dir)
    manifest = read_manifest(baseline_dir)
    results = [
        restore_container(item, baseline_dir, restart_services=not args.no_restart_services)
        for item in manifest.get("containers", [])
    ]
    payload = {
        "baseline_dir": str(baseline_dir),
        "started_at_utc": started_at.isoformat(),
        "ended_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - started_monotonic, 3),
        "results": results,
    }
    if args.output:
        write_json(Path(args.output), payload)
    else:
        print(__import__("json").dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
