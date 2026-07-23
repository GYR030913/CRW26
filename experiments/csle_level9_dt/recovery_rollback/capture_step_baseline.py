#!/usr/bin/env python3
"""Capture a service-level rollback baseline for CSLE level9 DT execution."""

from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import (
    DEFAULT_BASELINE_ROOT,
    build_audit_paths,
    build_restore_paths,
    collect_hashes_cmd,
    collect_inventory_cmd,
    default_containers,
    docker_cp,
    docker_exec,
    services_for_container,
    shell_array,
    timestamp,
    write_json,
)


def capture_container(container: str, out_dir: Path, restore_paths: list[str], audit_paths: list[str]) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    container_dir = out_dir / container
    container_dir.mkdir(parents=True, exist_ok=True)
    remote_tar = "/tmp/csle_recovery_baseline_files.tar.gz"

    tar_cmd = (
        f"rm -f {remote_tar}; "
        f"tar --ignore-failed-read --warning=no-file-changed -czf {remote_tar} {shell_array(restore_paths)} "
        "2>/tmp/csle_recovery_baseline_tar.stderr; "
        "rc=$?; cat /tmp/csle_recovery_baseline_tar.stderr >&2; "
        "test $rc -eq 0 -o $rc -eq 1"
    )
    tar_result = docker_exec(container, tar_cmd, timeout=600)
    cp_result = docker_cp(f"{container}:{remote_tar}", str(container_dir / "files.tar.gz"), timeout=600)
    cleanup_result = docker_exec(container, f"rm -f {remote_tar} /tmp/csle_recovery_baseline_tar.stderr", timeout=30)

    restore_inventory = docker_exec(container, collect_inventory_cmd(restore_paths), timeout=300)
    restore_hashes = docker_exec(container, collect_hashes_cmd(restore_paths), timeout=600)
    audit_inventory = docker_exec(container, collect_inventory_cmd(audit_paths), timeout=600)
    audit_hashes = docker_exec(container, collect_hashes_cmd(audit_paths), timeout=900)
    iptables = docker_exec(container, "iptables-save 2>/dev/null || true", timeout=60)
    processes = docker_exec(container, "ps auxww 2>/dev/null || true", timeout=60)
    listening_ports = docker_exec(container, "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true", timeout=60)
    service_status = docker_exec(container, "service --status-all 2>/dev/null || true", timeout=60)
    docker_diff = docker_exec(container, "true", timeout=5)

    (container_dir / "restore_inventory.txt").write_text(restore_inventory["stdout"], encoding="utf-8")
    (container_dir / "restore_hashes.txt").write_text(restore_hashes["stdout"], encoding="utf-8")
    (container_dir / "audit_inventory.txt").write_text(audit_inventory["stdout"], encoding="utf-8")
    (container_dir / "audit_hashes.txt").write_text(audit_hashes["stdout"], encoding="utf-8")
    (container_dir / "iptables.rules").write_text(iptables["stdout"], encoding="utf-8")
    (container_dir / "processes.txt").write_text(processes["stdout"], encoding="utf-8")
    (container_dir / "listening_ports.txt").write_text(listening_ports["stdout"], encoding="utf-8")
    (container_dir / "service_status.txt").write_text(service_status["stdout"], encoding="utf-8")

    return {
        "container": container,
        "started_at_utc": started_at.isoformat(),
        "ended_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - started_monotonic, 3),
        "paths_restored": restore_paths,
        "paths_audited": audit_paths,
        "services": services_for_container(container),
        "files_archive": str(container_dir / "files.tar.gz"),
        "commands": {
            "tar": tar_result,
            "docker_cp": cp_result,
            "cleanup": cleanup_result,
            "restore_inventory": restore_inventory,
            "restore_hashes": restore_hashes,
            "audit_inventory": audit_inventory,
            "audit_hashes": audit_hashes,
            "iptables": iptables,
            "processes": processes,
            "listening_ports": listening_ports,
            "service_status": service_status,
            "placeholder": docker_diff,
        },
    }


def main() -> int:
    started_at = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    parser = argparse.ArgumentParser(description="Capture a CSLE level9 service-level rollback baseline.")
    parser.add_argument("--execution-id", type=int, default=16)
    parser.add_argument("--label", default="step_0_after_attack")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--container", action="append", default=None, help="Container to include. Repeatable.")
    parser.add_argument("--include-web", action="store_true")
    parser.add_argument("--include-elasticsearch-config", action="store_true")
    parser.add_argument("--include-elasticsearch-data", action="store_true")
    args = parser.parse_args()

    out_dir = Path(args.out_dir or DEFAULT_BASELINE_ROOT / f"level9_{args.execution_id}_{args.label}_{timestamp()}")
    out_dir.mkdir(parents=True, exist_ok=True)
    containers = args.container or default_containers(args.execution_id)
    restore_paths = build_restore_paths(
        include_web=args.include_web,
        include_elasticsearch_config=args.include_elasticsearch_config,
        include_elasticsearch_data=args.include_elasticsearch_data,
    )
    audit_paths = build_audit_paths(
        restore_paths=restore_paths,
        include_elasticsearch_data=args.include_elasticsearch_data,
    )

    container_results = []
    for container in containers:
        print(f"capturing {container}", flush=True)
        container_results.append(capture_container(container, out_dir, restore_paths, audit_paths))

    manifest = {
        "kind": "csle_level9_service_rollback_baseline",
        "execution_id": args.execution_id,
        "label": args.label,
        "created_at_utc": timestamp(),
        "started_at_utc": started_at.isoformat(),
        "ended_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - started_monotonic, 3),
        "restore_paths": restore_paths,
        "audit_paths": audit_paths,
        "containers": container_results,
    }
    write_json(out_dir / "manifest.json", manifest)
    print(out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
