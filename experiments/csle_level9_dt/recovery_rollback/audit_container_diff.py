#!/usr/bin/env python3
"""Audit container changes against a captured CSLE level9 rollback baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from common import (
    collect_hashes_cmd,
    collect_inventory_cmd,
    docker_exec,
    is_under,
    parse_hashes,
    parse_inventory,
    read_manifest,
    write_json,
)


def audit_container(item: dict[str, Any], baseline_dir: Path) -> dict[str, Any]:
    container = item["container"]
    container_dir = baseline_dir / container
    audit_paths = item.get("paths_audited", [])
    restore_paths = item.get("paths_restored", [])
    baseline_hashes = parse_hashes((container_dir / "audit_hashes.txt").read_text(encoding="utf-8", errors="replace"))
    baseline_inventory = parse_inventory((container_dir / "audit_inventory.txt").read_text(encoding="utf-8", errors="replace"))

    current_hashes_result = docker_exec(container, collect_hashes_cmd(audit_paths), timeout=900)
    current_inventory_result = docker_exec(container, collect_inventory_cmd(audit_paths), timeout=600)
    current_hashes = parse_hashes(current_hashes_result["stdout"])
    current_inventory = parse_inventory(current_inventory_result["stdout"])
    docker_diff = __import__("subprocess").run(
        ["docker", "diff", container],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )

    baseline_paths = set(baseline_inventory)
    current_paths = set(current_inventory)
    created = sorted(current_paths - baseline_paths)
    deleted = sorted(baseline_paths - current_paths)
    metadata_changed = sorted(
        path for path in baseline_paths & current_paths if baseline_inventory[path] != current_inventory[path]
    )
    content_changed = sorted(
        path for path in set(baseline_hashes) & set(current_hashes) if baseline_hashes[path] != current_hashes[path]
    )
    outside_snapshot_scope = sorted(
        path
        for path in set(created + deleted + metadata_changed + content_changed)
        if not is_under(path, restore_paths)
    )

    return {
        "container": container,
        "created": created,
        "deleted": deleted,
        "metadata_changed": metadata_changed,
        "content_changed": content_changed,
        "outside_snapshot_scope": outside_snapshot_scope,
        "current_collection": {
            "hashes": current_hashes_result,
            "inventory": current_inventory_result,
        },
        "docker_diff": {
            "returncode": docker_diff.returncode,
            "stdout": docker_diff.stdout,
            "stderr": docker_diff.stderr,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit CSLE level9 container changes against a rollback baseline.")
    parser.add_argument("--baseline-dir", required=True)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    baseline_dir = Path(args.baseline_dir)
    manifest = read_manifest(baseline_dir)
    results = [audit_container(item, baseline_dir) for item in manifest.get("containers", [])]
    payload = {
        "baseline_dir": str(baseline_dir),
        "results": results,
        "has_outside_snapshot_scope_changes": any(r["outside_snapshot_scope"] for r in results),
    }
    if args.output:
        write_json(Path(args.output), payload)
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
