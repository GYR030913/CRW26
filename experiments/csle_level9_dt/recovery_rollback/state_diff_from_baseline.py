#!/usr/bin/env python3
"""Compare current CSLE level9 container state with a captured baseline.

This is aimed at attack/recovery evaluation. It highlights persistent state
changes that active login probes cannot distinguish from pre-existing accounts.
"""

from __future__ import annotations

import argparse
import json
import re
import tarfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from common import (
    collect_hashes_cmd,
    collect_inventory_cmd,
    docker_exec,
    parse_hashes,
    parse_inventory,
    read_manifest,
    write_json,
)


SUSPICIOUS_USER_PATTERNS = (
    "ssh_backdoor",
    "backdoor",
    "pwn",
    "pwned",
    "sambapwned",
    "shellshocked",
    "pablo",
)

SECURITY_RELEVANT_PREFIXES = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh",
    "/home",
    "/root/.ssh",
    "/var/www",
    "/etc/elasticsearch",
    "/var/lib/elasticsearch",
    "/etc/samba",
    "/var/lib/samba",
    "/var/spool/cron",
)


def normalize_tar_name(path: str) -> str:
    return path.lstrip("/")


def read_tar_text(tar_path: Path, abs_path: str) -> str:
    names = [
        normalize_tar_name(abs_path),
        "." + abs_path,
        abs_path,
    ]
    try:
        with tarfile.open(tar_path, "r:gz") as archive:
            members = {member.name: member for member in archive.getmembers() if member.isfile()}
            for name in names:
                member = members.get(name)
                if member is None:
                    continue
                fh = archive.extractfile(member)
                if fh is None:
                    return ""
                return fh.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    return ""


def read_tar_paths(tar_path: Path, path_pattern: re.Pattern[str]) -> dict[str, str]:
    results: dict[str, str] = {}
    try:
        with tarfile.open(tar_path, "r:gz") as archive:
            for member in archive.getmembers():
                abs_name = "/" + member.name.lstrip("./").lstrip("/")
                if not member.isfile() or not path_pattern.search(abs_name):
                    continue
                fh = archive.extractfile(member)
                if fh is None:
                    continue
                results[abs_name] = fh.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        pass
    return results


def parse_passwd_shadow(passwd_text: str, shadow_text: str) -> dict[str, dict[str, Any]]:
    shadow: dict[str, str] = {}
    for line in shadow_text.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            shadow[parts[0]] = parts[1]

    users: dict[str, dict[str, Any]] = {}
    for line in passwd_text.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, _pw, uid, gid, gecos, home, shell = parts[:7]
        shadow_value = shadow.get(username, "")
        lowered = username.lower()
        try:
            uid_int = int(uid)
        except ValueError:
            uid_int = -1
        users[username] = {
            "username": username,
            "uid": uid_int,
            "gid": gid,
            "gecos": gecos,
            "home": home,
            "shell": shell,
            "shadow_hash": shadow_value,
            "has_password_hash": bool(shadow_value and shadow_value not in {"!", "*"}),
            "locked": shadow_value.startswith("!") or shadow_value == "*",
            "suspicious": any(pattern in lowered for pattern in SUSPICIOUS_USER_PATTERNS)
            or (uid_int == 0 and username != "root"),
        }
    return users


def redact_user(user: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(user)
    shadow_hash = redacted.pop("shadow_hash", "")
    redacted["shadow_hash_present"] = bool(shadow_hash)
    if shadow_hash:
        redacted["shadow_hash_prefix"] = shadow_hash[:12]
    return redacted


def diff_users(
    baseline_users: dict[str, dict[str, Any]],
    current_users: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    baseline_names = set(baseline_users)
    current_names = set(current_users)
    added = sorted(current_names - baseline_names)
    deleted = sorted(baseline_names - current_names)
    changed = []
    for username in sorted(baseline_names & current_names):
        before = baseline_users[username]
        after = current_users[username]
        fields = ["uid", "gid", "home", "shell", "shadow_hash", "locked", "has_password_hash"]
        diffs = {
            field: {"before": before.get(field), "after": after.get(field)}
            for field in fields
            if before.get(field) != after.get(field)
        }
        if diffs:
            if "shadow_hash" in diffs:
                diffs["shadow_hash"] = {
                    "before_present": bool(before.get("shadow_hash")),
                    "after_present": bool(after.get("shadow_hash")),
                    "before_prefix": str(before.get("shadow_hash", ""))[:12],
                    "after_prefix": str(after.get("shadow_hash", ""))[:12],
                }
            changed.append({"username": username, "changes": diffs})
    return {
        "added": [redact_user(current_users[name]) for name in added],
        "deleted": [redact_user(baseline_users[name]) for name in deleted],
        "changed": changed,
        "suspicious_added": [redact_user(current_users[name]) for name in added if current_users[name]["suspicious"]],
        "suspicious_deleted": [redact_user(baseline_users[name]) for name in deleted if baseline_users[name]["suspicious"]],
    }


def collect_current_text(container: str, abs_path: str) -> str:
    result = docker_exec(container, f"cat {abs_path!r} 2>/dev/null || true", timeout=60)
    return result["stdout"]


def collect_current_authorized_keys(container: str) -> dict[str, str]:
    cmd = (
        "set +e; "
        "for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do "
        "  if [ -f \"$f\" ]; then echo \"__CSLE_FILE__ $f\"; cat \"$f\"; fi; "
        "done"
    )
    result = docker_exec(container, cmd, timeout=60)
    return parse_marked_files(result["stdout"])


def parse_marked_files(text: str) -> dict[str, str]:
    files: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("__CSLE_FILE__ "):
            current = line.split(" ", 1)[1]
            files.setdefault(current, [])
            continue
        if current is not None:
            files[current].append(line)
    return {path: "\n".join(lines).strip() for path, lines in files.items()}


def diff_text_files(before: dict[str, str], after: dict[str, str]) -> dict[str, Any]:
    before_paths = set(before)
    after_paths = set(after)
    changed = []
    for path in sorted(before_paths & after_paths):
        if before[path] != after[path]:
            changed.append(
                {
                    "path": path,
                    "before_line_count": len(before[path].splitlines()),
                    "after_line_count": len(after[path].splitlines()),
                }
            )
    return {
        "added_paths": sorted(after_paths - before_paths),
        "deleted_paths": sorted(before_paths - after_paths),
        "changed_paths": changed,
    }


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.rstrip("\n") for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]


def normalize_runtime_lines(lines: Iterable[str]) -> list[str]:
    normalized = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        normalized.append(stripped)
    return sorted(set(normalized))


def diff_line_sets(before: list[str], after: list[str]) -> dict[str, Any]:
    before_set = set(normalize_runtime_lines(before))
    after_set = set(normalize_runtime_lines(after))
    return {
        "added": sorted(after_set - before_set),
        "deleted": sorted(before_set - after_set),
    }


def is_security_relevant(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in SECURITY_RELEVANT_PREFIXES)


def diff_files_from_baseline(item: dict[str, Any], baseline_dir: Path) -> dict[str, Any]:
    container = item["container"]
    container_dir = baseline_dir / container
    audit_paths = item.get("paths_audited", [])
    baseline_hashes = parse_hashes((container_dir / "audit_hashes.txt").read_text(encoding="utf-8", errors="replace"))
    baseline_inventory = parse_inventory((container_dir / "audit_inventory.txt").read_text(encoding="utf-8", errors="replace"))
    current_hashes_result = docker_exec(container, collect_hashes_cmd(audit_paths), timeout=900)
    current_inventory_result = docker_exec(container, collect_inventory_cmd(audit_paths), timeout=600)
    current_hashes = parse_hashes(current_hashes_result["stdout"])
    current_inventory = parse_inventory(current_inventory_result["stdout"])

    baseline_paths = set(baseline_inventory)
    current_paths = set(current_inventory)
    created = sorted(path for path in current_paths - baseline_paths if is_security_relevant(path))
    deleted = sorted(path for path in baseline_paths - current_paths if is_security_relevant(path))
    metadata_changed = sorted(
        path
        for path in baseline_paths & current_paths
        if baseline_inventory[path] != current_inventory[path] and is_security_relevant(path)
    )
    content_changed = sorted(
        path
        for path in set(baseline_hashes) & set(current_hashes)
        if baseline_hashes[path] != current_hashes[path] and is_security_relevant(path)
    )
    return {
        "created": created,
        "deleted": deleted,
        "metadata_changed": metadata_changed,
        "content_changed": content_changed,
        "collection_status": {
            "hashes_returncode": current_hashes_result["returncode"],
            "inventory_returncode": current_inventory_result["returncode"],
        },
    }


def diff_container(item: dict[str, Any], baseline_dir: Path) -> dict[str, Any]:
    container = item["container"]
    container_dir = baseline_dir / container
    tar_path = container_dir / "files.tar.gz"

    baseline_users = parse_passwd_shadow(
        read_tar_text(tar_path, "/etc/passwd"),
        read_tar_text(tar_path, "/etc/shadow"),
    )
    current_users = parse_passwd_shadow(
        collect_current_text(container, "/etc/passwd"),
        collect_current_text(container, "/etc/shadow"),
    )

    baseline_sudo = read_tar_paths(tar_path, re.compile(r"^/etc/sudoers($|\.d/)|^/etc/sudoers\.d/"))
    current_sudo = {
        "/etc/sudoers": collect_current_text(container, "/etc/sudoers"),
        **parse_marked_files(
            docker_exec(
                container,
                "set +e; for f in /etc/sudoers.d/*; do [ -f \"$f\" ] && echo \"__CSLE_FILE__ $f\" && cat \"$f\"; done",
                timeout=60,
            )["stdout"]
        ),
    }

    baseline_authorized_keys = read_tar_paths(tar_path, re.compile(r"/\.ssh/authorized_keys$"))
    current_authorized_keys = collect_current_authorized_keys(container)

    current_processes = docker_exec(container, "ps auxww 2>/dev/null || true", timeout=60)["stdout"].splitlines()
    current_ports = docker_exec(container, "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true", timeout=60)[
        "stdout"
    ].splitlines()
    current_services = docker_exec(container, "service --status-all 2>/dev/null || true", timeout=60)[
        "stdout"
    ].splitlines()

    baseline_processes = read_lines(container_dir / "processes.txt")
    baseline_ports = read_lines(container_dir / "listening_ports.txt")
    baseline_services = read_lines(container_dir / "service_status.txt")

    file_diff = diff_files_from_baseline(item, baseline_dir)
    user_diff = diff_users(baseline_users, current_users)
    sudo_diff = diff_text_files(baseline_sudo, current_sudo)
    key_diff = diff_text_files(baseline_authorized_keys, current_authorized_keys)
    port_diff = diff_line_sets(baseline_ports, current_ports)
    service_diff = diff_line_sets(baseline_services, current_services)
    process_diff = diff_line_sets(baseline_processes, current_processes)

    has_persistent_change = any(
        [
            user_diff["added"],
            user_diff["deleted"],
            user_diff["changed"],
            sudo_diff["added_paths"],
            sudo_diff["deleted_paths"],
            sudo_diff["changed_paths"],
            key_diff["added_paths"],
            key_diff["deleted_paths"],
            key_diff["changed_paths"],
            file_diff["created"],
            file_diff["deleted"],
            file_diff["content_changed"],
        ]
    )
    return {
        "container": container,
        "has_persistent_security_relevant_change": bool(has_persistent_change),
        "users": user_diff,
        "sudoers": sudo_diff,
        "ssh_authorized_keys": key_diff,
        "security_relevant_files": file_diff,
        "listening_ports": port_diff,
        "service_status": service_diff,
        "processes": process_diff,
    }


def compact_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    changed = [item for item in results if item["has_persistent_security_relevant_change"]]
    return {
        "containers_with_persistent_security_relevant_change": [
            {
                "container": item["container"],
                "added_users": [user["username"] for user in item["users"]["added"]],
                "deleted_users": [user["username"] for user in item["users"]["deleted"]],
                "changed_users": [user["username"] for user in item["users"]["changed"]],
                "sudoers_changes": item["sudoers"],
                "ssh_key_changes": item["ssh_authorized_keys"],
                "created_file_count": len(item["security_relevant_files"]["created"]),
                "deleted_file_count": len(item["security_relevant_files"]["deleted"]),
                "content_changed_file_count": len(item["security_relevant_files"]["content_changed"]),
            }
            for item in changed
        ],
        "changed_container_count": len(changed),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Diff current CSLE level9 state against a rollback baseline.")
    parser.add_argument("--baseline-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    baseline_dir = Path(args.baseline_dir)
    manifest = read_manifest(baseline_dir)
    results = [diff_container(item, baseline_dir) for item in manifest.get("containers", [])]
    payload = {
        "kind": "csle_level9_state_diff_from_baseline",
        "baseline_dir": str(baseline_dir),
        "execution_id": manifest.get("execution_id"),
        "results": results,
        "summary": compact_summary(results),
    }
    write_json(Path(args.output), payload)
    print(json.dumps(payload["summary"], indent=2, ensure_ascii=False))
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
