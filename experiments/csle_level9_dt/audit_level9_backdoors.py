#!/usr/bin/env python3
"""Audit suspicious/backdoor-like users across a CSLE level9 execution."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = REPO_ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "baseline_validation"

SUSPICIOUS_PATTERNS = (
    "ssh_backdoor",
    "backdoor",
    "pwn",
    "pwned",
    "sambapwned",
    "shellshocked",
    "pablo",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(cmd: list[str], timeout: int = 60) -> dict[str, Any]:
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
    }


def docker_exec(container: str, command: str, timeout: int = 60) -> dict[str, Any]:
    return run(["docker", "exec", container, "bash", "-lc", command], timeout=timeout)


def list_containers(execution_id: int) -> list[str]:
    result = run(["docker", "ps", "--format", "{{.Names}}"], timeout=30)
    if result["returncode"] != 0:
        raise RuntimeError(result["stderr"] or result["stdout"])
    suffix = f"level9-{execution_id}"
    return sorted(name for name in result["stdout"].splitlines() if name.endswith(suffix))


def parse_passwd(passwd_text: str, shadow_text: str) -> list[dict[str, Any]]:
    shadow: dict[str, str] = {}
    for line in shadow_text.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            shadow[parts[0]] = parts[1]

    users = []
    for line in passwd_text.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, _pw, uid, gid, gecos, home, shell = parts[:7]
        try:
            uid_int = int(uid)
        except ValueError:
            uid_int = -1
        lowered = username.lower()
        shadow_value = shadow.get(username, "")
        suspicious = (
            any(pattern in lowered for pattern in SUSPICIOUS_PATTERNS)
            or (uid_int == 0 and username != "root")
        )
        users.append(
            {
                "username": username,
                "uid": uid_int,
                "gid": gid,
                "home": home,
                "shell": shell,
                "has_password_hash": bool(shadow_value and shadow_value not in {"!", "*"}),
                "locked": shadow_value.startswith("!") or shadow_value == "*",
                "suspicious": suspicious,
            }
        )
    return users


def parse_ips(text: str, execution_id: int) -> list[str]:
    ips = []
    for match in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", text):
        ip = match.group(1)
        if ip.startswith(f"{execution_id}.9."):
            ips.append(ip)
    return sorted(set(ips), key=lambda value: tuple(int(part) for part in value.split(".")))


def audit_container(container: str, execution_id: int) -> dict[str, Any]:
    passwd = docker_exec(container, "cat /etc/passwd 2>/dev/null || true", timeout=30)
    shadow = docker_exec(container, "cat /etc/shadow 2>/dev/null || true", timeout=30)
    ips = docker_exec(container, "ip -o -4 addr show 2>/dev/null || true", timeout=30)
    auth = docker_exec(
        container,
        "tail -n 80 /var/log/auth.log /var/log/secure 2>/dev/null || true",
        timeout=30,
    )
    listening = docker_exec(container, "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true", timeout=30)

    users = parse_passwd(passwd["stdout"], shadow["stdout"])
    suspicious_users = [user for user in users if user["suspicious"]]
    accepted_logins = [
        line for line in auth["stdout"].splitlines() if re.search(r"sshd.*Accepted", line, re.IGNORECASE)
    ]
    return {
        "container": container,
        "ips": parse_ips(ips["stdout"], execution_id),
        "suspicious_users": suspicious_users,
        "accepted_ssh_logins_tail": accepted_logins[-20:],
        "listening_ports_raw": listening["stdout"],
        "command_status": {
            "passwd": passwd["returncode"],
            "shadow": shadow["returncode"],
            "ips": ips["returncode"],
            "auth": auth["returncode"],
            "listening": listening["returncode"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execution-id", type=int, default=16)
    parser.add_argument("--out-file", type=Path)
    args = parser.parse_args()

    containers = list_containers(args.execution_id)
    results = [audit_container(container, args.execution_id) for container in containers]
    payload = {
        "generated_at_utc": utc_now(),
        "execution_id": args.execution_id,
        "container_count": len(containers),
        "containers": results,
        "containers_with_suspicious_users": [
            item for item in results if item["suspicious_users"]
        ],
    }

    out_file = args.out_file
    if out_file is None:
        DEFAULT_OUT_DIR.mkdir(parents=True, exist_ok=True)
        out_file = DEFAULT_OUT_DIR / f"level9_{args.execution_id}_all_container_backdoor_audit_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(
        {
            "container_count": payload["container_count"],
            "containers_with_suspicious_users": [
                {
                    "container": item["container"],
                    "ips": item["ips"],
                    "users": [user["username"] for user in item["suspicious_users"]],
                }
                for item in payload["containers_with_suspicious_users"]
            ],
        },
        indent=2,
        ensure_ascii=False,
    ))
    print(f"wrote {out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
