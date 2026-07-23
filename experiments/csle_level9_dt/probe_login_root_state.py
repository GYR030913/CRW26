#!/usr/bin/env python3
"""Probe CSLE-like logged_in/root state after a level9 attack.

This script is for attacks that bypass the CSLE attacker runtime.  It actively
tests whether known level9 credentials can log in from attacker/pivot
containers, then applies the same sudo output rule that CSLE uses for root.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = REPO_ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "model_outputs"

TARGETS = [
    {
        "role": "samba",
        "container_template": "csle_samba_2_1-level9-{execution_id}",
        "ips": ["{eid}.9.2.3", "{eid}.9.4.3"],
        "credentials": [
            {"username": "ssh_backdoor_sambapwned", "password": "sambapwnedpw", "service": "ssh", "port": 22},
        ],
    },
    {
        "role": "ssh",
        "container_template": "csle_ssh_1_1-level9-{execution_id}",
        "ips": ["{eid}.9.2.78"],
        "credentials": [
            {"username": "puppet", "password": "puppet", "service": "ssh", "port": 22},
            {"username": "ssh_backdoor_cve10_0426pwn", "password": "cve_2010_0426_pwnedpw", "service": "ssh", "port": 22},
        ],
    },
    {
        "role": "dvwa_sql_injection",
        "container_template": "csle_sql_injection_1_1-level9-{execution_id}",
        "ips": ["{eid}.9.4.74", "{eid}.9.5.74"],
        "credentials": [
            {"username": "pablo", "password": "0d107d09f5bbe40cade3de5c71e9e9b7", "service": "ssh", "port": 22},
        ],
    },
    {
        "role": "elasticsearch_cve_2015_1427",
        "container_template": "csle_cve_2015_1427_1_1-level9-{execution_id}",
        "ips": ["{eid}.9.5.62", "{eid}.9.6.62", "{eid}.9.7.62"],
        "credentials": [
            {
                "username": "ssh_backdoor_cve_2015_1427_pwned",
                "password": "cve_2015_1427_pwnedpw",
                "service": "ssh",
                "port": 22,
            },
        ],
    },
]

SOURCE_CONTAINERS = [
    "csle_hacker_kali_1_1-level9-{execution_id}",
    "csle_client_1_1-level9-{execution_id}",
    "csle_samba_2_1-level9-{execution_id}",
    "csle_sql_injection_1_1-level9-{execution_id}",
    "csle_cve_2015_1427_1_1-level9-{execution_id}",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(cmd: list[str], timeout: int = 20) -> dict[str, Any]:
    started = utc_now()
    try:
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
            "started_at_utc": started,
            "ended_at_utc": utc_now(),
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": cmd,
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"timeout after {timeout}s",
            "started_at_utc": started,
            "ended_at_utc": utc_now(),
            "timeout": True,
        }


def docker_exec(container: str, command: str, timeout: int = 20) -> dict[str, Any]:
    return run(["docker", "exec", container, "bash", "-lc", command], timeout=timeout)


def container_exists(container: str) -> bool:
    result = run(["docker", "inspect", "-f", "{{.State.Running}}", container], timeout=10)
    return result["returncode"] == 0 and result["stdout"].strip() == "true"


def expand_ip(template: str, execution_id: int) -> str:
    return template.format(eid=execution_id)


def sudo_is_root(stdout: str, stderr: str, username: str) -> bool:
    if f"{username} may not run sudo" in stderr or f"{username} may not run sudo" in stdout:
        return False
    return "(ALL) NOPASSWD: ALL" in stdout or "(ALL : ALL) ALL" in stdout


def probe_ssh(source_container: str, target_ip: str, credential: dict[str, Any]) -> dict[str, Any]:
    username = credential["username"]
    password = credential["password"]
    marker = "__CSLE_PROBE_LOGIN_OK__"
    quoted_password = shlex.quote(password)
    quoted_target = shlex.quote(f"{username}@{target_ip}")
    command = (
        "if ! command -v sshpass >/dev/null 2>&1; then "
        "echo '__CSLE_PROBE_MISSING_SSHPASS__'; exit 90; fi; "
        f"sshpass -p {quoted_password} ssh "
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "-o ConnectTimeout=5 "
        "-o PreferredAuthentications=password "
        "-o PubkeyAuthentication=no "
        f"{quoted_target} "
        f"\"echo {marker}; sudo -n -l 2>&1\""
    )
    result = docker_exec(source_container, command, timeout=20)
    stdout = result["stdout"]
    stderr = result["stderr"]
    login_verified = result["returncode"] == 0 and marker in stdout
    sudo_verified = login_verified and sudo_is_root(stdout=stdout, stderr=stderr, username=username)
    return {
        "source_container": source_container,
        "target_ip": target_ip,
        "credential": {
            "username": username,
            "port": credential.get("port", 22),
            "service": "ssh",
        },
        "login_verified": login_verified,
        "sudo_verified": sudo_verified,
        "returncode": result["returncode"],
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-2000:],
        "missing_sshpass": "__CSLE_PROBE_MISSING_SSHPASS__" in stdout,
        "timeout": result["timeout"],
    }


def probe_target(target: dict[str, Any], execution_id: int, source_containers: list[str]) -> dict[str, Any]:
    container = target["container_template"].format(execution_id=execution_id)
    ips = [expand_ip(ip, execution_id) for ip in target["ips"]]
    probes = []
    successful_probes = []
    for credential in target["credentials"]:
        for ip in ips:
            for source in source_containers:
                if source == container:
                    continue
                result = probe_ssh(source, ip, credential)
                probes.append(result)
                if result["login_verified"]:
                    successful_probes.append(result)
                    break
            if successful_probes and successful_probes[-1]["target_ip"] == ip:
                break

    best = next((item for item in successful_probes if item["sudo_verified"]), None)
    if best is None and successful_probes:
        best = successful_probes[0]

    credentials = []
    backdoor_credentials = []
    if best is not None:
        credential = {
            "username": best["credential"]["username"],
            "password": next(
                cred["password"]
                for cred in target["credentials"]
                if cred["username"] == best["credential"]["username"]
            ),
            "port": best["credential"]["port"],
            "protocol": "0",
            "root": False,
            "service": best["credential"]["service"],
        }
        if credential["username"].startswith("ssh_backdoor") or credential["username"] == "pablo":
            backdoor_credentials.append(credential)
        else:
            credentials.append(credential)

    return {
        "role": target["role"],
        "container": container,
        "container_running": container_exists(container),
        "ips": ips,
        "logged_in": bool(successful_probes),
        "root": any(item["sudo_verified"] for item in successful_probes),
        "shell_access": bool(successful_probes),
        "credentials": credentials,
        "backdoor_credentials": backdoor_credentials,
        "logged_in_services": ["ssh"] if successful_probes else [],
        "root_services": ["ssh"] if any(item["sudo_verified"] for item in successful_probes) else [],
        "probe_summary": {
            "successful_login_count": len(successful_probes),
            "successful_root_count": len([item for item in successful_probes if item["sudo_verified"]]),
            "best_source_container": best["source_container"] if best else None,
            "best_target_ip": best["target_ip"] if best else None,
            "best_username": best["credential"]["username"] if best else None,
        },
        "probes": probes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execution-id", type=int, default=16)
    parser.add_argument("--out-file", type=Path)
    parser.add_argument("--full-probes", action="store_true", help="Keep every failed probe in the output")
    args = parser.parse_args()

    source_containers = [
        item.format(execution_id=args.execution_id)
        for item in SOURCE_CONTAINERS
        if container_exists(item.format(execution_id=args.execution_id))
    ]
    targets = [probe_target(target, args.execution_id, source_containers) for target in TARGETS]
    if not args.full_probes:
        for target in targets:
            target["probes"] = [
                item
                for item in target["probes"]
                if item["login_verified"] or item["sudo_verified"] or item["missing_sshpass"]
            ]

    final_summary = [
        {
            "backdoor_credentials": target["backdoor_credentials"],
            "credentials": target["credentials"],
            "flags": [],
            "index": None,
            "ips": target["ips"],
            "logged_in": target["logged_in"],
            "logged_in_services": target["logged_in_services"],
            "root": target["root"],
            "root_services": target["root_services"],
            "shell_access": target["shell_access"],
        }
        for target in targets
        if target["logged_in"] or target["root"] or target["backdoor_credentials"]
    ]

    report = {
        "generated_at_utc": utc_now(),
        "execution_id": args.execution_id,
        "method": "post_attack_active_login_probe_using_csle_sudo_rule",
        "source_containers": source_containers,
        "targets": targets,
        "final_summary": final_summary,
    }

    out_file = args.out_file
    if out_file is None:
        DEFAULT_OUT_DIR.mkdir(parents=True, exist_ok=True)
        out_file = DEFAULT_OUT_DIR / f"level9_{args.execution_id}_active_login_root_probe_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(final_summary, indent=2))
    print(f"wrote {out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
