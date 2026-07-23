#!/usr/bin/env python3
"""Evidence-based evaluator for externally executed level9 attack commands.

This is intentionally not a replacement for CSLE attacker_transition. It checks
the post-attack container state with command-level evidence:

* local account/backdoor existence
* SSH login from the hacker container
* sudo/root availability using sudo -l plus a stricter sudo -n id -u check
* service reachability from the hacker container
* selected file hash changes against an optional rollback baseline
* recent auth/service evidence
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
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
DEFAULT_OUT_DIR = REPO_ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "model_outputs"
DEFAULT_BASELINE = (
    REPO_ROOT
    / "experiments"
    / "csle_level9_dt"
    / "artifacts"
    / "recovery_baselines"
    / "level9_16_clean_restart_verified_20260718T164419Z"
)

ROLE_TO_CONTAINER = {
    "samba": "csle_samba_2_1-level9-{execution_id}",
    "ssh": "csle_ssh_1_1-level9-{execution_id}",
    "dvwa_sql_injection": "csle_sql_injection_1_1-level9-{execution_id}",
    "elasticsearch_cve_2015_1427": "csle_cve_2015_1427_1_1-level9-{execution_id}",
}

ROLE_EXPECTED_PORTS = {
    "samba": [22, 445],
    "ssh": [22],
    "dvwa_sql_injection": [22, 80],
    "elasticsearch_cve_2015_1427": [22, 9200],
}

SUSPICIOUS_USER_HINTS = (
    "backdoor",
    "pwn",
    "pwned",
    "sambapwned",
    "cve_",
    "ssh_backdoor",
)

FILE_HASH_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d/README",
    "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run(cmd: list[str], timeout: int = 60) -> dict[str, Any]:
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
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "started_at_utc": started,
            "ended_at_utc": utc_now(),
            "timeout": True,
        }


def docker_exec(container: str, command: str, timeout: int = 60) -> dict[str, Any]:
    return run(["docker", "exec", container, "bash", "-lc", command], timeout=timeout)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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
        shadow_value = shadow.get(username, "")
        lower = username.lower()
        suspicious = (
            username == "pablo"
            or uid_int == 0 and username != "root"
            or any(hint in lower for hint in SUSPICIOUS_USER_HINTS)
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


def parse_listening_ports(text: str) -> list[int]:
    ports = set()
    for line in text.splitlines():
        match = re.search(r":(\d+)\s+", line)
        if match:
            ports.add(int(match.group(1)))
    return sorted(ports)


def hash_current_paths(container: str) -> dict[str, Any]:
    quoted_paths = " ".join(shlex.quote(path) for path in FILE_HASH_PATHS)
    command = (
        "for p in "
        + quoted_paths
        + "; do if [ -e \"$p\" ]; then sha256sum \"$p\"; else echo MISSING \"$p\"; fi; done"
    )
    result = docker_exec(container, command, timeout=30)
    hashes: dict[str, Any] = {}
    for line in result["stdout"].splitlines():
        if line.startswith("MISSING "):
            hashes[line.split(" ", 1)[1]] = None
            continue
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            hashes[parts[1]] = parts[0]
    return {"hashes": hashes, "raw_command": result}


def load_baseline_hashes(baseline_dir: Path | None, container: str) -> dict[str, str]:
    if baseline_dir is None:
        return {}
    hash_file = baseline_dir / container / "audit_hashes.txt"
    if not hash_file.exists():
        return {}
    hashes: dict[str, str] = {}
    for line in hash_file.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            hashes[parts[1]] = parts[0]
    return hashes


def compare_hashes(current: dict[str, Any], baseline: dict[str, str]) -> dict[str, Any]:
    if not baseline:
        return {"baseline_available": False, "changed": [], "missing_now": [], "note": "No baseline provided."}
    changed = []
    missing_now = []
    for path, current_hash in current.items():
        base_hash = baseline.get(path)
        if current_hash is None:
            if base_hash is not None:
                missing_now.append(path)
            continue
        if base_hash is None:
            continue
        if current_hash != base_hash:
            changed.append({"path": path, "baseline_sha256": base_hash, "current_sha256": current_hash})
    return {"baseline_available": True, "changed": changed, "missing_now": missing_now}


def ssh_command_from_hacker(
    hacker_container: str,
    username: str,
    password: str,
    ip: str,
    remote_command: str,
    timeout_seconds: int = 12,
) -> dict[str, Any]:
    ssh_cmd = (
        "timeout "
        + str(timeout_seconds)
        + " sshpass -p "
        + shlex.quote(password)
        + " ssh "
        + "-o StrictHostKeyChecking=no "
        + "-o UserKnownHostsFile=/dev/null "
        + "-o PreferredAuthentications=password "
        + "-o PubkeyAuthentication=no "
        + "-o ConnectTimeout=5 "
        + shlex.quote(f"{username}@{ip}")
        + " "
        + shlex.quote(remote_command)
    )
    return docker_exec(hacker_container, ssh_cmd, timeout=timeout_seconds + 5)


def evaluate_ssh_credential(hacker_container: str, credential: dict[str, Any], ip: str) -> dict[str, Any]:
    username = credential["username"]
    password = credential["password"]
    remote = (
        "printf '__CSLE_EXT_LOGIN_OK__\\n'; "
        "printf '__ID_U__\\n'; id -u 2>&1; "
        "printf '__WHOAMI__\\n'; whoami 2>&1; "
        "printf '__SUDO_L_START__\\n'; sudo -l 2>&1; printf '__SUDO_L_END__\\n'; "
        "printf '__SUDO_N_ID_START__\\n'; sudo -n id -u 2>&1; printf '__SUDO_N_ID_END__\\n'"
    )
    result = ssh_command_from_hacker(hacker_container, username, password, ip, remote)
    output = (result["stdout"] or "") + "\n" + (result["stderr"] or "")
    logged_in = "__CSLE_EXT_LOGIN_OK__" in output
    sudo_l = section(output, "__SUDO_L_START__", "__SUDO_L_END__")
    sudo_n_id = section(output, "__SUDO_N_ID_START__", "__SUDO_N_ID_END__")
    id_u = section(output, "__ID_U__", "__WHOAMI__").strip()

    csle_like_sudo_l_root = (
        logged_in
        and f"{username} may not run sudo" not in sudo_l
        and ("(ALL) NOPASSWD: ALL" in sudo_l or "(ALL : ALL) ALL" in sudo_l)
    )
    strict_sudo_root = logged_in and re.search(r"(^|\n)\s*0\s*(\n|$)", sudo_n_id) is not None
    login_as_root = logged_in and id_u.splitlines()[:1] == ["0"]
    root = bool(login_as_root or strict_sudo_root or csle_like_sudo_l_root)

    return {
        "ip": ip,
        "username": username,
        "password": password,
        "service": credential.get("service", "ssh"),
        "kind": credential.get("kind"),
        "logged_in": logged_in,
        "root": root,
        "root_evidence": {
            "login_uid_is_0": login_as_root,
            "csle_like_sudo_l_root": csle_like_sudo_l_root,
            "strict_sudo_n_id_root": strict_sudo_root,
            "id_u_section": id_u,
            "sudo_l_section": sudo_l,
            "sudo_n_id_section": sudo_n_id,
        },
        "raw_command": result,
    }


def section(text: str, start: str, end: str) -> str:
    if start not in text or end not in text:
        return ""
    return text.split(start, 1)[1].split(end, 1)[0]


def check_port_from_hacker(hacker_container: str, ip: str, port: int) -> dict[str, Any]:
    command = (
        "timeout 4 bash -lc "
        + shlex.quote(f"</dev/tcp/{ip}/{port}")
        + " >/dev/null 2>&1"
    )
    result = docker_exec(hacker_container, command, timeout=8)
    return {"ip": ip, "port": port, "reachable": result["returncode"] == 0, "raw_command": result}


def evaluate_machine(
    machine: dict[str, Any],
    execution_id: int,
    hacker_container: str,
    baseline_dir: Path | None,
) -> dict[str, Any]:
    role = machine.get("role", "unknown")
    container_template = ROLE_TO_CONTAINER.get(role)
    if container_template is None:
        raise ValueError(f"No container mapping for role={role}")
    container = container_template.format(execution_id=execution_id)
    ips = machine.get("ips", [])

    passwd = docker_exec(container, "cat /etc/passwd 2>/dev/null || true", timeout=30)
    shadow = docker_exec(container, "cat /etc/shadow 2>/dev/null || true", timeout=30)
    listening = docker_exec(container, "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true", timeout=30)
    auth_logs = docker_exec(container, "tail -n 120 /var/log/auth.log /var/log/secure 2>/dev/null || true", timeout=30)
    service_status = docker_exec(container, "service --status-all 2>/dev/null || true", timeout=30)
    users = parse_passwd(passwd["stdout"], shadow["stdout"])
    suspicious_users = [u for u in users if u["suspicious"]]
    ports = parse_listening_ports(listening["stdout"])

    ssh_tests = []
    for credential in machine.get("credentials", []):
        if credential.get("service", "ssh") != "ssh" or not credential.get("password"):
            continue
        for ip in ips:
            ssh_tests.append(evaluate_ssh_credential(hacker_container, credential, ip))

    port_tests = []
    for ip in ips:
        for port in ROLE_EXPECTED_PORTS.get(role, []):
            port_tests.append(check_port_from_hacker(hacker_container, ip, port))

    current_hash_info = hash_current_paths(container)
    baseline_hashes = load_baseline_hashes(baseline_dir, container)
    file_changes = compare_hashes(current_hash_info["hashes"], baseline_hashes)

    logged_in = any(t["logged_in"] for t in ssh_tests)
    root = any(t["root"] for t in ssh_tests)
    candidate_names = {cred.get("username") for cred in machine.get("credentials", [])}
    backdoor_users = [user for user in suspicious_users if user["username"] in candidate_names or user["suspicious"]]
    backdoor_credentials = [
        {
            "username": user["username"],
            "password": next(
                (cred.get("password") for cred in machine.get("credentials", []) if cred.get("username") == user["username"]),
                None,
            ),
            "port": 22 if 22 in ports else None,
            "protocol": "ssh" if 22 in ports else None,
            "service": "ssh" if 22 in ports else None,
            "root": user["uid"] == 0,
            "evidence": "local suspicious/backdoor account exists",
        }
        for user in backdoor_users
    ]

    return {
        "role": role,
        "container": container,
        "ips": ips,
        "local_evidence": {
            "open_listening_ports": ports,
            "suspicious_users": suspicious_users,
            "recent_auth_lines": auth_logs["stdout"].splitlines()[-80:],
            "service_status": service_status["stdout"].splitlines(),
        },
        "network_reachability_from_hacker": port_tests,
        "ssh_login_tests": ssh_tests,
        "file_integrity": {
            "selected_current_hashes": current_hash_info["hashes"],
            "baseline_comparison": file_changes,
        },
        "summary_like_csle": {
            "index": None,
            "ips": ips,
            "credentials": [],
            "backdoor_credentials": backdoor_credentials,
            "logged_in": logged_in,
            "root": root,
            "flags": [],
            "shell_access": bool(logged_in or 22 in ports or backdoor_credentials),
            "logged_in_services": ["ssh"] if logged_in else [],
            "root_services": ["ssh"] if root else [],
        },
        "raw_commands": {
            "passwd": {**passwd, "stdout": redact_passwd(passwd["stdout"])},
            "shadow": {**shadow, "stdout": "<redacted>"},
            "listening": listening,
            "auth_logs": auth_logs,
            "service_status": service_status,
            "hashes": current_hash_info["raw_command"],
        },
    }


def redact_passwd(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if line) + ("\n" if text else "")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate externally executed no-helper level9 attack evidence.")
    parser.add_argument("--execution-id", type=int, default=16)
    parser.add_argument("--candidate-credentials", type=Path, default=DEFAULT_CREDENTIALS)
    parser.add_argument("--baseline-dir", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--no-baseline", action="store_true")
    parser.add_argument("--out-file", type=Path)
    args = parser.parse_args()

    candidates = load_json(args.candidate_credentials)
    hacker_container = f"csle_hacker_kali_1_1-level9-{args.execution_id}"
    baseline_dir = None if args.no_baseline else args.baseline_dir
    machines = [
        evaluate_machine(machine, args.execution_id, hacker_container, baseline_dir)
        for machine in candidates.get("machines", [])
    ]

    final_summary = [
        machine["summary_like_csle"]
        for machine in machines
        if (
            machine["summary_like_csle"]["backdoor_credentials"]
            or machine["summary_like_csle"]["logged_in"]
            or machine["summary_like_csle"]["root"]
        )
    ]
    payload = {
        "schema_version": 1,
        "kind": "no_helper_external_evidence_evaluation",
        "created_at_utc": utc_now(),
        "execution_id": args.execution_id,
        "hacker_container": hacker_container,
        "candidate_credentials_file": str(args.candidate_credentials),
        "baseline_dir": None if baseline_dir is None else str(baseline_dir),
        "notes": [
            "This evaluator does not update CSLE EmulationEnvState.",
            "logged_in/root are based on real SSH command execution from the hacker container.",
            "root uses CSLE-like sudo -l matching plus stricter sudo -n id -u evidence.",
        ],
        "machines": machines,
        "final_summary_like": final_summary,
    }

    out_file = args.out_file or (
        DEFAULT_OUT_DIR / f"no_helper_external_evidence_execution{args.execution_id}_{timestamp()}.json"
    )
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("=== NO-HELPER EXTERNAL EVIDENCE SUMMARY ===", flush=True)
    print(json.dumps(final_summary, indent=2, ensure_ascii=False), flush=True)
    print(f"wrote {out_file}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
