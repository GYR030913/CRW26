#!/usr/bin/env python3
"""Collect post-attack host state for CSLE level9 DT/true executions.

The output is intentionally comparable to the CSLE attacker final summary, but
it is derived from container evidence instead of CSLE attacker runtime state.
Run it after generated attack commands and before rollback.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "experiments" / "csle_level9_dt" / "level9_manifest.json"
DEFAULT_OUT_DIR = REPO_ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "model_outputs"

TARGETS = [
    {
        "role": "samba",
        "container_template": "csle_samba_2_1-level9-{execution_id}",
        "hostname": "csle_samba_2_1",
        "expected_ports": [22, 445],
    },
    {
        "role": "ssh",
        "container_template": "csle_ssh_1_1-level9-{execution_id}",
        "hostname": "csle_ssh_1_1",
        "expected_ports": [22],
    },
    {
        "role": "dvwa_sql_injection",
        "container_template": "csle_sql_injection_1_1-level9-{execution_id}",
        "hostname": "csle_sql_injection_1_1",
        "expected_ports": [22, 80],
    },
    {
        "role": "elasticsearch_cve_2015_1427",
        "container_template": "csle_cve_2015_1427_1_1-level9-{execution_id}",
        "hostname": "csle_cve_2015_1427_1_1",
        "expected_ports": [22, 9200],
    },
]

BACKDOOR_HINTS = (
    "backdoor",
    "pwn",
    "pwned",
    "sambapwned",
    "cve_2015_1427_pwned",
    "ssh_backdoor",
)

KNOWN_BACKDOOR_CANDIDATES = [
    {"username": "ssh_backdoor_sambapwned", "password": "sambapwnedpw"},
    {"username": "ssh_backdoor_cve_2015_1427_pwned", "password": "cve_2015_1427_pwnedpw"},
    {"username": "ssh_backdoor_95349", "password": "csle"},
    {"username": "ssh_backdoor_8154", "password": "csle"},
    {"username": "ssh_backdoor_10544", "password": "csle"},
    {"username": "pablo", "password": "0d107d09f5bbe40cade3de5c71e9e9b7"},
]


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run(cmd: list[str], timeout: int = 60) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
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
    }


def docker_exec(container: str, command: str, timeout: int = 60) -> dict[str, Any]:
    return run(["docker", "exec", container, "bash", "-lc", command], timeout=timeout)


def load_manifest_hosts(path: Path, execution_id: int) -> dict[str, list[str]]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, list[str]] = {}
    for node in data.get("topology_nodes", []):
        hostname = node.get("hostname")
        ips = []
        for item in node.get("ips_gw_default_policy_networks", []):
            ip_template = item.get("ip")
            if ip_template:
                ips.append(ip_template.replace("<EXECUTION_ID>", str(execution_id)))
        if hostname:
            result[hostname] = ips
    return result


def parse_ips(ip_output: str, execution_id: int) -> list[str]:
    ips = []
    for match in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", ip_output):
        ip = match.group(1)
        if ip.startswith(f"{execution_id}.9."):
            ips.append(ip)
    return sorted(set(ips), key=lambda value: tuple(int(part) for part in value.split(".")))


def parse_users(passwd_text: str, shadow_text: str) -> list[dict[str, Any]]:
    shadow_users: dict[str, str] = {}
    for line in shadow_text.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            shadow_users[parts[0]] = parts[1]

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
        shadow_value = shadow_users.get(username, "")
        users.append(
            {
                "username": username,
                "uid": uid_int,
                "gid": gid,
                "gecos": gecos,
                "home": home,
                "shell": shell,
                "has_password_hash": bool(shadow_value and shadow_value not in {"!", "*"}),
                "locked": shadow_value.startswith("!") or shadow_value == "*",
                "suspicious": is_suspicious_user(username, uid_int, shell),
            }
        )
    return users


def is_suspicious_user(username: str, uid: int, shell: str) -> bool:
    lowered = username.lower()
    if any(hint in lowered for hint in BACKDOOR_HINTS):
        return True
    if username in {"pablo"}:
        return True
    if uid == 0 and username != "root":
        return True
    if shell.endswith(("bash", "sh")) and any(hint in lowered for hint in ("ssh_", "cve_", "samba")):
        return True
    return False


def parse_listening_ports(text: str) -> list[dict[str, Any]]:
    ports = []
    for line in text.splitlines():
        match = re.search(r":(\d+)\s+", line)
        if not match:
            continue
        ports.append({"port": int(match.group(1)), "raw": line})
    return ports


def collect_container(target: dict[str, Any], execution_id: int, manifest_ips: dict[str, list[str]]) -> dict[str, Any]:
    container = target["container_template"].format(execution_id=execution_id)
    ip_addr = docker_exec(container, "ip -o -4 addr show", timeout=30)
    passwd = docker_exec(container, "cat /etc/passwd 2>/dev/null || true", timeout=30)
    shadow = docker_exec(container, "cat /etc/shadow 2>/dev/null || true", timeout=30)
    authorized_keys = docker_exec(
        container,
        "find /root /home -path '*/.ssh/authorized_keys' -type f -maxdepth 4 "
        "-printf '--- %p\\n' -exec sed -n '1,20p' {} \\; 2>/dev/null || true",
        timeout=60,
    )
    listening = docker_exec(container, "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true", timeout=30)
    processes = docker_exec(container, "ps auxww 2>/dev/null || true", timeout=30)
    recent_auth = docker_exec(
        container,
        "tail -n 80 /var/log/auth.log /var/log/secure 2>/dev/null || true",
        timeout=30,
    )
    service_status = docker_exec(container, "service --status-all 2>/dev/null || true", timeout=30)

    live_ips = parse_ips(ip_addr["stdout"], execution_id)
    ips = sorted(
        set(live_ips + manifest_ips.get(target["hostname"], [])),
        key=lambda value: tuple(int(part) for part in value.split(".")),
    )
    users = parse_users(passwd["stdout"], shadow["stdout"])
    suspicious_users = [user for user in users if user["suspicious"]]
    listening_ports = parse_listening_ports(listening["stdout"])
    open_ports = sorted({item["port"] for item in listening_ports})
    expected_ports = target.get("expected_ports", [])

    backdoor_credentials = []
    for user in suspicious_users:
        known = next((item for item in KNOWN_BACKDOOR_CANDIDATES if item["username"] == user["username"]), None)
        backdoor_credentials.append(
            {
                "username": user["username"],
                "password": known["password"] if known else None,
                "port": 22 if 22 in open_ports else None,
                "protocol": "ssh" if 22 in open_ports else None,
                "service": "ssh" if 22 in open_ports else None,
                "root": user["uid"] == 0,
                "evidence": "suspicious local account",
            }
        )

    authorized_key_evidence = bool(authorized_keys["stdout"].strip())
    logged_in_evidence = [
        line
        for line in recent_auth["stdout"].splitlines()
        if re.search(r"sshd.*Accepted", line, re.IGNORECASE)
    ][-20:]

    compromised = bool(backdoor_credentials or authorized_key_evidence or logged_in_evidence)
    root = any(cred.get("root") for cred in backdoor_credentials)
    shell_access = bool(22 in open_ports or backdoor_credentials or authorized_key_evidence)

    return {
        "role": target["role"],
        "container": container,
        "hostname": target["hostname"],
        "ips": ips,
        "credentials": [],
        "backdoor_credentials": backdoor_credentials,
        "logged_in": bool(logged_in_evidence),
        "root": root,
        "flags": [],
        "shell_access": shell_access,
        "logged_in_services": ["ssh"] if logged_in_evidence else [],
        "root_services": ["ssh"] if root and 22 in open_ports else [],
        "compromised_evidence": {
            "compromised": compromised,
            "suspicious_users": suspicious_users,
            "authorized_keys_present": authorized_key_evidence,
            "recent_auth_events": logged_in_evidence,
            "open_ports": open_ports,
            "expected_ports_open": [port for port in expected_ports if port in open_ports],
        },
        "raw_commands": {
            "ip_addr": ip_addr,
            "passwd": {**passwd, "stdout": redact_passwd(passwd["stdout"])},
            "shadow": {**shadow, "stdout": "<redacted>"},
            "authorized_keys": authorized_keys,
            "listening": listening,
            "processes": {**processes, "stdout": processes["stdout"][:12000]},
            "recent_auth": recent_auth,
            "service_status": service_status,
        },
    }


def redact_passwd(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if line) + ("\n" if text else "")


def build_final_summary(containers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary = []
    for item in containers:
        evidence = item["compromised_evidence"]
        if (
            item["credentials"]
            or item["backdoor_credentials"]
            or item["logged_in"]
            or item["root"]
            or evidence["authorized_keys_present"]
        ):
            summary.append(
                {
                    "index": None,
                    "ips": item["ips"],
                    "credentials": item["credentials"],
                    "backdoor_credentials": item["backdoor_credentials"],
                    "logged_in": item["logged_in"],
                    "root": item["root"],
                    "flags": item["flags"],
                    "shell_access": item["shell_access"],
                    "logged_in_services": item["logged_in_services"],
                    "root_services": item["root_services"],
                    "container": item["container"],
                    "hostname": item["hostname"],
                    "role": item["role"],
                    "evidence_summary": item["compromised_evidence"],
                }
            )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect CSLE level9 post-attack state evidence.")
    parser.add_argument("--execution-id", type=int, default=16)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--out-file", default=None)
    args = parser.parse_args()

    manifest_ips = load_manifest_hosts(Path(args.manifest), args.execution_id)
    containers = [collect_container(target, args.execution_id, manifest_ips) for target in TARGETS]
    payload = {
        "kind": "csle_level9_post_attack_state",
        "execution_id": args.execution_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "containers": containers,
        "final_summary_like": build_final_summary(containers),
    }
    out_file = (
        Path(args.out_file)
        if args.out_file
        else DEFAULT_OUT_DIR / f"level9_{args.execution_id}_post_attack_state_{timestamp()}.json"
    )
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out_file}")
    print("\n=== FINAL SUMMARY LIKE ===")
    print(json.dumps(payload["final_summary_like"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
