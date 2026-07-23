"""Validate that two CSLE level9 executions are comparable twins.

This script is intentionally read-only. It checks Docker containers, resolved
IPs, key users, key services, and attacker reachability for a true execution and
a DT execution.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_OUTPUT = Path(__file__).resolve().with_name("twin_validation_report.json")

KEY_HOSTS = {
    "attacker": {
        "container_base": "csle_hacker_kali_1_1",
        "ip_suffixes": ["9.1.191"],
        "users": [],
        "services": [],
    },
    "ssh": {
        "container_base": "csle_ssh_1_1",
        "ip_suffixes": ["9.2.78", "9.3.78"],
        "users": ["puppet"],
        "services": [{"name": "ssh", "port": 22}],
    },
    "samba_telnet": {
        "container_base": "csle_samba_2_1",
        "ip_suffixes": ["9.2.3", "9.4.3"],
        "users": ["admin"],
        "services": [
            {"name": "telnet", "port": 23},
            {"name": "samba", "port": 445},
        ],
    },
    "ftp": {
        "container_base": "csle_ftp_1_1",
        "ip_suffixes": ["9.2.79"],
        "users": ["pi"],
        "services": [{"name": "ftp", "port": 21}],
    },
    "shellshock": {
        "container_base": "csle_shellshock_1_1",
        "ip_suffixes": ["9.3.54", "9.9.54"],
        "users": [],
        "services": [{"name": "http", "port": 80}],
    },
}


@dataclass
class CommandResult:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str


@dataclass
class CheckResult:
    name: str
    ok: bool
    details: dict[str, Any] = field(default_factory=dict)


def run_command(command: list[str], timeout: int = 30) -> CommandResult:
    proc = subprocess.run(
        command,
        check=False,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return CommandResult(
        command=command,
        exit_code=proc.returncode,
        stdout=proc.stdout.strip(),
        stderr=proc.stderr.strip(),
    )


def docker_exec(container: str, command: str, timeout: int = 30) -> CommandResult:
    return run_command(["docker", "exec", container, "bash", "-lc", command], timeout=timeout)


def docker_ps_names() -> list[str]:
    result = run_command(["docker", "ps", "--format", "{{.Names}}"])
    if result.exit_code != 0:
        raise RuntimeError(result.stderr or result.stdout)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def inspect_network_ips(container: str) -> list[str]:
    result = run_command(
        [
            "docker",
            "inspect",
            container,
            "--format",
            "{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}",
        ]
    )
    if result.exit_code != 0:
        return []
    return sorted(ip for ip in result.stdout.split() if ip)


def container_name(base: str, execution_id: int) -> str:
    return f"{base}-level9-{execution_id}"


def expected_ips(execution_id: int, suffixes: list[str]) -> list[str]:
    return [f"{execution_id}.{suffix}" for suffix in suffixes]


def check_container_counts(names: list[str], true_id: int, dt_id: int) -> CheckResult:
    true_names = [name for name in names if f"level9-{true_id}" in name]
    dt_names = [name for name in names if f"level9-{dt_id}" in name]
    return CheckResult(
        name="container_counts",
        ok=len(true_names) == 35 and len(dt_names) == 35,
        details={
            "true_count": len(true_names),
            "dt_count": len(dt_names),
            "expected_per_execution": 35,
        },
    )


def check_role_mapping(names: list[str], true_id: int, dt_id: int) -> CheckResult:
    missing: list[str] = []
    for role in KEY_HOSTS.values():
        for execution_id in (true_id, dt_id):
            name = container_name(role["container_base"], execution_id)
            if name not in names:
                missing.append(name)
    return CheckResult(
        name="key_role_containers_exist",
        ok=not missing,
        details={"missing": missing},
    )


def check_ip_mapping(true_id: int, dt_id: int) -> CheckResult:
    mismatches: list[dict[str, Any]] = []
    for role_name, role in KEY_HOSTS.items():
        for execution_id, label in ((true_id, "true"), (dt_id, "dt")):
            name = container_name(role["container_base"], execution_id)
            actual = inspect_network_ips(name)
            expected = expected_ips(execution_id, role["ip_suffixes"])
            missing = [ip for ip in expected if ip not in actual]
            if missing:
                mismatches.append(
                    {
                        "role": role_name,
                        "execution": label,
                        "container": name,
                        "expected": expected,
                        "actual": actual,
                        "missing": missing,
                    }
                )
    return CheckResult(name="key_ip_mapping", ok=not mismatches, details={"mismatches": mismatches})


def check_users(true_id: int, dt_id: int) -> CheckResult:
    mismatches: list[dict[str, Any]] = []
    for role_name, role in KEY_HOSTS.items():
        for user in role["users"]:
            for execution_id, label in ((true_id, "true"), (dt_id, "dt")):
                name = container_name(role["container_base"], execution_id)
                result = docker_exec(name, f"getent passwd {user}", timeout=15)
                if result.exit_code != 0:
                    mismatches.append(
                        {
                            "role": role_name,
                            "execution": label,
                            "container": name,
                            "user": user,
                            "exit_code": result.exit_code,
                            "stderr": result.stderr,
                        }
                    )
    return CheckResult(name="key_users_exist", ok=not mismatches, details={"mismatches": mismatches})


def check_services(true_id: int, dt_id: int) -> CheckResult:
    mismatches: list[dict[str, Any]] = []
    for role_name, role in KEY_HOSTS.items():
        for service in role["services"]:
            port = service["port"]
            for execution_id, label in ((true_id, "true"), (dt_id, "dt")):
                name = container_name(role["container_base"], execution_id)
                result = docker_exec(
                    name,
                    f"(ss -ltnup || netstat -ltnup) 2>/dev/null | grep -E '[:.]({port})\\s'",
                    timeout=15,
                )
                if result.exit_code != 0:
                    mismatches.append(
                        {
                            "role": role_name,
                            "execution": label,
                            "container": name,
                            "service": service["name"],
                            "port": port,
                            "exit_code": result.exit_code,
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                        }
                    )
    return CheckResult(name="key_services_listening", ok=not mismatches, details={"mismatches": mismatches})


def check_attacker_reachability(true_id: int, dt_id: int) -> CheckResult:
    mismatches: list[dict[str, Any]] = []
    target_specs = [
        ("ssh", "9.2.78", 22),
        ("telnet", "9.2.3", 23),
        ("ftp", "9.2.79", 21),
    ]
    for execution_id, label in ((true_id, "true"), (dt_id, "dt")):
        attacker = container_name(KEY_HOSTS["attacker"]["container_base"], execution_id)
        for target_name, suffix, port in target_specs:
            target_ip = f"{execution_id}.{suffix}"
            result = docker_exec(
                attacker,
                "if command -v nc >/dev/null 2>&1; then "
                f"timeout 8 nc -z -w 3 {target_ip} {port}; "
                "else "
                f"timeout 8 bash -c 'echo >/dev/tcp/{target_ip}/{port}'; "
                "fi",
                timeout=10,
            )
            if result.exit_code != 0:
                mismatches.append(
                    {
                        "execution": label,
                        "attacker": attacker,
                        "target": target_name,
                        "target_ip": target_ip,
                        "port": port,
                        "exit_code": result.exit_code,
                        "stderr": result.stderr,
                    }
                )
    return CheckResult(name="attacker_key_port_reachability", ok=not mismatches, details={"mismatches": mismatches})


def build_report(true_id: int, dt_id: int) -> dict[str, Any]:
    names = docker_ps_names()
    checks = [
        check_container_counts(names, true_id, dt_id),
        check_role_mapping(names, true_id, dt_id),
        check_ip_mapping(true_id, dt_id),
        check_users(true_id, dt_id),
        check_services(true_id, dt_id),
        check_attacker_reachability(true_id, dt_id),
    ]
    return {
        "true_execution_id": true_id,
        "dt_execution_id": dt_id,
        "checks": [asdict(check) for check in checks],
        "ready_for_attack_replay": all(check.ok for check in checks),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--true-id", type=int, default=15)
    parser.add_argument("--dt-id", type=int, default=16)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    report = build_report(true_id=args.true_id, dt_id=args.dt_id)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["ready_for_attack_replay"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
