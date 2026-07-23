#!/usr/bin/env python3
"""Collect post-attack observations from a CSLE level9 execution."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_PORTS = "21,22,23,80,445,9200"
ALERT_FILE_CANDIDATES = [
    "/var/snort/fast.log",
    "/var/snort/snort.alert",
    "/var/snort/alert.csv",
    "/var/log/alert.csv",
    "/var/log/snort/alert",
    "/var/log/snort/alert.fast",
    "/var/log/snort/fast.log",
    "/var/ossec/alerts/alerts.log",
    "/var/ossec/logs/alerts/alerts.log",
    "/var/ossec/logs/ossec.log",
]


def run(cmd: list[str], timeout: int = 30) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
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
            "started_at_utc": started.isoformat(),
            "ended_at_utc": datetime.now(timezone.utc).isoformat(),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": cmd,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "timeout": timeout,
            "started_at_utc": started.isoformat(),
            "ended_at_utc": datetime.now(timezone.utc).isoformat(),
        }


def docker_exec(container: str, shell_cmd: str, timeout: int = 30) -> dict[str, Any]:
    return run(["docker", "exec", container, "bash", "-lc", shell_cmd], timeout=timeout)


def load_attack_report(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def docker_container_names(execution_id: int) -> list[str]:
    result = run(["docker", "ps", "--format", "{{.Names}}"], timeout=20)
    names = result["stdout"].splitlines()
    suffix = f"level9-{execution_id}"
    return [name for name in names if name.endswith(suffix)]


def inspect_container(name: str) -> dict[str, Any]:
    result = run(["docker", "inspect", name], timeout=20)
    if result["returncode"] != 0:
        return {"name": name, "inspect_error": result}
    raw = json.loads(result["stdout"])[0]
    networks = raw.get("NetworkSettings", {}).get("Networks", {})
    ips = []
    for net_name, net in networks.items():
        ip = net.get("IPAddress")
        if ip:
            ips.append({"network": net_name, "ip": ip})
    return {
        "name": name,
        "id": raw.get("Id"),
        "image": raw.get("Config", {}).get("Image"),
        "status": raw.get("State", {}).get("Status"),
        "running": raw.get("State", {}).get("Running"),
        "networks": ips,
    }


def build_ip_map(container_infos: list[dict[str, Any]]) -> dict[str, str]:
    mapping = {}
    for info in container_infos:
        for item in info.get("networks", []):
            mapping[item["ip"]] = info["name"]
    return mapping


def final_compromised_state(report: dict[str, Any]) -> list[dict[str, Any]]:
    if "final_compromised_state" in report:
        return report["final_compromised_state"]
    steps = report.get("steps", [])
    if steps:
        return steps[-1].get("compromised_or_credentialed_after", [])
    return []


def attacker_actions(report: dict[str, Any]) -> list[dict[str, Any]]:
    actions = []
    for step in report.get("steps", []):
        action = step.get("action", {})
        actions.append(
            {
                "step": step.get("step"),
                "status": step.get("status"),
                "name": action.get("name"),
                "id": action.get("id"),
                "type": action.get("type"),
                "index": action.get("index"),
                "ips": action.get("ips"),
                "error": step.get("error"),
                "observed_machine_count": step.get("observed_machine_count"),
            }
        )
    return actions


def backdoor_users(machine: dict[str, Any]) -> list[str]:
    users = []
    for key in ("backdoor_credentials", "credentials"):
        for cred in machine.get(key, []):
            username = cred.get("username")
            if username and username not in users:
                users.append(username)
    return users


def collect_container_state(container: str, users: list[str]) -> dict[str, Any]:
    quoted_users = " ".join(users)
    user_checks = {}
    for user in users:
        user_checks[user] = {
            "getent_passwd": docker_exec(container, f"getent passwd {user} || true"),
            "passwd_status": docker_exec(container, f"passwd -S {user} 2>/dev/null || true"),
            "id": docker_exec(container, f"id {user} 2>/dev/null || true"),
            "processes": docker_exec(container, f"pgrep -a -u {user} 2>/dev/null || true"),
        }

    return {
        "container": container,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hostname": docker_exec(container, "hostname && hostname -I || true"),
        "users_checked": quoted_users,
        "user_checks": user_checks,
        "listening_ports": docker_exec(container, "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true"),
        "service_processes": docker_exec(
            container,
            "ps aux | grep -E '[s]shd|[s]mbd|[a]pache|[n]ginx|[j]ava|[e]lastic|[m]ysql' || true",
        ),
        "service_status_all": docker_exec(container, "service --status-all 2>/dev/null || true"),
        "auth_logs": docker_exec(
            container,
            "for f in /var/log/auth.log /var/log/secure; do "
            "test -f \"$f\" && echo ===== $f ===== && tail -200 \"$f\"; done 2>/dev/null || true",
        ),
        "system_logs": docker_exec(
            container,
            "for f in /var/log/syslog /var/log/messages; do "
            "test -f \"$f\" && echo ===== $f ===== && tail -120 \"$f\"; done 2>/dev/null || true",
        ),
        "service_logs": docker_exec(
            container,
            "for f in /var/log/apache2/access.log /var/log/apache2/error.log /var/log/nginx/access.log "
            "/var/log/nginx/error.log /var/log/mysql/error.log; do "
            "test -f \"$f\" && echo ===== $f ===== && tail -120 \"$f\"; done; "
            "for f in /var/log/samba/*; do test -f \"$f\" && echo ===== $f ===== && tail -80 \"$f\"; done "
            "2>/dev/null || true",
            timeout=45,
        ),
    }


def collect_reachability(hacker_container: str, ips: list[str]) -> dict[str, Any]:
    results = {}
    for ip in ips:
        results[ip] = {
            "ping": docker_exec(hacker_container, f"ping -c 1 -W 1 {ip}", timeout=8),
            "nmap_ports": docker_exec(
                hacker_container,
                f"sudo nmap -Pn -n -T4 --max-retries 1 -p {DEFAULT_PORTS} {ip}",
                timeout=30,
            ),
        }
    return results


def collect_alert_sources(container_infos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collect Snort/OSSEC alert/log snippets from all execution containers."""
    alert_sources = []
    for info in container_infos:
        container = info["name"]
        file_checks = {}
        for file_path in ALERT_FILE_CANDIDATES:
            file_checks[file_path] = docker_exec(
                container,
                (
                    f"if test -f {file_path}; then "
                    f"echo __CSLE_ALERT_FILE_FOUND__ path={file_path}; "
                    f"ls -lh {file_path}; "
                    f"strings {file_path}; "
                    "fi"
                ),
                timeout=120,
            )
        process_status = docker_exec(
            container,
            "ps aux | grep -E '[s]nort|[o]ssec|[s]uricata' || true",
        )
        service_status = docker_exec(
            container,
            "service --status-all 2>/dev/null | grep -E 'snort|ossec|suricata' || true",
        )
        if (
            any(check.get("stdout", "").strip() for check in file_checks.values())
            or process_status.get("stdout", "").strip()
            or service_status.get("stdout", "").strip()
        ):
            alert_sources.append(
                {
                    "container": container,
                    "networks": info.get("networks", []),
                    "process_status": process_status,
                    "service_status": service_status,
                    "files": file_checks,
                }
            )
    return alert_sources


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect CSLE level9 post-attack observations.")
    parser.add_argument("--execution-id", type=int, required=True)
    parser.add_argument("--attack-report", required=True)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    attack_report_path = Path(args.attack_report)
    report = load_attack_report(attack_report_path)
    compromised = final_compromised_state(report)

    container_infos = [inspect_container(name) for name in docker_container_names(args.execution_id)]
    ip_to_container = build_ip_map(container_infos)
    hacker_container = next(
        (info["name"] for info in container_infos if "hacker_kali" in info.get("name", "")),
        None,
    )

    target_observations = []
    all_target_ips = []
    for machine in compromised:
        ips = machine.get("ips", [])
        users = backdoor_users(machine)
        all_target_ips.extend(ips)
        containers = sorted({ip_to_container[ip] for ip in ips if ip in ip_to_container})
        target_observations.append(
            {
                "machine": machine,
                "containers": containers,
                "missing_ip_mappings": [ip for ip in ips if ip not in ip_to_container],
                "container_states": {
                    container: collect_container_state(container, users)
                    for container in containers
                },
            }
        )

    observation = {
        "schema_version": "level9-observations/v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": {
            "execution_id": args.execution_id,
            "attack_report": str(attack_report_path),
            "sequence": report.get("sequence"),
        },
        "attacker_actions": attacker_actions(report),
        "final_compromised_state": compromised,
        "container_inventory": container_infos,
        "target_observations": target_observations,
        "ids_alert_observations": collect_alert_sources(container_infos),
        "network_reachability_from_attacker": (
            collect_reachability(hacker_container, sorted(set(all_target_ips)))
            if hacker_container else {"error": "hacker container not found"}
        ),
    }

    if args.out:
        out_path = Path(args.out)
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = attack_report_path.parent / f"level9_{args.execution_id}_observations_{ts}.json"
    out_path.write_text(json.dumps(observation, indent=2, ensure_ascii=False), encoding="utf-8")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
