#!/usr/bin/env python3
"""Export level9 observation JSON into model-facing System/Logs/Incident text files."""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


KEY_HOSTS = {
    "csle_hacker_kali": "attacker host",
    "csle_router": "router / IDS sensor",
    "csle_samba_2_1": "Samba vulnerable host",
    "csle_ssh_1_1": "SSH vulnerable host",
    "csle_sql_injection": "DVWA / SQL injection vulnerable host",
    "csle_cve_2015_1427": "Elasticsearch CVE-2015-1427 vulnerable host",
    "csle_kafka": "Kafka monitoring host",
    "csle_elk": "ELK monitoring host",
}

FAST_ALERT_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+\[\*\*\]\s+"
    r"\[(?P<rule_id>[^\]]+)\]\s+"
    r"(?:(?P<interface><[^>]+>)\s+)?"
    r"(?P<message>.*?)\s+\[\*\*\]\s+"
    r"\[Classification:\s+(?P<classification>[^\]]+)\]\s+"
    r"\[Priority:\s+(?P<priority>\d+)\]\s+"
    r"\{(?P<protocol>[^}]+)\}\s+"
    r"(?P<src>\S+)\s+->\s+(?P<dst>\S+)"
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_ip(value: str) -> str:
    return value.replace("15.9.", "X.9.").replace("16.9.", "X.9.")


def container_ips(info: dict[str, Any]) -> list[str]:
    return [item.get("ip", "") for item in info.get("networks", []) if item.get("ip")]


def host_role(container_name: str) -> str | None:
    for prefix, role in KEY_HOSTS.items():
        if prefix in container_name:
            return role
    return None


def strip_command_headers(stdout: str) -> list[str]:
    lines = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        if line.startswith("__CSLE_ALERT_FILE_FOUND__"):
            continue
        if line.startswith("-rw"):
            continue
        lines.append(line)
    return lines


def snort_csv_lines(observation: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for source in observation.get("ids_alert_observations", []):
        if source.get("container") != "csle_router_2_1-level9-15":
            continue
        files = source.get("files", {})
        for path in ("/var/snort/alert.csv", "/var/log/alert.csv"):
            stdout = files.get(path, {}).get("stdout", "")
            lines.extend(strip_command_headers(stdout))
            if lines:
                return lines
    return lines


def snort_fast_lines(observation: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for source in observation.get("ids_alert_observations", []):
        if source.get("container") != "csle_router_2_1-level9-15":
            continue
        stdout = source.get("files", {}).get("/var/snort/fast.log", {}).get("stdout", "")
        lines.extend(strip_command_headers(stdout))
        return lines
    return lines


def parse_fast_alerts(alert_lines: list[str]) -> list[dict[str, str]]:
    alerts = []
    for line in alert_lines:
        match = FAST_ALERT_RE.search(line.strip())
        if not match:
            continue
        alert = match.groupdict()
        alert["raw"] = line.strip()
        alerts.append(alert)
    return alerts


def format_fast_alert_multiline(alert: dict[str, str]) -> str:
    return (
        f"{alert['timestamp']} [**] [{alert['rule_id']}] {alert['message']} [**] "
        f"[Classification: {alert['classification']}] [Priority: {alert['priority']}] "
        f"{{{alert['protocol']}}} {alert['src']} -> {alert['dst']}"
    )


def summarize_alerts(alert_lines: list[str]) -> tuple[list[str], Counter[str], Counter[tuple[str, str, str]]]:
    messages: list[str] = []
    msg_counter: Counter[str] = Counter()
    flow_counter: Counter[tuple[str, str, str]] = Counter()
    for line in alert_lines:
        try:
            row = next(csv.reader(io.StringIO(line), skipinitialspace=True))
        except Exception:
            continue
        if len(row) < 8:
            continue
        timestamp = row[0].strip()
        message = row[4].strip().strip('"')
        protocol = row[5].strip()
        src_ip = row[6].strip()
        dst_ip = row[8].strip() if len(row) > 8 else ""
        if not message or not src_ip or not dst_ip:
            continue
        messages.append(
            f"{timestamp} [{protocol}] {src_ip} -> {dst_ip}: {message}"
        )
        msg_counter[message] += 1
        flow_counter[(src_ip, dst_ip, message)] += 1
    return messages, msg_counter, flow_counter


def build_system_text(observation: dict[str, Any]) -> str:
    source = observation.get("source", {})
    inventory = observation.get("container_inventory", [])
    key_lines = []
    for info in inventory:
        role = host_role(info.get("name", ""))
        if role is None:
            continue
        ips = ", ".join(container_ips(info))
        key_lines.append(f"- {info['name']}: {role}; IPs: {ips}")

    networks = sorted(
        {
            item.get("network", "")
            for info in inventory
            for item in info.get("networks", [])
            if item.get("network")
        }
    )
    return "\n".join(
        [
            "The experiment uses CSLE level9 as a Dockerized cyber range.",
            "There are two isomorphic executions: true CSLE execution 15 and DT execution 16.",
            "This System file describes true CSLE execution 15, where the experienced attack was executed.",
            "",
            f"Emulation: {source.get('attack_report', 'csle-level9-0.10.0')}",
            f"Execution id: {source.get('execution_id')}",
            f"Attack sequence: {source.get('sequence')}",
            "",
            "IP convention:",
            "- True CSLE uses 15.9.x.x.",
            "- DT uses 16.9.x.x.",
            "- For model reasoning and comparison, both should be normalized to X.9.x.x.",
            "",
            "Important hosts:",
            *key_lines,
            "",
            "Observed Docker networks:",
            *[f"- {network}" for network in networks],
            "",
            "The router host acts as the main network IDS sensor. In execution 15, Snort alerts were collected from:",
            "- container: csle_router_2_1-level9-15",
            "- files: /var/snort/alert.csv and /var/log/alert.csv",
            "",
            "The task is to infer the experienced attack sequence, tactics, techniques, affected hosts, and confidence from the collected attacker outputs, host state, service state, and IDS alerts.",
        ]
    )


def build_logs_text(observation: dict[str, Any]) -> str:
    actions = observation.get("attacker_actions", [])
    final_state = observation.get("final_compromised_state", [])
    fast_alert_lines = snort_fast_lines(observation)
    fast_alerts = parse_fast_alerts(fast_alert_lines)
    alert_lines = snort_csv_lines(observation)
    alert_messages, msg_counter, flow_counter = summarize_alerts(alert_lines)

    sections = [
        "CSLE level9 experienced attack observations.",
        "",
        "### Attacker action outputs",
    ]
    for action in actions:
        ips = ", ".join(action.get("ips", []) or [])
        sections.append(
            f"Step {action.get('step')}: {action.get('name')} "
            f"(status={action.get('status')}, index={action.get('index')}, target_ips=[{ips}])"
        )

    sections.extend(["", "### Final compromised state"])
    for machine in final_state:
        ips = ", ".join(machine.get("ips", []))
        normalized = ", ".join(normalize_ip(ip) for ip in machine.get("ips", []))
        backdoors = [
            f"{cred.get('username')}:{cred.get('service')}/{cred.get('port')}"
            for cred in machine.get("backdoor_credentials", [])
        ]
        creds = [
            f"{cred.get('username')}:{cred.get('service')}/{cred.get('port')}"
            for cred in machine.get("credentials", [])
        ]
        sections.append(
            f"- ips=[{ips}] normalized=[{normalized}] "
            f"logged_in={machine.get('logged_in')} root={machine.get('root')} "
            f"shell_access={machine.get('shell_access')} "
            f"backdoors={backdoors} credentials={creds}"
        )

    sections.extend(["", "### IDS alert summary"])
    if fast_alerts:
        class_counter = Counter(
            (alert["classification"], alert["priority"])
            for alert in fast_alerts
        )
        msg_counter_fast = Counter(alert["message"] for alert in fast_alerts)
        flow_counter_fast = Counter(
            (alert["src"], alert["dst"], alert["protocol"], alert["message"])
            for alert in fast_alerts
        )
        sections.append("Source: /var/snort/fast.log from csle_router_2_1-level9-15.")
        sections.append("Alert counts by classification and priority:")
        for (classification, priority), count in class_counter.most_common(30):
            sections.append(f"- {count} x priority={priority} classification={classification}")
        sections.append("")
        sections.append("Alert message counts:")
        for message, count in msg_counter_fast.most_common(30):
            sections.append(f"- {count} x {message}")
        sections.append("")
        sections.append("Top alert flows:")
        for (src, dst, protocol, message), count in flow_counter_fast.most_common(40):
            sections.append(f"- {count} x {{{protocol}}} {src} -> {dst}: {message}")
        sections.append("")
        sections.append("Readable Snort fast-alert lines:")
        for alert in fast_alerts:
            sections.append(format_fast_alert_multiline(alert))
    elif not alert_messages:
        sections.append("No readable Snort CSV alerts were found in the observation bundle.")
    else:
        sections.append("Source: /var/snort/alert.csv or /var/log/alert.csv from csle_router_2_1-level9-15.")
        sections.append("Warning: CSV alerts do not preserve Snort Classification/Priority fields.")
        sections.append("Alert message counts:")
        for message, count in msg_counter.most_common(20):
            sections.append(f"- {count} x {message}")
        sections.append("")
        sections.append("Top alert flows:")
        for (src, dst, message), count in flow_counter.most_common(30):
            sections.append(f"- {count} x {src} -> {dst}: {message}")
        sections.append("")
        sections.append("Readable Snort alert lines:")
        sections.extend(alert_messages[:250])

    sections.extend(["", "### Host/service evidence"])
    for target in observation.get("target_observations", []):
        machine = target.get("machine", {})
        ips = ", ".join(machine.get("ips", []))
        containers = ", ".join(target.get("containers", []))
        sections.append(f"- target_ips=[{ips}] containers=[{containers}]")
        for container, state in target.get("container_states", {}).items():
            sections.append(f"  container={container}")
            users = state.get("users_checked", "")
            if users:
                sections.append(f"  users_checked={users}")
            ports = state.get("listening_ports", {}).get("stdout", "").strip().splitlines()
            for line in ports[:20]:
                sections.append(f"  listening_port: {line}")

    return "\n".join(sections).rstrip() + "\n"


def build_incident_text(observation: dict[str, Any]) -> str:
    return "\n".join(
        [
            "A CSLE level9 experienced attack was executed in true CSLE execution 15.",
            "The model must infer the attack sequence, tactics, techniques, affected hosts, and confidence from the provided System and Logs.",
            "The attack resulted in root compromise and persistence on multiple hosts, including Samba, SSH, DVWA/SQL injection, and Elasticsearch CVE-2015-1427 related hosts.",
            "The final evaluation will compare recovery outputs between true CSLE execution 15 and DT execution 16 to judge whether the model inferred the attack accurately.",
        ]
    ) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Export level9 model input text files.")
    parser.add_argument("--observation", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    observation_path = Path(args.observation)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    observation = load_json(observation_path)

    system_path = out_dir / "system_level9_experienced_execution15.txt"
    logs_path = out_dir / "logs_alerts_level9_experienced_execution15.txt"
    incident_path = out_dir / "incident_level9_experienced_execution15.txt"

    system_path.write_text(build_system_text(observation), encoding="utf-8")
    logs_path.write_text(build_logs_text(observation), encoding="utf-8")
    incident_path.write_text(build_incident_text(observation), encoding="utf-8")

    print(system_path)
    print(logs_path)
    print(incident_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
