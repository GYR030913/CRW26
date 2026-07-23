#!/usr/bin/env python3
"""Validate a DT16 attack plan before executing it.

The validator is intentionally non-destructive. It checks whether referenced
containers, tools, files, wordlists, source interfaces, and target ports exist,
but it does not run exploit, brute-force, or payload commands.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLAN = (
    ROOT
    / "experiments"
    / "csle_level9_dt"
    / "artifacts"
    / "model_outputs"
    / "deepseek_v4pro_dt16_experienced_attack_plan.json"
)
DEFAULT_REPORT = (
    ROOT
    / "experiments"
    / "csle_level9_dt"
    / "artifacts"
    / "model_outputs"
    / "deepseek_v4pro_dt16_experienced_attack_plan_validation.json"
)

KNOWN_SHELL_WORDS = {
    "bash",
    "sh",
    "sudo",
    "time",
    "timeout",
    "env",
    "cd",
    "set",
    "test",
    "echo",
    "true",
    "false",
    "which",
    "command",
    "ls",
    "for",
    "do",
    "done",
    "in",
    "then",
    "fi",
}
TOOL_ALIASES = {
    "python": ["python", "python3"],
    "python3": ["python3", "python"],
}
TARGET_RE = re.compile(r"(?P<host>16\.9\.\d+\.\d+)(?::(?P<port>\d{1,5}))?")
URL_RE = re.compile(r"https?://(?P<host>16\.9\.\d+\.\d+)(?::(?P<port>\d{1,5}))?")
PORT_OPTION_RE = re.compile(r"(?:^|\s)-p\s*(?P<port>\d{1,5})(?:\s|$)")
ABS_PATH_RE = re.compile(r"(?<![\w.-])(/[A-Za-z0-9_./+-]+)")


@dataclass
class CmdResult:
    returncode: int
    stdout: str
    stderr: str


def run(cmd: list[str], timeout: int = 20) -> CmdResult:
    proc = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    return CmdResult(proc.returncode, proc.stdout.strip(), proc.stderr.strip())


def docker_exec(container: str, command: str, timeout: int = 20) -> CmdResult:
    return run(["docker", "exec", container, "/bin/sh", "-c", command], timeout=timeout)


def load_plan(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    parsed = data.get("parsed")
    if isinstance(parsed, dict):
        return parsed
    return data


def docker_containers() -> set[str]:
    result = run(["docker", "ps", "--format", "{{.Names}}"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def command_items(plan: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for section in ("discovery_commands", "attack_commands"):
        values = plan.get(section, [])
        if not isinstance(values, list):
            continue
        for idx, item in enumerate(values, start=1):
            if isinstance(item, dict):
                copied = dict(item)
                copied["_section"] = section
                copied["_index"] = idx
                items.append(copied)
    return items


def tokenize(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def infer_tools(command: str) -> list[str]:
    tokens = tokenize(command)
    tools: list[str] = []
    command_separators = {"&&", "||", ";", "|"}
    expect_command = True
    skip_next_after = {"sudo", "timeout", "time", "env", "command", "which"}
    previous = ""
    for token in tokens:
        if token in command_separators:
            expect_command = True
            previous = token
            continue
        if token.startswith("-"):
            previous = token
            continue
        if previous in {"-c", "-lc"}:
            previous = token
            continue
        if expect_command:
            cleaned = token.strip(";")
            name = Path(cleaned).name if cleaned.startswith("/") else cleaned
            if name not in KNOWN_SHELL_WORDS and "=" not in name and not name.startswith("$"):
                tools.append(name)
            expect_command = name in skip_next_after
        previous = token
    return sorted(set(tools))


def infer_paths(command: str) -> list[str]:
    command_without_urls = re.sub(r"https?://\S+", "", command)
    paths = sorted(set(ABS_PATH_RE.findall(command_without_urls)))
    ignored_prefixes = ("/bin/bash", "/bin/sh")
    return [
        p
        for p in paths
        if not p.startswith(ignored_prefixes)
        and not p.startswith("//")
        and not re.search(r"://" + re.escape(p.lstrip("/")), command)
    ]


def infer_targets(command: str) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None]] = set()
    tokens = tokenize(command)
    for match in URL_RE.finditer(command):
        host = match.group("host")
        port = int(match.group("port") or ("443" if command[match.start() :].startswith("https://") else "80"))
        seen.add((host, port))
        targets.append({"host": host, "port": port, "source": "url"})
    for idx, token in enumerate(tokens[:-1]):
        if re.fullmatch(r"16\.9\.\d+\.\d+", token) and re.fullmatch(r"\d{1,5}", tokens[idx + 1]):
            host = token
            port = int(tokens[idx + 1])
            if (host, port) not in seen:
                seen.add((host, port))
                targets.append({"host": host, "port": port, "source": "host_port_args"})
    default_port: int | None = None
    port_match = PORT_OPTION_RE.search(command)
    if port_match:
        default_port = int(port_match.group("port"))
    for match in TARGET_RE.finditer(command):
        host = match.group("host")
        port = int(match.group("port")) if match.group("port") else default_port
        if (host, port) not in seen:
            seen.add((host, port))
            targets.append({"host": host, "port": port, "source": "ip"})
    return targets


def check_container(container: str | None, existing: set[str]) -> dict[str, Any]:
    if not container:
        return {"ok": False, "reason": "missing container"}
    if container not in existing:
        return {"ok": False, "reason": "container not running"}
    result = docker_exec(container, "hostname -I 2>/dev/null; ip -o -4 addr show 2>/dev/null | awk '{print $2, $4}'")
    return {
        "ok": result.returncode == 0,
        "ips": result.stdout.splitlines(),
        "stderr": result.stderr,
    }


def check_tools(container: str, tools: list[str]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for tool in tools:
        candidates = TOOL_ALIASES.get(tool, [tool])
        command = " || ".join(f"command -v {shlex.quote(candidate)}" for candidate in candidates)
        result = docker_exec(container, command)
        checks.append(
            {
                "tool": tool,
                "ok": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
    return checks


def check_paths(container: str, paths: list[str]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for path in paths:
        result = docker_exec(container, f"test -e {shlex.quote(path)} && ls -ld {shlex.quote(path)}")
        checks.append(
            {
                "path": path,
                "ok": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
    return checks


def check_targets(container: str, targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for target in targets:
        host = target["host"]
        port = target.get("port")
        if port is None:
            result = docker_exec(container, f"ping -c 1 -W 1 {shlex.quote(host)} >/dev/null 2>&1")
            probe = "ping"
        else:
            result = docker_exec(container, f"nc -z -w 2 {shlex.quote(host)} {int(port)}")
            probe = "tcp_connect"
        checks.append(
            {
                **target,
                "probe": probe,
                "ok": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
    return checks


def summarize_item(item_report: dict[str, Any]) -> bool:
    if not item_report["container_check"].get("ok"):
        return False
    for key in ("tool_checks", "path_checks", "target_checks"):
        for check in item_report.get(key, []):
            if not check.get("ok"):
                return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-file", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--output-file", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    plan = load_plan(args.plan_file)
    existing = docker_containers()
    reports: list[dict[str, Any]] = []
    for item in command_items(plan):
        container = item.get("container")
        command = str(item.get("command", ""))
        item_report: dict[str, Any] = {
            "section": item["_section"],
            "index": item["_index"],
            "description": item.get("description") or item.get("phase"),
            "container": container,
            "command": command,
            "container_check": check_container(container, existing),
            "inferred_tools": infer_tools(command),
            "inferred_paths": infer_paths(command),
            "inferred_targets": infer_targets(command),
            "tool_checks": [],
            "path_checks": [],
            "target_checks": [],
        }
        if container and item_report["container_check"].get("ok"):
            item_report["tool_checks"] = check_tools(container, item_report["inferred_tools"])
            item_report["path_checks"] = check_paths(container, item_report["inferred_paths"])
            item_report["target_checks"] = check_targets(container, item_report["inferred_targets"])
        item_report["ok"] = summarize_item(item_report)
        reports.append(item_report)

    summary = {
        "plan_file": str(args.plan_file),
        "total_commands": len(reports),
        "ok_commands": sum(1 for report in reports if report["ok"]),
        "failed_commands": sum(1 for report in reports if not report["ok"]),
    }
    output = {"summary": summary, "commands": reports}
    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    args.output_file.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {args.output_file}")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["failed_commands"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
