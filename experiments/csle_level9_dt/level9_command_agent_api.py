"""OpenAI-compatible command agent and validator for CSLE level9 recovery.

This module converts high-level recovery actions into concrete DT16
``docker exec`` command plans. It is intentionally level9-specific: the
validator knows the expected containers, services, accounts, and common paths
so that API-generated commands can be checked before execution.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from llm_ir_dt.recovery_loop.schemas import CommandPlan, CommandSpec, HighLevelAction, RecoveryState


DEFAULT_LEVEL9_SERVICES = {
    "csle_samba_2_1-level9-16": ("ssh", "smbd"),
    "csle_ssh_1_1-level9-16": ("ssh",),
    "csle_sql_injection_1_1-level9-16": ("ssh", "apache2"),
    "csle_cve_2015_1427_1_1-level9-16": ("ssh", "elasticsearch"),
}

DEFAULT_LEVEL9_USERS = {
    "csle_samba_2_1-level9-16": ("ssh_backdoor_sambapwned",),
    "csle_ssh_1_1-level9-16": ("puppet",),
    "csle_sql_injection_1_1-level9-16": ("pablo",),
    "csle_cve_2015_1427_1_1-level9-16": ("ssh_backdoor_cve_2015_1427_pwned",),
}

DEFAULT_LEVEL9_PATHS = {
    "csle_samba_2_1-level9-16": (
        "/etc/passwd",
        "/etc/shadow",
        "/etc/samba",
        "/var/lib/samba",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/home",
        "/root/.ssh",
    ),
    "csle_ssh_1_1-level9-16": (
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/home",
        "/root/.ssh",
    ),
    "csle_sql_injection_1_1-level9-16": (
        "/etc/passwd",
        "/etc/shadow",
        "/var/www",
        "/etc/apache2",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/home",
        "/root/.ssh",
    ),
    "csle_cve_2015_1427_1_1-level9-16": (
        "/etc/passwd",
        "/etc/shadow",
        "/etc/elasticsearch",
        "/var/lib/elasticsearch",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/home",
        "/root/.ssh",
    ),
}


DENIED_COMMAND_PATTERNS = (
    r"\brm\s+-rf\s+/",
    r"\brm\s+-fr\s+/",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\breboot\b",
    r"\bshutdown\b",
    r"\bpoweroff\b",
    r"\bdocker\b",
    r"\bsystemctl\s+reboot\b",
    r"\bapt(-get)?\s+(dist-upgrade|upgrade|remove|purge)\b",
    r"\bcurl\s+https?://",
    r"\bwget\s+https?://",
)


@dataclass(frozen=True)
class ValidationIssue:
    severity: str
    message: str
    container: str = ""
    command: str = ""


@dataclass
class ValidationReport:
    ok: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    environment: dict[str, Any] = field(default_factory=dict)

    def to_prompt_text(self) -> str:
        lines = ["Validation failed. Fix the command plan using the facts below."]
        if self.environment:
            lines.append("Known level9 environment:")
            lines.append(json.dumps(self.environment, indent=2, ensure_ascii=False))
        lines.append("Validation issues:")
        for issue in self.issues:
            where = f" [{issue.container}]" if issue.container else ""
            cmd = f" command={issue.command!r}" if issue.command else ""
            lines.append(f"- {issue.severity}{where}: {issue.message}{cmd}")
        return "\n".join(lines)


class Level9CommandValidator:
    """Validate API-generated level9 command plans before execution."""

    def __init__(
        self,
        *,
        known_targets: dict[str, dict[str, Any]],
        dynamic_checks: bool = True,
        repo_root: Path | None = None,
    ) -> None:
        self.known_targets = known_targets
        self.dynamic_checks = dynamic_checks
        self.repo_root = repo_root or Path.cwd()
        self.allowed_containers = tuple(
            sorted({container for info in known_targets.values() for container in info.get("containers", [])})
        )

    def environment_summary(self) -> dict[str, Any]:
        targets: dict[str, Any] = {}
        for name, info in self.known_targets.items():
            containers = list(info.get("containers", []))
            targets[name] = {
                "ips": info.get("ips", ""),
                "containers": containers,
                "backdoor_users": list(info.get("backdoor_users", [])),
                "services": list(info.get("services", [])),
                "common_paths": {
                    container: list(DEFAULT_LEVEL9_PATHS.get(container, ())) for container in containers
                },
            }
        return {
            "execution": "DT16",
            "allowed_containers": list(self.allowed_containers),
            "targets": targets,
            "notes": [
                "Commands are executed inside the target container as root via docker exec.",
                "Do not include docker exec in command strings.",
                "Prefer small reversible commands and explicit verification commands.",
            ],
        }

    def validate(self, plan: CommandPlan) -> ValidationReport:
        issues: list[ValidationIssue] = []
        for phase, specs in (
            ("recovery", plan.commands),
            ("verification", plan.verification_commands),
        ):
            for spec in specs:
                issues.extend(self._validate_spec(spec, phase=phase))
        if self.dynamic_checks and not any(issue.severity == "error" for issue in issues):
            for spec in tuple(plan.commands) + tuple(plan.verification_commands):
                issues.extend(self._dynamic_validate_spec(spec))
        ok = not any(issue.severity == "error" for issue in issues)
        return ValidationReport(ok=ok, issues=issues, environment=self.environment_summary())

    def _validate_spec(self, spec: CommandSpec, *, phase: str) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        if spec.container not in self.allowed_containers:
            issues.append(
                ValidationIssue(
                    "error",
                    f"unknown container; allowed containers are {', '.join(self.allowed_containers)}",
                    spec.container,
                    spec.command,
                )
            )
        command = spec.command.strip()
        if not command:
            issues.append(ValidationIssue("error", "empty command", spec.container, spec.command))
            return issues
        if "\n" in command:
            issues.append(ValidationIssue("error", "command must be one line", spec.container, spec.command))
        if "docker exec" in command:
            issues.append(
                ValidationIssue(
                    "error",
                    "command must not include docker exec; executor adds docker exec automatically",
                    spec.container,
                    spec.command,
                )
            )
        for pattern in DENIED_COMMAND_PATTERNS:
            if re.search(pattern, command):
                issues.append(
                    ValidationIssue("error", f"denied risky command pattern: {pattern}", spec.container, spec.command)
                )
        if phase == "verification" and spec.allowed_exit_codes != (0,):
            issues.append(
                ValidationIssue(
                    "warning",
                    "verification commands should normally require exit code 0",
                    spec.container,
                    spec.command,
                )
            )
        self._validate_service_names(spec, issues)
        self._validate_user_names(spec, issues)
        self._validate_obvious_paths(spec, issues)
        return issues

    def _validate_service_names(self, spec: CommandSpec, issues: list[ValidationIssue]) -> None:
        match = re.search(r"\bservice\s+([A-Za-z0-9_.@+-]+)\s+", spec.command)
        if not match:
            return
        service = match.group(1)
        allowed = set(DEFAULT_LEVEL9_SERVICES.get(spec.container, ()))
        if allowed and service not in allowed:
            issues.append(
                ValidationIssue(
                    "error",
                    f"service {service!r} is not expected for this container; expected {sorted(allowed)}",
                    spec.container,
                    spec.command,
                )
            )

    def _validate_user_names(self, spec: CommandSpec, issues: list[ValidationIssue]) -> None:
        user = ""
        for pattern in (r"\bpasswd\s+-l\s+([A-Za-z0-9_.@+-]+)", r"\bpkill\s+-KILL\s+-u\s+([A-Za-z0-9_.@+-]+)"):
            match = re.search(pattern, spec.command)
            if match:
                user = match.group(1)
                break
        if not user:
            return
        allowed = set(DEFAULT_LEVEL9_USERS.get(spec.container, ()))
        if allowed and user not in allowed:
            issues.append(
                ValidationIssue(
                    "warning",
                    f"user {user!r} is not one of the known attack/backdoor users for this container",
                    spec.container,
                    spec.command,
                )
            )

    def _validate_obvious_paths(self, spec: CommandSpec, issues: list[ValidationIssue]) -> None:
        paths = re.findall(r"(?<![A-Za-z0-9_.-])/[A-Za-z0-9_./@+-]+", spec.command)
        known_roots = tuple(DEFAULT_LEVEL9_PATHS.get(spec.container, ())) + ("/tmp", "/var/log", "/etc")
        for path in paths:
            if path in ("/dev/null",):
                continue
            if not path.startswith(known_roots):
                issues.append(
                    ValidationIssue(
                        "warning",
                        f"path {path!r} is outside the common level9 recovery paths for this container",
                        spec.container,
                        spec.command,
                    )
                )

    def _dynamic_validate_spec(self, spec: CommandSpec) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        inspect = self._host_cmd(["docker", "inspect", "-f", "{{.State.Running}}", spec.container], timeout=15)
        if inspect["returncode"] != 0 or inspect["stdout"].strip() != "true":
            issues.append(ValidationIssue("error", "container does not exist or is not running", spec.container, ""))
            return issues
        for service in re.findall(r"\bservice\s+([A-Za-z0-9_.@+-]+)\s+", spec.command):
            check = self._container_cmd(spec.container, f"service {service} status >/dev/null 2>&1 || test -x /etc/init.d/{service}", timeout=15)
            if check["returncode"] not in (0, 3):
                issues.append(
                    ValidationIssue("error", f"service {service!r} not found dynamically", spec.container, spec.command)
                )
        for user in re.findall(r"\b(?:passwd\s+-l|pkill\s+-KILL\s+-u|getent\s+(?:passwd|shadow))\s+([A-Za-z0-9_.@+-]+)", spec.command):
            check = self._container_cmd(spec.container, f"getent passwd {user} >/dev/null 2>&1", timeout=15)
            if check["returncode"] != 0:
                issues.append(
                    ValidationIssue("warning", f"user {user!r} does not currently exist", spec.container, spec.command)
                )
        return issues

    def _host_cmd(self, cmd: list[str], *, timeout: int) -> dict[str, Any]:
        proc = subprocess.run(
            cmd,
            cwd=str(self.repo_root),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

    def _container_cmd(self, container: str, command: str, *, timeout: int) -> dict[str, Any]:
        return self._host_cmd(["docker", "exec", container, "bash", "-lc", command], timeout=timeout)


class APILevel9CommandAgent:
    """Generate and repair level9 command plans with an OpenAI-compatible API."""

    def __init__(
        self,
        *,
        model: str,
        api_key_env: str,
        base_url: str,
        context: dict[str, str],
        validator: Level9CommandValidator,
        timeout_seconds: int = 120,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        top_p: float = 0.9,
        repair_attempts: int = 2,
        log_dir: Path | None = None,
    ) -> None:
        self.model = model
        self.api_key_env = api_key_env
        self.api_key = os.getenv(api_key_env, "").strip()
        self.base_url = base_url.rstrip("/")
        self.context = context
        self.validator = validator
        self.timeout_seconds = timeout_seconds
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.top_p = top_p
        self.repair_attempts = repair_attempts
        self.log_dir = log_dir
        self.call_index = 0
        if not self.api_key:
            raise ValueError(f"API key is missing. Set {api_key_env}.")

    def generate_plan(
        self,
        *,
        high_level_action: HighLevelAction,
        state: RecoveryState,
        target: str,
    ) -> CommandPlan:
        repair_feedback = ""
        attempts: list[dict[str, Any]] = []
        last_plan: CommandPlan | None = None
        last_report: ValidationReport | None = None

        for attempt in range(1, self.repair_attempts + 2):
            prompt = self._build_prompt(
                high_level_action=high_level_action,
                state=state,
                target=target,
                repair_feedback=repair_feedback,
            )
            raw_response, response_json = self._chat(prompt)
            plan = self._parse_plan(
                response_text=raw_response,
                high_level_action=high_level_action,
                response_json=response_json,
            )
            report = self.validator.validate(plan)
            attempts.append(
                {
                    "attempt": attempt,
                    "prompt": prompt,
                    "raw_response": raw_response,
                    "parsed_plan": self._plan_to_jsonable(plan),
                    "validation": self._report_to_jsonable(report),
                }
            )
            last_plan = plan
            last_report = report
            if report.ok:
                self._write_attempt_log(high_level_action, attempts)
                return plan
            repair_feedback = report.to_prompt_text()
            time.sleep(min(attempt, 3))

        self._write_attempt_log(high_level_action, attempts)
        raise RuntimeError(
            "API command agent failed validation after "
            f"{self.repair_attempts + 1} attempts: "
            f"{last_report.to_prompt_text() if last_report else 'no validation report'}\n"
            f"Last plan: {self._plan_to_jsonable(last_plan) if last_plan else None}"
        )

    def _build_prompt(
        self,
        *,
        high_level_action: HighLevelAction,
        state: RecoveryState,
        target: str,
        repair_feedback: str,
    ) -> str:
        env = self.validator.environment_summary()
        schema = {
            "commands": [
                {
                    "container": "csle_samba_2_1-level9-16",
                    "command": "passwd -l ssh_backdoor_sambapwned",
                    "allowed_exit_codes": [0],
                    "description": "lock known Samba backdoor account",
                }
            ],
            "verification_commands": [
                {
                    "container": "csle_samba_2_1-level9-16",
                    "command": "getent shadow ssh_backdoor_sambapwned | cut -d: -f2 | grep -q '^!'",
                    "allowed_exit_codes": [0],
                    "description": "verify Samba backdoor account is locked",
                }
            ],
        }
        parts = [
            "You are a command-generation agent for CSLE level9 DT16 recovery.",
            "Generate concrete bash commands to run inside existing DT16 containers.",
            "Return JSON only. Do not include markdown.",
            "Do not include docker exec; the executor adds docker exec automatically.",
            "Use only the containers, services, users, and paths in the environment summary unless the system/logs strongly justify otherwise.",
            "Prefer commands that are specific, reversible, and verifiable.",
            "If asked to patch/rebuild/restore, implement the closest safe container-level remediation available in this environment and include verification.",
            "",
            "Required JSON schema:",
            json.dumps(schema, indent=2),
            "",
            "Current recovery state:",
            json.dumps(state, indent=2),
            "",
            f"Target: {target}",
            "",
            "High-level recovery action:",
            high_level_action.action,
            "",
            "Action explanation:",
            high_level_action.explanation,
            "",
            "Known level9 environment:",
            json.dumps(env, indent=2, ensure_ascii=False),
            "",
            "System information:",
            self.context.get("System", ""),
            "",
            "Incident:",
            self.context.get("Incident", ""),
            "",
            "Relevant logs:",
            self.context.get("Logs", "")[:12000],
        ]
        if repair_feedback:
            parts.extend(["", "Previous command plan failed validation:", repair_feedback])
        return "\n".join(parts)

    def _chat(self, prompt: str) -> tuple[str, dict[str, Any]]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You generate validated CSLE level9 recovery command plans. "
                        "You must output a single JSON object."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
        }
        response = self._post_with_parameter_fallback(payload)
        if response.status_code >= 400:
            raise RuntimeError(f"command agent API failed: HTTP {response.status_code}: {response.text}")
        data = response.json()
        text = self._extract_message_text(data)
        if not text:
            raise RuntimeError(f"command agent API returned empty message: {data}")
        return text, data

    def _post_with_parameter_fallback(self, payload: dict[str, Any]) -> requests.Response:
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=self.timeout_seconds,
        )
        if response.status_code < 400:
            return response
        text = response.text.lower()
        for parameter in ("top_p", "temperature", "response_format"):
            if parameter in payload and "unsupported" in text and parameter in text:
                payload = dict(payload)
                payload.pop(parameter, None)
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=self.timeout_seconds,
                )
                if response.status_code < 400:
                    return response
                text = response.text.lower()
        return response

    @staticmethod
    def _extract_message_text(data: dict[str, Any]) -> str:
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            return ""
        message = choices[0].get("message") if isinstance(choices[0], dict) else {}
        if not isinstance(message, dict):
            return ""
        content = message.get("content") or message.get("reasoning_content")
        if isinstance(content, str):
            return content.strip()
        return ""

    def _parse_plan(
        self,
        *,
        response_text: str,
        high_level_action: HighLevelAction,
        response_json: dict[str, Any],
    ) -> CommandPlan:
        try:
            data = json.loads(response_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"command agent response was not JSON: {exc}: {response_text}") from exc
        commands = self._parse_specs(data.get("commands", ()), field_name="commands")
        checks = self._parse_specs(data.get("verification_commands", ()), field_name="verification_commands")
        if not commands:
            raise RuntimeError("command agent returned no recovery commands")
        if not checks:
            raise RuntimeError("command agent returned no verification commands")
        return CommandPlan(
            high_level_action=high_level_action.action,
            high_level_action_explanation=high_level_action.explanation,
            commands=tuple(commands),
            verification_commands=tuple(checks),
            raw_model_output=json.dumps(
                {"message": response_text, "api_response": response_json},
                ensure_ascii=False,
            ),
        )

    @staticmethod
    def _parse_specs(value: Any, *, field_name: str) -> list[CommandSpec]:
        if not isinstance(value, list):
            raise RuntimeError(f"{field_name} must be a list")
        specs: list[CommandSpec] = []
        for item in value:
            if not isinstance(item, dict):
                raise RuntimeError(f"{field_name} item must be an object: {item!r}")
            exit_codes = item.get("allowed_exit_codes", [0])
            if not isinstance(exit_codes, list) or not all(isinstance(code, int) for code in exit_codes):
                raise RuntimeError(f"{field_name} allowed_exit_codes must be a list of ints: {item!r}")
            specs.append(
                CommandSpec(
                    container=str(item.get("container", "")).strip(),
                    command=str(item.get("command", "")).strip(),
                    allowed_exit_codes=tuple(exit_codes),
                    description=str(item.get("description", "")).strip(),
                )
            )
        return specs

    def _write_attempt_log(self, action: HighLevelAction, attempts: list[dict[str, Any]]) -> None:
        if not self.log_dir:
            return
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.call_index += 1
        safe_action = re.sub(r"[^A-Za-z0-9_.-]+", "_", action.action[:80]).strip("_")
        path = self.log_dir / f"command_agent_call_{self.call_index:04d}_{safe_action}.json"
        path.write_text(json.dumps(attempts, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def _plan_to_jsonable(plan: CommandPlan | None) -> Any:
        if plan is None:
            return None
        return {
            "high_level_action": plan.high_level_action,
            "commands": [spec.__dict__ for spec in plan.commands],
            "verification_commands": [spec.__dict__ for spec in plan.verification_commands],
        }

    @staticmethod
    def _report_to_jsonable(report: ValidationReport) -> dict[str, Any]:
        return {
            "ok": report.ok,
            "issues": [issue.__dict__ for issue in report.issues],
            "environment": report.environment,
        }
