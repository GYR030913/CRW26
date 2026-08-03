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
        "/elasticsearch/config/elasticsearch.yml",
        "/elasticsearch/config/logging.yml",
        "/etc/elasticsearch",
        "/var/lib/elasticsearch",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/home",
        "/root/.ssh",
    ),
}


DENIED_COMMAND_PATTERNS = (
    r"\brm\s+-rf\s+/(?:\s|$)",
    r"\brm\s+-fr\s+/(?:\s|$)",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"/proc/kcore",
    r"\btar\b.*\s-C\s+/\s+\.",
    r"\bsha256sum\s+\*",
    r"\breboot\b",
    r"\bshutdown\b",
    r"\bpoweroff\b",
    r"\bdocker\b",
    r"\bsystemctl\b",
    r"\bapt(-get)?\s+(dist-upgrade|upgrade|remove|purge)\b",
    r"\bcurl\s+https?://",
    r"\bwget\s+https?://",
    r"\bip\s+link\s+set\b.*\bdown\b",
    r"\bpkill\s+-f\b",
    r"\bpkill\s+-HUP\b",
    r"\bkill\s+-HUP\b",
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
        return self.environment_summary_for_containers(self.allowed_containers)

    def environment_summary_for_containers(self, containers: tuple[str, ...] | list[str]) -> dict[str, Any]:
        allowed = set(containers)
        targets: dict[str, Any] = {}
        for name, info in self.known_targets.items():
            target_containers = [container for container in info.get("containers", []) if container in allowed]
            if not target_containers:
                continue
            targets[name] = {
                "ips": info.get("ips", ""),
                "containers": target_containers,
                "backdoor_users": list(info.get("backdoor_users", [])),
                "services": list(info.get("services", [])),
                "common_paths": {
                    container: list(DEFAULT_LEVEL9_PATHS.get(container, ())) for container in target_containers
                },
            }
        return {
            "execution": "DT16",
            "allowed_containers": list(containers),
            "targets": targets,
            "notes": [
                "Commands are executed inside the target container as root via docker exec.",
                "Do not include docker exec in command strings.",
                "Prefer small reversible commands and explicit verification commands.",
                "Do not disable container network interfaces with ip link set ... down; use reversible iptables rules for containment.",
                "For forensic preservation, collect compact evidence snapshots under /tmp/recovery_evidence; do not create full disk images or memory dumps.",
                "Evidence collection commands must be exit-code safe: optional missing files must not make the command fail.",
                "Do not run `sha256sum *`; hash only regular files and exclude sha256sums.txt itself: `find /tmp/recovery_evidence -type f ! -name sha256sums.txt -print0 | xargs -0 sha256sum > /tmp/recovery_evidence/sha256sums.txt`.",
                "Do not verify evidence by running `sha256sum -c /tmp/recovery_evidence/sha256sums.txt`; verify that sha256sums.txt exists and contains hash-looking lines.",
                "Do not use `test ! -w` as a read-only evidence verification when commands run as root; use stat mode checks if needed.",
                "Do not use broad `pkill -f`; it can kill the active command shell. Prefer `pkill -KILL -u USER` for known backdoor users or service commands for services.",
                "Do not use systemctl; these Docker containers are not systemd hosts.",
                "Do not invent services that are not listed for the target container, such as telnetd.",
                "Do not send HUP signals to sshd/smbd/elasticsearch; restart only known service-managed services with `service ssh restart` when needed.",
                "In csle_cve_2015_1427_1_1-level9-16, Elasticsearch config is normally /elasticsearch/config/elasticsearch.yml, not /etc/elasticsearch/elasticsearch.yml. Use `test -f` before editing or verifying any Elasticsearch config path.",
                "For iptables verification, do not grep one exact full rule string; verify independent components so /32 normalization or inserted match modules do not break checks.",
                "When grepping for patterns beginning with dashes, e.g. --dport, use `grep -- '--dport 22'` or `grep -E -- '--dport 22|dport 22'` so grep does not treat the pattern as an option.",
            ],
        }

    def validate(self, plan: CommandPlan) -> ValidationReport:
        issues: list[ValidationIssue] = []
        self._current_recovery_command_text = "\n".join(spec.command for spec in plan.commands)
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
        if (
            spec.container == "csle_cve_2015_1427_1_1-level9-16"
            and "/etc/elasticsearch/elasticsearch.yml" in command
            and "test -f /etc/elasticsearch/elasticsearch.yml" not in command
            and "[ -f /etc/elasticsearch/elasticsearch.yml ]" not in command
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "do not assume /etc/elasticsearch/elasticsearch.yml exists in level9; discover with `test -f` or `[ -f ... ]` and prefer /elasticsearch/config/elasticsearch.yml when present",
                    spec.container,
                    spec.command,
                )
            )
        if (
            phase == "verification"
            and re.search(r"grep\s+-q\s+['\"]\^PermitRootLogin no['\"]", command)
            and "PermitRootLogin prohibit-password" not in command
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "PermitRootLogin verification is too narrow; use `grep -Eq '^(PermitRootLogin no|PermitRootLogin prohibit-password)' /etc/ssh/sshd_config`",
                    spec.container,
                    spec.command,
                )
            )
        if "/etc/ssh/sshd_config" in command and re.search(
            r"sed\s+-i\s+['\"]s/\^#\*(PasswordAuthentication|PermitRootLogin) ",
            command,
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "SSH hardening sed pattern is too brittle for level9; use whitespace-tolerant patterns like `^[#[:space:]]*PasswordAuthentication[[:space:]].*` and `^[#[:space:]]*PermitRootLogin[[:space:]].*`",
                    spec.container,
                    spec.command,
                )
            )
        if (
            phase == "recovery"
            and "/etc/ssh/sshd_config" in command
            and re.search(r"\becho\s+['\"](?:PasswordAuthentication no|PermitRootLogin (?:no|prohibit-password))['\"]\s*>>\s*/etc/ssh/sshd_config", command)
            and not re.search(r"(printf|sed\s+-i\s+['\"]\$\s*a\\\\|tail\s+-c1\s+/etc/ssh/sshd_config|echo\s*$)", command)
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "do not append sshd_config directives with plain `echo ... >> /etc/ssh/sshd_config`; use one-line sed append commands such as `sed -i -e '$aPasswordAuthentication no' -e '$aPermitRootLogin no' /etc/ssh/sshd_config`",
                    spec.container,
                    spec.command,
                )
            )
        if (
            phase == "recovery"
            and "/etc/ssh/sshd_config" in command
            and "printf '%s\\\\012'" in command
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "do not use `printf '%s\\\\012'` for sshd_config hardening; it can write a literal backslash sequence. Use awk print statements to append separate lines.",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "recovery" and "/etc/ssh/sshd_config" in command and "awk" in command and r"\"" in command:
            issues.append(
                ValidationIssue(
                    "error",
                    "do not use awk print statements with backslash-escaped quotes for sshd_config hardening; use `sed -i -e '$aPasswordAuthentication no' -e '$aPermitRootLogin no' /etc/ssh/sshd_config` instead",
                    spec.container,
                    spec.command,
                )
            )
        if (
            phase == "verification"
            and "/etc/ssh/sshd_config" in command
            and re.search(r"grep\s+-q\s+['\"]\^PasswordAuthentication no['\"]", command)
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "PasswordAuthentication verification is too brittle; use `grep -Eq '^[[:space:]]*PasswordAuthentication[[:space:]]+no([[:space:]]|$)' /etc/ssh/sshd_config`",
                    spec.container,
                    spec.command,
                )
            )
        if (
            re.search(r"\bgrep\s+(?:-[A-Za-z]*E[A-Za-z]*\s+)?['\"]--", command)
            or re.search(r"\bgrep\s+-[A-Za-z]*\s+['\"]--dport", command)
        ) and not re.search(r"\bgrep\s+(?:-[A-Za-z]*E[A-Za-z]*\s+)?--\s+['\"]--", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "grep patterns that start with '-' must use `grep -- 'PATTERN'` or `grep -E -- 'PATTERN'`; otherwise grep treats the pattern as an option",
                    spec.container,
                    spec.command,
                )
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
        if phase == "verification" and re.search(r"\btest\s+!\s+-w\s+", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "do not verify read-only evidence with `test ! -w` when running as root; use stat mode checks or verify evidence files and hashes exist",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and re.search(r"\bsha256sum\s+-c\s+/tmp/recovery_evidence/sha256sums\.txt\b", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "`sha256sum -c /tmp/recovery_evidence/sha256sums.txt` is brittle because sha256sums.txt may be included in its own manifest or evidence may be appended; verify hash-looking lines instead",
                    spec.container,
                    spec.command,
                )
            )
        if "sha256sums.txt" in command and re.search(r"find\s+/tmp/recovery_evidence\s+-type\s+f\b", command):
            if "! -name sha256sums.txt" not in command:
                issues.append(
                    ValidationIssue(
                        "error",
                        "evidence hash generation must exclude sha256sums.txt itself: `find /tmp/recovery_evidence -type f ! -name sha256sums.txt -print0 | xargs -0 sha256sum > /tmp/recovery_evidence/sha256sums.txt`",
                        spec.container,
                        spec.command,
                    )
                )
        if re.search(r"\bcat\s+\"\$[A-Za-z_][A-Za-z0-9_]*\"\s+2>/dev/null", command) and not re.search(
            r"\bcat\s+\"\$[A-Za-z_][A-Za-z0-9_]*\"\s+2>/dev/null\s*(\|\|\s*true|;\s*true)",
            command,
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "optional file reads must not make the whole command fail; add `|| true` to optional cat commands",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and "/tmp/quarantine/" in command and re.search(r"test\s+!?\s+-d\s+/home/", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "verification must not require quarantine copies of optional directories; verify the security outcome instead",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and re.search(r"test\s+!\s+-d\s+/home/[A-Za-z0-9_.@+-]+/\.ssh\b", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "verification must not require a user's .ssh directory to be absent; verify the backdoor account is locked and authorized_keys is absent or empty if that file was cleaned",
                    spec.container,
                    spec.command,
                )
            )
        for ssh_option in ("ChallengeResponseAuthentication", "PubkeyAuthentication"):
            if phase == "verification" and ssh_option in command:
                issues.append(
                    ValidationIssue(
                        "error",
                        f"verification must not require {ssh_option}; it is too brittle across level9 containers. Verify PasswordAuthentication, PermitRootLogin, account locks, and firewall outcomes instead",
                        spec.container,
                        spec.command,
                    )
                )
        if phase == "verification" and re.search(r"\bpgrep\b.*\b(smbd|elasticsearch|org\.elasticsearch)\b", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "verification must not depend on unstable smbd/elasticsearch process names; verify config, account, firewall, or port outcome instead",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and re.search(r"getent\s+shadow\s+[A-Za-z0-9_.@+-]+.*grep\s+-q\s+['\"]\^!", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "verification of locked accounts must use `passwd -S USER | grep -q ' L '` or accept both ! and * lock prefixes",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and re.search(r"\biptables\s+-C\b", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "iptables verification must not require exact rule identity with `iptables -C`; use `iptables -S | grep` outcome checks instead",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and command.count("&&") > 2:
            issues.append(
                ValidationIssue(
                    "error",
                    "verification command chains too many unrelated checks with &&; split verification by outcome and keep each check atomic",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and "iptables" in command and re.search(r"\brecent\s+--(?:set|update)\b", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "iptables recent-module text is too brittle for verification; verify broad firewall outcomes such as source DROP or dport DROP instead",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and "iptables" in command and re.search(r"grep\s+-q\s+(?:--\s+)?['\"]-P\s+DROP['\"]", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "iptables policy verification is malformed; include the chain name such as `-P OUTPUT DROP`, or prefer narrower source/port DROP checks",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and "iptables" in command and re.search(r"grep\s+-E\s+--\s+['\"]\s+-P\s+(?:INPUT|OUTPUT|FORWARD)\s+DROP['\"]", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "iptables policy verification must not require a leading space before `-P`; `iptables -S` prints policy lines starting with `-P INPUT DROP`. Use `iptables -S | grep -q -- '-P INPUT DROP'` or a component check.",
                    spec.container,
                    spec.command,
                )
            )
        if (
            phase == "verification"
            and "/etc/samba/smb.conf" in command
            and re.search(r"grep\s+-q\s+['\"]server min protocol\.\*SMB2['\"]", command)
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "Samba SMB protocol verification is too narrow; guard smb.conf with test -f and accept equivalent min-protocol forms, or verify firewall/account outcomes instead",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and re.search(
            r"iptables\s+-S\s*\|\s*grep\s+-q\s+(?:--\s+)?['\"][^'\"]*(?:-A\s+\w+|-s\s+\d+\.\d+\.\d+\.\d+\s|-d\s+\d+\.\d+\.\d+\.\d+\s|--dport\s+\d+)[^'\"]*-j\s+DROP",
            command,
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "iptables verification is too exact; iptables -S may normalize IPs to /32 or insert match modules. Use component checks like `iptables -S | grep -F IP | grep -F -- --dport | grep -q DROP`",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and "iptables" in command and re.search(
            r"grep\s+-qE?\s+['\"][^'\"]*(?:DROP|ACCEPT)\.\*",
            command,
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "iptables verification must not assume printed field order such as `DROP.*IP` or `ACCEPT.*IP`; chain component greps instead, e.g. `iptables -S INPUT | grep -F IP | grep -q -- '-j DROP'`",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and "iptables" in command and re.search(
            r"grep\s+(?:-[A-Za-z]*\s+)*(?:--\s+)?['\"][^'\"]*!\s+-[sd]",
            command,
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "iptables verification must not depend on textual negation like `! -s` or `! -d`; verify the positive allow/drop rules that matter instead",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and "--string" in command and "iptables" in command:
            issues.append(
                ValidationIssue(
                    "error",
                    "firewall verification must not require payload-specific iptables string-match rules; verify broad containment or service exposure outcomes instead",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and re.search(r"\bss\b.*\bgrep\b.*['\"]:(80|445|9200)(?:\s|['\"])", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "recovery verification must not require vulnerable service ports 80/445/9200 to be publicly listening after containment/hardening; verify SSH management access, account cleanup, or firewall-scoped exposure instead",
                    spec.container,
                    spec.command,
                )
            )
        if phase == "verification" and re.search(r"\bcurl\s+-s\s+https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|16\.9\.)", command):
            issues.append(
                ValidationIssue(
                    "error",
                    "recovery verification must not depend on brittle HTTP page contents such as `curl localhost | grep dvwa`; verify account cleanup, config hardening, or scoped firewall/service policy instead",
                    spec.container,
                    spec.command,
                )
            )
        if "/root/.ssh/authorized_keys" in command and (
            re.search(r"\brm\s+-f\s+/root/\.ssh/authorized_keys\b", command)
            or re.search(r"!\s*test\s+-f\s+/root/\.ssh/authorized_keys\b", command)
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "do not delete or require absence of /root/.ssh/authorized_keys unless root-key persistence is explicitly observed; focus on known level9 backdoor users",
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
            service_segment = next(
                (segment for segment in spec.command.split(";") if re.search(rf"\bservice\s+{re.escape(service)}\s+", segment)),
                "",
            )
            if "|| true" in service_segment:
                continue
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
        if target == "all":
            return self._generate_split_plan_by_container(
                high_level_action=high_level_action,
                state=state,
                target=target,
            )
        target_containers = self._containers_for_target(target)
        return self._generate_single_plan(
            high_level_action=high_level_action,
            state=state,
            target=target,
            allowed_containers=target_containers,
        )

    def _containers_for_target(self, target: str) -> tuple[str, ...] | None:
        target_info = self.validator.known_targets.get(target)
        if not target_info:
            return None
        containers = tuple(
            container
            for container in target_info.get("containers", ())
            if container in self.validator.allowed_containers
        )
        return containers or None

    def _generate_split_plan_by_container(
        self,
        *,
        high_level_action: HighLevelAction,
        state: RecoveryState,
        target: str,
    ) -> CommandPlan:
        commands: list[CommandSpec] = []
        verification_commands: list[CommandSpec] = []
        raw_parts: list[str] = []
        for container in self.validator.allowed_containers:
            plan = self._generate_single_plan(
                high_level_action=high_level_action,
                state=state,
                target=target,
                allowed_containers=(container,),
            )
            commands.extend(plan.commands)
            verification_commands.extend(plan.verification_commands)
            raw_parts.append(plan.raw_model_output)
        combined = CommandPlan(
            high_level_action=high_level_action.action,
            high_level_action_explanation=high_level_action.explanation,
            commands=tuple(commands),
            verification_commands=tuple(verification_commands),
            raw_model_output=json.dumps({"split_by_container": raw_parts}, ensure_ascii=False),
        )
        report = self.validator.validate(combined)
        if not report.ok and not self._can_soft_accept_recovery_validation(high_level_action, combined, report):
            raise RuntimeError(
                "combined split command plan failed validation: "
                f"{report.to_prompt_text()}"
            )
        return combined

    def _generate_single_plan(
        self,
        *,
        high_level_action: HighLevelAction,
        state: RecoveryState,
        target: str,
        allowed_containers: tuple[str, ...] | None,
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
                allowed_containers=allowed_containers,
            )
            raw_response, response_json = self._chat(prompt)
            try:
                plan = self._parse_plan(
                    response_text=raw_response,
                    high_level_action=high_level_action,
                    response_json=response_json,
                )
            except Exception as exc:
                attempts.append(
                    {
                        "attempt": attempt,
                        "prompt": prompt,
                        "raw_response": raw_response,
                        "parsed_plan": None,
                        "validation": {
                            "ok": False,
                            "issues": [
                                {
                                    "severity": "error",
                                    "message": f"response was not a valid command-plan JSON object: {exc}",
                                    "container": "",
                                    "command": "",
                                }
                            ],
                            "environment": self.validator.environment_summary(),
                        },
                    }
                )
                repair_feedback = (
                    "The previous response was not valid JSON or was truncated. "
                    "Return one complete JSON object only. Keep the plan compact: "
                    "at most 2 recovery commands and at most 2 verification commands. "
                    "Use only allowed target containers. Do not include router/hacker containers. "
                    "Do not create full disk images, memory dumps, or tar the whole filesystem. "
                    f"JSON parse error: {exc}. "
                    f"Previous response prefix: {raw_response[:800]}"
                )
                time.sleep(min(attempt, 3))
                continue
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
            if allowed_containers:
                disallowed_specs = [
                    spec
                    for spec in tuple(plan.commands) + tuple(plan.verification_commands)
                    if spec.container not in allowed_containers
                ]
                if disallowed_specs:
                    report = ValidationReport(
                        ok=True,
                        issues=[
                            ValidationIssue(
                                "warning",
                                f"single-target call was scoped to {', '.join(allowed_containers)} but produced a command for another allowed level9 target container",
                                spec.container,
                                spec.command,
                            )
                            for spec in disallowed_specs
                        ],
                        environment=self.validator.environment_summary_for_containers(allowed_containers),
                    )
                    attempts[-1]["validation"] = self._report_to_jsonable(report)
                    last_report = report
            if report.ok:
                self._write_attempt_log(high_level_action, attempts)
                return plan
            if self._can_soft_accept_recovery_validation(high_level_action, plan, report):
                attempts[-1]["validation"]["soft_accepted_recovery_verification"] = True
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

    @staticmethod
    def _is_recovery_like_action(high_level_action: HighLevelAction) -> bool:
        text = f"{high_level_action.action} {high_level_action.explanation}".lower()
        return any(
            token in text
            for token in (
                "recover",
                "recovery",
                "restore",
                "return",
                "production",
                "operational",
                "service",
            )
        )

    def _can_soft_accept_recovery_validation(
        self,
        high_level_action: HighLevelAction,
        plan: CommandPlan,
        report: ValidationReport,
    ) -> bool:
        """Allow final recovery plans when only service verification is brittle.

        The recovery loop still records the validator errors in the API-call log.
        This only bypasses validation failures that belong to verification
        commands for recovery/restore actions; recovery commands remain strict.
        """
        if not self._is_recovery_like_action(high_level_action):
            return False
        verification_commands = {spec.command for spec in plan.verification_commands}
        allowed_fragments = (
            "verification must not depend on unstable smbd/elasticsearch process names",
            "recovery verification must not require vulnerable service ports",
            "recovery verification must not depend on brittle HTTP page contents",
        )
        error_issues = [issue for issue in report.issues if issue.severity == "error"]
        if not error_issues:
            return False
        for issue in error_issues:
            if issue.command not in verification_commands:
                return False
            if not any(fragment in issue.message for fragment in allowed_fragments):
                return False
        return True

    def _build_prompt(
        self,
        *,
        high_level_action: HighLevelAction,
        state: RecoveryState,
        target: str,
        repair_feedback: str,
        allowed_containers: tuple[str, ...] | None,
    ) -> str:
        env = (
            self.validator.environment_summary_for_containers(allowed_containers)
            if allowed_containers
            else self.validator.environment_summary()
        )
        target_container = allowed_containers[0] if allowed_containers else ""
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
                    "command": "passwd -S ssh_backdoor_sambapwned | grep -q ' L '",
                    "allowed_exit_codes": [0],
                    "description": "verify Samba backdoor account is locked",
                }
            ],
        }
        good_examples = [
            {
                "name": "contain attacker source without disabling interfaces",
                "plan": {
                    "commands": [
                        {
                            "container": "csle_samba_2_1-level9-16",
                            "command": "iptables -I INPUT 1 -s 16.9.1.191 -j DROP",
                            "allowed_exit_codes": [0],
                            "description": "block attacker traffic to Samba host",
                        }
                    ],
                    "verification_commands": [
                        {
                            "container": "csle_samba_2_1-level9-16",
                            "command": "iptables -S INPUT | grep -F '16.9.1.191' | grep -q -- '-j DROP'",
                            "allowed_exit_codes": [0],
                            "description": "verify attacker source is blocked",
                        }
                    ],
                },
            },
            {
                "name": "preserve compact evidence safely",
                "plan": {
                    "commands": [
                        {
                            "container": "csle_sql_injection_1_1-level9-16",
                            "command": "mkdir -p /tmp/recovery_evidence; cp /etc/passwd /tmp/recovery_evidence/passwd 2>/dev/null || true; cp /etc/shadow /tmp/recovery_evidence/shadow 2>/dev/null || true; ps aux > /tmp/recovery_evidence/ps_aux.txt 2>/dev/null || true; ss -tulpn > /tmp/recovery_evidence/ss_tulpn.txt 2>/dev/null || true; iptables-save > /tmp/recovery_evidence/iptables_save.txt 2>/dev/null || true; find /tmp/recovery_evidence -type f ! -name sha256sums.txt -print0 | xargs -0 sha256sum > /tmp/recovery_evidence/sha256sums.txt",
                            "allowed_exit_codes": [0],
                            "description": "collect compact local evidence and hash it",
                        }
                    ],
                    "verification_commands": [
                        {
                            "container": "csle_sql_injection_1_1-level9-16",
                            "command": "test -s /tmp/recovery_evidence/sha256sums.txt && grep -Eq '^[0-9a-fA-F]{64}[[:space:]]+' /tmp/recovery_evidence/sha256sums.txt",
                            "allowed_exit_codes": [0],
                            "description": "verify evidence hash manifest exists",
                        }
                    ],
                },
            },
            {
                "name": "eradicate known backdoor account",
                "plan": {
                    "commands": [
                        {
                            "container": "csle_cve_2015_1427_1_1-level9-16",
                            "command": "pkill -KILL -u ssh_backdoor_cve_2015_1427_pwned 2>/dev/null || true; passwd -l ssh_backdoor_cve_2015_1427_pwned",
                            "allowed_exit_codes": [0],
                            "description": "kill sessions and lock Elasticsearch backdoor account",
                        }
                    ],
                    "verification_commands": [
                        {
                            "container": "csle_cve_2015_1427_1_1-level9-16",
                            "command": "passwd -S ssh_backdoor_cve_2015_1427_pwned | grep -q ' L '",
                            "allowed_exit_codes": [0],
                            "description": "verify Elasticsearch backdoor account is locked",
                        }
                    ],
                },
            },
            {
                "name": "harden SSH without brittle service-port checks",
                "plan": {
                    "commands": [
                        {
                            "container": "csle_ssh_1_1-level9-16",
                            "command": "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.recovery.bak 2>/dev/null || true; sed -i -E 's/^[#[:space:]]*PasswordAuthentication[[:space:]].*/# recovery disabled old PasswordAuthentication/' /etc/ssh/sshd_config; sed -i -E 's/^[#[:space:]]*PermitRootLogin[[:space:]].*/# recovery disabled old PermitRootLogin/' /etc/ssh/sshd_config; sed -i -e '$aPasswordAuthentication no' -e '$aPermitRootLogin no' /etc/ssh/sshd_config; service ssh restart",
                            "allowed_exit_codes": [0],
                            "description": "disable password authentication and root SSH login",
                        }
                    ],
                    "verification_commands": [
                        {
                            "container": "csle_ssh_1_1-level9-16",
                            "command": "grep -Eq '^[[:space:]]*PasswordAuthentication[[:space:]]+no([[:space:]]|$)' /etc/ssh/sshd_config && grep -Eq '^[[:space:]]*PermitRootLogin[[:space:]]+(no|prohibit-password)([[:space:]]|$)' /etc/ssh/sshd_config",
                            "allowed_exit_codes": [0],
                            "description": "verify SSH hardening directives",
                        }
                    ],
                },
            },
            {
                "name": "restrict exploited Elasticsearch port without requiring port 9200 to listen",
                "plan": {
                    "commands": [
                        {
                            "container": "csle_cve_2015_1427_1_1-level9-16",
                            "command": "iptables -I INPUT 1 -s 16.9.1.191 -p tcp --dport 9200 -j DROP",
                            "allowed_exit_codes": [0],
                            "description": "block attacker access to Elasticsearch service port",
                        }
                    ],
                    "verification_commands": [
                        {
                            "container": "csle_cve_2015_1427_1_1-level9-16",
                            "command": "iptables -S INPUT | grep -F '16.9.1.191' | grep -- '--dport 9200' | grep -q -- '-j DROP'",
                            "allowed_exit_codes": [0],
                            "description": "verify attacker is blocked from Elasticsearch port",
                        }
                    ],
                },
            },
            {
                "name": "final recovery verification without re-exposing vulnerable service ports",
                "plan": {
                    "commands": [
                        {
                            "container": "csle_sql_injection_1_1-level9-16",
                            "command": "service ssh restart 2>/dev/null || true",
                            "allowed_exit_codes": [0],
                            "description": "restart stable management service without changing public DVWA exposure",
                        }
                    ],
                    "verification_commands": [
                        {
                            "container": "csle_sql_injection_1_1-level9-16",
                            "command": "passwd -S pablo | grep -q ' L '",
                            "allowed_exit_codes": [0],
                            "description": "verify known DVWA backdoor account remains locked after recovery",
                        }
                    ],
                },
            },
        ]
        parts = [
            "You are a command-generation agent for CSLE level9 DT16 recovery.",
            "Generate concrete bash commands to run inside existing DT16 containers.",
            "Return JSON only. Do not include markdown.",
            "Do not include docker exec; the executor adds docker exec automatically.",
            "Use only the containers, services, users, and paths in the environment summary unless the incident summary strongly justifies otherwise.",
            "Prefer commands that are specific, reversible, and verifiable.",
            "For containment, prefer iptables rules over disabling network interfaces.",
            "If the high-level action mentions router, perimeter firewall, or IDS, implement the closest safe equivalent inside the allowed target containers using host-level iptables; do not use router or IDS containers.",
            "Never bring Docker container interfaces down with ip link set ... down; rollback baselines restore files and firewall state, not live link state.",
            "If you must inspect interfaces, note that `ip -o link show` may print names like eth0@if574; use `/sys/class/net` or strip the @suffix before passing names to `ip link`.",
            "If asked to patch/rebuild/restore, implement the closest safe container-level remediation available in this environment and include verification.",
            "Optional evidence files may not exist. Guard them with `[ -f path ] && ... || true` so missing files do not fail the recovery action.",
            "When hashing evidence, exclude the manifest itself: `find /tmp/recovery_evidence -type f ! -name sha256sums.txt -print0 | xargs -0 sha256sum > /tmp/recovery_evidence/sha256sums.txt`; never use `sha256sum *`.",
            "For evidence verification, do not run `sha256sum -c /tmp/recovery_evidence/sha256sums.txt`; instead verify the manifest exists and contains hash-looking lines: `test -s /tmp/recovery_evidence/sha256sums.txt && grep -Eq '^[0-9a-fA-F]{64}[[:space:]]+' /tmp/recovery_evidence/sha256sums.txt`.",
            "Do not verify write-protection with `test ! -w /tmp/recovery_evidence`; commands run as root, so writability checks are misleading. If permissions matter, use `stat -c %a` mode checks.",
            "Do not use broad `pkill -f ...`; it can match and terminate the active shell running the recovery command.",
            "If moving an optional directory such as a user's .ssh directory, verification must not require the quarantine copy to exist when the source did not exist.",
            "Do not use systemctl. Use `service ssh restart` for SSH hardening when needed; avoid service management for smbd/elasticsearch unless the command is explicitly guarded with `|| true` and not required by verification.",
            "Do not invent services that are not listed in Known level9 environment.services for that container. In particular, do not use `service telnetd ...` unless telnetd appears in the service list.",
            "Do not use HUP signals to reload sshd/smbd/elasticsearch. Prefer config/account/firewall changes with explicit verification.",
            "For SSH hardening, do not append directives with plain `echo ... >> /etc/ssh/sshd_config`; that can concatenate directives onto the previous line if the file lacks a trailing newline.",
            "Safe SSH hardening template: `cp /etc/ssh/sshd_config /etc/ssh/sshd_config.recovery.bak 2>/dev/null || true; sed -i -E 's/^[#[:space:]]*PasswordAuthentication[[:space:]].*/# recovery disabled old PasswordAuthentication/' /etc/ssh/sshd_config; sed -i -E 's/^[#[:space:]]*PermitRootLogin[[:space:]].*/# recovery disabled old PermitRootLogin/' /etc/ssh/sshd_config; sed -i -e '$aPasswordAuthentication no' -e '$aPermitRootLogin no' /etc/ssh/sshd_config; service ssh restart`.",
            "For SSH hardening verification, prefer whitespace-tolerant checks: `grep -Eq '^[[:space:]]*PasswordAuthentication[[:space:]]+no([[:space:]]|$)' /etc/ssh/sshd_config` and `grep -Eq '^[[:space:]]*PermitRootLogin[[:space:]]+(no|prohibit-password)([[:space:]]|$)' /etc/ssh/sshd_config`.",
            "For locked-account verification, prefer `passwd -S USER | grep -q ' L '` instead of parsing /etc/shadow with a single `^!` pattern.",
            "For SSH hardening verification, accept equivalent safe outcomes such as `PermitRootLogin no` or `PermitRootLogin prohibit-password`.",
            "For firewall verification, use `iptables -S | grep ...` outcome checks; do not require exact rule identity with `iptables -C`.",
            "For iptables verification, do not grep one exact full rule string. iptables may print IPs as /32 and may insert modules such as `-m tcp`; verify components with multiple greps instead.",
            "For iptables verification, never assume printed field order such as `DROP.*16.9.1.191` or `ACCEPT.*127.0.0.0/8`; iptables usually prints match components first and target last.",
            "For iptables verification, do not grep textual negation such as `! -s 16.9.253.0/24` or `! -d 16.9.253.0/24`; verify the positive allow/drop rules that matter instead.",
            "When a grep pattern starts with a dash, especially `--dport`, write `grep -- '--dport 22'` or `grep -E -- '--dport 22|dport 22'`; never write `grep -E '--dport 22|dport 22'`.",
            "For iptables policy verification, never grep only `-P DROP`; include the chain name such as `-P OUTPUT DROP`, or prefer narrower source/port DROP checks.",
            "For iptables policy verification, do not include a leading space before `-P`; `iptables -S` prints policy lines starting with `-P INPUT DROP`. Use `iptables -S | grep -q -- '-P INPUT DROP'`.",
            "Avoid setting broad default policies such as `iptables -P OUTPUT DROP` during hardening/recovery actions because it can break normal service and management traffic; prefer specific attacker/source/port DROP rules. Broad default DROP is only appropriate for explicit isolation/quarantine actions.",
            "Do not make iptables `recent --set` or `recent --update` text a required verification outcome. The recent module may print as `-m recent --name NAME --set`; verify broad containment such as attacker source DROP or dport DROP instead.",
            "Do not verify firewall hardening by requiring exact payload-specific string-match rules such as SQL keywords; verify broad DROP/allow-list outcomes for the relevant port instead.",
            "Do not verify Samba hardening with one exact string like `grep -q 'server min protocol.*SMB2' /etc/samba/smb.conf`. If Samba config is used, guard the file with `test -f` and use a whitespace-tolerant expression that accepts equivalent `server min protocol = SMB2` or `min protocol = SMB2` forms; otherwise verify firewall/account cleanup.",
            "In this experiment, recovered means the host is stable and manageable after cleanup without re-exposing vulnerable public attack paths. Do not require SMB 445, DVWA HTTP 80, or Elasticsearch 9200 to be publicly listening after containment/hardening unless the high-level action explicitly says to restore that business service.",
            "If a high-level action says recover/restore services, verify stable management and security outcomes first. Do not use brittle checks such as `curl http://localhost/ | grep dvwa`; page titles/content differ across images and may be intentionally hidden after containment.",
            "For Elasticsearch hardening in csle_cve_2015_1427_1_1-level9-16, do not assume `/etc/elasticsearch/elasticsearch.yml` exists. First set a config variable using `test -f /elasticsearch/config/elasticsearch.yml` or `test -f /etc/elasticsearch/elasticsearch.yml`; skip or choose firewall/account hardening if no config file exists.",
            "Do not delete or require absence of `/root/.ssh/authorized_keys` unless root-key persistence is explicitly observed in the incident evidence.",
            "Keep verification commands short and aligned with the recovery command. Avoid adding unrelated checks that the command did not implement.",
            "Do not require a backdoor user's entire `.ssh` directory to be absent. It is enough to lock the account and, if you explicitly cleaned SSH keys, verify `authorized_keys` is absent or empty.",
            "Do not require `ChallengeResponseAuthentication no` or `PubkeyAuthentication yes` in verification. They are brittle across level9 containers; verify `PasswordAuthentication no`, `PermitRootLogin`, account locks, and firewall outcomes instead.",
            "",
            "Required JSON schema:",
            json.dumps(schema, indent=2),
            "",
            "Good command-plan examples to imitate:",
            json.dumps(good_examples, indent=2),
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
            "Container scope:",
            (
                f"Generate commands only for container `{target_container}`. "
                "Do not include commands for any other container."
                if target_container
                else "Generate commands only for containers listed in Known level9 environment.allowed_containers."
            ),
            "",
            "Hard command-generation constraints:",
            "- Use only containers listed in Known level9 environment.allowed_containers.",
            "- Do not use csle_router_* or csle_hacker_* containers.",
            "- If the action says router/perimeter/IDS blocking, translate it to host-level iptables rules inside the allowed target containers.",
            "- Keep output compact: at most 2 recovery commands and at most 2 verification commands.",
            "- For forensic preservation, create compact evidence under /tmp/recovery_evidence, e.g. copy selected auth/service logs, iptables-save, ps output, ss output, and account snapshots.",
            "- Do not create full disk images, memory dumps, /proc/kcore dumps, or tar the full root filesystem.",
            "- Do not disable network interfaces; use reversible iptables rules for containment.",
            "- Optional file reads must be non-fatal; append `|| true` to optional `cat`/`cp` operations.",
            "- Hash only regular files; do not hash directories.",
            "- Exclude `/tmp/recovery_evidence/sha256sums.txt` from its own hash manifest.",
            "- Do not verify evidence with `sha256sum -c /tmp/recovery_evidence/sha256sums.txt`; verify that sha256sums.txt exists and contains hash-looking lines.",
            "- Do not use `test ! -w` for evidence read-only verification under root.",
            "- Do not use `pkill -f`; use `pkill -KILL -u <known_backdoor_user>` for attacker accounts, or `service <service> stop/restart` for services.",
            "- Do not invent services such as telnetd. Use only the services listed for that container in Known level9 environment.",
            "- Verification should check the security outcome, not optional side effects. For example, verify a backdoor account is locked and, only if cleaned, its authorized_keys file is absent or empty; do not require a user's entire .ssh directory or a quarantine directory to exist.",
            "- Do not use `systemctl`; these containers are not systemd hosts.",
            "- Do not verify smbd/elasticsearch with `pgrep`; use account locks, config file changes, firewall rules, or listening-port checks instead.",
            "- For SSH hardening commands, use whitespace-tolerant `sed -i -E` patterns and append final directives with `sed -i -e '$aPasswordAuthentication no' -e '$aPermitRootLogin no' /etc/ssh/sshd_config`; never use plain `echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config`, never use `printf '%s\\\\012'`, never use awk with escaped quotes, and never put literal newline characters inside the JSON command string.",
            "- Verify locked users with `passwd -S <user> | grep -q ' L '`, not only `getent shadow ... | grep '^!'`.",
            "- Verify SSH hardening with whitespace-tolerant checks: `grep -Eq '^[[:space:]]*PasswordAuthentication[[:space:]]+no([[:space:]]|$)' /etc/ssh/sshd_config` and `grep -Eq '^[[:space:]]*PermitRootLogin[[:space:]]+(no|prohibit-password)([[:space:]]|$)' /etc/ssh/sshd_config`.",
            "- Do not verify `ChallengeResponseAuthentication no` or `PubkeyAuthentication yes`; use `PasswordAuthentication no`, `PermitRootLogin`, account locks, and firewall outcomes instead.",
            "- Verify firewall outcomes with broad `iptables -S | grep -- '--dport PORT' | grep DROP` style checks, not exact `iptables -C` checks.",
            "- Do not verify iptables with one exact full-rule grep such as `grep -q '-A INPUT -s IP -p tcp --dport PORT -j DROP'`; use multiple component greps so `/32` normalization and inserted `-m tcp` do not break verification.",
            "- Do not verify iptables with order-assuming regex such as `DROP.*16.9.1.191` or `ACCEPT.*127.0.0.0/8`; use component greps like `iptables -S INPUT | grep -F '16.9.1.191' | grep -q -- '-j DROP'`.",
            "- Do not verify iptables negation text such as `! -s 16.9.253.0/24` or `! -d 16.9.253.0/24`; verify the allow/drop outcomes with positive component checks.",
            "- If grepping for `--dport`, use `grep -- '--dport PORT'` or `grep -E -- '--dport PORT|dport PORT'`; do not use `grep -E '--dport ...'`.",
            "- Do not verify iptables policies with `grep -q -- '-P DROP'`; include the chain name, e.g. `grep -q -- '-P OUTPUT DROP'`, or use narrower source/port checks.",
            "- Do not verify iptables policies with a leading-space pattern such as `grep -E -- ' -P INPUT DROP'`; `iptables -S` starts the line with `-P`, so use `grep -q -- '-P INPUT DROP'`.",
            "- Avoid `iptables -P OUTPUT DROP` in hardening/recovery actions unless the action is explicitly isolation/quarantine; prefer precise DROP rules for the attacker IP or exploited service port.",
            "- Do not use `recent --set` or `recent --update` as required verification text. If SSH rate limiting is added, verify the simpler security outcome, such as attacker/source DROP or SSH dport DROP.",
            "- Do not verify firewall outcomes by requiring exact SQL/CVE payload string matching rules; broad port/source DROP or allow-list checks are preferred.",
            "- Do not verify Samba protocol hardening with exact `server min protocol.*SMB2` text. Prefer account/firewall verification, or use guarded whitespace-tolerant smb.conf checks that accept equivalent min-protocol forms.",
            "- Do not verify recovered state by requiring vulnerable ports 80, 445, or 9200 to be listening after the plan has contained or hardened them. Verify management SSH, account cleanup, config hardening, and scoped firewall state instead.",
            "- Do not combine a vulnerable service-port listening check such as `ss ... | grep ':9200'` with firewall DROP checks in the same verification command; prefer the firewall/scoped exposure check.",
            "- Do not verify recovered state with brittle web-content checks like `curl http://localhost/ | grep dvwa`; use explicit security and manageability checks instead.",
            "- Elasticsearch config path in `csle_cve_2015_1427_1_1-level9-16` is usually `/elasticsearch/config/elasticsearch.yml`; always guard config edits/verifications with `test -f` discovery and do not fail if only the package-style `/etc/elasticsearch/elasticsearch.yml` path is missing.",
            "- Do not remove or verify absence of `/root/.ssh/authorized_keys`; only clean known level9 backdoor users listed in the environment summary.",
            "- Do not verify `test ! -d /home/USER/.ssh`; prefer account lock checks and optional authorized_keys absence/empty checks.",
            "- Prefer atomic verification commands; do not chain many unrelated outcomes into one brittle check. Each verification command should check one outcome, or at most two tightly related conditions.",
            "",
            "System information:",
            self.context.get("System", ""),
            "",
            "Incident:",
            self.context.get("Incident", ""),
            "",
            "Relevant logs:",
            "Raw IDS alerts are intentionally omitted for command generation because they were already summarized into the incident. Generate commands from the current recovery state, high-level action, incident summary, and known level9 target mapping.",
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
        response = self._post_with_retry(payload, headers=headers)
        if response.status_code < 400:
            return response
        text = response.text.lower()
        for parameter in ("top_p", "temperature", "response_format"):
            if parameter in payload and "unsupported" in text and parameter in text:
                payload = dict(payload)
                payload.pop(parameter, None)
                response = self._post_with_retry(payload, headers=headers)
                if response.status_code < 400:
                    return response
                text = response.text.lower()
        return response

    def _post_with_retry(self, payload: dict[str, Any], *, headers: dict[str, str]) -> requests.Response:
        last_exc: requests.RequestException | None = None
        for attempt in range(1, 4):
            try:
                return requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=self.timeout_seconds,
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt == 3:
                    raise
                time.sleep(attempt)
        raise RuntimeError(f"command agent API request failed: {last_exc}")

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
