#!/usr/bin/env python3
"""Run a CSLE level9 DT16 recovery loop with LLM-predicted recovery states.

This is the level9-specific counterpart of
``llm_ir_dt_new/run_recovery_loop_llm_state.py``. It keeps the old rollout
algorithm but replaces the old 10.0.x Docker DT baseline/executor with CSLE
level9 execution-16 rollback baselines and ``docker exec``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
OLD_DT_ROOT = REPO_ROOT / "llm_ir_dt_new"
OLD_DT_SRC = OLD_DT_ROOT / "src"
for path in (OLD_DT_ROOT, OLD_DT_SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from llm_ir_dt.recovery_loop.action_provider import LocalModelActionProvider
from llm_ir_dt.recovery_loop.high_level_actions import deduplicate_actions
from llm_ir_dt.recovery_loop.plan_store import PlanStore
from llm_ir_dt.recovery_loop.schemas import (
    ActionExecutionResult,
    CandidateEvaluation,
    CommandPlan,
    CommandResult,
    CommandSpec,
    HighLevelAction,
    RECOVERY_STATE_FIELDS,
    RecoveryState,
    dataclass_to_jsonable,
    has_regression,
    initial_recovery_state,
    is_terminal_state,
    state_progress,
)
from level9_command_agent_api import APILevel9CommandAgent, Level9CommandValidator


LEVEL9_TARGETS = {
    "samba": {
        "ips": "16.9.2.3 / 16.9.4.3",
        "containers": ["csle_samba_2_1-level9-16"],
        "backdoor_users": ["ssh_backdoor_sambapwned"],
        "services": ["ssh", "smbd"],
        "attack_blocks": [
            {"source": "16.9.1.0/24", "port": 445, "protocol": "tcp"},
        ],
    },
    "ssh": {
        "ips": "16.9.2.78",
        "containers": ["csle_ssh_1_1-level9-16"],
        "backdoor_users": ["puppet"],
        "services": ["ssh"],
        "attack_blocks": [
            {"source": "16.9.1.191", "port": 22, "protocol": "tcp"},
        ],
    },
    "dvwa": {
        "ips": "16.9.4.74 / 16.9.5.74",
        "containers": ["csle_sql_injection_1_1-level9-16"],
        "backdoor_users": ["pablo"],
        "services": ["ssh", "apache2"],
        "attack_blocks": [
            {"source": "16.9.4.3", "port": 80, "protocol": "tcp"},
        ],
    },
    "elasticsearch": {
        "ips": "16.9.5.62 / 16.9.6.62 / 16.9.7.62",
        "containers": ["csle_cve_2015_1427_1_1-level9-16"],
        "backdoor_users": ["ssh_backdoor_cve_2015_1427_pwned"],
        "services": ["ssh", "elasticsearch"],
        "attack_blocks": [
            {"source": "16.9.5.74", "port": 9200, "protocol": "tcp"},
        ],
    },
}


DEFAULT_ATTACK_AFTER_BASELINE = (
    REPO_ROOT
    / "experiments/csle_level9_dt/artifacts/recovery_baselines/"
    "level9_16_experienced_attack_after_20260722"
)


IGNORED_BASELINE_AUDIT_PATHS = (
    "/etc",
    "/etc/ssh",
    "/etc/hostname",
    "/etc/hosts",
    "/etc/mtab",
    "/etc/resolv.conf",
    "/etc/passwd-",
    "/etc/shadow-",
    "/etc/group-",
    "/etc/gshadow-",
    "/etc/filebeat",
    "/etc/heartbeat",
    "/etc/metricbeat",
    "/etc/packetbeat",
    "/root",
    "/root/miniconda3",
)


def is_ignored_baseline_audit_path(path: str) -> bool:
    normalized = path.rstrip("/")
    for prefix in IGNORED_BASELINE_AUDIT_PATHS:
        prefix_norm = prefix.rstrip("/")
        if normalized == prefix_norm or normalized.startswith(prefix_norm + "/"):
            return True
    return False


def read_text_arg(inline_value: str | None, file_value: str | None, default_value: str) -> str:
    if file_value:
        return Path(file_value).expanduser().read_text(encoding="utf-8").strip()
    if inline_value:
        return inline_value.strip()
    return default_value


def run_cmd(cmd: list[str], *, cwd: Path | None = None, timeout: int = 600) -> dict[str, Any]:
    started = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
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
        "elapsed_seconds": round(time.perf_counter() - started, 3),
    }


class FixedLevel9ActionProvider:
    """Deterministic smoke-test action provider for level9 recovery."""

    def candidates(
        self,
        state: RecoveryState,
        history: list[HighLevelAction],
        limit: int,
    ) -> list[HighLevelAction]:
        del history
        if not state.get("is_attack_contained", False):
            actions = [
                HighLevelAction("Contain the attacker and known pivot access paths in CSLE level9."),
                HighLevelAction("Preserve forensic evidence from compromised level9 hosts."),
                HighLevelAction("Disable known backdoor accounts on compromised level9 hosts."),
            ]
        elif not state.get("is_knowledge_sufficient", False):
            actions = [
                HighLevelAction("Collect host, auth, service, and web evidence from compromised level9 hosts."),
                HighLevelAction("Preserve forensic evidence from compromised level9 hosts."),
                HighLevelAction("Disable known backdoor accounts on compromised level9 hosts."),
            ]
        elif not state.get("are_forensics_preserved", False):
            actions = [
                HighLevelAction("Preserve forensic evidence from compromised level9 hosts."),
                HighLevelAction("Disable known backdoor accounts on compromised level9 hosts."),
                HighLevelAction("Restart affected services after preserving evidence."),
            ]
        elif not state.get("is_eradicated", False):
            actions = [
                HighLevelAction("Disable known backdoor accounts on compromised level9 hosts."),
                HighLevelAction("Kill active sessions owned by known backdoor accounts."),
                HighLevelAction("Restart affected services after eradicating attacker access."),
            ]
        elif not state.get("is_hardened", False):
            actions = [
                HighLevelAction("Harden SSH and vulnerable services on compromised level9 hosts."),
                HighLevelAction("Block recurrence of the observed attack paths in level9."),
                HighLevelAction("Restart affected services after hardening."),
            ]
        else:
            actions = [
                HighLevelAction("Restart affected services and verify level9 service recovery."),
                HighLevelAction("Verify that known backdoor accounts can no longer log in."),
                HighLevelAction("Collect final post-recovery evidence from compromised level9 hosts."),
            ]
        return deduplicate_actions(actions)[:limit]


class Level9RecoveryExecutor:
    """Execute recovery command plans inside CSLE level9 DT16 containers."""

    def execute_plan(
        self,
        plan: CommandPlan,
        *,
        state_before: RecoveryState | None = None,
        state_after: RecoveryState | None = None,
    ) -> ActionExecutionResult:
        command_results = tuple(self._run_command(spec, "recovery") for spec in plan.commands)
        verification_results = tuple(
            self._run_command(spec, "verification") for spec in plan.verification_commands
        )
        action_time = sum(item.elapsed_seconds for item in command_results)
        verification_time = sum(item.elapsed_seconds for item in verification_results)
        all_results = command_results + verification_results
        success = all(item.success for item in all_results)
        return ActionExecutionResult(
            high_level_action=plan.high_level_action,
            high_level_action_explanation=plan.high_level_action_explanation,
            success=success,
            action_execution_time_seconds=action_time,
            action_verification_time_seconds=verification_time,
            action_total_time_seconds=action_time + verification_time,
            command_results=command_results,
            verification_results=verification_results,
            state_before=state_before,
            state_after=state_after,
        )

    def _run_command(self, spec: CommandSpec, phase: str) -> CommandResult:
        started = time.perf_counter()
        result = run_cmd(
            ["docker", "exec", spec.container, "bash", "-lc", spec.command],
            cwd=REPO_ROOT,
            timeout=120,
        )
        return CommandResult(
            container=spec.container,
            command=spec.command,
            exit_code=int(result["returncode"]),
            output=(result["stdout"] + result["stderr"]).strip(),
            elapsed_seconds=time.perf_counter() - started,
            phase=phase,
            allowed_exit_codes=spec.allowed_exit_codes,
        )


class Level9BaselineManager:
    """Restore the level9 attack-after baseline and replay selected plans."""

    def __init__(self, *, baseline_dir: Path, executor: Level9RecoveryExecutor) -> None:
        self.baseline_dir = baseline_dir
        self.executor = executor

    def _container_names(self) -> list[str]:
        manifest = json.loads((self.baseline_dir / "manifest.json").read_text(encoding="utf-8"))
        return [item["container"] for item in manifest.get("containers", [])]

    def _tmp_evidence_state(self) -> list[dict[str, Any]]:
        results = []
        for container in self._container_names():
            result = run_cmd(
                [
                    "docker",
                    "exec",
                    container,
                    "bash",
                    "-lc",
                    (
                        "if [ -e /tmp/recovery_evidence ]; then "
                        "find /tmp/recovery_evidence -maxdepth 4 "
                        "\\( -type f -o -type d -o -type l \\) "
                        "-printf '%y\\t%p\\t%s\\n' 2>/dev/null | sort | head -200; "
                        "else exit 0; fi"
                    ),
                ],
                cwd=REPO_ROOT,
                timeout=120,
            )
            entries = [line for line in result["stdout"].splitlines() if line.strip()]
            results.append(
                {
                    "container": container,
                    "returncode": result["returncode"],
                    "exists": bool(entries),
                    "entry_count_limited": len(entries),
                    "entries_limited": entries,
                    "stderr": result["stderr"],
                }
            )
        return results

    def _service_state(self) -> list[dict[str, Any]]:
        results = []
        for container in self._container_names():
            result = run_cmd(
                [
                    "docker",
                    "exec",
                    container,
                    "bash",
                    "-lc",
                    "service --status-all 2>/dev/null || true; ss -lntup 2>/dev/null || true",
                ],
                cwd=REPO_ROOT,
                timeout=120,
            )
            results.append(
                {
                    "container": container,
                    "returncode": result["returncode"],
                    "stdout": result["stdout"],
                    "stderr": result["stderr"],
                }
            )
        return results

    def _audit_against_baseline(self) -> dict[str, Any]:
        audit_script = REPO_ROOT / "experiments/csle_level9_dt/recovery_rollback/audit_container_diff.py"
        result = run_cmd(
            [sys.executable, str(audit_script), "--baseline-dir", str(self.baseline_dir)],
            cwd=REPO_ROOT,
            timeout=2400,
        )
        try:
            raw_payload = json.loads(result["stdout"])
        except json.JSONDecodeError:
            payload = {
                "parse_error": True,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
            }
        else:
            container_summaries = []
            has_unignored_outside_changes = False
            for item in raw_payload.get("results", []):
                outside = item.get("outside_snapshot_scope", [])
                unignored_outside = [
                    path for path in outside if not is_ignored_baseline_audit_path(path)
                ]
                has_unignored_outside_changes = has_unignored_outside_changes or bool(unignored_outside)
                container_summaries.append(
                    {
                        "container": item.get("container"),
                        "created_count": len(item.get("created", [])),
                        "deleted_count": len(item.get("deleted", [])),
                        "metadata_changed_count": len(item.get("metadata_changed", [])),
                        "content_changed_count": len(item.get("content_changed", [])),
                        "outside_snapshot_scope_count": len(outside),
                        "outside_snapshot_scope_limited": outside[:50],
                        "unignored_outside_snapshot_scope_count": len(unignored_outside),
                        "unignored_outside_snapshot_scope_limited": unignored_outside[:50],
                        "docker_diff_returncode": item.get("docker_diff", {}).get("returncode"),
                    }
                )
            payload = {
                "baseline_dir": raw_payload.get("baseline_dir"),
                "has_outside_snapshot_scope_changes": raw_payload.get(
                    "has_outside_snapshot_scope_changes", True
                ),
                "has_unignored_outside_snapshot_scope_changes": has_unignored_outside_changes,
                "containers": container_summaries,
            }
        return {
            "command": result["cmd"],
            "returncode": result["returncode"],
            "elapsed_seconds": result["elapsed_seconds"],
            "payload": payload,
        }

    def _security_state_diff(self) -> dict[str, Any]:
        diff_script = REPO_ROOT / "experiments/csle_level9_dt/recovery_rollback/state_diff_from_baseline.py"
        result = run_cmd(
            [
                sys.executable,
                str(diff_script),
                "--baseline-dir",
                str(self.baseline_dir),
                "--output",
                "/tmp/csle_level9_candidate_start_state_diff.json",
            ],
            cwd=REPO_ROOT,
            timeout=2400,
        )
        output_path = Path("/tmp/csle_level9_candidate_start_state_diff.json")
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {
                "parse_error": True,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
            }
        return {
            "command": result["cmd"],
            "returncode": result["returncode"],
            "elapsed_seconds": result["elapsed_seconds"],
            "payload": payload,
        }

    def _security_state_is_clean(self, security_diff: dict[str, Any]) -> bool:
        if security_diff["returncode"] != 0:
            return False
        payload = security_diff["payload"]
        if payload.get("parse_error"):
            return False
        for item in payload.get("results", []):
            users = item.get("users", {})
            keys = item.get("ssh_authorized_keys", {})
            sudoers = item.get("sudoers", {})
            files = item.get("security_relevant_files", {})
            sudo_changed = [
                change
                for change in sudoers.get("changed_paths", [])
                if change.get("path") != "/etc/sudoers.d/README"
            ]
            if any(
                [
                    users.get("added"),
                    users.get("deleted"),
                    users.get("changed"),
                    keys.get("added_paths"),
                    keys.get("deleted_paths"),
                    keys.get("changed_paths"),
                    sudoers.get("added_paths"),
                    sudoers.get("deleted_paths"),
                    sudo_changed,
                    files.get("created"),
                    files.get("deleted"),
                    files.get("content_changed"),
                ]
            ):
                return False
        return True

    def _validate_pure_baseline(self, restore_payload: dict[str, Any] | None) -> dict[str, Any]:
        tmp_state = self._tmp_evidence_state()
        audit = self._audit_against_baseline()
        security_diff = self._security_state_diff()
        tmp_clean = all(not item["exists"] and item["returncode"] == 0 for item in tmp_state)
        audit_clean = (
            audit["returncode"] == 0
            and not audit["payload"].get("has_unignored_outside_snapshot_scope_changes", True)
        )
        security_clean = self._security_state_is_clean(security_diff)
        cleanup_results = []
        if restore_payload:
            for item in restore_payload.get("results", []):
                cleanup = item.get("cleanup_recovery_evidence", {})
                cleanup_results.append(
                    {
                        "container": item.get("container"),
                        "returncode": cleanup.get("returncode"),
                        "elapsed_seconds": cleanup.get("elapsed_seconds"),
                    }
                )
        cleanup_ok = all(item.get("returncode") == 0 for item in cleanup_results) if cleanup_results else True
        return {
            "stage": "after_restore_before_replay",
            "is_valid": tmp_clean and audit_clean and cleanup_ok and security_clean,
            "tmp_recovery_evidence_clean": tmp_clean,
            "audit_clean": audit_clean,
            "security_state_clean": security_clean,
            "cleanup_recovery_evidence_ok": cleanup_ok,
            "cleanup_recovery_evidence": cleanup_results,
            "tmp_recovery_evidence": tmp_state,
            "audit": audit,
            "security_state_diff": security_diff,
        }

    def _validate_candidate_start(self, history_plans: list[CommandPlan]) -> dict[str, Any]:
        return {
            "stage": "after_restore_and_history_replay",
            "history_plan_count": len(history_plans),
            "tmp_recovery_evidence": self._tmp_evidence_state(),
            "service_state": self._service_state(),
        }

    def restore(self, history_plans: list[CommandPlan]) -> tuple[RecoveryState, float, dict[str, Any]]:
        started = time.perf_counter()
        restore_script = REPO_ROOT / "experiments/csle_level9_dt/recovery_rollback/restore_step_baseline.py"
        result = run_cmd(
            [
                sys.executable,
                str(restore_script),
                "--baseline-dir",
                str(self.baseline_dir),
            ],
            cwd=REPO_ROOT,
            timeout=1800,
        )
        try:
            restore_payload = json.loads(result["stdout"])
        except json.JSONDecodeError:
            restore_payload = None
        if result["returncode"] != 0:
            raise RuntimeError(
                "level9 baseline restore failed\n"
                f"stdout:\n{result['stdout']}\nstderr:\n{result['stderr']}"
            )
        pure_baseline_validation = self._validate_pure_baseline(restore_payload)
        if not pure_baseline_validation["is_valid"]:
            raise RuntimeError(
                "level9 baseline validation failed after restore; candidate comparison would be unfair"
            )
        for plan in history_plans:
            replay = self.executor.execute_plan(plan)
            if not replay.success:
                raise RuntimeError(f"replay selected recovery plan failed: {plan.high_level_action}")
        validation = {
            "restore": {
                "command": result["cmd"],
                "returncode": result["returncode"],
                "elapsed_seconds": result["elapsed_seconds"],
                "stderr": result["stderr"],
                "payload": restore_payload,
            },
            "pure_baseline_validation": pure_baseline_validation,
            "candidate_start_validation": self._validate_candidate_start(history_plans),
        }
        return initial_recovery_state(), time.perf_counter() - started, validation


class Level9MockCommandAgent:
    """Map high-level level9 recovery actions to conservative docker exec plans."""

    def generate_plan(
        self,
        *,
        high_level_action: HighLevelAction,
        state: RecoveryState,
        target: str,
    ) -> CommandPlan:
        del state
        action = high_level_action.action.lower()
        if "preserve" in action or "forensic" in action or "collect" in action or "evidence" in action:
            return self._preserve(high_level_action, target)
        if "disable" in action or "backdoor" in action or "eradicate" in action or "kill" in action:
            return self._eradicate(high_level_action, target)
        if "harden" in action or "recurrence" in action:
            return self._harden(high_level_action, target)
        if "restart" in action or "recover" in action or "verify" in action:
            return self._recover(high_level_action, target)
        if "contain" in action or "block" in action:
            return self._contain(high_level_action, target)
        return self._preserve(high_level_action, target)

    def _target_items(self, target: str) -> list[tuple[str, dict[str, Any]]]:
        if target == "all":
            return list(LEVEL9_TARGETS.items())
        return [(target, LEVEL9_TARGETS[target])]

    def _block_observed_attack_paths(
        self,
        target: str,
    ) -> tuple[list[CommandSpec], list[CommandSpec]]:
        commands: list[CommandSpec] = []
        checks: list[CommandSpec] = []
        for _name, info in self._target_items(target):
            for container in info["containers"]:
                for rule in info.get("attack_blocks", []):
                    proto = rule.get("protocol", "tcp")
                    source = rule["source"]
                    port = int(rule["port"])
                    rule_args = f"-p {proto} -s {source} --dport {port} -j DROP"
                    commands.append(
                        CommandSpec(
                            container,
                            f"iptables -C INPUT {rule_args} 2>/dev/null || "
                            f"iptables -I INPUT {rule_args}",
                            description=f"Block observed level9 attack path {source} -> tcp/{port}.",
                        )
                    )
                    checks.append(
                        CommandSpec(
                            container,
                            f"iptables -S INPUT | grep -F -- '-s {source}' | "
                            f"grep -F -- '--dport {port}' | grep -F -- '-j DROP'",
                            description=f"Verify block for {source} -> tcp/{port}.",
                        )
                    )
        return commands, checks

    def _lock_backdoor_users(
        self,
        target: str,
    ) -> tuple[list[CommandSpec], list[CommandSpec]]:
        commands: list[CommandSpec] = []
        checks: list[CommandSpec] = []
        for _name, info in self._target_items(target):
            for container in info["containers"]:
                for user in info["backdoor_users"]:
                    commands.extend(
                        [
                            CommandSpec(
                                container,
                                f"pkill -KILL -u {user} 2>/dev/null || true",
                                (0, 1),
                                description=f"Terminate active sessions for {user}.",
                            ),
                            CommandSpec(
                                container,
                                f"passwd -l {user} 2>/dev/null || true",
                                (0, 1),
                                description=f"Lock password login for {user}.",
                            ),
                        ]
                    )
                    checks.append(
                        CommandSpec(
                            container,
                            f"getent shadow {user} | cut -d: -f2 | grep -q '^!'",
                            (0, 1),
                            description=f"Verify {user} is locked when the account exists.",
                        )
                    )
        return commands, checks

    def _preserve(self, action: HighLevelAction, target: str) -> CommandPlan:
        commands = []
        checks = []
        for name, info in self._target_items(target):
            for container in info["containers"]:
                base = f"/tmp/recovery_evidence/{name}"
                commands.extend(
                    [
                        CommandSpec(container, f"mkdir -p {base}"),
                        CommandSpec(container, f"cp /etc/passwd {base}/passwd.txt 2>/dev/null || true"),
                        CommandSpec(container, f"cp /etc/shadow {base}/shadow.txt 2>/dev/null || true"),
                        CommandSpec(container, f"ps auxww > {base}/processes.txt 2>/dev/null || true"),
                        CommandSpec(container, f"ss -lntup > {base}/listening_ports.txt 2>/dev/null || true"),
                    ]
                )
                checks.append(CommandSpec(container, f"test -s {base}/passwd.txt"))
        return CommandPlan(
            high_level_action=action.action,
            high_level_action_explanation=action.explanation,
            commands=tuple(commands),
            verification_commands=tuple(checks),
        )

    def _eradicate(self, action: HighLevelAction, target: str) -> CommandPlan:
        commands, checks = self._lock_backdoor_users(target)
        block_commands, block_checks = self._block_observed_attack_paths(target)
        commands.extend(block_commands)
        checks.extend(block_checks)
        return CommandPlan(
            high_level_action=action.action,
            high_level_action_explanation=action.explanation,
            commands=tuple(commands),
            verification_commands=tuple(checks),
        )

    def _harden(self, action: HighLevelAction, target: str) -> CommandPlan:
        commands = []
        checks = []
        for _name, info in self._target_items(target):
            for container in info["containers"]:
                commands.extend(
                    [
                        CommandSpec(container, "mkdir -p /etc/ssh/sshd_config.d"),
                        CommandSpec(
                            container,
                            "printf '%s\\n' 'PermitRootLogin no' 'PasswordAuthentication no' "
                            "> /etc/ssh/sshd_config.d/99-csle-recovery.conf",
                        ),
                    ]
                )
                checks.append(CommandSpec(container, "/usr/sbin/sshd -t 2>/dev/null || sshd -t 2>/dev/null"))
                for service in info["services"]:
                    commands.append(CommandSpec(container, f"service {service} restart 2>/dev/null || true"))
        block_commands, block_checks = self._block_observed_attack_paths(target)
        commands.extend(block_commands)
        checks.extend(block_checks)
        return CommandPlan(
            high_level_action=action.action,
            high_level_action_explanation=action.explanation,
            commands=tuple(commands),
            verification_commands=tuple(checks),
        )

    def _recover(self, action: HighLevelAction, target: str) -> CommandPlan:
        commands = []
        checks = []
        for _name, info in self._target_items(target):
            for container in info["containers"]:
                for service in info["services"]:
                    commands.append(CommandSpec(container, f"service {service} restart 2>/dev/null || true"))
                checks.append(CommandSpec(container, "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true"))
        return CommandPlan(
            high_level_action=action.action,
            high_level_action_explanation=action.explanation,
            commands=tuple(commands),
            verification_commands=tuple(checks),
        )

    def _contain(self, action: HighLevelAction, target: str) -> CommandPlan:
        commands, checks = self._lock_backdoor_users(target)
        block_commands, block_checks = self._block_observed_attack_paths(target)
        commands.extend(block_commands)
        checks.extend(block_checks)
        return CommandPlan(
            high_level_action=action.action,
            high_level_action_explanation=action.explanation,
            commands=tuple(commands),
            verification_commands=tuple(checks),
        )


class Level9RecoveryLoop:
    def __init__(
        self,
        *,
        context: dict[str, str],
        target: str,
        action_provider: Any,
        command_agent: Level9MockCommandAgent,
        state_predictor: Any,
        executor: Level9RecoveryExecutor,
        baseline_manager: Level9BaselineManager,
        plan_store: PlanStore,
        num_candidates: int,
        num_rollouts: int,
        max_plan_steps: int,
        max_rollout_depth: int,
    ) -> None:
        self.context = context
        self.target = target
        self.action_provider = action_provider
        self.command_agent = command_agent
        self.state_predictor = state_predictor
        self.executor = executor
        self.baseline_manager = baseline_manager
        self.plan_store = plan_store
        self.num_candidates = num_candidates
        self.num_rollouts = num_rollouts
        self.max_plan_steps = max_plan_steps
        self.max_rollout_depth = max_rollout_depth
        self.selected_plans: list[CommandPlan] = []
        self.history_actions: list[HighLevelAction] = []

    def run(self) -> list[CandidateEvaluation]:
        self.plan_store.write_context(self.context)
        selected = []
        state = initial_recovery_state()
        for step in range(1, self.max_plan_steps + 1):
            if is_terminal_state(state):
                break
            candidates = self.action_provider.candidates(state, self.history_actions, self.num_candidates)
            evaluations = [
                self.evaluate_candidate(step, idx, state, candidate, rollout_index=rollout_idx)
                for idx, candidate in enumerate(candidates, 1)
                for rollout_idx in range(1, self.num_rollouts + 1)
            ]
            for evaluation in evaluations:
                self.plan_store.save_candidate_evaluation(evaluation)
            best = self._select_best_candidate(evaluations)
            if best is None or best.first_action_plan is None:
                break
            selected.append(best)
            self.selected_plans.append(best.first_action_plan)
            self.history_actions.append(best.high_level_action)
            self.plan_store.save_selected_plan(step=step, plan=best.first_action_plan, evaluation=best)
            first = best.action_results[0] if best.action_results else None
            state = dict(first.state_after or best.state_after) if first else dict(best.state_after)
        return selected

    def evaluate_candidate(
        self,
        step: int,
        candidate_index: int,
        state: RecoveryState,
        candidate: HighLevelAction,
        *,
        rollout_index: int,
    ) -> CandidateEvaluation:
        wall_start = time.perf_counter()
        _, baseline_time, baseline_validation = self.baseline_manager.restore(self.selected_plans)
        rollout_state = dict(state)
        next_action = candidate
        action_results: list[ActionExecutionResult] = []
        first_plan: CommandPlan | None = None
        invalid_reason = ""
        rollout_time = 0.0
        for _depth in range(self.max_rollout_depth):
            before = dict(rollout_state)
            try:
                plan = self.command_agent.generate_plan(
                    high_level_action=next_action,
                    state=before,
                    target=self.target,
                )
                if first_plan is None:
                    first_plan = plan
                exec_result = self.executor.execute_plan(plan, state_before=before)
                after, raw_state_output, parsed_state = self.state_predictor.predict(before, next_action)
                self._save_state_prediction(
                    step, candidate_index, rollout_index, next_action, before, raw_state_output, parsed_state, after
                )
            except Exception as exc:
                invalid_reason = f"{type(exc).__name__}: {exc}"
                break
            exec_result = replace(exec_result, state_after=after)
            action_results.append(exec_result)
            rollout_time += exec_result.action_total_time_seconds
            if not exec_result.success:
                invalid_reason = "command execution failed"
                break
            if has_regression(before, after):
                invalid_reason = "state regression detected"
                break
            rollout_state = after
            if is_terminal_state(rollout_state):
                break
            rollout_candidates = self.action_provider.candidates(
                rollout_state, self.history_actions + [next_action], 1
            )
            if not rollout_candidates:
                invalid_reason = "no rollout action generated"
                break
            next_action = rollout_candidates[0]
        progress = state_progress(state, rollout_state)
        success = bool(action_results) and all(item.success for item in action_results)
        reached_terminal = is_terminal_state(rollout_state)
        valid = success and reached_terminal and not invalid_reason
        if not valid and not invalid_reason:
            if progress <= 0:
                invalid_reason = "candidate did not improve LLM-predicted recovery state"
            else:
                invalid_reason = "rollout did not reach terminal recovery state"
        return CandidateEvaluation(
            step=step,
            candidate_index=candidate_index,
            server=self.target,
            server_ip=LEVEL9_TARGETS.get(self.target, {}).get("ips", "multiple"),
            high_level_action=candidate,
            success=success,
            valid=valid,
            state_before=state,
            state_after=rollout_state,
            rollout_total_time_seconds=rollout_time,
            baseline_restore_time_seconds=baseline_time,
            wall_clock_time_seconds=time.perf_counter() - wall_start,
            action_results=tuple(action_results),
            baseline_validation=baseline_validation,
            first_action_plan=first_plan,
            invalid_reason=invalid_reason,
            rollout_index=rollout_index,
            rollout_count=self.num_rollouts,
        )

    def _select_best_candidate(self, evaluations: list[CandidateEvaluation]) -> CandidateEvaluation | None:
        scored = []
        grouped: dict[int, list[CandidateEvaluation]] = {}
        for item in evaluations:
            grouped.setdefault(item.candidate_index, []).append(item)
        for samples in grouped.values():
            if len(samples) != self.num_rollouts:
                continue
            terminal_samples = [
                item
                for item in samples
                if item.success and not item.invalid_reason and is_terminal_state(item.state_after)
            ]
            if not terminal_samples:
                continue
            terminal_ratio = len(terminal_samples) / len(samples)
            avg_time = (
                sum(item.rollout_total_time_seconds for item in terminal_samples)
                / len(terminal_samples)
            )
            avg_progress = (
                sum(state_progress(item.state_before, item.state_after) for item in terminal_samples)
                / len(terminal_samples)
            )
            representative = min(terminal_samples, key=lambda item: item.rollout_total_time_seconds)
            scored.append(
                (
                    terminal_ratio,
                    avg_time,
                    avg_progress,
                    replace(
                        representative,
                        rollout_total_time_seconds=avg_time,
                        rollout_count=self.num_rollouts,
                    ),
                )
            )
        if not scored:
            return None
        return min(scored, key=lambda item: (-item[0], item[1], -item[2]))[3]

    def _save_state_prediction(
        self,
        step: int,
        candidate_index: int,
        rollout_index: int,
        action: HighLevelAction,
        state_before: RecoveryState,
        raw_output: str,
        parsed_state: dict[str, Any] | None,
        state_after: RecoveryState,
    ) -> None:
        path = (
            self.plan_store.run_dir
            / "llm_state_predictions"
            / f"step_{step:03d}_candidate_{candidate_index:03d}_rollout_{rollout_index:03d}.json"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "step": step,
                    "candidate_index": candidate_index,
                    "rollout_index": rollout_index,
                    "action": action.action,
                    "state_before": state_before,
                    "raw_output": raw_output,
                    "parsed_state": parsed_state,
                    "state_after": state_after,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CSLE level9 DT16 recovery loop with checkpoint state prediction.")
    parser.add_argument("--checkpoint", default=str(REPO_ROOT / "models/checkpoint-850"))
    parser.add_argument("--base-model", default=None)
    parser.add_argument("--system-file", required=True)
    parser.add_argument("--logs-file", required=True)
    parser.add_argument("--incident-file", required=True)
    parser.add_argument("--target", choices=("all", *LEVEL9_TARGETS.keys()), default="all")
    parser.add_argument("--baseline-dir", default=str(DEFAULT_ATTACK_AFTER_BASELINE))
    parser.add_argument("--artifacts-dir", default=str(REPO_ROOT / "experiments/csle_level9_dt/artifacts/model_outputs/recovery_loop_llm_state"))
    parser.add_argument("--action-provider", choices=("fixed", "local-model"), default="local-model")
    parser.add_argument("--num-candidates", type=int, default=3)
    parser.add_argument("--num-rollouts", type=int, default=1)
    parser.add_argument("--max-plan-steps", type=int, default=6)
    parser.add_argument("--max-rollout-depth", type=int, default=7)
    parser.add_argument("--torch-dtype", default="bfloat16")
    parser.add_argument("--device-map", default="auto")
    parser.add_argument("--action-temperature", type=float, default=0.6)
    parser.add_argument("--action-top-p", type=float, default=0.9)
    parser.add_argument("--action-max-new-tokens", type=int, default=700)
    parser.add_argument("--state-temperature", type=float, default=0.0)
    parser.add_argument("--state-top-p", type=float, default=0.9)
    parser.add_argument("--state-max-new-tokens", type=int, default=1200)
    parser.add_argument("--command-agent", choices=("mock", "deepseek"), default="mock")
    parser.add_argument("--deepseek-model", default="deepseek-v4-pro")
    parser.add_argument("--deepseek-api-key-env", default="DEEPSEEK_API_KEY")
    parser.add_argument("--deepseek-base-url", default="https://api.deepseek.com")
    parser.add_argument("--deepseek-timeout-seconds", type=int, default=120)
    parser.add_argument("--deepseek-max-tokens", type=int, default=4096)
    parser.add_argument("--deepseek-temperature", type=float, default=0.1)
    parser.add_argument("--deepseek-top-p", type=float, default=0.9)
    parser.add_argument("--deepseek-repair-attempts", type=int, default=2)
    parser.add_argument("--disable-command-dynamic-validation", action="store_true")
    args = parser.parse_args()

    target_info = LEVEL9_TARGETS.get(args.target)
    target_server = "all compromised level9 targets" if args.target == "all" else f"{args.target} / {target_info['ips']}"
    context = {
        "System": Path(args.system_file).read_text(encoding="utf-8").strip(),
        "Logs": Path(args.logs_file).read_text(encoding="utf-8").strip(),
        "Incident": Path(args.incident_file).read_text(encoding="utf-8").strip(),
        "TargetServer": target_server,
    }

    if args.action_provider == "local-model":
        action_provider: Any = LocalModelActionProvider(
            adapter_path=args.checkpoint,
            base_model=args.base_model,
            context=context,
            device_map=args.device_map,
            torch_dtype=args.torch_dtype,
            max_new_tokens=args.action_max_new_tokens,
            temperature=args.action_temperature,
            top_p=args.action_top_p,
        )
        shared_model_loader = action_provider._load
    else:
        action_provider = FixedLevel9ActionProvider()
        shared_model_loader = None

    from run_recovery_loop_llm_state import LLMStatePredictor

    state_predictor = LLMStatePredictor(
        checkpoint_path=args.checkpoint,
        context=context,
        base_model=args.base_model,
        device_map=args.device_map,
        torch_dtype=args.torch_dtype,
        max_new_tokens=args.state_max_new_tokens,
        temperature=args.state_temperature,
        top_p=args.state_top_p,
        shared_model_loader=shared_model_loader,
    )
    executor = Level9RecoveryExecutor()
    plan_store = PlanStore(args.artifacts_dir)
    if args.command_agent == "deepseek":
        command_agent: Any = APILevel9CommandAgent(
            model=args.deepseek_model,
            api_key_env=args.deepseek_api_key_env,
            base_url=args.deepseek_base_url,
            context=context,
            validator=Level9CommandValidator(
                known_targets=LEVEL9_TARGETS,
                dynamic_checks=not args.disable_command_dynamic_validation,
                repo_root=REPO_ROOT,
            ),
            timeout_seconds=args.deepseek_timeout_seconds,
            max_tokens=args.deepseek_max_tokens,
            temperature=args.deepseek_temperature,
            top_p=args.deepseek_top_p,
            repair_attempts=args.deepseek_repair_attempts,
            log_dir=plan_store.run_dir / "command_agent_api_calls",
        )
    else:
        command_agent = Level9MockCommandAgent()
    loop = Level9RecoveryLoop(
        context=context,
        target=args.target,
        action_provider=action_provider,
        command_agent=command_agent,
        state_predictor=state_predictor,
        executor=executor,
        baseline_manager=Level9BaselineManager(baseline_dir=Path(args.baseline_dir), executor=executor),
        plan_store=plan_store,
        num_candidates=args.num_candidates,
        num_rollouts=args.num_rollouts,
        max_plan_steps=args.max_plan_steps,
        max_rollout_depth=args.max_rollout_depth,
    )
    selected = loop.run()
    print(f"Selected {len(selected)} actions. Artifacts: {loop.plan_store.run_dir}")
    for item in selected:
        print(
            f"step={item.step} action={item.high_level_action.action} "
            f"rollout_total_time_seconds={item.rollout_total_time_seconds:.3f} "
            f"llm_state_after={item.state_after}"
        )
    (loop.plan_store.run_dir / "summary.json").write_text(
        json.dumps(
            {
                "selected_count": len(selected),
                "selected": [dataclass_to_jsonable(item) for item in selected],
                "recovery_state_fields": RECOVERY_STATE_FIELDS,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
