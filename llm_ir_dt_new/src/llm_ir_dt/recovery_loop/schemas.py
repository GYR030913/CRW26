"""Shared schemas for the recovery loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


RECOVERY_STATE_FIELDS: tuple[str, ...] = (
    "is_attack_contained",
    "is_knowledge_sufficient",
    "are_forensics_preserved",
    "is_eradicated",
    "is_hardened",
    "is_recovered",
)

RecoveryState = dict[str, bool]


def initial_recovery_state() -> RecoveryState:
    """Return the default all-false recovery state."""
    return {field: False for field in RECOVERY_STATE_FIELDS}


def terminal_recovery_state() -> RecoveryState:
    """Return the terminal all-true recovery state."""
    return {field: True for field in RECOVERY_STATE_FIELDS}


def is_terminal_state(state: RecoveryState) -> bool:
    """Return whether all recovery state fields are true."""
    return all(bool(state.get(field, False)) for field in RECOVERY_STATE_FIELDS)


def state_progress(before: RecoveryState, after: RecoveryState) -> int:
    """Count false-to-true transitions between two states."""
    return sum(
        1
        for field in RECOVERY_STATE_FIELDS
        if not bool(before.get(field, False)) and bool(after.get(field, False))
    )


def has_regression(before: RecoveryState, after: RecoveryState) -> bool:
    """Return whether any state field regressed from true to false."""
    return any(
        bool(before.get(field, False)) and not bool(after.get(field, False))
        for field in RECOVERY_STATE_FIELDS
    )


@dataclass(frozen=True)
class HighLevelAction:
    """A parsed high-level recovery action from the local model."""

    action: str
    explanation: str = ""
    raw_model_output: str = ""


@dataclass(frozen=True)
class CommandSpec:
    """A shell command to execute inside one digital-twin container."""

    container: str
    command: str
    allowed_exit_codes: tuple[int, ...] = (0,)
    description: str = ""


@dataclass(frozen=True)
class CommandPlan:
    """Concrete command plan for one high-level recovery action."""

    high_level_action: str
    high_level_action_explanation: str = ""
    commands: tuple[CommandSpec, ...] = field(default_factory=tuple)
    verification_commands: tuple[CommandSpec, ...] = field(default_factory=tuple)
    expected_state_change: RecoveryState = field(default_factory=dict)
    rollback_commands: tuple[CommandSpec, ...] = field(default_factory=tuple)
    raw_model_output: str = ""


@dataclass(frozen=True)
class CommandResult:
    """Execution result for one command."""

    container: str
    command: str
    exit_code: int
    output: str
    elapsed_seconds: float
    phase: str
    allowed_exit_codes: tuple[int, ...]

    @property
    def success(self) -> bool:
        """Return whether the command exit code is accepted."""
        return self.exit_code in self.allowed_exit_codes


@dataclass(frozen=True)
class ActionExecutionResult:
    """Execution result for one high-level action command plan."""

    high_level_action: str
    high_level_action_explanation: str
    success: bool
    action_execution_time_seconds: float
    action_verification_time_seconds: float
    action_total_time_seconds: float
    command_results: tuple[CommandResult, ...]
    verification_results: tuple[CommandResult, ...]
    state_before: RecoveryState | None = None
    state_after: RecoveryState | None = None


@dataclass(frozen=True)
class CandidateEvaluation:
    """Strict rollout evaluation for one candidate action."""

    step: int
    candidate_index: int
    server: str
    server_ip: str
    high_level_action: HighLevelAction
    success: bool
    valid: bool
    state_before: RecoveryState
    state_after: RecoveryState
    rollout_total_time_seconds: float
    baseline_restore_time_seconds: float
    wall_clock_time_seconds: float
    action_results: tuple[ActionExecutionResult, ...]
    baseline_validation: dict[str, Any] = field(default_factory=dict)
    first_action_plan: CommandPlan | None = None
    invalid_reason: str = ""
    rollout_index: int = 1
    rollout_count: int = 1


def dataclass_to_jsonable(value: Any) -> Any:
    """Convert nested dataclasses and tuples into JSON-serializable values."""
    if hasattr(value, "__dataclass_fields__"):
        return {
            key: dataclass_to_jsonable(getattr(value, key))
            for key in value.__dataclass_fields__
        }
    if isinstance(value, tuple):
        return [dataclass_to_jsonable(item) for item in value]
    if isinstance(value, list):
        return [dataclass_to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): dataclass_to_jsonable(item) for key, item in value.items()}
    return value
