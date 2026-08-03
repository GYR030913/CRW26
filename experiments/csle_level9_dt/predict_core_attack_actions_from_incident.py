#!/usr/bin/env python3
"""Predict only core CSLE level9 attack actions with the local LoRA model.

This script intentionally asks the model for exploit / credential-guessing
actions only. CSLE runtime support actions such as PING_SCAN, SERVICE_LOGIN,
and INSTALL_TOOLS should be added later by adapt_core_attack_to_csle_sequence.py.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CHECKPOINT = ROOT / "models" / "checkpoint-850"
DEFAULT_INPUT_DIR = ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "model_inputs" / "experienced"
DEFAULT_OUTPUT_DIR = ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "model_outputs" / "attack_plans"

CORE_ACTIONS: dict[str, set[str]] = {
    "SAMBACRY_EXPLOIT": {"samba"},
    "SSH_SAME_USER_PASS_DICTIONARY": {"ssh"},
    "CVE_2010_0426_PRIV_ESC": {"ssh"},
    "DVWA_SQL_INJECTION": {"dvwa"},
    "CVE_2015_1427_EXPLOIT": {"elasticsearch"},
    "TELNET_SAME_USER_PASS_DICTIONARY": {"samba", "ssh", "dvwa", "elasticsearch"},
    "FTP_SAME_USER_PASS_DICTIONARY": {"dvwa"},
    "SHELLSHOCK_EXPLOIT": {"dvwa"},
    "CVE_2015_3306_EXPLOIT": {"ftp"},
    "CVE_2016_10033_EXPLOIT": {"mail"},
    "CVE_2015_5602_PRIV_ESC": {"ssh"},
}

DEFAULT_TARGETS = {
    "SAMBACRY_EXPLOIT": "samba",
    "SSH_SAME_USER_PASS_DICTIONARY": "ssh",
    "CVE_2010_0426_PRIV_ESC": "ssh",
    "DVWA_SQL_INJECTION": "dvwa",
    "CVE_2015_1427_EXPLOIT": "elasticsearch",
    "TELNET_SAME_USER_PASS_DICTIONARY": "samba",
    "FTP_SAME_USER_PASS_DICTIONARY": "dvwa",
    "SHELLSHOCK_EXPLOIT": "dvwa",
    "CVE_2015_3306_EXPLOIT": "ftp",
    "CVE_2016_10033_EXPLOIT": "mail",
    "CVE_2015_5602_PRIV_ESC": "ssh",
}

TARGET_ALIASES = {
    "16.9.2.3": "samba",
    "16.9.4.3": "samba",
    "16.9.253.3": "samba",
    "16.9.2.78": "ssh",
    "16.9.3.78": "ssh",
    "16.9.253.78": "ssh",
    "16.9.4.74": "dvwa",
    "16.9.5.74": "dvwa",
    "16.9.253.74": "dvwa",
    "16.9.5.62": "elasticsearch",
    "16.9.6.62": "elasticsearch",
    "16.9.7.62": "elasticsearch",
    "16.9.253.62": "elasticsearch",
}

ACTION_ALIASES = {
    "SAMBA": "SAMBACRY_EXPLOIT",
    "SAMBACRY": "SAMBACRY_EXPLOIT",
    "SSH": "SSH_SAME_USER_PASS_DICTIONARY",
    "SSH_PASSWORD_GUESSING": "SSH_SAME_USER_PASS_DICTIONARY",
    "SSH_BRUTE_FORCE": "SSH_SAME_USER_PASS_DICTIONARY",
    "DVWA": "DVWA_SQL_INJECTION",
    "SQL_INJECTION": "DVWA_SQL_INJECTION",
    "DVWA_SQLI": "DVWA_SQL_INJECTION",
    "ELASTICSEARCH": "CVE_2015_1427_EXPLOIT",
    "ELASTICSEARCH_CVE_2015_1427": "CVE_2015_1427_EXPLOIT",
    "ELASTICSEARCH_CVE_2015_1427_EXPLOIT": "CVE_2015_1427_EXPLOIT",
}

PROMPT_TEMPLATE = """Below is a CSLE level9 system description and an incident summary. Write a response that appropriately completes the request. Before generating the response, think carefully about which core attack actions are justified by the incident.

### System:
{system}

### Incident:
{incident}
{execution_feedback_section}

### Core CSLE Attack Actions:
Only choose from these core attack actions. Do not output support/runtime actions.

- SAMBACRY_EXPLOIT(target=samba): SambaCry exploit against the Samba host.
- SSH_SAME_USER_PASS_DICTIONARY(target=ssh): SSH password guessing against the SSH host.
- CVE_2010_0426_PRIV_ESC(target=ssh): Local post-exploitation privilege escalation on the SSH host after SSH password guessing/login. The ssh target is the csle_ssh_1_1 host, not the separate topology host named csle_cve_2010_0426_1_1.
- DVWA_SQL_INJECTION(target=dvwa): DVWA SQL injection against the web/DVWA host.
- CVE_2015_1427_EXPLOIT(target=elasticsearch): Elasticsearch Groovy sandbox escape exploit.
- TELNET_SAME_USER_PASS_DICTIONARY(target=samba|ssh|dvwa|elasticsearch): Telnet password guessing.
- FTP_SAME_USER_PASS_DICTIONARY(target=dvwa): FTP password guessing.
- SHELLSHOCK_EXPLOIT(target=dvwa): ShellShock exploitation against the web/ShellShock target.
- CVE_2015_3306_EXPLOIT(target=ftp): ProFTPD CVE-2015-3306 exploit.
- CVE_2016_10033_EXPLOIT(target=mail): PHPMailer CVE-2016-10033 exploit.
- CVE_2015_5602_PRIV_ESC(target=ssh): CVE-2015-5602 local privilege escalation.

### Instruction:
Predict only the core attack actions that are supported by the visible incident summary.

Important:
- Do not output PING_SCAN.
- Do not output SERVICE_LOGIN.
- Do not output INSTALL_TOOLS.
- Do not output Docker commands, shell commands, exploit script paths, or recovery actions.
- Output actions in the inferred attack order.
- Use only the action names listed above.
- Use only valid target aliases for each action.
- If the incident summary does not support a core action, omit it.
- If execution feedback is provided, use it only to identify differences in logged_in/root/backdoor state and revise the core attack sequence. Do not copy support/runtime actions from feedback.
- Treat the predicted summary as the result of the current guessed core attack sequence, not as the desired final ground truth.
- Treat the reference summary as the desired attack outcome that a correct core attack sequence should explain.
- If a host has lower privilege in the predicted summary than in the reference summary, infer which additional core attack action could explain the missing privilege level.

Return valid JSON only with this schema:
{{
  "sequence_name": "short lowercase identifier",
  "prediction_basis": "brief explanation based only on System/Incident",
  "core_attacks": [
    {{
      "action": "one core action from the list above",
      "target": "one valid target alias for that action",
      "reason": "brief evidence-based reason"
    }}
  ]
}}

### Response:
<think>"""


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def resolve_local_hf_snapshot(model_name_or_path: str) -> str:
    path = Path(model_name_or_path)
    if path.exists():
        return str(path)
    cache_dir = Path.home() / ".cache" / "huggingface" / "hub" / f"models--{model_name_or_path.replace('/', '--')}"
    ref_path = cache_dir / "refs" / "main"
    if ref_path.exists():
        snapshot = cache_dir / "snapshots" / ref_path.read_text(encoding="utf-8").strip()
        if snapshot.exists():
            return str(snapshot)
    return model_name_or_path


def dtype_from_name(name: str) -> torch.dtype:
    normalized = name.lower()
    if normalized in {"bf16", "bfloat16"}:
        return torch.bfloat16
    if normalized in {"fp16", "float16"}:
        return torch.float16
    if normalized in {"fp32", "float32"}:
        return torch.float32
    raise ValueError(f"Unsupported dtype: {name}")


def load_model_and_tokenizer(
    checkpoint_path: Path,
    dtype: torch.dtype,
    base_model: str | None,
    tokenizer_max_length: int | None,
) -> tuple[AutoTokenizer, AutoModelForCausalLM]:
    adapter_config_path = checkpoint_path / "adapter_config.json"
    if adapter_config_path.exists():
        adapter_meta = json.loads(adapter_config_path.read_text(encoding="utf-8"))
        base_model_name = resolve_local_hf_snapshot(base_model or str(adapter_meta["base_model_name_or_path"]))
        tokenizer = AutoTokenizer.from_pretrained(base_model_name, use_fast=True)
        model_base = AutoModelForCausalLM.from_pretrained(
            base_model_name,
            device_map="auto",
            torch_dtype=dtype,
        )
        model = PeftModel.from_pretrained(model_base, str(checkpoint_path))
    else:
        tokenizer = AutoTokenizer.from_pretrained(str(checkpoint_path), use_fast=True)
        model = AutoModelForCausalLM.from_pretrained(
            str(checkpoint_path),
            device_map="auto",
            torch_dtype=dtype,
        )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    if tokenizer_max_length:
        tokenizer.model_max_length = tokenizer_max_length
    model.eval()
    return tokenizer, model


def build_execution_feedback_section(predicted_summary: str | None, reference_summary: str | None) -> str:
    if not predicted_summary and not reference_summary:
        return ""
    sections = ["", "### Execution Feedback:"]
    if predicted_summary:
        sections.extend(
            [
                "Predicted DT16 attack output summary:",
                predicted_summary.strip(),
            ]
        )
    if reference_summary:
        sections.extend(
            [
                "",
                "Reference experienced attack output summary:",
                reference_summary.strip(),
            ]
        )
    sections.append(
        "\nCompare the predicted and reference summaries across Samba, SSH, DVWA, and Elasticsearch hosts. "
        "Focus on logged_in, root, and backdoor/credential differences."
    )
    return "\n".join(sections)


def build_prompt(
    system_text: str,
    incident_text: str,
    predicted_summary: str | None = None,
    reference_summary: str | None = None,
) -> str:
    return PROMPT_TEMPLATE.format(
        system=system_text.strip(),
        incident=incident_text.strip(),
        execution_feedback_section=build_execution_feedback_section(predicted_summary, reference_summary),
    )


def generate_once(
    *,
    model: AutoModelForCausalLM,
    tokenizer: AutoTokenizer,
    prompt: str,
    max_new_tokens: int,
    temperature: float,
    top_p: float,
) -> str:
    inputs = tokenizer(prompt, return_tensors="pt", truncation=False)
    inputs = {key: value.to(model.device) for key, value in inputs.items()}
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=temperature > 0.0,
            temperature=temperature,
            top_p=top_p,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )
    decoded = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    if decoded.startswith(prompt):
        decoded = decoded[len(prompt):]
    return decoded.strip()


def extract_json_object(text: str) -> dict[str, Any] | None:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", cleaned):
        try:
            obj, _ = decoder.raw_decode(cleaned[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def normalize_core_plan(plan: dict[str, Any] | None) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(plan, dict):
        return None, ["no JSON object parsed"]
    raw_actions = (
        plan.get("core_attacks")
        or plan.get("Core_attacks")
        or plan.get("coreActions")
        or plan.get("core_actions")
        or plan.get("actions")
    )
    if not isinstance(raw_actions, list) or not raw_actions:
        return None, ["missing non-empty core_attacks array"]
    errors: list[str] = []
    normalized: list[dict[str, str]] = []
    for idx, item in enumerate(raw_actions, start=1):
        if isinstance(item, str):
            raw = item.strip()
            compact_match = re.fullmatch(r"([A-Za-z0-9_]+)\(([^()]+)\)", raw)
            if compact_match:
                action = compact_match.group(1).strip().upper()
                target = compact_match.group(2).strip().lower()
                reason = "Model returned compact ACTION(TARGET) string; parsed into action and target."
            else:
                action = raw.upper()
                target = DEFAULT_TARGETS.get(action, "")
                reason = "Model returned a string action; target inferred from core-action defaults."
        elif isinstance(item, dict):
            action = str(item.get("action", item.get("attack", ""))).strip().upper()
            target = str(item.get("target", "")).strip().lower()
            reason = str(item.get("reason", item.get("evidence", ""))).strip()
        else:
            errors.append(f"core action {idx} is neither an object nor a string")
            continue
        action = ACTION_ALIASES.get(action, action)
        target = re.sub(r"^(target|host|service)\s*=\s*", "", target).strip()
        target = TARGET_ALIASES.get(target, target)
        if not target:
            target = DEFAULT_TARGETS.get(action, "")
        if action not in CORE_ACTIONS:
            errors.append(f"core action {idx} unsupported action={action!r}")
            continue
        if target not in CORE_ACTIONS[action]:
            errors.append(f"core action {idx} invalid target={target!r} for action={action}")
            continue
        normalized.append({"action": action, "target": target, "reason": reason})
    if not normalized:
        return None, errors or ["no valid core attacks"]
    return {
        "schema_version": 1,
        "sequence_name": str(plan.get("sequence_name") or "checkpoint850_core_attack_prediction"),
        "prediction_basis": str(plan.get("prediction_basis") or ""),
        "core_attacks": normalized,
    }, errors


def sequence_key(plan: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    return tuple((str(action["action"]), str(action["target"])) for action in plan.get("core_attacks", []))


def choose_selected_plan(valid_plans: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not valid_plans:
        return None
    counts = Counter(sequence_key(plan) for plan in valid_plans)
    best_key, _ = counts.most_common(1)[0]
    for plan in valid_plans:
        if sequence_key(plan) == best_key:
            return plan
    return valid_plans[0]


def aggregate_core_actions(valid_plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str]] = Counter()
    for plan in valid_plans:
        for item in plan.get("core_attacks", []):
            counts[(str(item["action"]), str(item["target"]))] += 1
    total = max(len(valid_plans), 1)
    return [
        {"action": action, "target": target, "count": count, "ratio": count / total}
        for (action, target), count in counts.most_common()
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--base-model", default=None)
    parser.add_argument("--system-file", type=Path, default=DEFAULT_INPUT_DIR / "system_level9_experienced_execution15.txt")
    parser.add_argument(
        "--incident-file",
        type=Path,
        default=DEFAULT_INPUT_DIR / "incident_level9_experienced_checkpoint850_thresholded.txt",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=DEFAULT_OUTPUT_DIR / "checkpoint850_core_attack_prediction.json",
    )
    parser.add_argument(
        "--selected-core-file",
        type=Path,
        default=DEFAULT_OUTPUT_DIR / "checkpoint850_selected_core_attack_prediction.json",
    )
    parser.add_argument("--write-prompt-file", type=Path)
    parser.add_argument(
        "--predicted-summary-file",
        type=Path,
        help="Optional DT16 predicted-attack output summary to feed back for a second/refinement pass.",
    )
    parser.add_argument(
        "--reference-summary-file",
        type=Path,
        help="Optional reference experienced-attack output summary to compare against the predicted summary.",
    )
    parser.add_argument("--dtype", default="bfloat16")
    parser.add_argument("--temperature", type=float, default=0.4)
    parser.add_argument("--top-p", type=float, default=0.95)
    parser.add_argument("--max-new-tokens", type=int, default=1600)
    parser.add_argument("--num-runs", type=int, default=10)
    parser.add_argument("--tokenizer-max-length", type=int, default=None)
    args = parser.parse_args()

    predicted_summary = read_text(args.predicted_summary_file) if args.predicted_summary_file else None
    reference_summary = read_text(args.reference_summary_file) if args.reference_summary_file else None
    prompt = build_prompt(
        system_text=read_text(args.system_file),
        incident_text=read_text(args.incident_file),
        predicted_summary=predicted_summary,
        reference_summary=reference_summary,
    )
    if args.write_prompt_file:
        args.write_prompt_file.parent.mkdir(parents=True, exist_ok=True)
        args.write_prompt_file.write_text(prompt, encoding="utf-8")

    dtype = dtype_from_name(args.dtype)
    tokenizer, model = load_model_and_tokenizer(
        checkpoint_path=args.checkpoint,
        dtype=dtype,
        base_model=args.base_model,
        tokenizer_max_length=args.tokenizer_max_length,
    )
    prompt_tokens = len(tokenizer(prompt, return_tensors="pt", truncation=False)["input_ids"][0])
    runs: list[dict[str, Any]] = []
    valid_plans: list[dict[str, Any]] = []
    for run_idx in range(1, args.num_runs + 1):
        raw = generate_once(
            model=model,
            tokenizer=tokenizer,
            prompt=prompt,
            max_new_tokens=args.max_new_tokens,
            temperature=args.temperature,
            top_p=args.top_p,
        )
        parsed = extract_json_object(raw)
        normalized, validation_errors = normalize_core_plan(parsed)
        if normalized is not None:
            valid_plans.append(normalized)
        runs.append(
            {
                "run": run_idx,
                "raw_output": raw,
                "parsed": parsed,
                "normalized_core_plan": normalized,
                "validation_errors": validation_errors,
            }
        )
        print(f"run={run_idx} valid={normalized is not None} errors={validation_errors}", flush=True)

    selected = choose_selected_plan(valid_plans)
    result = {
        "schema_version": 1,
        "kind": "checkpoint850_core_attack_prediction",
        "checkpoint": str(args.checkpoint),
        "system_file": str(args.system_file),
        "incident_file": str(args.incident_file),
        "predicted_summary_file": str(args.predicted_summary_file) if args.predicted_summary_file else None,
        "reference_summary_file": str(args.reference_summary_file) if args.reference_summary_file else None,
        "prompt_tokens": prompt_tokens,
        "generation": {
            "num_runs": args.num_runs,
            "temperature": args.temperature,
            "top_p": args.top_p,
            "max_new_tokens": args.max_new_tokens,
            "dtype": args.dtype,
        },
        "valid_run_count": len(valid_plans),
        "core_action_consensus": aggregate_core_actions(valid_plans),
        "selected_core_plan": selected,
        "runs": runs,
    }
    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    args.output_file.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output_file}")
    if selected is not None:
        args.selected_core_file.parent.mkdir(parents=True, exist_ok=True)
        args.selected_core_file.write_text(json.dumps(selected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"wrote selected core plan {args.selected_core_file}")
    else:
        print("no valid selected core plan")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
