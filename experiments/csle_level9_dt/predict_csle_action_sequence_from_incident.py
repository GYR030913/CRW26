#!/usr/bin/env python3
"""Predict a CSLE level9 action-space attack sequence with the local LoRA model.

This script is the no-raw-logs variant:

    System + Incident + compact CSLE action-space manifest
        -> predicted high-level CSLE action sequence

The selected plan can be executed by run_predicted_csle_action_sequence.py,
which resolves target aliases to current CSLE runtime indexes and executes
Attacker.attacker_transition / Defender.defender_transition.
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
DEFAULT_ACTION_SPACE = ROOT / "experiments" / "csle_level9_dt" / "action_space_level9_manifest.json"


PROMPT_TEMPLATE = """Below is a CSLE level9 system description, an incident summary, and a compact CSLE attacker action space. Write a response that appropriately completes the request. Before generating the response, think carefully about which attacker actions are supported by the action space and which actions are justified by the incident summary.

### System:
{system}

### Incident:
{incident}

### CSLE Action Space:
{action_space}

### Instruction:
You are selecting a candidate CSLE level9 attacker action sequence for a digital twin. Use only the System, Incident, and CSLE Action Space above. Do not use hidden static-sequence metadata or any ground-truth attack script.

Return valid JSON only with this schema:
{{
  "sequence_name": "short lowercase identifier",
  "prediction_basis": "brief explanation based only on the visible inputs",
  "actions": [
    {{
      "action": "one action from allowed_actions",
      "target": "one valid target alias for that action",
      "reason": "brief reason based on System/Incident"
    }}
  ]
}}

Example action item format:
{{
  "action": "SAMBACRY_EXPLOIT",
  "target": "samba",
  "reason": "The incident mentions SambaCry against the Samba host."
}}

Do not write actions as strings like:
["PING_SCAN", "SAMBACRY_EXPLOIT"]

Rules:
- Use only action names from allowed_actions.
- Use only target aliases allowed for that action.
- Use target aliases such as all, samba, ssh, dvwa, elasticsearch; do not output CSLE machine indexes.
- Do not use SSH, DVWA, or ELASTICSEARCH as action values. Use SSH_SAME_USER_PASS_DICTIONARY, DVWA_SQL_INJECTION, or CVE_2015_1427_EXPLOIT with targets ssh, dvwa, or elasticsearch.
- Output a CSLE executable sequence, not only a semantic list of exploit names.
- Include PING_SCAN before major new discovery/exploitation stages when reachable hosts must be known or refreshed.
- Include SERVICE_LOGIN after actions that may create or discover credentials/backdoors before treating a host as logged_in/root.
- Include INSTALL_TOOLS after SERVICE_LOGIN when the newly compromised host must be used as a later jump host or pivot.
- If the incident implies a multi-stage pivot chain, include the support actions needed between stages, not just the final exploit names.
- Do not output Docker commands, shell commands, exploit script paths, or recovery actions.
- Return only JSON, nothing else.

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


def build_prompt(system_text: str, incident_text: str, action_space_text: str) -> str:
    return PROMPT_TEMPLATE.format(
        system=system_text.strip(),
        incident=incident_text.strip(),
        action_space=action_space_text.strip(),
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


def allowed_action_target_map(action_space: dict[str, Any]) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for item in action_space.get("allowed_actions", []):
        if not isinstance(item, dict):
            continue
        action = str(item.get("action", "")).strip().upper()
        raw_targets = item.get("valid_targets", item.get("targets", []))
        targets = {str(target).strip().lower() for target in raw_targets}
        if action:
            mapping[action] = targets
    return mapping


def normalize_plan(
    plan: dict[str, Any] | None,
    action_space: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(plan, dict):
        return None, ["no JSON object parsed"]
    actions = plan.get("actions")
    if not isinstance(actions, list) or not actions:
        return None, ["missing non-empty actions array"]
    allowed = allowed_action_target_map(action_space)
    default_targets = {
        "PING_SCAN": "all",
        "TCP_SYN_STEALTH_SCAN": "all",
        "VULSCAN": "all",
        "NMAP_VULNERS": "all",
        "SSH_SAME_USER_PASS_DICTIONARY": "ssh",
        "TELNET_SAME_USER_PASS_DICTIONARY": "samba",
        "FTP_SAME_USER_PASS_DICTIONARY": "dvwa",
        "SERVICE_LOGIN": "all",
        "INSTALL_TOOLS": "all",
        "SSH_BACKDOOR": "all",
        "SAMBACRY_EXPLOIT": "samba",
        "DVWA_SQL_INJECTION": "dvwa",
        "CVE_2015_1427_EXPLOIT": "elasticsearch",
        "CVE_2010_0426_PRIV_ESC": "ssh",
        "SHELLSHOCK_EXPLOIT": "dvwa",
        "CVE_2015_3306_EXPLOIT": "ftp",
        "CVE_2016_10033_EXPLOIT": "mail",
        "CVE_2015_5602_PRIV_ESC": "ssh",
    }
    errors: list[str] = []
    normalized_actions: list[dict[str, str]] = []
    for idx, item in enumerate(actions, start=1):
        if isinstance(item, str):
            raw = item.strip()
            compact_match = re.fullmatch(r"([A-Za-z0-9_]+)\(([^()]+)\)", raw)
            if compact_match:
                action = compact_match.group(1).strip().upper()
                target = compact_match.group(2).strip().lower()
                reason = "Model returned compact ACTION(TARGET) string; parsed into action and target."
            else:
                action = raw.upper()
                target = default_targets.get(action, "")
                reason = "Model returned a string action; target inferred from action-space defaults."
        elif isinstance(item, dict):
            action = str(item.get("action", "")).strip().upper()
            target = str(item.get("target", "")).strip().lower()
            reason = str(item.get("reason", "")).strip()
        else:
            errors.append(f"action {idx} is neither an object nor a string")
            continue
        if action not in allowed:
            errors.append(f"action {idx} unsupported action={action!r}")
            continue
        if target not in allowed[action]:
            errors.append(f"action {idx} invalid target={target!r} for action={action}")
            continue
        normalized_actions.append({"action": action, "target": target, "reason": reason})
    if not normalized_actions:
        return None, errors or ["no valid actions"]
    return {
        "schema_version": 1,
        "sequence_name": str(plan.get("sequence_name") or "checkpoint850_action_space_prediction"),
        "prediction_basis": str(plan.get("prediction_basis") or ""),
        "execution_model": (
            "Run these high-level actions through run_predicted_csle_action_sequence.py so CSLE "
            "performs target-index resolution, attacker_transition, defender_transition, credential "
            "insertion, service login, root detection, and final attacker-state updates."
        ),
        "actions": normalized_actions,
    }, errors


def sequence_key(plan: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    return tuple((str(action["action"]), str(action["target"])) for action in plan.get("actions", []))


def choose_selected_plan(valid_plans: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not valid_plans:
        return None
    counts = Counter(sequence_key(plan) for plan in valid_plans)
    best_key, _ = counts.most_common(1)[0]
    for plan in valid_plans:
        if sequence_key(plan) == best_key:
            return plan
    return valid_plans[0]


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
    parser.add_argument("--action-space-file", type=Path, default=DEFAULT_ACTION_SPACE)
    parser.add_argument(
        "--output-file",
        type=Path,
        default=DEFAULT_OUTPUT_DIR / "checkpoint850_action_space_prediction_no_logs.json",
    )
    parser.add_argument(
        "--selected-plan-file",
        type=Path,
        default=DEFAULT_OUTPUT_DIR / "checkpoint850_selected_csle_action_sequence_no_logs.json",
    )
    parser.add_argument("--write-prompt-file", type=Path)
    parser.add_argument("--dtype", default="bfloat16")
    parser.add_argument("--temperature", type=float, default=0.4)
    parser.add_argument("--top-p", type=float, default=0.95)
    parser.add_argument("--max-new-tokens", type=int, default=3000)
    parser.add_argument("--num-runs", type=int, default=10)
    parser.add_argument("--tokenizer-max-length", type=int, default=None)
    args = parser.parse_args()

    action_space = json.loads(read_text(args.action_space_file))
    prompt = build_prompt(
        system_text=read_text(args.system_file),
        incident_text=read_text(args.incident_file),
        action_space_text=json.dumps(action_space, indent=2, ensure_ascii=False),
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
        normalized, validation_errors = normalize_plan(parsed, action_space)
        if normalized is not None:
            valid_plans.append(normalized)
        runs.append(
            {
                "run": run_idx,
                "raw_output": raw,
                "parsed": parsed,
                "normalized_plan": normalized,
                "validation_errors": validation_errors,
            }
        )
        print(f"run={run_idx} valid={normalized is not None} errors={validation_errors}")

    selected = choose_selected_plan(valid_plans)
    result = {
        "schema_version": 1,
        "kind": "checkpoint850_csle_action_space_prediction_no_logs",
        "checkpoint": str(args.checkpoint),
        "system_file": str(args.system_file),
        "incident_file": str(args.incident_file),
        "action_space_file": str(args.action_space_file),
        "prompt_tokens": prompt_tokens,
        "generation": {
            "num_runs": args.num_runs,
            "temperature": args.temperature,
            "top_p": args.top_p,
            "max_new_tokens": args.max_new_tokens,
            "dtype": args.dtype,
            "tokenizer_max_length": tokenizer.model_max_length,
        },
        "selected_plan": selected,
        "sequence_counts": [
            {
                "count": count,
                "sequence": [{"action": action, "target": target} for action, target in key],
            }
            for key, count in Counter(sequence_key(plan) for plan in valid_plans).most_common()
        ],
        "runs": runs,
    }

    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    args.output_file.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.output_file}")

    if selected is not None:
        args.selected_plan_file.parent.mkdir(parents=True, exist_ok=True)
        args.selected_plan_file.write_text(json.dumps(selected, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote selected plan {args.selected_plan_file}")
    else:
        print("no valid selected plan")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
