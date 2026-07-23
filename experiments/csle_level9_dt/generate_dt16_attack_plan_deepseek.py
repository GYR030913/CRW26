#!/usr/bin/env python3
"""Generate a DT16 attack hypothesis with DeepSeek V4 Pro.

This script intentionally does not execute commands. It only asks an external
model to produce a structured attack plan from model-visible inputs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import requests


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_DIR = ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "model_inputs" / "experienced"
DEFAULT_OUTPUT_DIR = ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "model_outputs"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.S)
        if not match:
            raise
        data = json.loads(match.group(0))
    if not isinstance(data, dict):
        raise ValueError("model output JSON must be an object")
    return data


def build_prompt(
    system_text: str,
    logs_text: str,
    incident_text: str,
    previous_plan_text: str = "",
    validation_text: str = "",
) -> str:
    feedback_section = ""
    if previous_plan_text or validation_text:
        feedback_section = f"""

### Previous candidate plan
{previous_plan_text}

### Non-destructive validation report for the previous plan
{validation_text}

Revision instruction:
- Fix the previous plan using the validation report.
- Do not repeat commands that failed because files, tools, or routes were missing.
- If a target is not reachable from the original source container, choose a
  source container whose interface is consistent with the observed Logs.
- If an exploit cannot be implemented without a missing helper script, provide a
  best-effort no-helper traffic-reproduction command and mark the uncertainty.
- Keep all commands reviewable; do not execute anything automatically.
"""
    return f"""You are generating a candidate attack reproduction plan for a CSLE level9 digital-twin execution.

Use only the provided System, Logs, and Incident inputs. Do not assume access to
any hidden static sequence, ground-truth attack script, or final compromised
state. The plan will be reviewed before execution.

Target environment:
- Use DT execution 16 only.
- Use 16.9.x.x IP addresses only.
- Commands should be suitable for manual execution with docker exec or inside
  the appropriate DT16 container.
- Do not include commands for the true CSLE execution 15.
- Prefer a two-phase plan:
  1. discovery_commands: non-destructive checks for tools, helper scripts,
     routes, listening services, credentials, and files.
  2. attack_commands: candidate commands to reproduce the inferred attack.

Available non-answer context:
- The attacker platform is likely csle_hacker_kali_1_1-level9-16.
- Common tools may include nmap, hydra, curl, ssh, sshpass, smbclient.
- Common wordlists may include /SecLists/Usernames/top-usernames-shortlist.txt
  and /SecLists/Passwords/Common-Credentials/top-20.txt.
- Helper scripts may or may not exist. Check before using paths such as
  /sambacry_exploit.py, /sql_injection_exploit.sh, and
  /cve_2015_1427_exploit.sh.

Return valid JSON with this schema:
{{
  "attack_hypothesis": "short explanation derived from the inputs",
  "expected_alert_themes": ["..."],
  "target_hosts": [
    {{
      "role": "service role inferred from system/logs",
      "ips": ["16.9.x.x"],
      "reason": "why this host is relevant"
    }}
  ],
  "discovery_commands": [
    {{
      "description": "what this verifies",
      "container": "container name or null",
      "command": "shell command",
      "expected_signal": "what output would support the hypothesis"
    }}
  ],
  "attack_commands": [
    {{
      "phase": "ordered phase name",
      "description": "what this command attempts",
      "container": "container name or null",
      "command": "shell command",
      "expected_alert_or_state": "expected observable result",
      "risk": "low|medium|high",
      "needs_manual_review": true
    }}
  ],
  "uncertainties": ["..."]
}}

### System
{system_text}

### Logs
{logs_text}

### Incident
{incident_text}
{feedback_section}
"""


def call_deepseek(
    *,
    api_key: str,
    base_url: str,
    model: str,
    prompt: str,
    max_tokens: int,
    temperature: float,
    top_p: float,
    timeout_seconds: int,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a careful cybersecurity testbed planner. "
                    "Return only valid JSON. Do not claim certainty where the "
                    "inputs are ambiguous."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
        "max_tokens": max_tokens,
        "temperature": temperature,
        "top_p": top_p,
    }
    response = requests.post(
        f"{base_url.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=timeout_seconds,
    )
    if response.status_code >= 400:
        raise RuntimeError(f"DeepSeek API failed: HTTP {response.status_code}: {response.text}")
    data = response.json()
    message = data.get("choices", [{}])[0].get("message", {})
    content = message.get("content") or message.get("reasoning_content") or ""
    parsed = extract_json_object(content)
    return {"request": {"model": model, "base_url": base_url}, "raw_response": data, "parsed": parsed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system-file", type=Path, default=DEFAULT_INPUT_DIR / "system_level9_experienced_execution15.txt")
    parser.add_argument(
        "--logs-file",
        type=Path,
        default=DEFAULT_INPUT_DIR / "logs_alerts_level9_experienced_execution15_sidecar_chronological_dedup.txt",
    )
    parser.add_argument(
        "--incident-file",
        type=Path,
        default=DEFAULT_INPUT_DIR / "incident_level9_experienced_checkpoint850_thresholded.txt",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=DEFAULT_OUTPUT_DIR / "deepseek_v4pro_dt16_experienced_attack_plan.json",
    )
    parser.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    parser.add_argument("--base-url", default="https://api.deepseek.com")
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--top-p", type=float, default=0.9)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--write-prompt-file", type=Path)
    parser.add_argument("--previous-plan-file", type=Path)
    parser.add_argument("--validation-file", type=Path)
    args = parser.parse_args()

    api_key = os.getenv(args.api_key_env, "").strip()
    if not api_key:
        print(f"Missing API key. Set {args.api_key_env}, for example:", file=sys.stderr)
        print(f'  export {args.api_key_env}="your-deepseek-api-key"', file=sys.stderr)
        return 2

    prompt = build_prompt(
        system_text=read_text(args.system_file),
        logs_text=read_text(args.logs_file),
        incident_text=read_text(args.incident_file),
        previous_plan_text=read_text(args.previous_plan_file) if args.previous_plan_file else "",
        validation_text=read_text(args.validation_file) if args.validation_file else "",
    )
    if args.write_prompt_file:
        args.write_prompt_file.parent.mkdir(parents=True, exist_ok=True)
        args.write_prompt_file.write_text(prompt, encoding="utf-8")

    result = call_deepseek(
        api_key=api_key,
        base_url=args.base_url,
        model=args.model,
        prompt=prompt,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        top_p=args.top_p,
        timeout_seconds=args.timeout_seconds,
    )
    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    args.output_file.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {args.output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
