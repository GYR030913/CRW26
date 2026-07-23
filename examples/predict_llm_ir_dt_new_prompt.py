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


DEFAULT_CHECKPOINT = "/content/drive/MyDrive/llm_recovery_runs-FOURdatasets/checkpoint-850"

ATTACK_TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TACTIC_ORDER_INDEX = {
    tactic: idx for idx, tactic in enumerate(ATTACK_TACTIC_ORDER)
}

TACTIC_ID_TO_NAME = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

TACTIC_TEXT_ALIASES = {
    "reconnaissance": "Reconnaissance",
    "resource development": "Resource Development",
    "initial access": "Initial Access",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege escalation": "Privilege Escalation",
    "defense evasion": "Defense Evasion",
    "defense_evasion": "Defense Evasion",
    "credential access": "Credential Access",
    "discovery": "Discovery",
    "lateral movement": "Lateral Movement",
    "collection": "Collection",
    "command and control": "Command and Control",
    "command_and_control": "Command and Control",
    "command and control c2": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

TECHNIQUE_ID_TO_NAME = {
    "T1021": "Remote Services",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.004": "Remote Services: SSH",
    "T1040": "Network Sniffing",
    "T1046": "Network Service Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1087": "Account Discovery",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.002": "Brute Force: Password Cracking",
    "T1110.003": "Brute Force: Password Spraying",
    "T1110.004": "Brute Force: Credential Stuffing",
    "T1190": "Exploit Public-Facing Application",
    "T1595": "Active Scanning",
    "T1595.001": "Active Scanning: Scanning IP Blocks",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1595.003": "Active Scanning: Wordlist Scanning",
}

TECHNIQUE_TEXT_ALIASES = {
    "account discovery": "T1087",
    "active scanning": "T1595",
    "active scanning icmp": "T1595.001",
    "active scanning scanning ip blocks": "T1595.001",
    "active scanning vulnerability scanning": "T1595.002",
    "active scanning wordlist scanning": "T1595.003",
    "brute force": "T1110",
    "brute force credential stuffing": "T1110.004",
    "brute force password cracking": "T1110.002",
    "brute force password guessing": "T1110.001",
    "brute force password spraying": "T1110.003",
    "command and scripting interpreter": "T1059",
    "command and scripting interpreter unix shell": "T1059.004",
    "exploit public facing application": "T1190",
    "network service discovery": "T1046",
    "network service scanning": "T1046",
    "network sniffing": "T1040",
    "password cracking": "T1110.002",
    "password guessing": "T1110.001",
    "password spraying": "T1110.003",
    "remote services": "T1021",
    "remote services smb windows admin shares": "T1021.002",
    "remote services ssh": "T1021.004",
    "scanning ip blocks": "T1595.001",
    "unix shell": "T1059.004",
    "vulnerability scanning": "T1595.002",
    "wordlist scanning": "T1595.003",
}

DEFAULT_SYSTEM = """The testbed is a Dockerized incident response digital twin designed for autonomous incident response research. It emulates a small segmented IT infrastructure with two networks: a client network (10.0.1.0/24) and a server network (10.0.2.0/24). These two networks are connected through a gateway container that functions both as a router and as a Snort IDS sensor.

The gateway container has IP address 10.0.1.10 on the client network and 10.0.2.10 on the server network. It runs Snort IDS for traffic monitoring and iptables for network control. A client container with IP address 10.0.1.11 resides on the client network and includes common network testing utilities such as nmap, hydra, curl, smbclient, and sshpass, which are used to generate experimental traffic.

The server network contains five servers. server_ssh at 10.0.2.11 provides OpenSSH. server_samba at 10.0.2.12 provides Samba file-sharing services. server_shellshock at 10.0.2.13 runs Apache with CGI support. In addition, server_web1 at 10.0.2.14 and server_web2 at 10.0.2.15 run Nginx and OpenSSH as additional web servers.

The gateway monitors traffic flowing between the client and server networks. """

DEFAULT_LOGS = """The IDS observed extensive ICMP traffic from the client-side attack platform, consistent with host discovery and reconnaissance across the server network.
The IDS detected repeated SSH connection attempts against the SSH server (10.0.2.11).
The IDS raised multiple alerts for a potential SSH brute force attack, indicating repeated authentication attempts against the SSH service.
The IDS detected repeated SMB traffic to the Samba server (10.0.2.12), including NetBIOS-related SMB traffic, consistent with probing or exploitation activity against the Samba service.
The IDS detected repeated HTTP traffic toward web-facing services in the server network.
The IDS raised multiple Shellshock attack attempt alerts against the Shellshock-vulnerable web server (10.0.2.13).
Overall, the alert stream indicates a multi-stage attack involving reconnaissance, password guessing or credential attacks, SMB probing or exploitation attempts, and web exploitation attempts originating from the attack platform (10.0.1.11) toward vulnerable services in the server network."""

PROMPT_TEMPLATE = """Below is a system description, a sequence of network logs (e.g., from an intrusion detection system), and an instruction that describes a task.
Write a response that appropriately completes the request.
Before generating the response, think carefully about the system, the logs, and the instruction, then create a step-by-step chain of thoughts to ensure a logical and accurate response.

### System:
{system}

### Logs:
{logs}

### Instruction:
You are a security operator with advanced knowledge in cybersecurity and IT systems.
You have been given information about a system and some logs generated by it, e.g., security alerts.
Your task is to determine if the logs indicate a cyber incident (i.e., attack) that requires recovery actions.
If the logs are just indicative of normal system activity or if they are unrelated to security, then you should classify the logs/system as not being an incident that requires recovery.
Similarly, if the logs contain very minor security alerts that do not warrant any recovery action, then you should classify the logs/system as not being an incident that requires recovery.
If there is an incident that requires action, you should concisely describe the incident and explain why it is an incident, i.e., you should indicate which parts of the logs or system description indicate that there is an incident that requires immediate action.
It is important that any conclusions you make in the incident description are supported by the logs/system description, don't make guesses.
You should also associate the incident with tactics and techniques from the MITRE ATT&CK taxonomy. You should also identify entities involved in the incident.
Return a JSON object with five fields: 'Incident', 'Incident description', 'MITRE ATT&CK Tactics', 'MITRE ATT&CK Techniques', and 'Entities'.
'Incident' should be a string that is either 'Yes' or 'No'.
'Incident description' should be a string with a concise summary of the incident and explanation of why the logs/system description indicate that there is an incident.
'MITRE ATT&CK Tactics' should be an array of strings, each of which corresponds to one tactic used by the attacker in the incident.
'MITRE ATT&CK Techniques' should be an array of strings, each of which corresponds to one technique used by the attacker in the incident.
For MITRE ATT&CK tactics and techniques, include only items directly supported by explicit evidence in the logs or analyst description.
Do not infer Privilege Escalation unless the logs show elevation from a lower-privileged user to a higher-privileged user.
Do not infer Persistence unless the logs show a durable mechanism to maintain access.
Do not infer Command and Control unless there is evidence of an ongoing attacker control channel.
Do not infer Valid Accounts or SSH Remote Services unless authentication succeeds.
Do not infer Web Shell unless a persistent web shell file or server software component is created.
Do not infer Exfiltration, Impact, Defense Evasion, or Credential Access unless explicit evidence is present.
A file write to an SMB share should be treated as unauthorized modification or lateral movement only, not Persistence by default.
'Entities' should be a JSON object with five properties: 'Attacker', 'System', 'Targeted', 'Compromised', and 'Recovery Targets'.
'Attacker' should be an array of strings, each of which is either an IP or a hostname that is related to the attacker/adversary.
'System' should be an array of strings, each of which is either an IP or a hostname that corresponds to some component in the system.
'Targeted' should be an array of strings, each of which is either an IP or a hostname that corresponds to some component in the system that is under attack, including systems that are probed or attacked but not necessarily compromised.
'Compromised' should be an array of strings, each of which is either an IP or a hostname that corresponds to a system with evidence of successful exploitation, unauthorized access, command execution, credential compromise, unauthorized file modification, or use as a pivot host.
'Recovery Targets' should be an array of strings, each of which is either an IP or a hostname that corresponds to a compromised or materially affected system that requires recovery actions. Do not include systems that were only scanned, probed, or found reachable unless the logs show compromise, unauthorized modification, service disruption, or required recovery.
If the 'Incident' field is set to 'No', then 'Incident description' should be 'No incident can be inferred from the logs because they contain no substantial information.', 'MITRE ATT&CK Tactics' should be an empty array, 'MITRE ATT&CK Techniques' should be an empty array, and 'Entities' should be an empty JSON object.
Return only the JSON with the above five fields, nothing else.

### Response:
<think>"""


def load_text_arg(inline_value: str | None, file_value: str | None, default_value: str) -> str:
    if file_value:
        return Path(file_value).read_text(encoding="utf-8")
    if inline_value:
        return inline_value
    return default_value


def load_model_and_tokenizer(
    checkpoint_path: str,
    dtype: torch.dtype,
) -> tuple[AutoTokenizer, AutoModelForCausalLM]:
    def resolve_local_hf_snapshot(model_name_or_path: str) -> str:
        path = Path(model_name_or_path)
        if path.exists():
            return str(path)
        cache_dir = (
            Path.home()
            / ".cache"
            / "huggingface"
            / "hub"
            / f"models--{model_name_or_path.replace('/', '--')}"
        )
        ref_path = cache_dir / "refs" / "main"
        if ref_path.exists():
            snapshot = cache_dir / "snapshots" / ref_path.read_text(encoding="utf-8").strip()
            if snapshot.exists():
                return str(snapshot)
        return model_name_or_path

    adapter_config_path = Path(checkpoint_path) / "adapter_config.json"
    if adapter_config_path.exists():
        adapter_meta = json.loads(adapter_config_path.read_text(encoding="utf-8"))
        base_model_name = resolve_local_hf_snapshot(str(adapter_meta["base_model_name_or_path"]))
        tokenizer = AutoTokenizer.from_pretrained(base_model_name, use_fast=True)
        base_model = AutoModelForCausalLM.from_pretrained(
            base_model_name,
            device_map="auto",
            torch_dtype=dtype,
        )
        model = PeftModel.from_pretrained(base_model, checkpoint_path)
    else:
        tokenizer = AutoTokenizer.from_pretrained(checkpoint_path, use_fast=True)
        model = AutoModelForCausalLM.from_pretrained(
            checkpoint_path,
            device_map="auto",
            torch_dtype=dtype,
        )

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model.eval()
    return tokenizer, model


def build_prompt(system_text: str, logs_text: str) -> str:
    return PROMPT_TEMPLATE.format(system=system_text.strip(), logs=logs_text.strip())


def generate_once(
    *,
    model: AutoModelForCausalLM,
    tokenizer: AutoTokenizer,
    prompt: str,
    max_new_tokens: int,
    temperature: float,
    top_p: float,
) -> str:
    inputs = tokenizer(prompt, return_tensors="pt")
    inputs = {k: v.to(model.device) for k, v in inputs.items()}

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
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            obj, _ = decoder.raw_decode(text[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def canonicalize_tactic(raw_tactic: Any) -> str | None:
    raw = str(raw_tactic).strip()
    if not raw:
        return None

    tactic_id_match = re.search(r"\bTA\d{4}\b", raw, flags=re.IGNORECASE)
    if tactic_id_match:
        tactic_id = tactic_id_match.group(0).upper()
        if tactic_id in TACTIC_ID_TO_NAME:
            return TACTIC_ID_TO_NAME[tactic_id]

    lowered = raw.lower().replace("&", "and")
    lowered = re.sub(r"[\(\)\[\]\{\}:,/-]+", " ", lowered)
    lowered = re.sub(r"\s+", " ", lowered).strip()
    if lowered in TACTIC_TEXT_ALIASES:
        return TACTIC_TEXT_ALIASES[lowered]

    compact = lowered.replace(" ", "_")
    if compact in TACTIC_TEXT_ALIASES:
        return TACTIC_TEXT_ALIASES[compact]

    for alias, canonical in TACTIC_TEXT_ALIASES.items():
        alias_tokens = alias.replace("_", " ")
        if re.search(rf"\b{re.escape(alias_tokens)}\b", lowered):
            return canonical

    return None


def sort_tactics_in_attack_order(tactics: list[str]) -> list[str]:
    return sorted(
        tactics,
        key=lambda tactic: (
            TACTIC_ORDER_INDEX.get(tactic, len(ATTACK_TACTIC_ORDER)),
            tactic,
        ),
    )


def normalize_attack_text(raw_text: str) -> str:
    lowered = raw_text.lower().replace("&", "and")
    lowered = re.sub(r"[\(\)\[\]\{\}:,/-]+", " ", lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def normalize_tactics(obj: dict[str, Any] | None) -> list[str]:
    if not isinstance(obj, dict):
        return []
    tactics = obj.get("MITRE ATT&CK Tactics", [])
    if not isinstance(tactics, list):
        return []

    seen: set[str] = set()
    normalized: list[str] = []
    for item in tactics:
        tactic = canonicalize_tactic(item)
        if tactic and tactic not in seen:
            seen.add(tactic)
            normalized.append(tactic)
    return sort_tactics_in_attack_order(normalized)


def canonicalize_technique(raw_technique: Any) -> str | None:
    raw = str(raw_technique).strip()
    if not raw:
        return None

    technique_id_match = re.search(
        r"\bT\d{4}(?:\.\d{3})?\b",
        raw,
        flags=re.IGNORECASE,
    )
    if technique_id_match:
        technique_id = technique_id_match.group(0).upper()
        technique_name = TECHNIQUE_ID_TO_NAME.get(technique_id)
        if technique_name:
            return f"{technique_id} {technique_name}"

    lowered = normalize_attack_text(raw)
    technique_id = TECHNIQUE_TEXT_ALIASES.get(lowered)
    if technique_id:
        return f"{technique_id} {TECHNIQUE_ID_TO_NAME[technique_id]}"

    for alias, alias_id in TECHNIQUE_TEXT_ALIASES.items():
        if re.search(rf"\b{re.escape(alias)}\b", lowered):
            return f"{alias_id} {TECHNIQUE_ID_TO_NAME[alias_id]}"

    return re.sub(r"\s+", " ", raw)


def normalize_techniques(obj: dict[str, Any] | None) -> list[str]:
    if not isinstance(obj, dict):
        return []
    techniques = obj.get("MITRE ATT&CK Techniques", [])
    if not isinstance(techniques, list):
        return []

    seen: set[str] = set()
    normalized: list[str] = []
    for item in techniques:
        technique = canonicalize_technique(item)
        if technique and technique not in seen:
            seen.add(technique)
            normalized.append(technique)
    return normalized


def normalize_entity_field(obj: dict[str, Any] | None, field: str) -> list[str]:
    if not isinstance(obj, dict):
        return []
    entities = obj.get("Entities", {})
    if not isinstance(entities, dict):
        return []
    values = entities.get(field, [])
    if not isinstance(values, list):
        return []

    seen: set[str] = set()
    normalized: list[str] = []
    for item in values:
        entity = str(item).strip()
        if entity and entity not in seen:
            seen.add(entity)
            normalized.append(entity)
    return normalized


def normalize_targeted_entities(obj: dict[str, Any] | None) -> list[str]:
    return normalize_entity_field(obj, "Targeted")


def normalize_compromised_entities(obj: dict[str, Any] | None) -> list[str]:
    return normalize_entity_field(obj, "Compromised")


def normalize_recovery_targets(obj: dict[str, Any] | None) -> list[str]:
    return normalize_entity_field(obj, "Recovery Targets")


def summarize_tactics(tactic_runs: list[list[str]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    total_runs = len(tactic_runs)
    for tactics in tactic_runs:
        for tactic in tactics:
            counts[tactic] += 1

    summary: list[dict[str, Any]] = []
    for tactic, count in sorted(
        counts.items(),
        key=lambda item: (
            -item[1],
            TACTIC_ORDER_INDEX.get(item[0], len(ATTACK_TACTIC_ORDER)),
            item[0],
        ),
    ):
        summary.append(
            {
                "tactic": tactic,
                "count": count,
                "ratio": count / total_runs if total_runs else 0.0,
            }
        )
    return summary


def summarize_techniques(technique_runs: list[list[str]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    total_runs = len(technique_runs)
    for techniques in technique_runs:
        for technique in techniques:
            counts[technique] += 1

    summary: list[dict[str, Any]] = []
    for technique, count in sorted(
        counts.items(),
        key=lambda item: (-item[1], item[0]),
    ):
        summary.append(
            {
                "technique": technique,
                "count": count,
                "ratio": count / total_runs if total_runs else 0.0,
            }
        )
    return summary


def summarize_entity_runs(entity_runs: list[list[str]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    total_runs = len(entity_runs)
    for entities in entity_runs:
        for entity in entities:
            counts[entity] += 1

    summary: list[dict[str, Any]] = []
    for entity, count in sorted(
        counts.items(),
        key=lambda item: (-item[1], item[0]),
    ):
        summary.append(
            {
                "entity": entity,
                "count": count,
                "ratio": count / total_runs if total_runs else 0.0,
            }
        )
    return summary


def summarize_targeted_entities(targeted_runs: list[list[str]]) -> list[dict[str, Any]]:
    return summarize_entity_runs(targeted_runs)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a fine-tuned checkpoint on the llm_ir_dt_new incident sample.",
    )
    parser.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT)
    parser.add_argument(
        "--dtype",
        choices=("float16", "bfloat16"),
        default="float16",
    )
    parser.add_argument("--max-new-tokens", type=int, default=1024)
    parser.add_argument("--temperature", type=float, default=0.5)
    parser.add_argument("--top-p", type=float, default=0.95)
    parser.add_argument("--num-runs", type=int, default=10)
    parser.add_argument("--top-k-tactics", type=int, default=6)
    parser.add_argument("--top-k-techniques", type=int, default=10)
    parser.add_argument("--top-k-targeted", type=int, default=10)
    parser.add_argument("--top-k-compromised", type=int, default=10)
    parser.add_argument("--top-k-recovery-targets", type=int, default=10)
    parser.add_argument("--system", default=None, help="Inline system description override.")
    parser.add_argument("--logs", default=None, help="Inline logs override.")
    parser.add_argument("--system-file", default=None, help="Path to system description file.")
    parser.add_argument("--logs-file", default=None, help="Path to logs file.")
    parser.add_argument(
        "--print-prompt",
        action="store_true",
        help="Print the final prompt before generation.",
    )
    args = parser.parse_args()

    dtype = torch.float16 if args.dtype == "float16" else torch.bfloat16
    system_text = load_text_arg(args.system, args.system_file, DEFAULT_SYSTEM)
    logs_text = load_text_arg(args.logs, args.logs_file, DEFAULT_LOGS)
    prompt = build_prompt(system_text, logs_text)

    if args.print_prompt:
        print("=== Prompt ===")
        print(prompt)
        print()

    tokenizer, model = load_model_and_tokenizer(args.checkpoint, dtype=dtype)
    outputs: list[dict[str, Any]] = []
    tactic_runs: list[list[str]] = []
    technique_runs: list[list[str]] = []
    targeted_runs: list[list[str]] = []
    compromised_runs: list[list[str]] = []
    recovery_target_runs: list[list[str]] = []

    for run_idx in range(args.num_runs):
        generated = generate_once(
            model=model,
            tokenizer=tokenizer,
            prompt=prompt,
            max_new_tokens=args.max_new_tokens,
            temperature=args.temperature,
            top_p=args.top_p,
        )
        parsed = extract_json_object(generated)
        tactics = normalize_tactics(parsed)
        techniques = normalize_techniques(parsed)
        targeted_entities = normalize_targeted_entities(parsed)
        compromised_entities = normalize_compromised_entities(parsed)
        recovery_targets = normalize_recovery_targets(parsed)
        tactic_runs.append(tactics)
        technique_runs.append(techniques)
        targeted_runs.append(targeted_entities)
        compromised_runs.append(compromised_entities)
        recovery_target_runs.append(recovery_targets)
        outputs.append(
            {
                "run": run_idx + 1,
                "raw_output": generated,
                "parsed_json": parsed,
                "tactics": tactics,
                "techniques": techniques,
                "targeted_entities": targeted_entities,
                "compromised_entities": compromised_entities,
                "recovery_targets": recovery_targets,
            }
        )

    tactic_summary = summarize_tactics(tactic_runs)
    technique_summary = summarize_techniques(technique_runs)
    targeted_summary = summarize_targeted_entities(targeted_runs)
    compromised_summary = summarize_entity_runs(compromised_runs)
    recovery_target_summary = summarize_entity_runs(recovery_target_runs)
    top_tactics = sort_tactics_in_attack_order(
        [item["tactic"] for item in tactic_summary[: args.top_k_tactics]]
    )
    top_techniques = [
        item["technique"] for item in technique_summary[: args.top_k_techniques]
    ]
    top_targeted_entities = [
        item["entity"] for item in targeted_summary[: args.top_k_targeted]
    ]
    top_compromised_entities = [
        item["entity"] for item in compromised_summary[: args.top_k_compromised]
    ]
    top_recovery_targets = [
        item["entity"]
        for item in recovery_target_summary[: args.top_k_recovery_targets]
    ]

    result = {
        "prompt": prompt,
        "num_runs": args.num_runs,
        "top_k_tactics": args.top_k_tactics,
        "top_k_techniques": args.top_k_techniques,
        "top_k_targeted": args.top_k_targeted,
        "top_k_compromised": args.top_k_compromised,
        "top_k_recovery_targets": args.top_k_recovery_targets,
        "outputs": outputs,
        "tactic_summary": tactic_summary,
        "technique_summary": technique_summary,
        "targeted_summary": targeted_summary,
        "compromised_summary": compromised_summary,
        "recovery_target_summary": recovery_target_summary,
        "MITRE ATT&CK Tactics": top_tactics,
        "MITRE ATT&CK Techniques": top_techniques,
        "Targeted Entities": top_targeted_entities,
        "Compromised Entities": top_compromised_entities,
        "Recovery Targets": top_recovery_targets,
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
