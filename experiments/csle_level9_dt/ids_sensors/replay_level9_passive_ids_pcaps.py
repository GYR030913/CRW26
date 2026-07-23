#!/usr/bin/env python3
"""Replay passive level9 IDS pcaps through Snort in the router container."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_RULES = REPO_ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "snort_rules" / "level9_execution15_local.rules"


def run(cmd: list[str], timeout: int = 120) -> dict[str, Any]:
    proc = subprocess.run(
        cmd,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return {"cmd": cmd, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def docker_exec(container: str, shell_cmd: str, timeout: int = 120) -> dict[str, Any]:
    return run(["docker", "exec", container, "bash", "-lc", shell_cmd], timeout=timeout)


def materialize_execution_rules(rules: Path, execution_id: int, out_dir: Path) -> Path:
    """Create a replay rules file with the execution-specific first octet."""
    rules_text = rules.read_text(encoding="utf-8")
    if execution_id != 15:
        rules_text = rules_text.replace("15.9.", f"{execution_id}.9.")
    generated = out_dir / f"level9_execution{execution_id}_local.rules"
    generated.write_text(rules_text, encoding="utf-8")
    return generated


def replay_pcap(router_container: str, pcap: Path, rules: Path, out_dir: Path) -> dict[str, Any]:
    sensor_name = pcap.stem
    remote_pcap = f"/tmp/{pcap.name}"
    remote_rules = "/tmp/level9_ids_local.rules"
    remote_out = f"/tmp/snort_replay_{sensor_name}"
    local_out = out_dir / f"{sensor_name}_fast.log"

    copy_rules = run(["docker", "cp", str(rules), f"{router_container}:{remote_rules}"])
    copy_pcap = run(["docker", "cp", str(pcap), f"{router_container}:{remote_pcap}"])
    replay_cmd = (
        f"rm -rf {remote_out}; mkdir -p {remote_out}; "
        "cp /etc/snort/rules/local.rules /tmp/local.rules.before_replay 2>/dev/null || true; "
        f"cp {remote_rules} /etc/snort/rules/local.rules; "
        "cp /etc/snort/snort.conf /etc/snort/snort_replay.conf; "
        "sed -i "
        "-e 's/^config policy_mode:inline/# replay disables inline policy mode/' "
        "-e 's/^config daq: afpacket/# replay disables afpacket daq/' "
        "-e 's/^config daq_mode: inline/# replay disables inline daq mode/' "
        "-e 's/^config daq_var: buffer_size_mb=1024/# replay disables afpacket buffer/' "
        "/etc/snort/snort_replay.conf; "
        f"snort -q -A fast -k none -c /etc/snort/snort_replay.conf -r {remote_pcap} -l {remote_out} "
        "> /tmp/snort_replay_stdout.log 2> /tmp/snort_replay_stderr.log; "
        "rc=$?; "
        f"test -f {remote_out}/alert && cp {remote_out}/alert {remote_out}/fast.log || true; "
        "cat /tmp/snort_replay_stdout.log; cat /tmp/snort_replay_stderr.log >&2; "
        "exit $rc"
    )
    replay = docker_exec(router_container, replay_cmd, timeout=240)
    fetch = run(["docker", "cp", f"{router_container}:{remote_out}/fast.log", str(local_out)])
    if fetch["returncode"] != 0:
        local_out.write_text("", encoding="utf-8")
    return {
        "sensor": sensor_name,
        "pcap": str(pcap),
        "local_fast_log": str(local_out),
        "copy_rules": copy_rules,
        "copy_pcap": copy_pcap,
        "replay": replay,
        "fetch": fetch,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay level9 passive IDS pcaps through Snort.")
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--execution-id", type=int, required=True)
    parser.add_argument("--router-container", default=None)
    parser.add_argument("--rules", default=str(DEFAULT_RULES))
    args = parser.parse_args()

    session_dir = Path(args.session_dir)
    out_dir = session_dir / "snort_replay"
    out_dir.mkdir(parents=True, exist_ok=True)
    router_container = args.router_container or f"csle_router_2_1-level9-{args.execution_id}"
    rules = materialize_execution_rules(Path(args.rules), args.execution_id, out_dir)
    pcaps = sorted(session_dir.glob("*.pcap"))
    results = [replay_pcap(router_container, pcap, rules, out_dir) for pcap in pcaps]
    summary = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "router_container": router_container,
        "rules": str(rules),
        "session_dir": str(session_dir),
        "results": results,
    }
    summary_path = out_dir / "snort_replay_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(summary_path)
    for result in results:
        fast_log = Path(result["local_fast_log"])
        lines = fast_log.read_text(encoding="utf-8", errors="replace").splitlines() if fast_log.exists() else []
        print(f"{result['sensor']}: alerts={len(lines)} log={fast_log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
