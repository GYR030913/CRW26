#!/usr/bin/env python3
"""Start or stop passive packet captures for CSLE level9 IDS coverage.

This script captures the lateral-movement subnets that the default level9
router Snort sensor cannot see. The default sidecar mode runs temporary
tcpdump containers in the network namespace of the relevant level9 pivot
containers. The generated pcaps are intended for offline Snort replay with
replay_level9_passive_ids_pcaps.py.

Example:
    sudo python experiments/csle_level9_dt/ids_sensors/start_level9_passive_ids_capture.py start \
      --execution-id 15 --label experienced

    sudo python experiments/csle_level9_dt/ids_sensors/start_level9_passive_ids_capture.py stop \
      --session-dir experiments/csle_level9_dt/artifacts/ids_sensors/level9_15_experienced_...
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACT_ROOT = REPO_ROOT / "experiments" / "csle_level9_dt" / "artifacts" / "ids_sensors"
DEFAULT_CONFIG = Path(__file__).resolve().with_name("level9_ids_sensors.json")


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_config(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run(cmd: list[str], timeout: int = 30) -> dict[str, Any]:
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


def resolve_container_interface(container: str, subnet: str, fallback: str) -> tuple[str, dict[str, Any]]:
    """Find the interface inside a container that owns an address in subnet."""
    result = run(["docker", "exec", container, "ip", "-o", "-4", "addr", "show"], timeout=20)
    if result["returncode"] != 0:
        return fallback, {"method": "fallback", "reason": "ip_addr_failed", "result": result}

    network = ipaddress.ip_network(subnet, strict=False)
    parsed = []
    for line in result["stdout"].splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[2] != "inet":
            continue
        interface = fields[1]
        cidr = fields[3]
        try:
            address = ipaddress.ip_interface(cidr).ip
        except ValueError:
            continue
        parsed.append({"interface": interface, "cidr": cidr, "ip": str(address)})
        if address in network:
            return interface, {
                "method": "subnet_match",
                "subnet": subnet,
                "matched_interface": interface,
                "matched_cidr": cidr,
                "interfaces": parsed,
            }
    return fallback, {
        "method": "fallback",
        "reason": "no_subnet_match",
        "subnet": subnet,
        "fallback": fallback,
        "interfaces": parsed,
    }


def start(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    session_dir = Path(args.out_dir or DEFAULT_ARTIFACT_ROOT / f"level9_{args.execution_id}_{args.label}_{timestamp()}")
    session_dir.mkdir(parents=True, exist_ok=True)

    processes = []
    for sensor in config["passive_capture_sensors"]:
        sensor_id = sensor["id"]
        subnet = sensor["subnet"].replace("15.", f"{args.execution_id}.", 1)
        pcap_path = session_dir / f"{sensor_id}_{subnet.replace('/', '_').replace('.', '_')}.pcap"
        log_path = session_dir / f"{sensor_id}_tcpdump.log"
        if args.mode == "host":
            capture_interface = args.interface
            cmd = [
                "tcpdump",
                "-i",
                capture_interface,
                "-U",
                "-s",
                "0",
                "-nn",
                "-w",
                str(pcap_path),
                f"net {subnet}",
            ]
            log_file = log_path.open("ab")
            proc = subprocess.Popen(cmd, stdout=log_file, stderr=log_file)
            pid = proc.pid
            container_name = None
            capture_target = "host"
        else:
            target_container = sensor["sidecar_container_template"].format(execution_id=args.execution_id)
            configured_interface = sensor.get("sidecar_interface", args.interface)
            if args.resolve_interface_by_subnet:
                capture_interface, interface_resolution = resolve_container_interface(
                    target_container, subnet, configured_interface
                )
            else:
                capture_interface = configured_interface
                interface_resolution = {"method": "configured", "configured_interface": configured_interface}
            container_name = f"level9_ids_{args.execution_id}_{args.label}_{sensor_id}".replace("-", "_")
            run(["docker", "rm", "-f", container_name], timeout=20)
            docker_cmd = [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "--network",
                f"container:{target_container}",
                "--cap-add",
                "NET_ADMIN",
                "--cap-add",
                "NET_RAW",
                "-v",
                f"{session_dir.resolve()}:/captures",
                args.sidecar_image,
                "bash",
                "-lc",
                (
                    f"tcpdump -i {capture_interface} -U -s 0 -nn "
                    f"-w /captures/{pcap_path.name} 'net {subnet}' "
                    f">/captures/{log_path.name} 2>&1"
                ),
            ]
            result = run(docker_cmd, timeout=30)
            if result["returncode"] != 0:
                raise RuntimeError(f"failed to start sidecar {container_name}: {result}")
            pid = None
            capture_target = target_container
        processes.append(
            {
                "sensor_id": sensor_id,
                "subnet": subnet,
                "pcap": str(pcap_path),
                "log": str(log_path),
                "pid": pid,
                "mode": args.mode,
                "interface": capture_interface,
                "configured_interface": sensor.get("sidecar_interface", args.interface),
                "interface_resolution": interface_resolution,
                "sidecar_container": container_name,
                "capture_target": capture_target,
                "cmd": cmd if args.mode == "host" else docker_cmd,
                "reason": sensor["reason"],
            }
        )

    metadata = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "execution_id": args.execution_id,
        "label": args.label,
        "mode": args.mode,
        "interface": args.interface,
        "session_dir": str(session_dir),
        "processes": processes,
    }
    (session_dir / "capture_session.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"started {len(processes)} passive IDS captures")
    print(session_dir)
    for item in processes:
        print(
            f"{item['sensor_id']} mode={item['mode']} target={item['capture_target']} "
            f"sidecar={item['sidecar_container']} pid={item['pid']} subnet={item['subnet']} pcap={item['pcap']}"
        )
    return 0


def stop(args: argparse.Namespace) -> int:
    session_dir = Path(args.session_dir)
    metadata_path = session_dir / "capture_session.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    stopped = []
    for item in metadata["processes"]:
        if item.get("mode") == "sidecar":
            container = item.get("sidecar_container")
            result = run(["docker", "rm", "-f", container], timeout=30)
            status = "removed" if result["returncode"] == 0 else f"remove_failed:{result['stderr']}"
        else:
            pid = int(item["pid"])
            status = "not_running"
            try:
                os.kill(pid, signal.SIGTERM)
                status = "terminated"
                time.sleep(0.2)
            except ProcessLookupError:
                pass
            except PermissionError:
                status = "permission_denied"
        item["stop_status"] = status
        stopped.append(item)
    metadata["stopped_at_utc"] = datetime.now(timezone.utc).isoformat()
    metadata["processes"] = stopped
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"stopped captures recorded in {metadata_path}")
    return 0


def status(args: argparse.Namespace) -> int:
    metadata = json.loads((Path(args.session_dir) / "capture_session.json").read_text(encoding="utf-8"))
    for item in metadata["processes"]:
        if item.get("mode") == "sidecar":
            container = item.get("sidecar_container")
            inspect = run(["docker", "inspect", "-f", "{{.State.Running}}", container], timeout=10)
            running = inspect["returncode"] == 0 and inspect["stdout"].strip() == "true"
            pid = item.get("pid")
        else:
            pid = int(item["pid"])
            running = Path(f"/proc/{pid}").exists()
        pcap = Path(item["pcap"])
        size = pcap.stat().st_size if pcap.exists() else 0
        print(f"{item['sensor_id']} pid={pid} running={running} pcap_bytes={size} subnet={item['subnet']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage passive IDS packet captures for CSLE level9.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    start_parser = subparsers.add_parser("start")
    start_parser.add_argument("--execution-id", type=int, required=True)
    start_parser.add_argument("--label", default="attack")
    start_parser.add_argument("--interface", default="any")
    start_parser.add_argument("--mode", choices=["sidecar", "host"], default="sidecar")
    start_parser.add_argument("--sidecar-image", default="kimham/csle_hacker_kali_1:0.10.0")
    start_parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    start_parser.add_argument("--out-dir", default=None)
    start_parser.add_argument(
        "--no-resolve-interface-by-subnet",
        action="store_false",
        dest="resolve_interface_by_subnet",
        help="Use configured sidecar interfaces verbatim instead of resolving the current container interface by subnet.",
    )
    start_parser.set_defaults(resolve_interface_by_subnet=True)
    start_parser.set_defaults(func=start)

    stop_parser = subparsers.add_parser("stop")
    stop_parser.add_argument("--session-dir", required=True)
    stop_parser.set_defaults(func=stop)

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--session-dir", required=True)
    status_parser.set_defaults(func=status)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
