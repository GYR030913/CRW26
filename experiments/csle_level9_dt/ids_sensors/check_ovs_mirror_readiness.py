#!/usr/bin/env python3
"""Check whether the current host can run a level9 OVS mirror prototype."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def run(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def docker_network(name: str) -> dict:
    rc, out, _ = run(["docker", "network", "inspect", name])
    if rc != 0 or not out:
        return {"name": name, "exists": False}
    data = json.loads(out)[0]
    return {
        "name": name,
        "exists": True,
        "driver": data.get("Driver"),
        "scope": data.get("Scope"),
        "subnets": [item.get("Subnet") for item in data.get("IPAM", {}).get("Config", [])],
        "vxlan_id": data.get("Options", {}).get("com.docker.network.driver.overlay.vxlanid_list"),
        "container_count": len(data.get("Containers", {})),
    }


def main() -> int:
    print("OVS mirror readiness")
    print("====================")
    ovs_vsctl = shutil.which("ovs-vsctl")
    print(f"ovs-vsctl: {ovs_vsctl or 'missing'}")

    rc, lsmod_out, _ = run(["bash", "-lc", "lsmod | rg '^openvswitch\\b|^vxlan\\b|^bridge\\b' || true"])
    print("kernel_modules:")
    print(lsmod_out or "  none matched")

    rc, images_out, _ = run(["bash", "-lc", "docker images --format '{{.Repository}}:{{.Tag}}' | rg 'ovs|csle_ovs' || true"])
    print("ovs_images:")
    print(images_out or "  none")

    for subnet in (2, 4, 5, 6, 7):
        info = docker_network(f"csle_net_9_{subnet}_15")
        print(json.dumps(info, indent=2))

    print()
    if not ovs_vsctl:
        print("BLOCKER: openvswitch userspace tools are not installed on the host.")
    if "openvswitch" not in lsmod_out:
        print("BLOCKER: openvswitch kernel module is not loaded.")
    if not images_out:
        print("BLOCKER: no local CSLE OVS image is available.")
    print("NOTE: current level9 networks are Docker overlay networks; live OVS mirror requires a new topology or OVS switch containers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
