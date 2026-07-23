"""Lightweight state model for the CSLE level9 digital twin."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_MANIFEST = Path(__file__).resolve().with_name("level9_manifest.json")


def resolve_execution_ip(value: str, execution_first_octet: int) -> str:
    """Resolve a CSLE `<EXECUTION_ID>` address template."""
    return value.replace("<EXECUTION_ID>", str(execution_first_octet))


@dataclass
class HostState:
    """DT state for one CSLE level9 host."""

    ip_template: str
    hostname: str
    services: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    users: list[dict[str, Any]] = field(default_factory=list)
    flags: list[dict[str, Any]] = field(default_factory=list)
    credentials_found: list[dict[str, Any]] = field(default_factory=list)
    logged_in: bool = False
    root: bool = False
    backdoor_users: list[str] = field(default_factory=list)

    def resolved_ip(self, execution_first_octet: int) -> str:
        return resolve_execution_ip(self.ip_template, execution_first_octet)


@dataclass
class Level9DTState:
    """In-memory level9 DT state initialized from the CSLE-derived manifest."""

    manifest: dict[str, Any]
    hosts: dict[str, HostState]
    attacker_actions: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_manifest(cls, manifest_path: Path = DEFAULT_MANIFEST) -> "Level9DTState":
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        hosts: dict[str, HostState] = {}

        for node in manifest["topology_nodes"]:
            ip_templates = [
                item["ip"]
                for item in node["ips_gw_default_policy_networks"]
                if item.get("ip")
            ]
            if not ip_templates:
                continue
            primary_ip = ip_templates[0]
            hosts[primary_ip] = HostState(
                ip_template=primary_ip,
                hostname=node["hostname"],
            )

        for service_cfg in manifest["services"]:
            host = hosts.setdefault(
                service_cfg["ip"],
                HostState(ip_template=service_cfg["ip"], hostname=service_cfg["ip"]),
            )
            host.services.extend(service_cfg.get("services", []))

        for vuln_cfg in manifest["vulnerabilities"]:
            host = hosts.setdefault(
                vuln_cfg["ip"],
                HostState(ip_template=vuln_cfg["ip"], hostname=vuln_cfg["ip"]),
            )
            host.vulnerabilities.append(vuln_cfg)

        for user_cfg in manifest["users"]:
            host = hosts.setdefault(
                user_cfg["ip"],
                HostState(ip_template=user_cfg["ip"], hostname=user_cfg["ip"]),
            )
            host.users.extend(user_cfg.get("users", []))

        for flag_cfg in manifest["flags"]:
            host = hosts.setdefault(
                flag_cfg["ip"],
                HostState(ip_template=flag_cfg["ip"], hostname=flag_cfg["ip"]),
            )
            host.flags.extend(flag_cfg.get("flags", []))

        return cls(manifest=manifest, hosts=hosts)

    def apply_compromised_observation(
        self,
        *,
        ip: str,
        credentials: list[dict[str, Any]] | None = None,
        logged_in: bool = False,
        root: bool = False,
        backdoor_users: list[str] | None = None,
    ) -> None:
        """Apply one observed CSLE compromised-state entry to the DT."""
        host = self.hosts.setdefault(ip, HostState(ip_template=ip, hostname=ip))
        host.credentials_found.extend(credentials or [])
        host.logged_in = host.logged_in or logged_in
        host.root = host.root or root
        for user in backdoor_users or []:
            if user not in host.backdoor_users:
                host.backdoor_users.append(user)

    def compromised_hosts(self) -> list[dict[str, Any]]:
        """Return hosts with credentials, login, root, or backdoor evidence."""
        result = []
        for host in self.hosts.values():
            if host.credentials_found or host.logged_in or host.root or host.backdoor_users:
                result.append(
                    {
                        "ip_template": host.ip_template,
                        "hostname": host.hostname,
                        "credentials_found": host.credentials_found,
                        "logged_in": host.logged_in,
                        "root": host.root,
                        "backdoor_users": host.backdoor_users,
                    }
                )
        return result
