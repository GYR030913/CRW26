# Level9 OVS Mirror Plan

## Goal

Build a longer-term IDS topology where Snort sees level9 lateral movement traffic through live mirror ports, rather than relying on sidecar tcpdump plus offline Snort replay.

This is intended for a future `csle-level9-ids-0.10.0` variant. The original `csle-level9-0.10.0` should remain unchanged so true/DT comparisons are not polluted by ad hoc topology edits.

## Current Findings

The existing level9 execution uses Docker overlay networks:

```text
csle_net_9_2_15 overlay
csle_net_9_4_15 overlay
csle_net_9_5_15 overlay
csle_net_9_6_15 overlay
csle_net_9_7_15 overlay
```

The host initially did not expose a ready OVS setup:

```text
ovs-vsctl: missing
openvswitch kernel module: not loaded
local csle_ovs image: missing
```

After pulling `kimham/csle_ovs_1:0.10.0`, the image blocker is resolved, but
the host kernel blocker remains:

```text
kimham/csle_ovs_1:0.10.0: available
openvswitch kernel module: missing from /lib/modules/6.8.0-1063-gcp
```

A privileged probe container could run `ovs-vsctl --version`, but OVS startup
reported:

```text
modprobe: FATAL: Module openvswitch not found in directory /lib/modules/6.8.0-1063-gcp
```

The probe did not reach a usable bridge state, so this GCP VM currently cannot
run a practical OVS datapath without installing/enabling host Open vSwitch
support or moving to a kernel/image that includes the module.

CSLE has OVS support, but level9 currently returns an empty OVS config:

```python
OVSConfig(switch_configs=[])
```

Level12 is the CSLE example that actually places `csle_ovs_1` containers into the emulation and configures them as OVS switches.

## Why Direct Mirror On Current Level9 Is Not Enough

The current level9 subnets are Docker overlay networks. A normal IDS container attached to `csle_net_9_4_15` only saw ARP, not third-party unicast traffic such as:

```text
15.9.4.3 -> 15.9.4.74
```

This means adding another ordinary container to the subnet is not equivalent to switch port mirroring.

## Proposed OVS Variant

Create a new environment:

```text
csle-level9-ids-0.10.0
```

It should preserve level9 services, vulnerabilities, static sequences, and host IP semantics, but add OVS/IDS visibility for the lateral movement subnets:

```text
15.9.2.0/24  SambaCry / SSH weak-password path
15.9.4.0/24  Samba -> DVWA SQL injection path
15.9.5.0/24  DVWA -> Elasticsearch CVE-2015-1427 path
15.9.6.0/24  expert path toward 15.9.6.7
15.9.7.0/24  Elasticsearch multi-homed exposure
```

## Implementation Direction

Preferred design:

```text
target subnet traffic
    -> OVS bridge/switch
        -> normal forwarding path
        -> mirrored copy to Snort IDS port
```

This is better than inline IDS because the IDS does not become part of the forwarding path and should not change attack timing or reachability.

## Phased Work

1. Install/enable host OVS support.
2. Verify `ovs-vsctl`, the `openvswitch` kernel module, and a privileged `csle_ovs_1` probe.
3. Study level12 OVS container wiring and copy the minimal pattern.
4. Create a level9 IDS variant instead of modifying original level9.
5. Add OVS mirror for one subnet first, preferably `15.9.4.0/24`.
6. Validate with a simple probe that IDS sees third-party unicast traffic.
7. Run experienced attack and compare alerts against sidecar baseline.
8. Extend to `15.9.2.0/24`, `15.9.5.0/24`, `15.9.6.0/24`, and `15.9.7.0/24`.
9. Only after true execution 15 works, repeat the same environment for DT execution 16.

## Current Recommendation

Do not replace the working sidecar pipeline yet. Use it as the baseline while the OVS mirror variant is built. The sidecar pipeline already captures experienced high-level alerts; OVS mirror is a topology improvement, not a blocker for model input generation.
