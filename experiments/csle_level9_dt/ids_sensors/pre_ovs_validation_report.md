# Pre-OVS IDS Validation Report

Date: 2026-07-15

## Goal

Validate whether we can capture level9 lateral movement traffic before building
a full OVS live mirror topology.

Target lateral movement coverage:

- `15.9.4.0/24`: Samba host `15.9.4.3` to DVWA host `15.9.4.74`
- `15.9.5.0/24`: DVWA host `15.9.5.74` to Elasticsearch host `15.9.5.62`
- `15.9.6.0/24`: Elasticsearch host `15.9.6.62` to Samba target `15.9.6.7`
- `15.9.7.0/24`: Elasticsearch host `15.9.7.62` to 15.9.7 subnet hosts

## Result

The simple sensor-container approach is not enough.

A temporary container attached directly to `csle_net_9_4_15` saw only ARP for
`15.9.4.3 -> 15.9.4.74`, not the unicast ICMP/HTTP traffic. This confirms that
just adding a normal container to the subnet does not provide full subnet
visibility.

The sidecar capture approach works.

A temporary sidecar container using `--network container:<target-container>`
successfully captured unicast traffic on the relevant source/pivot host
interfaces. For example, the Samba sidecar captured:

```text
15.9.4.3 -> 15.9.4.74 ICMP
15.9.4.3 -> 15.9.4.74 TCP/80 HTTP
```

The generated pcap files were successfully replayed through Snort after using
Ethernet interfaces instead of `tcpdump -i any`.

## Validated Capture Points

The current sidecar mapping is:

```text
ids-4: csle_samba_2_1-level9-15, interface eth2, subnet 15.9.4.0/24
ids-5: csle_sql_injection_1_1-level9-15, interface eth2, subnet 15.9.5.0/24
ids-6: csle_cve_2015_1427_1_1-level9-15, interface eth3, subnet 15.9.6.0/24
ids-7: csle_cve_2015_1427_1_1-level9-15, interface eth4, subnet 15.9.7.0/24
```

Validation output:

```text
ids-4 pcap: 15.9.4.3 -> 15.9.4.74 ICMP and HTTP
ids-5 pcap: 15.9.5.74 -> 15.9.5.62 ICMP and TCP/9200 attempt
ids-6 pcap: 15.9.6.62 -> 15.9.6.7 ICMP
ids-7 pcap: 15.9.7.62 -> 15.9.7.15 ICMP
```

Snort replay output:

```text
ids-4: 12 alerts
ids-5: 12 alerts
ids-6: 12 alerts
ids-7: 12 alerts
```

The validation session is stored at:

```text
experiments/csle_level9_dt/artifacts/ids_sensors/level9_15_sidecar_probe_eth_20260715T105954Z
```

## Interpretation

This validates the capture/replay pipeline:

```text
sidecar tcpdump -> pcap -> Snort replay -> per-subnet fast.log -> merged IDS log
```

It does not yet validate high-level SQLi/CVE alerts, because the probe traffic
was simple ICMP/HTTP reachability traffic. High-level alerts should be validated
by running the real `experienced` or `expert` sequence while sidecar capture is
active.

## Implication For OVS

The ordinary sensor-container test supports the need for OVS mirror:

```text
normal container in subnet: sees ARP only, not third-party unicast
sidecar on source/pivot host: sees source/pivot traffic
OVS mirror: needed for clean subnet-wide passive IDS visibility
```

The sidecar method is therefore a low-risk pre-OVS validation layer. It preserves
the original CSLE level9 topology and helps confirm which subnets and rules are
worth moving into a later live OVS mirror variant.
