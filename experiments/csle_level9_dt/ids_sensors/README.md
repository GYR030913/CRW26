# Level9 IDS Sensors

This directory adds sidecar passive IDS coverage for the CSLE level9 lateral
movement subnets without modifying the original `csle-level9-0.10.0` topology.

Current coverage:

- Existing router Snort sensor: `15.9.1.0/24 <-> 15.9.2.0/24`
- Passive capture sensor `ids-4`: `15.9.4.0/24`
- Passive capture sensor `ids-5`: `15.9.5.0/24`
- Passive capture sensor `ids-6`: `15.9.6.0/24`
- Passive capture sensor `ids-7`: `15.9.7.0/24`

Workflow:

```bash
cd /home/yu3194924316/llm-recovery-dt

/home/yu3194924316/llm-recovery-dt/external/csle/.venv/bin/python \
  experiments/csle_level9_dt/ids_sensors/start_level9_passive_ids_capture.py start \
  --execution-id 15 \
  --label experienced

# Run the CSLE attack in another terminal.

/home/yu3194924316/llm-recovery-dt/external/csle/.venv/bin/python \
  experiments/csle_level9_dt/ids_sensors/start_level9_passive_ids_capture.py stop \
  --session-dir <printed-session-dir>

/home/yu3194924316/llm-recovery-dt/external/csle/.venv/bin/python \
  experiments/csle_level9_dt/ids_sensors/replay_level9_passive_ids_pcaps.py \
  --execution-id 15 \
  --session-dir <printed-session-dir>

/home/yu3194924316/llm-recovery-dt/external/csle/.venv/bin/python \
  experiments/csle_level9_dt/ids_sensors/merge_level9_ids_alerts.py \
  --execution-id 15 \
  --session-dir <printed-session-dir>
```

The replay step writes per-subnet Snort fast logs under:

```text
<session-dir>/snort_replay/
<session-dir>/merged_ids_fast.log
```

This is not yet a true OVS mirror topology. It is the first practical
instrumentation layer: sidecar passive capture plus offline Snort replay.
It preserves the attack path and does not replace the original level9
environment. A later `csle-level9-ids-0.10.0` variant can replace this with
live OVS mirror sensors if needed.
