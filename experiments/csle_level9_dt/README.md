# CSLE Level9 Digital Twin

This directory contains a level9-specific digital twin scaffold. It is not based
on the older `llm_ir_dt_new` topology. The DT topology, container list, services,
vulnerabilities, flags, users, firewall nodes, and static attacker sequences are
exported directly from:

`external/csle/emulation-system/envs/0.10.0/level_9/config.py`

The manifest intentionally keeps CSLE address templates such as
`<EXECUTION_ID>.9.2.78`. For a running execution with first octet `15`, that host
is resolved as `15.9.2.78`.

## Generate Manifest

```bash
CSLE_HOME=/home/yu3194924316/llm-recovery-dt/external/csle \
  /home/yu3194924316/llm-recovery-dt/external/csle/.venv/bin/python \
  experiments/csle_level9_dt/export_level9_manifest.py
```

The output is written to:

`experiments/csle_level9_dt/level9_manifest.json`

## Manifest Scope

The generated manifest includes:

- 33 CSLE level9 containers/nodes.
- 33 topology firewall node configs.
- service definitions per node.
- user definitions per node.
- vulnerability definitions per node.
- flag definitions per node.
- all three static attacker sequences: `novice`, `experienced`, `expert`.

This is the source of truth for the level9 DT. Recovery adapters and observation
normalizers should consume this manifest instead of reusing old `10.0.x.x`
digital-twin assumptions.
