# CSLE Level9 与 DT 闭环实验设计草案

## 核心建议

本实验需要的是“可执行系统级 DT”，不是简单状态机。因此 DT 也应该是一套 CSLE level9 execution：有同样的 nodes、containers、services、logs、static sequences、Docker 命令执行能力。

```text
CSLE true = level9 true emulation execution
DT        = second level9 emulation execution, used as the digital twin
```

也就是说：

- CSLE true 和 DT 都由 CSLE level9 配置启动。
- 两边都有真实 Docker containers。
- 两边都可以执行真实 recovery commands。
- 两边都可以收集 service/auth/host/network/IDS logs。
- DT 仍然根据 true CSLE 的观测推断 attack tactics/techniques，并生成 recovery actions。
- 同一组 recovery actions：
  - 在 DT execution 里执行一遍真实命令。
  - 在 CSLE true execution 里执行一遍真实命令。
- 最后比较两边 recovery 后的 normalized observations。

最推荐的实现不是复制 CSLE 源码，而是用同一个 CSLE stack 启动两套 level9 execution：

```text
true execution: 15.9.x.x, containers end with level9-15
DT execution:   16.9.x.x, containers end with level9-16
```

这样 DT 和 true emulation 都是 level9，但 IP first octet 和 container suffix 不同。adapter 只需要把同一个逻辑目标从 true execution 映射到 DT execution：

```text
15.9.2.78  -> 16.9.2.78
csle_ssh_1_1-level9-15 -> csle_ssh_1_1-level9-16
```

## 推荐闭环流程

```text
1. Start CSLE level9
2. Run one static attack sequence in CSLE true, e.g. novice
3. Collect true CSLE observations
4. Build incident bundle from true CSLE observations
5. Feed incident bundle to DT inference
6. DT infers attack tactics / techniques / affected hosts / confidence
7. DT infers or selects an attack sequence, e.g. novice / experienced / expert
8. Run the inferred attack sequence in the DT level9 execution
9. Collect pre-recovery DT observations and check whether they align with true CSLE post-attack observations
10. DT generates recovery actions based on its inferred attack and DT observations
11. Apply recovery actions to DT level9 containers
12. Apply same recovery actions to CSLE true level9 containers
13. Collect post-recovery observations from both DT and true CSLE
14. Compare DT recovery output vs true CSLE recovery output
```

这里 DT 可以真实执行 recovery commands。是否在 DT 中也重放 attack，要看实验阶段：

```text
true CSLE 执行真实 attack
DT 根据 true observations 猜测 attack sequence
DT 在自己的 level9 execution 中执行猜测出来的 attack sequence
DT 基于猜测和自身 attack 结果生成 recovery actions
同一组 recovery actions 分别在 DT 和 true CSLE 中真实执行
最后比较两边 recovery output
```

如果 DT 猜错 attack sequence，那么 DT replay 后的 pre-recovery observations 可能无法对齐 true CSLE post-attack observations；后续 recovery output 也更可能不一致。这种不一致正是实验用来判断 DT attack inference 是否准确的证据。

这里的“same recovery actions”仍然建议先定义为同一组高层语义动作，然后由 adapter 翻译成两边各自的具体 container/IP 命令。由于两边都是 level9，命令模板可以完全相同，只替换 execution id、IP first octet 和 container suffix。

```text
same high-level recovery action
  -> DT adapter: concrete commands against level9-16 containers / 16.9.x.x
  -> CSLE adapter: concrete commands against level9-15 containers / 15.9.x.x
```

例如高层动作是：

```json
{
  "id": "disable_compromised_ssh_user",
  "target_ip": "15.9.2.78",
  "account": "puppet",
  "expected_effect": {
    "attacker_login_blocked": true,
    "ssh_service_available": true,
    "root_compromise_removed": true
  }
}
```

在 DT execution 中执行真实命令：

```bash
docker exec <container_for_16.9.2.78> passwd -l puppet
docker exec <container_for_16.9.2.78> pkill -KILL -u puppet
docker exec <container_for_16.9.2.78> service ssh restart
```

在 CSLE true execution 中也执行真实命令：

```bash
docker exec <container_for_15.9.2.78> passwd -l puppet
docker exec <container_for_15.9.2.78> pkill -KILL -u puppet
docker exec <container_for_15.9.2.78> service ssh restart
```

最后比较两边命令输出、logs 和 expected effect。命令输出可以作为证据保存，但核心评价仍建议用 normalized observations：

```text
attacker 是否不能再 SSH 登录
SSH 服务是否仍然可用
root compromise 状态是否被清除
相关告警或失败登录是否停止增长
```

如果 DT 初始状态和 CSLE true 初始状态不一致，比较结果会失真。因此每次闭环前必须先做 execution alignment：确认两边由同一个 level9 manifest 启动，并且 recovery 前关键观测一致或已被校准一致。

## 建议代码结构

```text
experiments/csle_level9_dt/
  level9_manifest.json
  dt_state.py
  execution_mapping.py
  csle_attack_runner.py
  csle_observation_collector.py
  incident_normalizer.py
  dt_inference.py
  recovery_actions.py
  dt_recovery_executor.py
  csle_recovery_executor.py
  state_comparator.py
  run_closed_loop.py
```

## 模块职责

### csle_attack_runner.py

- 调用 CSLE static sequence。
- 支持 `novice / experienced / expert`。
- 保存每一步 attacker action 输出。
- 保存 final compromised state。
- 支持指定 execution first octet，例如 true=`15`、DT=`16`。
- 在 true execution 中执行 ground-truth static sequence。
- 在 DT execution 中执行 DT inferred static sequence。

### execution_mapping.py

- 维护 true execution 和 DT execution 的映射。
- 把 true IP 映射到 DT IP，例如 `15.9.2.78 -> 16.9.2.78`。
- 把 true container 映射到 DT container，例如 `level9-15 -> level9-16`。
- 保证同一组 high-level recovery actions 能被翻译成两边对应的真实命令。

### csle_observation_collector.py

从真实 CSLE 容器收集：

- Docker 容器名/IP 映射
- auth logs
- host logs
- service status
- listening ports
- attacker reachability
- login test
- backdoor user check
- Snort/OSSEC logs，如果 level9 这次启动了 IDS

### incident_normalizer.py

不是做 IP 映射，而是做“语义归一化”。

例如把：

```text
15.9.2.78
```

结合 manifest 解释成：

```json
{
  "ip": "15.9.2.78",
  "template_ip": "<EXECUTION_ID>.9.2.78",
  "hostname": "csle_ssh_1_1",
  "services": ["ssh", "dns", "http"],
  "known_vulnerabilities": ["ssh-weak-password"],
  "observed_compromise": {
    "logged_in": true,
    "root": true
  }
}
```

### dt_inference.py

输入 incident bundle，输出：

```json
{
  "tactics": ["Discovery", "Credential Access", "Initial Access", "Privilege Escalation"],
  "techniques": ["Network Service Discovery", "Brute Force", "Valid Accounts"],
  "affected_hosts": ["15.9.2.78", "15.9.2.3", "15.9.2.79"],
  "confidence": 0.82,
  "inferred_attack_sequence": "novice"
}
```

第一版这里可以先 rule-based，后面再接 LLM/DT 模型。原因是我们要先跑通闭环，不要一开始把模型不稳定性和 CSLE 不稳定性混在一起。正式实验时，DT 的 attack sequence 推断可以输出：

```json
{
  "sequence": "novice",
  "confidence": 0.82,
  "evidence": [
    "observed SSH dictionary attack",
    "observed telnet weak credential",
    "observed FTP weak credential",
    "observed root login on csle_ssh_1_1"
  ]
}
```

### recovery_actions.py

定义统一 action schema，例如：

```json
{
  "id": "disable_compromised_ssh_user",
  "target_ip": "15.9.2.78",
  "target_host": "csle_ssh_1_1",
  "service": "ssh",
  "account": "puppet",
  "expected_effect": {
    "attacker_login_blocked": true,
    "service_available": true,
    "root_compromise_removed": true
  }
}
```

注意：这组 action 是高层动作，不直接等于 bash。

### dt_recovery_executor.py

在 DT level9 execution 里执行真实 Docker/container 命令，例如：

```bash
docker exec <container_for_16.9.2.78> passwd -l puppet
docker exec <container_for_16.9.2.78> pkill -KILL -u puppet
docker exec <container_for_16.9.2.78> service ssh restart
```

### csle_recovery_executor.py

把同一个 action 转成 true CSLE execution 的真实命令，例如：

```bash
docker exec <container_for_15.9.2.78> passwd -l puppet
docker exec <container_for_15.9.2.78> pkill -KILL -u puppet
docker exec <container_for_15.9.2.78> service ssh restart
```

然后分别从 DT attacker Kali 容器和 true attacker Kali 容器验证：

```bash
sshpass -p puppet ssh puppet@15.9.2.78 whoami
```

预期应该失败。

### pre_recovery_alignment.py

DT 执行猜测出来的 attack sequence 后，先不要急着 recovery。需要先比较：

```text
true CSLE post-attack observations
DT post-attack observations
```

重点比较：

```text
compromised hosts 是否一致
logged_in/root 是否一致
found credentials 是否一致
reachable services 是否一致
关键 auth/service/network logs 是否语义一致
```

如果 recovery 前已经不一致，要记录下来。后续 recovery output 不一致时，可以区分是：

```text
attack inference/replay 错了
还是 recovery action 本身错了
```

### state_comparator.py

比较 DT execution 和 true CSLE execution。保存 raw command output 和 raw logs，但核心判断使用 normalized recovery outcome：

```json
{
  "target_ip": "15.9.2.78",
  "checks": {
    "ssh_service_running": {
      "dt": true,
      "csle": true,
      "match": true
    },
    "attacker_login_blocked": {
      "dt": true,
      "csle": true,
      "match": true
    },
    "root_compromise_removed": {
      "dt": true,
      "csle": true,
      "match": true
    }
  }
}
```

## 为什么优先用“双 level9 execution”而不是复制 CSLE 源码

实验需要真实 DT，因此 DT 需要启动同样的 level9 containers。最简单可靠的办法是启动第二套 level9 execution，而不是复制 CSLE 源码。

复制 CSLE 源码并只保留 level9 的风险是：

- level9/config.py 依赖 `csle_common`、`csle_collector`、`csle_attacker`、`csle_defender`、metastore、cluster manager 等大量模块。
- 裁剪后很容易漏掉 runtime dependency。
- 后续 CSLE 修复或配置调整难以同步。

双 execution 的做法是：

```text
same CSLE stack
  -> start true level9 execution
  -> start DT level9 execution
```

这样既满足“DT 也是真实 containers”，又避免维护一份 forked CSLE。

需要注意资源成本：

```text
one level9 execution 约 33 个 containers
true + DT 两套约 66 个 level9 containers
再加 metastore / managers
```

如果机器资源不足，可以采用 sequential execution：

```text
1. start true level9, run attack, collect observations, optionally snapshot/export
2. start DT level9, align/replay attack or apply compromise setup, run recovery
3. restore/start true level9 compromised run, run same recovery
```

但第一选择仍然是同时运行两套 execution，因为比较更直接。

## 第一版实验建议

先只做 level9 novice，目标主机集中在：

```text
15.9.2.78  csle_ssh_1_1    SSH weak password, root compromise
15.9.2.3   csle_samba_2_1  Telnet weak password observed
15.9.2.79  csle_ftp_1_1    FTP weak password observed
```

第一版可以把 true ground-truth sequence 设为 novice。DT 读取 true CSLE observations 后，也应该推断出 `inferred_attack_sequence=novice`。然后：

```text
true execution: 已经跑过 novice
DT execution:   根据推断再跑 novice
```

接着比较 recovery 前两边是否对齐，再执行 recovery。

第一组 recovery actions：

```text
1. Disable compromised SSH account puppet on 15.9.2.78
2. Kill active sessions/processes owned by puppet
3. Restart SSH service
4. Verify attacker can no longer SSH login
5. Preserve ssh/auth logs
```

这组非常适合闭环，因为可验证：

```text
recovery 前：ssh puppet@15.9.2.78 可以成功
recovery 后：ssh puppet@15.9.2.78 应该失败
SSH 服务本身仍然可用
host root compromise 状态应被清除
```

然后再扩展到：

```text
telnet admin/admin on 15.9.2.3
ftp pi/pi on 15.9.2.79
ShellShock failed attempt on 15.9.1.254
experienced/expert sequences
```

## 一句话总结

CSLE 负责真实世界，DT 负责理解和预测。不要复制旧 DT，也不要再造完整 CSLE；用 level9 manifest 构建 level9-aware DT，再用 CSLE stack 做真实执行和验证。
