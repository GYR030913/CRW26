# CSLE Level9 闭环恢复实验流程

## 当前实验设定

我们使用两套互不干扰、但同构的 CSLE level9 执行环境：

```text
True CSLE: execution 15, IPs 15.9.x.x, containers *-level9-15
DT:        execution 16, IPs 16.9.x.x, containers *-level9-16
```

这里的 DT 不是上一个项目里的 `10.0.x.x` 简化系统，而是另一套真实运行的 CSLE level9。它有相同的 nodes、containers、services、vulnerabilities 和 static attack sequences，只是 execution id 和 first octet 不同。

核心目标不是单纯验证 recovery 是否能修好系统，而是评估微调模型能否根据 CSLE 观测准确猜出 attack。

实验逻辑是：

```text
True CSLE 15 真实发生攻击
-> 收集真实观测
-> 微调模型根据这些信息猜测 attack sequence / tactics / techniques
-> DT 根据模型猜到的 attack 复现攻击并生成 recovery actions
-> 同一组 recovery actions 分别作用到 DT 16 和 True CSLE 15
-> 比较两边 recovery 后的真实输出是否一致
-> 用一致性判断模型猜测的 attack 是否准确
```

也就是说，DT 和 CSLE 的 recovery output comparison 是评价手段，真正要验证的是：

```text
微调模型看到 attacker outputs / logs / host state / service state 后，
是否能正确推断真实发生的 attack。
```

## A-I 实验流程

### A. True CSLE 15 执行 experienced attack

在 true CSLE execution 15 里真实执行 level9 `experienced` static attack sequence。

当前选择 `experienced` 的原因：

```text
1. 它已经能在 15 和 16 两套环境中对齐运行。
2. 它包含比较清楚的 lateral movement。
3. 它比 novice 更适合作为闭环恢复实验的第一版目标。
```

当前已验证的 experienced attack chain：

```text
15.9.2.3 / 15.9.4.3
  -> 15.9.4.74 / 15.9.5.74
    -> 15.9.5.62 / 15.9.6.62 / 15.9.7.62
```

对应到 normalized form：

```text
X.9.2.3 / X.9.4.3
  -> X.9.4.74 / X.9.5.74
    -> X.9.5.62 / X.9.6.62 / X.9.7.62
```

### B. 收集 CSLE 15 observations

攻击完成后，从 true CSLE 15 收集真实观测。

第一版已经收集：

```text
attacker action outputs
final compromised state
target host auth/account state
target host service/process/listening-port state
target host logs
attacker-to-target network reachability
backdoor user existence/status
container inventory
```

后续再加：

```text
Snort alerts
OSSEC alerts
更细的 host logs
更细的 service-specific logs
```

当前 B 步骤输出：

```text
experiments/csle_level9_dt/artifacts/observations/level9_15_observations_with_alerts_clean_20260714.json
```

### C. 生成 incident_bundle.json

把 CSLE 15 的原始观测标准化成 DT 可读的 incident bundle。

这个步骤不是简单把 `15.9.x.x` 塞给 DT，而是要同时保留真实 IP 和 level9 语义。

incident bundle 里应该包含：

```text
source: csle-level9 execution 15
sequence: experienced
hosts: samba, ssh, dvwa, elasticsearch
compromised chain
observed credentials
observed backdoors
affected services
observed logs
network reachability
suspected tactics
suspected techniques
evidence snippets
```

IP 需要保留两种表达：

```text
true_ip: 15.9.5.62
template_ip: X.9.5.62
dt_ip: 16.9.5.62
```

这样 DT 后续才能把 true CSLE 15 的观测映射到 DT 16。

### D. 微调模型根据 incident_bundle 猜测 attack

微调模型读取 `incident_bundle.json`，根据观测推断：

```text
attack sequence
tactics
techniques
affected hosts
affected services
confidence
evidence used
```

这里的核心评估对象是微调模型。第一版工程联调时可以先做 rule-based baseline，但最终实验要让微调模型根据 CSLE 观测来猜 attack。

这一阶段的输出应该类似：

```json
{
  "predicted_sequence": "experienced",
  "affected_hosts": ["X.9.2.3", "X.9.4.74", "X.9.5.62"],
  "tactics": ["Initial Access", "Privilege Escalation", "Lateral Movement", "Persistence"],
  "techniques": ["Valid Accounts", "Exploit Public-Facing Application", "Create Account"],
  "confidence": 0.86
}
```

### E. DT 16 执行它猜到的 attack

DT 不能直接看真实 attack label。它只能根据微调模型猜到的 attack，在 execution 16 里复现对应攻击。

例如 DT 判断 true CSLE 15 发生的是 `experienced` attack，那么就在 DT 16 运行：

```text
level9 experienced static sequence
```

然后收集 DT 16 的 post-attack observations。

如果 DT 16 的 post-attack state 和 CSLE 15 的 post-attack state 对不上，说明微调模型对 attack sequence / tactics / techniques 的推断可能不准确。

### F. DT 基于猜到的 attack 生成 high-level recovery actions

DT 根据微调模型推断出的 attack 和 DT 16 的 post-attack state 生成高层 recovery actions。

这里可以复用上一个实验的思想：

```text
System: level9 topology and service context
Logs: incident bundle summary and collected observations
Incident: inferred level9 attack chain
State: current recovery state
Target hosts: affected level9 hosts
Previous recovery actions: already selected actions
```

但不能直接复用上一个项目的 `10.0.x.x` 系统 prompt 和命令上下文。这里所有 host、service、container、backdoor 都必须是 level9 的语义。

high-level recovery actions 示例：

```json
{
  "action": "remove SSH backdoor account",
  "target_host": "X.9.2.3",
  "target_user": "ssh_backdoor_sambapwned",
  "reason": "attacker created persistence after Samba compromise"
}
```

### G. recovery_action_adapter 生成具体 commands

把 high-level recovery actions 转成两套环境各自可执行的命令。

同一个 high-level action：

```text
remove SSH backdoor account on X.9.2.3
```

需要生成两组具体命令：

```text
True CSLE 15:
docker exec csle_samba_2_1-level9-15 ...

DT 16:
docker exec csle_samba_2_1-level9-16 ...
```

adapter 的职责：

```text
X.9.x.x -> 15.9.x.x / 16.9.x.x
host semantic name -> container name
backdoor username -> concrete Linux account
service semantic name -> concrete service command
verification target -> concrete check command
```

这里可以继续使用 DeepSeek/API 做 command generation，但必须加 allowlist 和 verifier，避免生成破坏性命令。

### H. 同一组 recovery actions 分别在 DT 16 和 CSLE 15 执行

执行顺序：

```text
1. 在 DT 16 执行 recovery commands
2. 收集 DT 16 post-recovery observations
3. 在 True CSLE 15 执行同一组 high-level recovery actions 对应的 commands
4. 收集 CSLE 15 post-recovery observations
```

注意：比较的是同一组 high-level recovery actions 在两套同构系统上的效果，不是简单比较原始 IP 字符串。

比较前需要 normalize：

```text
15.9.x.x -> X.9.x.x
16.9.x.x -> X.9.x.x
```

### I. 输出 comparison_report.json

最后比较 DT 16 和 True CSLE 15 的 post-recovery observations。

重点比较：

```text
backdoor accounts 是否删除或禁用
compromised credentials 是否失效
attacker 是否还能 SSH/Telnet/FTP 登录
root/shell access 是否被移除
关键服务是否仍然正常运行
network reachability 是否符合预期
IDS/logs 是否停止出现同类告警
host 状态是否一致
DT normalized state 和 True CSLE normalized state 是否一致
```

输出：

```text
comparison_report.json
```

这个 report 用来判断：

```text
微调模型是否正确猜到了 attack sequence / tactics / techniques
DT 生成的 recovery actions 是否有效
DT 和 True CSLE 的恢复结果是否一致
```

## 当前已验证 baseline

当前 15 和 16 的 `experienced` attack 已经对齐。

True CSLE 15 artifact：

```text
experiments/csle_level9_dt/artifacts/level9_15_experienced_20260713T141523Z.json
```

DT 16 artifact：

```text
experiments/csle_level9_dt/artifacts/level9_16_experienced_20260713T151633Z.json
```

两边 normalized final compromised state 一致：

```text
X.9.2.3 / X.9.4.3
  backdoor: ssh_backdoor_sambapwned
  root: true

X.9.2.78
  root: true

X.9.4.74 / X.9.5.74
  credential/backdoor user: pablo
  root: true

X.9.5.62 / X.9.6.62 / X.9.7.62
  backdoor: ssh_backdoor_cve_2015_1427_pwned
  root: true
```

## 已做过的 runtime 修复

### 1. experienced static sequence index 修复

原始 experienced sequence 里部分 action index 会指到错误或不存在的 machine list position。

已修：

```text
DVWA_SQL_INJECTION index=10
CVE_2015_1427_EXPLOIT index=10
```

### 2. jump host stale SSH connection 修复

experienced attack 里后续 exploit 需要通过已经攻陷的 host 作为 jump host 发起。

之前可能出现：

```text
host 已经 compromised
backdoor 也存在
但是内存里的 Paramiko SSH connection 已经死了
导致后续 lateral movement 失败
```

已修为：

```text
如果 jump host 满足条件但 SSH connection 不活跃
就重新建立 SSH connection
如果 reconnect 成功，再继续后续 attack
```

这更符合真实攻击逻辑：只要 backdoor account 还在、网络可达，攻击者可以重新 SSH 登录。

## 下一步

当前已经完成：

```text
A. True CSLE 15 执行 experienced attack
B. 收集 CSLE 15 observations
```

下一步建议做：

```text
C. 生成 incident_bundle.json
```

第一版 `incident_bundle.json` 不需要太复杂，先把 attack chain、affected hosts、credentials/backdoors、service state、network reachability 标准化出来，让后面的 DT inference 能开始跑。
