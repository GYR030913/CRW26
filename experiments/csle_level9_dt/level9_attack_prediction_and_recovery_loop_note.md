# Level9 Attack Prediction And Recovery Loop Note

## 核心目标

当前实验的核心目标是评估：微调模型 checkpoint-850 能否根据 CSLE true emulation 中收集到的系统信息和 IDS/logs，准确推断 level9 experienced attack 的攻击内容。

我们关心的不是单纯生成 recovery commands，而是：

- 模型是否猜中了真实 attack。
- 如果猜错，DT16 中运行猜测 attack 后的输出是否能和 CSLE15 真实 attack 后的输出拉开差异。
- 如果基于猜测 attack 生成 recovery actions，同一组 recovery commands 在 DT16 和 CSLE15 上执行后，输出差异是否能反映 attack 猜测是否准确。

## 主线 A：直接验证 Attack 猜测是否准确

1. 在真实 CSLE15 中运行真实 `experienced attack`。

2. 从 CSLE15 收集 observations：
   - sidecar IDS alerts
   - attacker action outputs
   - final summary / compromised state
   - host/service/backdoor evidence

3. 将 CSLE15 的 observations 映射成 DT16 语义：
   - `15.9.x.x -> 16.9.x.x`
   - 目标是让模型看到 DT16 system 信息和 DT16 风格的 logs。

4. 给 checkpoint-850 输入：
   - DT16 system 信息
   - 映射后的 alerts/logs

5. checkpoint-850 生成 incident 文件。

6. 再让 Codex / checkpoint-850 / DeepSeek 根据 incident 从 CSLE level9 action space 里猜测 attack sequence。

7. 在 DT16 中用 CSLE runtime 执行 predicted attack sequence。

8. 收集 DT16 predicted attack 后的输出：
   - final summary
   - sidecar alerts
   - host evidence
   - backdoor / logged_in / root

9. 对比真实 CSLE15 experienced attack 后的输出。

如果 attack 猜错，输出应该体现差异，例如：

- 少了某个 backdoor。
- 某个 host 没有 root。
- lateral movement 没走到某个网段。
- alerts 缺少 SQL injection / CVE-2015-1427 / SSH backdoor login。
- compromised hosts 少了或多了。

## 主线 B：通过 Recovery 结果反推 Attack 猜测是否准确

1. CSLE15 运行真实 experienced attack，得到 true attack-after 状态。

2. DT16 运行 predicted attack，得到 predicted attack-after 状态。

3. 在 DT16 predicted attack-after 状态上运行 recovery-loop：
   - checkpoint-850 生成 high-level recovery actions
   - DeepSeek v4 pro 生成 concrete recovery commands

4. 把同一组 recovery commands 分别执行在：
   - DT16 predicted attack-after
   - CSLE15 true experienced attack-after

5. 比较 recovery 后输出是否一致：
   - 后门是否都清掉。
   - 服务是否都恢复。
   - attacker 是否还能登录。
   - IDS alerts 是否停止。
   - host state 是否一致。

这条线不是直接问“attack 猜对了吗”，而是看“基于这个 attack 猜测生成的 recovery 是否能同时修复 DT 和 true CSLE”。

如果两边 recovery 后结果差异大，说明 predicted attack 和 true attack 的 state 不对齐。

## 当前建议

优先走主线 A。

原因是主线 A 更基础：先确认 predicted attack 在 DT16 中能否打出和 true CSLE15 experienced attack 类似的 compromised state。

等主线 A 稳定后，再跑主线 B。否则如果 predicted attack 本身不准，后续 recovery-loop 的差异会混杂 attack prediction error 和 recovery action error，分析会变得不清楚。
