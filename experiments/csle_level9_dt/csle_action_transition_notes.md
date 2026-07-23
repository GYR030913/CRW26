# CSLE Action state 笔记
 EmulationEnvState
    └── attacker_obs_state
          ├── machines
          │     ├── machine 1
          │     ├── machine 2
          │     └── ...
          ├── agent_reachable
          ├── actions_tried
          └── catched_flags
 每个 machine 里会记录：
  ips
  ports
  cve_vulns
  osvdb_vulns
  shell_access
  shell_access_credentials
  backdoor_credentials
  logged_in
  root
  ssh_connections
  ftp_connections
  telnet_connections
  logged_in_services
  root_services
  tools_installed
  backdoor_installed
  reachable

比如 experienced 运行到最后，Samba host 的 state 里可能是：

  {
    "ips": ["16.9.2.3", "16.9.4.3"],
    "shell_access": true,
    "backdoor_credentials": [
      {
        "username": "ssh_backdoor_sambapwned",
        "password": "sambapwnedpw",
        "service": "ssh",
        "port": 22
      }
    ],
    "logged_in": true,
    "root": true,
    "tools_installed": true,
    "backdoor_installed": true,
    "reachable": ["16.9.4.74", "16.9.2.78"]
  }

  它是怎么维持的：

  1. 初始化 state
     state = EmulationEnvState(emulation_env_config=env_config)

  2. 每执行一个 attacker action
     state = Attacker.attacker_transition(s=state, attacker_action=action)

  3. transition 内部根据 action 类型更新 state.attacker_obs_state

  4. Defender transition 也会接着更新 defender 侧状态
     state = Defender.defender_transition(...)

PING_SCAN
    -> 扫描网络
    -> 把发现的 IP/host 加入 attacker_obs_state.machines

  SAMBACRY_EXPLOIT
    -> exploit 成功
    -> 给对应 machine 写入 backdoor credential
    -> shell_access=True

  SERVICE_LOGIN
    -> 用已有 credential 尝试 SSH 登录
    -> 登录成功 logged_in=True
    -> sudo -l 成功 root=True
    -> 保存 ssh_connections

  INSTALL_TOOLS
    -> 如果 machine.logged_in=True 且 root=True
    -> 在目标上装工具
    -> tools_installed=True

  后续 PING_SCAN
    -> 如果已有 compromised/pivot host
    -> 会从这些 host 再扫描
    -> 更新 reachable
    -> 发现更多内部 IP

  所以 attacker state 是一条链式更新：

  state_0
    -> action_1
    -> state_1
    -> action_2
    -> state_2
    -> ...
    -> final_state

# csle defender 
  Defender transition:
    防御者根据当前环境和监控数据，更新 defender state

  host metrics
  docker stats
  Snort alerts
  OSSEC alerts
  client population metrics
  aggregated metrics
  defender action history
  attacker action history

  所以完整一步是：

  1. attacker action 发生
  2. attacker state 更新：发现了什么、攻陷了什么、拿到什么 credential
  3. defender state 更新：监控看到什么、IDS 有什么 alert、host metrics 如何变化

# 初始化state
python run_static_sequence_once.py --execution-id 16 --sequence experienced
  
  脚本里会创建一个新的 Python state：
  state = EmulationEnvState(emulation_env_config=env_config)
  
  这个 state 初始化时会建立：
  state.attacker_obs_state
  state.defender_obs_state
  attacker_action_config
  defender_action_config
  service lookup
  vulnerability lookup
  os lookup
  cached connections

  刚初始化时，attacker 一开始基本不知道内部机器：
  attacker_obs_state.machines = []
  
  所以 experienced 第一 步通常是：
  PING_SCAN
 
  它会扫描网络，然后把发现的 machines 写入：
  state.attacker_obs_state.machines
  
  所以关系是：
  csle clean/restart
    -> 初始化真实 Docker/网络/服务环境
  EmulationEnvState(...)
    -> 初始化 Python 里的 attacker/defender observation state
  
  二者都重要。
  如果只 EmulationEnvState(...)，但容器环境已经被之前 attack 污染，state 是干净的，但真实系统不是干净的。
  如果只 clean/restart，但不创建新的 EmulationEnvState，CSLE runtime 没有新的 attacker state 去记录攻击过程。




# CSLE Action Transition 笔记
## 核心概念

`CSLE action transition` 可以理解成：

```text
CSLE 里执行一个 attack action 后，系统状态如何更新的核心过程。
更白话地说：
action transition = 执行一步动作，并把执行后的结果写回 CSLE 状态

例如 level9 experienced attack 里面有一步：
SAMBACRY_EXPLOIT(target=16.9.2.3)
```

CSLE runtime 不只是运行 `/samba_exploit.py`，它还会做这些事情：

```text
1. 读取当前 state，找到 target IP。
    这里的 `index=1` 不是固定等于 `16.9.2.3`，而是表示：
    从当前 attacker_obs_state.machines 里取 list position = 1 的 machine  
2. 找到能攻击这个 target 的 attacker 或 pivot connection。
3. 执行真实 exploit command。
4. 解析 exploit 输出。
5. 判断 exploit 是否成功。
6. 如果成功，把新 credential/backdoor 写入 attacker state。
7. 更新 machine.shell_access。
8. 更新 machine.backdoor_credentials。
9. 后续 SERVICE_LOGIN 再尝试登录。
10. 如果登录成功，再更新 machine.logged_in/root。
```

所以 action transition 不只是“运行命令”，而是：

```text
命令执行 + 结果解析 + 状态更新
```

## 前五步详细解释

### 1. 读取当前 state，找到 target IP
每个 CSLE action 不是直接写死攻击哪个 IP，而是通常带一个 `index` 或 `ips`。
例如 experienced 里的 SambaCry：
```python
EmulationAttackerShellActions.SAMBACRY_EXPLOIT(index=1)
```
这里的 `index=1` 不是固定等于 `16.9.2.3`，而是表示：
从当前 attacker_obs_state.machines 里取 list position = 1 的 machine。
因此 CSLE 会先看当前 attacker state：
state.attacker_obs_state.machines
然后调用类似下面的逻辑解析 target：
```python
action.ips = state.attacker_obs_state.get_action_ips(
    a=action,
    emulation_env_config=env_config,
)
```
如果当前 machines 排列是：
```text
list_position 0 -> 16.9.1.2
list_position 1 -> 16.9.2.3
list_position 2 -> 16.9.2.4
...

SAMBACRY_EXPLOIT(index=1)
  -> target_ips = ["16.9.2.3"]
如果是 `index=-1`，通常表示攻击所有 subnet 或所有已知目标，例如：
PING_SCAN(index=-1)
  -> target_ips = [
       16.9.1.0/24,
       16.9.2.0/24,
       ...
       16.9.9.0/24
     ]

如果当前 state 里的机器顺序变了，
同一个 index 可能会指向不同 target。
index=10 正常应该指向 16.9.4.74 或 16.9.5.62；
如果 state 没扩展对，index=10 可能错误指向 16.9.2.79。
这种情况下，attack sequence 本身没变，但 target IP 解析错了，后续 exploit 就会失败。
```

### 2. 找到能攻击 target 的 attacker 或 pivot connection

CSLE 不是所有攻击都直接从 hacker container 发出。

最开始 attacker container 是：16.9.1.191
它能直接攻击边界网段里的目标，例如：

16.9.2.3
16.9.2.78
但 experienced 后续有 lateral movement，例如：
```text
16.9.2.3 / 16.9.4.3
  -> 攻击 16.9.4.74 / 16.9.5.74
    -> 攻击 16.9.5.62 / 16.9.6.62 / 16.9.7.62
```
因此 CSLE 在执行 exploit 前，需要先找：
```text
当前哪个已经 logged_in/root/tools_installed/backdoor_installed 的 host
可以到达这个 target？
```

代码里会走类似：

```python
jump_connection = ConnectionUtil.find_jump_host_connection(ip=ip, s=s)
```

它会检查当前 attacker state 里的已攻陷机器，例如：

```text
machine.logged_in
machine.root
machine.tools_installed
machine.backdoor_installed
machine.reachable
```

如果 target 是 `16.9.4.74`，CSLE 可能选择已经攻陷的 Samba host：

```text
16.9.2.3 / 16.9.4.3
```

作为 pivot。

如果 target 是 `16.9.5.62`，CSLE 可能选择已经攻陷的 DVWA host：

16.9.4.74 / 16.9.5.74
作为 pivot。

所以这一步决定了：
攻击流量从哪里发出。

这也是我们之前说 lateral movement 的关键：

不是所有流量都回到 attacker 16.9.1.191；
后续攻击可以从已经攻陷的内部 host 发出。

如果 CSLE 找不到合适的 jump host，就会出现类似：
```text
No JumpHost found for ip: 16.9.5.62
```

这种时候不是 exploit payload 一定错了，而是当前 attacker state 没有可用 pivot connection。

### 3. 执行真实 exploit command
找到 target 和 jump/pivot connection 后，CSLE 才会执行真实命令。
例如 SambaCry：
```text
SAMBACRY_EXPLOIT
  -> /samba_exploit.py
```
实际命令类似：

```bash
sudo /root/miniconda3/envs/samba/bin/python /samba_exploit.py \
  -e /libbindshell-samba.so \
  -s data \
  -r /data/libbindshell-samba.so \
  -u sambacry \
  -p nosambanocry \
  -P 6699 \
  -t 16.9.2.3
```

DVWA SQL Injection：
```text
DVWA_SQL_INJECTION
  -> /sql_injection_exploit.sh 16.9.4.74
```

CVE-2015-1427：
```text
CVE_2015_1427_EXPLOIT
  -> /cve_2015_1427_exploit.sh 16.9.5.62:9200
```
注意，这些命令通常不是在宿主机直接执行，而是在：
```text
hacker container
或者已经攻陷的 pivot container
```
里通过 SSH connection 执行。
这就是：
```python
EmulationUtil.execute_ssh_cmd(cmd=cmd, conn=jump_connection.conn)
```
的作用。
所以第 3 步是真实执行攻击 payload，不是模拟。

### 4. 解析 exploit 输出

命令执行完后，CSLE 会读取：
```text
stdout
stderr
生成的临时结果文件
后续登录测试结果
```

不同 exploit 的解析方式不一样。

SambaCry 会看输出里有没有类似：
```text
Authentication ok
user already exists
error
```

DVWA SQL Injection 会执行 `/sql_injection_exploit.sh` 后读取结果文件：
```text
dvwa_sql_injection_result.txt
```
然后从 HTML 结果里提取：
```text
pablo:<password/hash>
```

CVE-2015-1427 不只是看脚本输出，还会进一步检查后门 SSH 是否真的可用：
```text
ssh_backdoor_cve_2015_1427_pwned
cve_2015_1427_pwnedpw
```
能否登录目标 host。

所以 CSLE 的解析不是统一的，而是每个 exploit helper 有自己的判定逻辑。

### 5. 判断 exploit 是否成功

解析完输出后，CSLE 会得到一个布尔结果：

```text
exploit_successful = True / False
```

例如 SambaCry 成功的依据大概是：
```text
没有错误
并且输出里有 Authentication ok
或者后门用户 already exists
```

DVWA SQL Injection 成功的依据是：
```text
结果文件里能提取到 pablo 的有效密码/hash
```

CVE-2015-1427 成功的依据是：
```text
执行 exploit 后，能用预期 backdoor credential 登录目标 SSH
```

如果成功，CSLE 才会继续写入：

```text
credential
backdoor_credentials
shell_access=True
backdoor_installed=True
cve_vulns
```

如果失败，则通常只会记录：
xxx_tried=True
但不会把 host 标记为 compromised。

例如这轮 experienced 里 Step 8：
```text
CVE-2010-0426 against was not successful
```
所以 `16.9.2.78` 虽然：
```text
logged_in=True
```

但在 experienced runtime summary 里：
```text
root=False
```
因为 privilege escalation exploit 没成功。

## 代码入口

CSLE attacker action transition 的主要入口是：
```python
Attacker.attacker_transition(s=state, attacker_action=action)
```

它会根据 action 类型分发到不同模块：

```text
Recon action
  -> ReconMiddleware / NmapUtil

Exploit action
  -> ExploitMiddleware / ExploitUtil

Post-exploit action
  -> PostExploitMiddleware / ShellUtil / ConnectionUtil
```

## 典型例子

### SAMBACRY_EXPLOIT

```text
SAMBACRY_EXPLOIT
  -> ExploitUtil.sambacry_helper()
  -> 执行 /samba_exploit.py
  -> 成功后写入 ssh_backdoor_sambapwned
```

这一步不仅执行 SambaCry exploit，还会在成功后把后门账号写入 CSLE attacker state。

### SERVICE_LOGIN

```text
SERVICE_LOGIN
  -> ConnectionUtil.login_service_helper()
  -> 用已有 credential 真实尝试 SSH/Telnet/FTP 登录
  -> 登录成功后设置 logged_in=True
  -> 再执行 sudo -l / sudo -n -l 判断 root
  -> 如果有 sudo/root 权限，设置 root=True
```

所以 CSLE 的 `logged_in/root` 是由真实连接和 sudo 检查得到的。

### DVWA_SQL_INJECTION

```text
DVWA_SQL_INJECTION
  -> ExploitUtil.dvwa_sql_injection_helper()
  -> 执行 /sql_injection_exploit.sh
  -> 解析 pablo 密码
  -> 写入 pablo credential，credential是可用凭证，CSLE 把通过 SQL injection 得到的 pablo 账号密码，记录到 attacker state 里
```

这一步通过 SQL injection 拿到 DVWA host 上的 `pablo` SSH credential。

### CVE_2015_1427_EXPLOIT
```text
CVE_2015_1427_EXPLOIT
  -> ExploitUtil.cve_2015_1427_helper()
  -> 执行 /cve_2015_1427_exploit.sh
  -> 检查后门 SSH 是否可用
  -> 写入 Elasticsearch backdoor credential
      CVE-2015-1427 exploit 成功后，会有一个 SSH 后门账号：

      {
        "username": "ssh_backdoor_cve_2015_1427_pwned",
        "password": "cve_2015_1427_pwnedpw",
        "service": "ssh",
        "port": 22
      }

      写入 backdoor credential 就是把这个账号密码加入 CSLE attacker state 里的：

      machine.backdoor_credentials
      machine.shell_access_credentials
```

## 为什么 no-helper commands 和 CSLE runtime summary 不天然一致

之前的 `codex no-helper commands` 是我们用类似下面的方式直接执行的：

```text
docker exec ...
curl ...
nmap ...
ssh ...
```

这些命令可以产生真实网络流量，甚至可能改变容器状态，但它们没有经过：

```text
Attacker.attacker_transition()
```

因此 CSLE attacker state 不会自动知道：

```text
哪个 exploit 成功了
哪个 credential 被发现了
哪个 host logged_in=True
哪个 host root=True
哪个 host 可以作为 pivot
```

也就是说：

```text
no-helper commands 可能真的执行了攻击流量；
但 CSLE runtime 的 attacker state 不一定会被更新。
```

而 experienced attack 是每一步都经过：

```text
Attacker.attacker_transition()
```

所以 experienced 的 final summary 是 CSLE runtime 自己维护出来的。

## 可以如何理解 CSLE state

可以把 CSLE attacker state 想成攻击者脑子里的笔记本：

```text
我发现了哪些机器
我有哪些账号密码
我能登录哪些机器
哪些机器有 root
哪些机器装了 backdoor
哪些机器可以作为 pivot
```

`action transition` 就是每执行一步攻击后，更新这个笔记本的过程。

## 对我们实验设计的影响

如果希望攻击判定完全使用 CSLE runtime，最好让模型输出：

```text
CSLE action sequence
```

而不是裸 commands。

例如模型猜：

```json
[
  {"action": "PING_SCAN", "target": "all"},
  {"action": "SAMBACRY_EXPLOIT", "target": "samba"},
  {"action": "SERVICE_LOGIN", "target": "all"},
  {"action": "INSTALL_TOOLS", "target": "all"},
  {"action": "SSH_SAME_USER_PASS_DICTIONARY", "target": "ssh"},
  {"action": "SERVICE_LOGIN", "target": "all"},
  {"action": "CVE_2010_0426_PRIV_ESC", "target": "ssh"},
  {"action": "DVWA_SQL_INJECTION", "target": "dvwa"},
  {"action": "SERVICE_LOGIN", "target": "all"},
  {"action": "CVE_2015_1427_EXPLOIT", "target": "elasticsearch"}
]
```

然后我们用 adapter 把这个 predicted action sequence 转成 CSLE action objects，再执行：

```text
Attacker.attacker_transition()
Defender.defender_transition()
```

这样最终的：

```text
logged_in
root
backdoor_credentials
final_compromised_state
```

都来自 CSLE runtime 原生状态更新。

## 简短结论

```text
CSLE action transition 是 CSLE 攻击实验的核心。
它决定了每一步攻击是否成功，以及成功后如何更新 attacker state。
如果我们想严格比较 predicted attack 和 ground-truth attack，
最好让两者都通过 CSLE action transition 执行。
```
