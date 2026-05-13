# Agentic Pentest Framework — 架构文档

版本: v4.0  
状态: 设计定稿，实现进行中

---

## 一、项目定位

目标驱动型渗透测试 Agent 系统。区别于传统"LLM 辅助写脚本"的 Copilot 模式，本系统是完全自主的 Agentic 架构：LLM 负责推理决策，纯代码负责执行，所有组件通过统一的 Blackboard State 协作，无任何横向直连。

**核心设计原则：**
- LLM 只负责推理，不直接触网，不直接写数据库
- 所有数据流经过 State Blackboard，可审计、可追溯、可重放
- 非线性执行：机会主义跳转，不被预设阶段绑架
- 快准狠：并发 Executor、快速修正小循环、opportunity_flag 秒响应

---

## 二、七层架构总览

```
L0  Human-on-the-Loop 授权层
L1  Attack State { } — Blackboard 唯一真相来源
    ├── [静态] mission
    ├── [动态] assets / focus / context_retrievals
    ├── [动态] pending_payloads / pending_recon_tasks / async_tasks
    └── [审计] tried_vectors / footprints
         ↕ Orchestrator + Event Bus（纯代码守护进程）
         ↕ State Pruner（视图生成器，token 预算控制）
L2  Planner（状态机 · ReAct · Blackboard 监听者）
L3  Multi-Agent 网络（Blackboard 严格模式）
    ├── Recon Agent
    ├── Exploit Agent
    ├── Critic Agent
    └── Cleanup Agent
         ↕ Executor（唯一触网者 · 高并发 · 纯代码）
L4  工具层（Function Call · JSON 返回）+ 双沙箱
L5  分层记忆（Scratchpad · Neo4j · RAG）
L6  输出层（授权测试目标 · 报告生成）
```

---

## 三、七条不可违背的架构约束

这七条是系统的"宪法层"，任何新功能扩展都不得违背。

| # | 约束 | 说明 |
|---|------|------|
| ① | mission 只读 | 启动时加载，运行时任何组件不得修改，签名校验 |
| ② | tried_vectors / footprints 追加不可改 | 审计完整性，只 APPEND，永不 UPDATE/DELETE |
| ③ | Sandbox 防灾非连通验证 | 拦截语法错误和破坏性指令，不验证漏洞是否打通 |
| ④ | Agent 间无横向通信 | 所有 Agent 只与 State 交互，禁止直接调用彼此 |
| ⑤ | footprints 必记 | 所有写入目标系统的动作必须记录，支撑 Cleanup |
| ⑥ | Executor 是唯一触网者 | 所有网络动作经 Executor，配额受 max_noise 约束 |
| ⑦ | Cleanup 需 Human 审批 | 逆向操作执行前必须人工确认，不可全自动 |

---

## 四、L1 Attack State 七域设计

### 存储后端分组

**静态配置组（YAML 只读）**
- `mission` — 授权范围、风险等级、噪音上限等

**动态状态组（Redis + Neo4j 高频读写）**
- `assets` — Neo4j 图谱，Host/Service/Credential 节点和 TRUSTS/VALID_ON/RUNS 边
- `focus` — 当前意图，priority_queue、opportunity_flag、stall_count
- `context_retrievals` — RAG/Cypher 召回结果，单轮有效，每次 Think 后清空
- `pending_payloads` — Exploit 写入，Critic 监听，PENDING/APPROVED/BLOCKED 状态流转
- `pending_recon_tasks` — Recon 写入侦察意图，Executor 统一调度（不允许 Recon 直接调工具）
- `async_tasks` — 长耗时任务队列，挂起后 Planner 继续处理其他目标

**审计日志组（ClickHouse 追加）**
- `tried_vectors` — 所有攻击尝试记录，含 result/fail_reason/info_gain/novelty
- `footprints` — 所有写入目标系统的动作，Cleanup Agent 读取生成逆向操作

### tried_vectors 关键字段

```python
{
    "id":           "uuid",
    "target":       "ip:port/path",
    "type":         VectorType 枚举,
    "payload":      "string",
    "result":       VectorResult 枚举,
    "fail_reason":  FailReason 枚举,   # 枚举化，不用自由文本
    "info_gain":    0.0-1.0,           # 防死循环核心字段
    "novelty":      0.0-1.0,           # 已试过的向量自动衰减
    "retry_count":  int,
    "tokens_used":  int,
    "duration_ms":  int,
    "agent_id":     "string",
    "ts":           datetime
}
```

### focus 关键字段

```python
{
    "active_target":       "ip:port",
    "current_goal":        "RECON/EXPLOIT/PRIVESC/LATERAL/PERSIST/REPORT",
    "priority_queue":      [...],      # score = asset_value × exploitability × novelty ÷ cost
    "hypothesis":          "string",   # 当前最可能的攻击路径，给 Critic 看的上下文
    "confidence":          0.0-1.0,
    "opportunity_flag":    bool,       # true 时跳过 T4/T5，直出 Act
    "opportunity_target":  "ip",
    "opportunity_reason":  "string",
    "stall_count":         int,        # 连续无进展计数
    "blocked":             bool,
    "novelty_score":       float       # 从 tried_vectors 聚合计算
}
```

### opportunity_flag 四条触发规则（硬编码）

1. assets 中新增凭据且 access_level ≥ ADMIN → 立即跳转 EXPLOIT
2. 发现未授权暴露服务（Redis/ES/K8s API） → 插队到 priority_queue 队首
3. Graph DB 查到 TRUSTS 边：已控主机 → 高价值目标 → 直接 LATERAL
4. stall_count ≥ 3 → blocked=true，强制请求 Recon 补充情报或人工介入

### priority_queue 评分公式

```
score = asset_value × exploitability × novelty ÷ cost_estimate

asset_value:    目标重要性（DB=1.0，边缘服务=0.3）
exploitability: CVSS / 历史成功率，从 RAG 查询
novelty:        未试过=1.0，已试过×0.2（防死循环）
cost_estimate:  预估 token 消耗，历史平均值
```

---

## 五、核心组件设计

### Orchestrator + Event Bus

纯代码守护进程，不含 LLM。职责：
- 订阅所有事件，按优先级路由
- 100ms 内合并同类普通事件（防事件风暴）
- CRITICAL 事件立即处理，不合并
- 管理 Executor 并发配额
- 判定 CLEANUP_STATE 进入条件

**事件类型与优先级：**

| 事件 | 优先级 | 处理方式 |
|------|--------|----------|
| PAYLOAD_REJECTED | CRITICAL | 立即触发快速修正循环 |
| EXPLOIT_SUCCESS | CRITICAL | 立即更新 assets.access_level |
| OPPORTUNITY_FOUND | CRITICAL | 立即更新 focus，强制 Think |
| TASK_COMPLETED | HIGH | 100ms 合并，触发 Planner 重算 |
| ASSET_DISCOVERED | HIGH | 100ms 合并，查横向路径 |
| STALL_DETECTED | NORMAL | 500ms 合并 |
| CLEANUP_STATE | CRITICAL | 立即暂停 Exploit，唤醒 Cleanup Agent |

### State Pruner

在 State 流入 Planner 之前裁剪，控制在 token 预算内（默认 8000 token）。

**裁剪规则：**
- `mission` + `focus`：全量，约 800 token
- `tried_vectors`：ClickHouse 聚合摘要，约 300 token（不加载原始记录）
- `assets`：active_target 全量展开，同网段只传 ip+access_level，其他只传计数
- `context_retrievals`：relevance > 0.6 且总量 ≤ budget×20%，按 relevance 降序截断
- `pending_*`：只传状态计数，不传 payload 内容

### Planner

基于 LLM 的状态机大脑。每轮 Think 的五步节拍：

```
T1  读 mission → 校验授权边界
T2  分析 tried_vectors → 检测 HALLUCINATION / stall_count
T2b 发现长耗时任务 → 写 async_tasks · 标 PENDING · 继续（非阻塞）
T3  检查 opportunity_flag → true 则跳过 T4/T5 直出 Act
T4  重算 priority_queue（score 公式）→ 取队首为 active_target
T5  生成 hypothesis + confidence → < 0.4 先派 Recon 补情报
    生成 RAG_QUERY 指令（如需要）→ 结果写 context_retrievals
    输出 Act 指令
```

**Planner 输出严格 JSON，不允许自由文本：**

```json
{
  "think":               "推理过程（简洁，供审计）",
  "hypothesis":          "当前最可能的攻击路径",
  "confidence":          0.0-1.0,
  "opportunity_detected": true/false,
  "act": {
    "agent":       "recon|exploit|critic|cleanup",
    "action_type": "具体动作",
    "params":      {},
    "priority":    0.0-1.0
  },
  "rag_query":       "查询语句或 null",
  "async_task":      "任务描述或 null",
  "stall_assessment": "是否陷入僵局",
  "focus_update": {
    "active_target": "IP 或 null",
    "current_goal":  "目标阶段",
    "stall_count":   0
  }
}
```

---

## 六、Multi-Agent 设计

### Blackboard 严格模式

所有 Agent 遵守三个协议（见 core/protocols.py）：

1. **StateMutation 协议**：Agent 不直接写数据库，只返回 mutation 列表，由 Orchestrator 统一提交
2. **Event 协议**：Agent 不直接调用其他 Agent，只发事件
3. **Node 协议**：Agent 是无副作用的纯函数，输入 NodeInput，输出 NodeOutput

### Recon Agent

- 读 `assets` 和 `focus`，生成侦察意图
- **只写 `pending_recon_tasks`，不直接调用 Nmap/Nuclei（约束⑥）**
- Executor 统一调度工具，结果写回 `assets`
- confidence < 0.4 时被 Planner 召回补情报
- 长任务写 `async_tasks`，不阻塞主循环

### Exploit Agent

两种工作模式：

**正常模式**：读 `assets.edr_profile` → 生成 LotL 链 → 写 `pending_payloads`

**快速修正模式**（绕过 Planner）：
- 触发条件：PAYLOAD_REJECTED 事件
- Orchestrator 直接注入 `reject_reason + original_payload`
- 只做一件事：针对拒绝原因修改 Payload，重新写 `pending_payloads`
- 防无限循环：`retry_count ≥ max_payload_retry` → 写 ABANDONED，Planner 换 VectorType

### Critic Agent

监听 `pending_payloads`，四维评分：

| 维度 | 说明 |
|------|------|
| 噪音评分 | EDR 日志触发量，低噪音优先 |
| 稳定性评分 | Sandbox 成功率 > 0.8 才候选 |
| 破坏性评分 | DoS 风险评分，归零硬拒绝 |
| 合规评分 | mission.scope 校验，越界硬拒绝 |

**reject_reason 枚举（硬编码，不用自由文本）：**
- `DOS_RISK` → 移除破坏性操作
- `SYNTAX_ERROR` → 修复语法
- `OUT_OF_SCOPE` → 替换目标
- `HALLUCINATION` → CVE 不存在，查 RAG 验证
- `HIGH_NOISE` → 降低并发数
- `REQUIRES_APPROVAL` → 上报 Human，不走快速循环

**硬编码检查（不过 LLM）：**
- `rm -rf /`、`mkfs`、`DROP DATABASE` 等危险指令 → 直接 DOS_RISK
- target 不在 mission.scope → 直接 OUT_OF_SCOPE

### Cleanup Agent

触发条件（任一满足）：
1. `mission.deadline` 到达
2. `focus.current_goal = REPORT`
3. Human 发出终止指令
4. `stall_count` 耗尽所有向量

**工作流程：**
1. 读 `footprints` 全量（不经 StatePruner）
2. 按时间逆序生成逆向操作（`userdel`、`rm webshell`、`reg delete`）
3. 写 `pending_cleanup_tasks`（独立队列）
4. 独立 Critic 审查（判据：精确对应 footprints、无误伤、scope 内）
5. **Human 审批（硬性节点，不可绕过）**
6. Executor 执行，每步立即验证
7. 验证失败 → 写 `cleanup_failures` → 上报 Human
8. 二次清理自身 footprint（递归，最多两轮）

---

## 七、Executor 设计

唯一触网者，纯代码，不含 LLM。

**职责：**
- 监听 `pending_payloads` 中 APPROVED 状态的条目
- 按 payload.type 路由到对应 L4 工具
- 管理连接池、超时重试、断线重连
- 并发配额：所有 RUNNING 任务的 `noise_cost` 之和 ≤ `mission.max_noise`
- Response 写回 `tried_vectors`，新发现资产写 `assets`，执行动作写 `footprints`
- 同时处理 `pending_recon_tasks`（Recon 侦察任务）

---

## 八、双沙箱设计

| | 外部 Sandbox | 内部 Sandbox |
|---|---|---|
| 防御对象 | 目标系统（防 DoS/破坏） | 宿主机（防 Agent 自爆） |
| 网络 | 允许访问目标网段 | 完全断网 |
| 挂载 | 读写测试文件 | 只读挂载 |
| 技术 | Docker + iptables 白名单 | gVisor（runsc） |
| 资源 | 按需 | CPU 1核 / 内存 256MB / 超时 30s |
| 失败处理 | 写 SANDBOX_FAIL，回传修正 | Kill 容器，写告警到 footprints |
| 用途 | Payload 语法+破坏性检查 | Tool-Making 脚本执行 |

**外部 Sandbox 的正确定位**（约束③）：
- 拦截语法错误、破坏性指令（`rm -rf /`）、越权操作
- **不验证漏洞是否能打通**（Blind SSRF / Kerberoasting 无法在沙箱预演）

---

## 九、LotL 免杀链路

### 执行流程

1. **环境感知**（落地后第一步）
   - 进程枚举 → 识别 EDR 产品（CrowdStrike / Defender / 火绒）
   - PATH 枚举 → 确认可用二进制（certutil / mshta / wmic / powershell）
   - GPO/AppLocker 检测 → 确认策略限制
   - 结果写入 `assets[:Host].edr_profile`

2. **LLM 动态生成 LotL 链**
   - 输入：`edr_profile + 目标OS + 可用二进制 + 任务目标`
   - 输出：3条候选链路（certutil+mshta / PowerShell反射加载 / WMI事件订阅）

3. **Critic 四维筛选** → Sandbox 语法检查 → Executor 执行

### LLM 的核心价值

- 传统：靠 LOLBAS 数据库静态查表
- LLM：根据当前环境约束**动态组合**链路，无需预设模板
- 传统：混淆靠手工
- LLM：读 EDR 报错信息**自动调整变形**，AMSI 绕过变形迭代速度 10x+

---

## 十、三条关键小循环

### Loop A：PAYLOAD_REJECTED 快速修正

```
Exploit 写 pending_payloads
→ Critic 审查 → BLOCKED
→ EventBus 抛 PAYLOAD_REJECTED（CRITICAL 优先级）
→ Orchestrator 检查 retry_count
  → 超限：写 ABANDONED，Planner 下轮换 VectorType
  → REQUIRES_APPROVAL：上报 Human
  → 正常：直接触发 Exploit 快速修正模式（绕过 Planner）
→ Exploit 读 reject_reason + original_payload
→ 生成修正版，写新 pending_payloads
→ Critic 重新审查（循环直到 APPROVED 或超限）
```

**关键点**：绕过 Planner 大循环，省去 T1-T5 的延迟，只做局部修正。

### Loop B：context_retrievals RAG 召回

```
Planner T5 生成 hypothesis + RAG_QUERY 指令
→ Orchestrator 执行向量检索 Top-K
→ 结果写 context_retrievals（单轮有效）
→ 触发下一轮 Think
→ State Pruner 读 context_retrievals（relevance > 0.6，≤ budget×20%）
→ 打包进 Planner Prompt 的 knowledge_context 区
→ Think 结束后清空 context_retrievals
```

**关键点**：外部知识先上黑板再进 Planner，不绕过 StatePruner，不污染 token 预算。

### Loop C：Cleanup 清道夫

```
Orchestrator 判定 CLEANUP_STATE（四种触发条件）
→ 暂停所有 Exploit 调度
→ Cleanup Agent 读 footprints 全量
→ 按时间逆序生成逆向操作
→ 独立 Critic 审查（精确对应 footprints，无误伤，scope 内）
→ Human 审批（硬性节点）
→ Executor 执行，每步立即验证
→ 验证结果写 footprints.cleaned
→ 生成最终报告（攻击发现 + 清理验证）
→ 二次清理自身 footprint
```

---

## 十一、存储技术选型

| 组 | 包含域 | 存储 | 理由 |
|---|---|---|---|
| 静态配置 | mission | YAML 文件 | 启动时签名校验，防运行时篡改 |
| 动态状态 | focus / pending_* / async_tasks | Redis | 毫秒级读写，天然支持 Pub/Sub |
| 动态状态 | assets | Neo4j | 图结构天然表达资产拓扑，Cypher 查询横向路径 |
| 审计日志 | tried_vectors / footprints | ClickHouse | 列存储聚合查询极快，StatePruner 直接跑 SQL |
| 召回结果 | context_retrievals | Redis | 单轮有效，需要快速清空 |

---

## 十二、核心协议（core/protocols.py）

三个协议定义了整个系统的数据流契约：

### StateMutation 协议

```python
@dataclass
class StateMutation:
    operation:  MutationOperation   # APPEND / UPSERT / UPDATE_STATUS / WRITE / ADD_EDGE / DELETE
    domain:     StateDomain         # 目标域
    payload:    dict

    def validate(self) -> bool:
        # tried_vectors / footprints 只允许 APPEND（约束②）
        # focus 只允许 WRITE
```

### Event 协议

```python
@dataclass
class Event:
    type:       EventType
    payload:    dict
    source:     str
    priority:   EventPriority       # CRITICAL=0 / HIGH=1 / NORMAL=2 / LOW=3
```

### Node 协议（BaseAgent）

```python
@dataclass
class NodeInput:
    state_view:     dict    # StatePruner 裁剪后的视图
    trigger_event:  Event
    agent_id:       str

@dataclass
class NodeOutput:
    mutations:  list[StateMutation]   # 声明式副作用，不直接执行
    events:     list[Event]
    next_hint:  Optional[AgentType]
    think_log:  str
    tokens_used: int

class BaseAgent(ABC):
    @abstractmethod
    async def run(self, input: NodeInput) -> NodeOutput: ...
```

---

## 十三、项目文件结构

```
agentic-pentest/
├── ARCHITECTURE.md              # 本文档
├── requirements.txt
├── Dockerfile                   # 容器化构建
├── docker-compose.yml           # 一键部署（Redis + Neo4j + ClickHouse + App）
├── .env.example                 # 环境变量模板
├── config/
│   ├── mission_example.yaml     # 任务配置模板
│   ├── db_init.sql              # ClickHouse 表结构
│   └── neo4j_init.cypher        # Neo4j 约束和索引
├── core/
│   ├── protocols.py             # 三个核心协议（宪法层）
│   ├── state_api.py             # Blackboard 访问层
│   ├── state_pruner.py          # 视图裁剪器
│   ├── orchestrator.py          # 调度核心 + EventBus
│   ├── planner.py               # 状态机大脑
│   └── report_generator.py      # 渗透测试报告生成器（L6 输出层）
├── agents/
│   ├── recon_agent.py           # 侦察 Agent
│   ├── exploit_agent.py         # 利用 Agent（含快速修正模式）
│   ├── critic_agent.py          # 审查 Agent
│   └── cleanup_agent.py         # 清道夫 Agent
├── executor/
│   ├── executor.py              # 唯一触网者
│   ├── sandbox_external.py      # 外部沙箱（Docker）
│   ├── sandbox_internal.py      # 内部沙箱（gVisor）
│   └── tools/
│       ├── nmap_tool.py
│       ├── nuclei_tool.py
│       ├── msf_tool.py
│       └── codeql_tool.py
├── memory/
│   └── rag_engine.py            # RAG 检索引擎
├── api/
│   └── main.py                  # FastAPI 入口（Human 审批 + 报告查询）
└── tests/
    ├── test_protocols.py
    ├── test_orchestrator.py
    ├── test_critic.py
    ├── test_state_api.py
    ├── test_planner.py
    └── test_agents.py
```

---

## 十四、实现路径

| 阶段 | 周次 | 交付物 | 验收标准 |
|------|------|--------|----------|
| P0 地基 | 1-2 | State API + Orchestrator 骨架 | Redis/Neo4j/ClickHouse 能读写，EventBus 能发收 |
| P0 决策层 | 3-4 | StatePruner + Planner | Planner 能基于裁剪后 State 输出结构化 JSON |
| P1 Agent 层 | 5-7 | Recon + Exploit + Critic | 三个 Agent 能写 State，快速修正循环跑通 |
| P1 执行层 | 8-9 | Executor + 双沙箱 | Payload 能打出去，结果能回写，沙箱能拦危险操作 |
| P2 收尾 | 10-11 | Cleanup Agent + 报告生成 | 清理能验证，报告包含攻击发现和清理验证两部分 |

**当前进度：P0-P2 全部代码已实现，协议约束已验证，核心测试通过。**

---

## 十五、重要设计决策记录

**为什么不用 LangGraph / LangChain？**
全部自己写。LangGraph 帮省的是前两周样板代码，但会在第三个月产生框架升级带来的破坏性重构。核心执行流程绑在第三方框架上，主动权不在自己手里。参考了 LangGraph 的节点设计思想、Temporal.io 的长任务处理模式、BurpSuite 的工具注册架构——但不引入任何第三方框架作为生产依赖。

**为什么 RAG 结果要先上黑板（context_retrievals）？**
如果 Planner 直接查 RAG，绕过了 StatePruner，token 预算失控。所有外部知识必须经过 StatePruner 的 relevance 过滤和 budget 截断，才能进入 Planner 的 Context。

**为什么 Recon Agent 不能直接写 assets？**
直接写意味着 Recon Agent 自己调用了 Nmap 并处理结果，绕过了 Executor 的 max_noise 配额。两个 Recon Agent 并发时可能远超噪音上限触发 IDS。所有网络动作必须经过 Executor 这一个受控通道。

**为什么 tried_vectors 用 ClickHouse 而不是 PostgreSQL？**
StatePruner 需要对爆破类操作做聚合查询（`COUNT(*) WHERE result=AUTH_FAIL`）。ClickHouse 的列存储在聚合查询上比 PostgreSQL 快一个数量级，5000条记录的摘要在毫秒级返回，而不是加载到内存再处理。

**为什么 Sandbox 不做连通性验证？**
Blind SSRF 需要探测真实内网 IP，Kerberoasting 依赖目标域控的真实响应——这类操作在本地 Docker 沙箱里永远失败，不代表真实环境失败。Sandbox 的正确定位是"防灾层"：拦截语法错误和破坏性指令，不是验证利用成功率。
