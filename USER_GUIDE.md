# 用户指南 — Agentic Pentest Framework

本文档面向**使用者**（不是开发者），说明如何部署、配置和运行系统，以及运行过程中如何介入。

---

## 1. 快速开始

### 方式一：Docker Compose（推荐）

```bash
# 1. 克隆项目
cd agentic-pentest

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env，至少填写：
#   ANTHROPIC_API_KEY=sk-ant-你的密钥
#   API_KEY=一个强密码

# 3. 编辑任务配置
# 编辑 config/mission_example.yaml 或新建自己的 mission.yaml
# 如果新建，修改 .env 中的 MISSION_FILE 指向它

# 4. 启动
docker-compose up

# 等待日志出现：
#   === Agentic Pentest Framework starting ===
#   API server listening on 0.0.0.0:8080
#   Mission scope: ['10.0.0.0/24']
```

### 方式二：本地运行

前提：已安装 Redis、Neo4j、ClickHouse 并启动。

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置
cp .env.example .env
# 编辑 .env

# 3. 初始化数据库
# ClickHouse
clickhouse-client --multiquery < config/db_init.sql
# Neo4j（在 Neo4j Browser 或 cypher-shell 中执行）
# :source config/neo4j_init.cypher

# 4. 启动
python main.py
```

---

## 2. 指定测试目标（最关键）

系统通过 `config/mission_example.yaml`（或你自己新建的 mission 文件）来定义**测谁、怎么测**。这是启动前必须编辑的文件。

### 2.1 我要测试一个域名

```yaml
mission:
  goal: "测试 example.com 的安全性"
  scope:
    - "example.com"          # 域名目标
  oob: []                     # 无禁止目标
  risk_level: 3
  approved_ops:
    - "port_scan"
    - "vulnerability_scan"
    - "exploitation"
  max_noise: 30
  context_budget: 8000
  max_payload_retry: 3
  human_approve_threshold: 4
  deadline: 0
  max_stall_count: 10
```

### 2.2 我要测试一个 IP 地址

```yaml
mission:
  goal: "测试 192.168.1.100 的安全性"
  scope:
    - "192.168.1.100/32"     # 单个 IP 用 /32
  oob: []
  risk_level: 3
  approved_ops:
    - "port_scan"
    - "vulnerability_scan"
    - "exploitation"
  max_noise: 30
  context_budget: 8000
  max_payload_retry: 3
  human_approve_threshold: 4
  deadline: 0
  max_stall_count: 10
```

### 2.3 我要测试一个网段

```yaml
mission:
  goal: "全面评估 10.0.0.0/24 网段的安全态势"
  scope:
    - "10.0.0.0/24"          # 整个 C 段
    - "10.0.1.0/24"          # 可以多个
  oob:
    - "10.0.0.1"             # 排除网关
    - "10.0.0.254"           # 排除管理主机
  risk_level: 3
  approved_ops:
    - "port_scan"
    - "vulnerability_scan"
    - "exploitation"
    - "privilege_escalation"
    - "lateral_movement"
  max_noise: 50
  context_budget: 8000
  max_payload_retry: 3
  human_approve_threshold: 4
  deadline: 0
  max_stall_count: 10
```

### 2.4 关键字段说明

| 字段 | 作用 | 示例 |
|------|------|------|
| `goal` | 告诉 LLM 任务目标，影响 Planner 推理方向 | `"获取数据库服务器权限"` |
| `scope` | **严格限制**的授权范围，所有 Agent 生成的目标都会被校验 | `["10.0.0.0/24"]` 或 `["example.com"]` |
| `oob` | scope 内明确禁止触碰的目标 | `["10.0.0.1"]` |
| `risk_level` | 1-5，越低越保守，越容易触发人工审批 | `3` |
| `approved_ops` | 允许的操作类型 | 见下方列表 |
| `max_noise` | 并发连接上限，防止触发 IDS | `30`（保守）到 `100`（激进） |
| `deadline` | Unix 时间戳，0=无限制 | `0` 或 `1735689600` |

**approved_ops 可选值：**
- `port_scan` — 端口扫描
- `vulnerability_scan` — 漏洞扫描（Nuclei）
- `exploitation` — 漏洞利用
- `privilege_escalation` — 提权
- `lateral_movement` — 横向移动

### 2.5 启动流程

```bash
# 1. 编辑 mission 配置（指定你的目标）
vim config/mission_example.yaml
# 或新建一个文件，如 config/my_mission.yaml
# 如果新建，同步修改 .env:
#   MISSION_FILE=config/my_mission.yaml

# 2. 如果之前已经运行过，需要清除旧 mission（Redis 中缓存了旧的）
redis-cli DEL mission focus

# 3. 启动
python main.py
```

**注意：** mission 加载后只读不可修改（架构约束①）。如果需要改目标，必须：
1. 停止系统（Ctrl+C）
2. 清除 Redis 缓存：`redis-cli DEL mission focus`/`docker exec $(docker compose ps -q redis) redis-cli DEL mission focus`
3. 修改 YAML
4. 重新启动

---

## 3. 环境变量说明

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `ANTHROPIC_API_KEY` | **是** | — | Claude API 密钥 |
| `LLM_MODEL` | 否 | `claude-sonnet-4-6` | 使用的模型 |
| `REDIS_URL` | 否 | `redis://localhost:6379` | Redis 连接 |
| `NEO4J_URL` | 否 | `bolt://localhost:7687` | Neo4j 连接 |
| `NEO4J_USER` | 否 | `neo4j` | Neo4j 用户名 |
| `NEO4J_PASSWORD` | 否 | `password` | Neo4j 密码 |
| `CLICKHOUSE_HOST` | 否 | `localhost` | ClickHouse 主机 |
| `CLICKHOUSE_PORT` | 否 | `9000` | ClickHouse 端口 |
| `CLICKHOUSE_DB` | 否 | `pentest` | ClickHouse 数据库 |
| `API_HOST` | 否 | `0.0.0.0` | API 监听地址 |
| `API_PORT` | 否 | `8086` | API 端口 |
| `API_KEY` | **是** | `changeme` | API 认证密钥，请修改 |
| `MISSION_FILE` | 否 | `config/mission_example.yaml` | Mission 配置路径 |
| `REPORT_OUTPUT_DIR` | 否 | `reports` | 报告输出目录 |

---

## 4. 运行中的操作

系统启动后完全自主运行，但有几个地方需要你介入。

### 4.1 查看运行状态

```bash
# 查看当前状态
curl -H "X-API-Key: 你的API_KEY" http://localhost:8086/status
```

返回内容包括：
- 当前 focus（正在打哪个目标、什么阶段）
- 各队列中的 payload / recon 任务数量
- 活跃目标和置信度

### 4.2 处理人工审批

Critic Agent 遇到以下情况会暂停并请求人工审批：
- **REQUIRES_APPROVAL** — 操作敏感（如关闭防火墙、修改注册表），需要你判断是否放行
- **stall_count 耗尽** — Agent 多次无进展，需要你研判方向

```bash
# 查看待审批的 Payload
curl -H "X-API-Key: 你的API_KEY" http://localhost:8086/payloads/pending-approval

# 批准某个 Payload
curl -X POST -H "X-API-Key: 你的API_KEY" \
  http://localhost:8086/payloads/{payload_id}/approve \
  -d '{"approved": true}'

# 拒绝
curl -X POST -H "X-API-Key: 你的API_KEY" \
  http://localhost:8086/payloads/{payload_id}/approve \
  -d '{"approved": false}'
```

### 4.3 查看攻击痕迹（Footprints）

系统记录了所有写入目标系统的动作（约束⑤），你可以随时查看：

```bash
# 查看所有痕迹
curl -H "X-API-Key: 你的API_KEY" http://localhost:8086/footprints

# 只看未清理的
curl -H "X-API-Key: 你的API_KEY" "http://localhost:8086/footprints?cleaned=false"

# 只看已清理的
curl -H "X-API-Key: 你的API_KEY" "http://localhost:8086/footprints?cleaned=true"
```

### 4.4 清理阶段审批

当系统进入清理阶段（deadline 到达 / 目标达成 / stall 耗尽）：

1. Cleanup Agent 读取所有 footprints，生成逆向操作（`userdel`、`rm webshell`、`reg delete` 等）
2. 系统暂停，等待你审批清理方案

```bash
# 查看待审批的清理任务
curl -H "X-API-Key: 你的API_KEY" http://localhost:8086/cleanup/tasks

# 批准清理
curl -X POST -H "X-API-Key: 你的API_KEY" \
  http://localhost:8086/cleanup/approve \
  -d '{"task_ids": ["task1", "task2"], "approved": true}'
```

清理完成后，系统会二次验证每个 footprint 是否真正清理干净，验证失败的会上报你。

### 4.5 查看和生成报告

```bash
# 获取最新报告（JSON）
curl -H "X-API-Key: 你的API_KEY" http://localhost:8086/report

# 手动触发报告生成
curl -X POST -H "X-API-Key: 你的API_KEY" http://localhost:8086/report/generate
```

报告同时以 Markdown 和 JSON 格式保存在 `reports/` 目录下。报告包含：
- **执行摘要** — 范围、尝试次数、成功率、攻破主机数
- **攻击发现** — 每次成功攻击的详情（按时间排序）
- **清理验证** — 每个 footprint 的清理状态
- **统计数据** — 尝试次数/成功率/信息增益/幻觉次数
- **修复建议** — 由 LLM 生成的具体修复方案

---

## 5. 系统行为说明

### 5.1 完全自主运行

系统启动后的执行循环完全自主，不需要你手操作：

```
启动 → 加载 Mission → Planner 推理 → 调度 Agent → Executor 执行
           ↑                                              |
           └──────── 结果写回 Blackboard ←────────────────┘
```

- **Planner** 每 3 秒做一次推理（CRITICAL 事件时 0.5 秒），决定下一步行动
- **Recon Agent** 生成侦察任务（端口扫描、服务识别等）
- **Exploit Agent** 生成利用 Payload（LotL 技术为主）
- **Critic Agent** 审查每个 Payload（噪音/稳定性/破坏性/合规四维评分）
- **Executor** 执行通过审查的 Payload，是唯一触网的组件

### 5.2 机会主义跳转

系统不是线性执行的。当发现高价值机会时会立即跳转：
- 发现未授权暴露服务（Redis/ES/K8s API）→ 插队到队首
- 发现新凭据且权限 ≥ ADMIN → 立即跳转利用
- 图谱中发现横向移动路径 → 直接跳转

### 5.3 快速修正循环

当 Critic 拒绝一个 Payload（如 HIGH_NOISE）：
1. **不会**回到 Planner 重新推理（太慢）
2. 直接触发 Exploit Agent 的**快速修正模式**
3. Exploit Agent 只针对拒绝原因做最小改动
4. 重新提交给 Critic
5. 循环直到通过或超过重试上限

### 5.4 知识库查询

Agent 在推理过程中如果需要知识（如 CVE 详情、EDR 绕过技巧），会通过两种方式查询：
- **Planner 发起**：Planner 在 `rag_query` 字段中写查询，Orchestrator 执行
- **Agent 发起**：Agent 在输出中写 `knowledge_query`，Orchestrator 拦截执行

查询结果经过 StatePruner 裁剪后进入下一轮推理上下文，每轮推理结束后自动清空。

---

## 6. 停止系统

```bash
# Docker Compose
docker-compose down

# 本地运行
Ctrl+C（优雅关闭，会停止 Orchestrator 和 API 服务器）
```

停止后：
- Redis / Neo4j / ClickHouse 中的数据持久化，重启后继续
- Mission 配置已加载到 Redis，重启后不会重复加载
- 进行中的任务不会回滚，但不会产生新的执行

---

## 7. 日志和监控

日志格式：`时间 级别 模块名 — 消息`

关键日志关注：

| 日志内容 | 含义 |
|---------|------|
| `Planner Think 失败` | LLM 调用异常，系统会自动降级 |
| `Agent X: 过滤 N 个越界任务` | LLM 生成了 scope 外的目标，已被硬编码规则丢弃 |
| `Executor: 沙箱拦截` | Payload 被外部沙箱阻止（语法错误或破坏性指令） |
| `[HUMAN APPROVAL REQUIRED]` | 需要你介入审批 |
| `进入 CLEANUP_STATE` | 系统进入清理阶段 |
| `ReportGenerator: 报告已生成` | 最终报告已输出 |

---

## 8. 常见问题

**Q: 系统一直 Recon 不进 Exploit？**
A: 检查 `focus.confidence`，Planner 在 confidence < 0.4 时会持续派 Recon 补充情报。可能是目标信息太少，等侦察完成。

**Q: Payload 全被 Critic 拒绝？**
A: 查看 reject_reason。如果是 `HALLUCINATION`，说明 LLM 引用了不存在的 CVE，系统会自动通过知识库查询修正。如果是 `DOS_RISK`，说明 payload 包含破坏性操作。

**Q: 如何扩展知识库？**
A: 将 CVE 描述、绕过技巧等文档通过 `RAGEngine.index_documents()` 写入 ChromaDB。格式：
```python
[{
    "id": "cve-2024-xxxx",
    "content": "CVE 描述和利用方法...",
    "source": "cve_db",
    "metadata": {"cve": "CVE-2024-XXXX", "cvss": 9.8}
}]
```

**Q: Token 消耗很快怎么办？**
A: 调低 `context_budget`（默认 8000），或换用更便宜的模型（如 `claude-haiku-4-5`）。

**Q: 可以中途修改 Mission 吗？**
A: 不可以。Mission 加载后只读（约束①）。如需更改，停止系统 → 清除 Redis 中的 mission key → 修改 YAML → 重启。
