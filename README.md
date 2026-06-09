# Locus: Agentic Pentest Framework

![Locus](https://img.shields.io/badge/Agentic-Pentest-blue) ![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-green) ![Docker](https://img.shields.io/badge/Docker-Required-blue)

**Locus** 是一个高度自动化、基于多智能体（Multi-Agent）架构的渗透测试框架。它利用大语言模型（LLM）的深度推理能力，结合底层图数据库（Neo4j）和内存缓存（Redis/Clickhouse），实现了从资产发现、漏洞扫描到攻击路径利用的自动化全流程闭环。

---

## 🚀 核心特性

- **🤖 多智能体协同协同 (Multi-Agent System)**
  - **Planner**: 状态机大脑，通过 LLM 推理生成结构化的攻击指令。
  - **Recon Agent**: 负责信息收集和漏洞扫描，快速探测目标环境。
  - **Exploit Agent**: 执行具体的漏洞利用（Payload）和深度渗透。
  - **Critic Agent**: 对高风险操作和执行结果进行评估与反馈。
- **🧠 大小模型架构 (Dual-Model Architecture)**
  - **Base 模型**: 用于轻量、高频的常规探测任务（如 Recon 分析），速度快、成本低。
  - **Strong 模型**: 用于复杂利用逻辑（Exploit）和战术规划（Planner），具备强大的推理和 RAG 能力。
- **📊 知识图谱与状态流 (State-Driven)**
  - 抛弃死板的线性脚本，采用 Neo4j 图数据库实时构建 `Host -> Service -> Vulnerability` 的攻击面拓扑。
  - 自动剪枝 (State Pruner) 控制上下文窗口，保证模型长时间运行不会发生遗忘或产生幻觉。
- **💻 工业级命令行交互 (Locus CLI)**
  - 媲美顶级开源工具的终端交互，提供实时的看板、数据库监控、配置管理以及挂起/恢复控制。

---

## 🛠️ 安装与快速开始

### 1. 环境准备

- Python 3.10 或更高版本
- Docker 及 Docker Compose (用于启动底层数据库服务)
- Git

克隆本仓库到本地：
```bash
git clone https://github.com/GLA32005/locus.git
cd locus
```

### 2. 配置底层存储服务

Locus 强依赖 Redis、Neo4j 和 ClickHouse。**你不需要强制安装 Docker**，只要能连接到这三个服务即可：

**方案 A：使用现有服务 (非 Docker 环境)**
如果你已经有这些服务（本地原生安装或云端服务），只需复制环境模板并修改为你自己的连接地址：
```bash
cp .env.example .env
# 编辑 .env 文件中的 REDIS_URL, NEO4J_URL, CLICKHOUSE_HOST 等配置
```

**方案 B：使用 Docker 一键启动 (推荐新手)**
如果你安装了 Docker，可以直接通过项目提供的 Compose 文件一键拉起所有依赖环境：
```bash
docker-compose up -d
```

### 3. 安装项目依赖

推荐使用虚拟环境进行安装：
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 4. 初始化配置与依赖工具

**1) LLM 配置初始化**
Locus 彻底剥离了基础设施与模型的配置。请运行向导完成 Base 和 Strong 模型的配置：
```bash
locus config init
```
配置会自动保存在 `~/.locus/config.yaml` 中，并且支持多配置方案管理 (Profile)。

**2) 下载底层扫描引擎**
Locus 在底层依赖一些知名的安全工具（如 `nuclei`, `httpx`），你可以使用 Locus 自带的包管理器自动安装到 `~/.locus/bin`：
```bash
locus tools update
```
*(注意：请确保 `~/.locus/bin` 已经加入到你的系统 `$PATH` 环境变量中。)*

---

## 🎮 使用指南

Locus 提供了极其丰富的 CLI 工具链，核心命令如下：

### 🎯 启动渗透任务
```bash
locus scan target.com
```

### 📈 实时状态查看
在扫描进行时，打开另一个终端窗口，你可以随时查看战果：
- **`locus assets`**: 以表格形式查看当前图数据库中已收集的资产拓扑（IP、域名、端口）。
- **`locus vulns`**: 实时提取并高亮展示已经发现的高危漏洞与获取的凭据。
- **`locus db info`**: 监控 Redis 任务队列、Neo4j 节点数等底层存储的状态。
- **`locus logs`**: 追踪系统的底层流转日志（支持错误与成功事件的高亮）。

### ⚙️ 任务控制与管理
- **挂起/恢复任务**: 
  - `locus pause`：发送挂起信号，当前 Payload 执行完毕后，大模型将暂停规划新动作。
  - `locus resume`：恢复系统运行，接管任务控制权。
- **清理环境**: 
  - `locus db clean`：一键清空所有的数据库（Neo4j、Redis、ClickHouse），重置环境以准备下一次扫描。
- **配置管理**:
  - `locus config profile list`：列出你保存的所有的模型配置预设。
  - `locus config profile save <name>`：保存当前配置为预设。
  - `locus config profile use <name>`：一键切换模型配置方案。

---

## 📁 目录结构与架构

```
.
├── agents/             # 各类智能体逻辑 (Recon, Exploit, Critic, Cleanup)
├── api/                # 提供外部交互的 FastAPI 接口 (Human-in-the-loop, Pause/Resume)
├── cli/                # 终端命令行工具 (基于 Click + Rich)
├── config/             # Mission YAML 配置模板
├── core/               # 核心引擎 (Orchestrator, Planner, StateAPI, LLM Provider)
├── executor/           # 执行器抽象 (对接第三方二进制工具)
├── main.py             # Locus CLI 入口程序
└── requirements.txt    # 依赖清单
```
<img width="1278" height="1018" alt="截屏2026-06-09 17 11 44" src="https://github.com/user-attachments/assets/47f65350-a4ec-4811-a37e-58d6b02f011a" />

---

## ⚠️ 免责声明

本工具及其源代码仅用于授权范围内的渗透测试与网络安全教育研究。任何未经授权的测试行为均属违法。开发者不对使用此工具导致的任何滥用行为、系统损坏或法律责任承担任何后果。**请在使用前确保你拥有对目标的合法授权。**
