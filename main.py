"""
Agentic Pentest Framework — 根启动脚本

职责：
  1. 从环境变量读取连接参数
  2. 初始化 StateAPI（Redis + Neo4j + ClickHouse）
  3. 加载 mission.yaml 写入 State
  4. 实例化全部 Agents、Executor、Planner、Orchestrator
  5. 将 StateAPI 注入 FastAPI（Human 审批接口）
  6. 并发启动 Orchestrator（asyncio 主循环）+ uvicorn（API 服务器）

使用方式：
  # 复制并填写 .env，然后：
  python main.py

  # 或直接指定环境变量：
  REDIS_URL=redis://localhost:6379 \
  NEO4J_URL=bolt://localhost:7687 \
  API_KEY=secret123 \
  MISSION_FILE=config/mission_example.yaml \
  python main.py
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import yaml

# 防止 HuggingFace tokenizer fork 死锁警告
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

# Load .env before any os.environ reads (no-op if file absent)
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

import uvicorn

from core.state_api import StateAPI
from core.orchestrator import EventBus, Orchestrator
from core.planner import Planner
from agents.recon_agent import ReconAgent
from agents.exploit_agent import ExploitAgent
from agents.critic_agent import CriticAgent
from agents.cleanup_agent import CleanupAgent
from executor.executor import Executor
from memory.rag_engine import RAGEngine
from core.report_generator import ReportGenerator
from api.main import app as fastapi_app, register_state_api, register_report_generator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)
logging.getLogger("neo4j.notifications").setLevel(logging.ERROR)


# ── 环境变量读取 ─────────────────────────────────────────────

def _env(key: str, default: str = "") -> str:
    val = os.environ.get(key, default)
    if not val:
        logger.warning(f"Environment variable {key!r} is not set")
    return val


REDIS_URL        = _env("REDIS_URL",        "redis://localhost:6379")
NEO4J_URL        = _env("NEO4J_URL",        "bolt://localhost:7687")
NEO4J_USER       = _env("NEO4J_USER",       "neo4j")
NEO4J_PASSWORD   = _env("NEO4J_PASSWORD",   "password")
CH_HOST          = _env("CLICKHOUSE_HOST",  "localhost")
CH_PORT          = int(os.environ.get("CLICKHOUSE_PORT", "9000"))
CH_DATABASE      = _env("CLICKHOUSE_DB",    "pentest")
MISSION_FILE     = _env("MISSION_FILE",     "config/mission_example.yaml")
API_HOST         = _env("API_HOST",         "0.0.0.0")
API_PORT         = int(os.environ.get("API_PORT", "8086"))
LLM_MODEL        = _env("LLM_MODEL",        "claude-sonnet-4-20250514")
ANTHROPIC_BASE_URL = os.environ.get("ANTHROPIC_BASE_URL")
ANTHROPIC_API_KEY  = os.environ.get("ANTHROPIC_API_KEY")

logger.info(f"Main: Loaded ANTHROPIC_BASE_URL={ANTHROPIC_BASE_URL}")
if ANTHROPIC_API_KEY:
    logger.info(f"Main: Loaded ANTHROPIC_API_KEY, length={len(ANTHROPIC_API_KEY)}")
else:
    logger.warning("Main: ANTHROPIC_API_KEY is empty")


# ── 初始化各层 ───────────────────────────────────────────────

def _build_clickhouse():
    try:
        from clickhouse_driver import Client
        # 使用连接池 (Pool) 或至少增加设置以处理并发
        # clickhouse_driver.Client 默认不支持多线程，但我们可以增加 settings
        return Client(
            host=CH_HOST, port=CH_PORT, database=CH_DATABASE,
            settings={"max_threads": 8, "max_block_size": 100000}
        )
    except Exception as e:
        logger.error(f"ClickHouse 连接失败: {e}")
        return None
        logger.error(f"ClickHouse 连接失败: {e}")
        raise


def _load_mission(path: str) -> dict:
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        return data.get("mission", data)
    except FileNotFoundError:
        logger.error(f"Mission file not found: {path}")
        raise
    except yaml.YAMLError as e:
        logger.error(f"Mission YAML parse error: {e}")
        raise


async def _init_state_api() -> StateAPI:
    ch = _build_clickhouse()
    state_api = StateAPI(
        redis_url=REDIS_URL,
        neo4j_url=NEO4J_URL,
        neo4j_auth=(NEO4J_USER, NEO4J_PASSWORD),
        clickhouse_client=ch,
    )
    # Verify Redis connectivity
    await state_api.redis.ping()
    logger.info("StateAPI: Redis OK")
    return state_api


async def _load_mission_into_state(state_api: StateAPI, mission: dict):
    """将 mission dict 写入 Redis，并自动展开域名 scope"""
    import json
    import socket
    
    # 自动展开域名 scope -> IP
    scope = mission.get("scope", [])
    resolved_scope = list(scope)
    for entry in scope:
        if "/" not in entry: # 不是 CIDR
            try:
                import ipaddress
                ipaddress.ip_address(entry)
            except ValueError:
                # 是域名，尝试解析
                try:
                    _, _, ips = socket.gethostbyname_ex(entry)
                    for ip in ips:
                        if ip not in resolved_scope:
                            resolved_scope.append(ip)
                    logger.info(f"Main: 域名解析 {entry} -> {ips}")
                except Exception as e:
                    logger.warning(f"Main: 域名解析失败 {entry}: {e}")
    
    mission["scope_expanded"] = resolved_scope
    
    existing = await state_api.redis.get("mission")
    if existing:
        logger.info("StateAPI: 覆盖旧 mission 配置")
    await state_api.redis.set("mission", json.dumps(mission))
    logger.info(f"StateAPI: mission loaded (scope={mission.get('scope')}, expanded_len={len(resolved_scope)})")


async def _clean_all_state(state_api: StateAPI):
    """清空全部运行时状态（Redis / Neo4j / ClickHouse），用于全新任务"""
    logger.info("=== 正在清理所有历史数据 ===")

    # Redis: 清空全库
    await state_api.redis.flushdb()
    logger.info("Clean: Redis flushdb 完成")

    # Neo4j: 删除所有节点和关系
    try:
        with state_api.neo4j.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
        logger.info("Clean: Neo4j 所有节点已删除")
    except Exception as e:
        logger.error(f"Clean: Neo4j 清理失败: {e}")

    # ClickHouse: 清空 tried_vectors 和 footprints 表
    try:
        state_api.ch.execute("TRUNCATE TABLE IF EXISTS tried_vectors")
        state_api.ch.execute("TRUNCATE TABLE IF EXISTS footprints")
        logger.info("Clean: ClickHouse 表已清空")
    except Exception as e:
        logger.error(f"Clean: ClickHouse 清理失败: {e}")

    # ChromaDB: 删除持久化目录（防止嵌入函数冲突）
    chroma_path = os.environ.get("CHROMA_PATH", "./memory/chroma_db")
    if os.path.exists(chroma_path):
        import shutil
        try:
            shutil.rmtree(chroma_path)
            logger.info(f"Clean: ChromaDB 目录已删除: {chroma_path}")
        except Exception as e:
            logger.warning(f"Clean: ChromaDB 清理失败: {e}")

    logger.info("=== 历史数据清理完成 ===")


def _build_orchestrator(state_api: StateAPI) -> tuple[Orchestrator, EventBus, ReportGenerator]:
    event_bus    = EventBus()
    executor     = Executor(state_api=state_api, event_bus=event_bus)
    planner      = Planner(model=LLM_MODEL, api_key=ANTHROPIC_API_KEY, base_url=ANTHROPIC_BASE_URL)
    rag_engine   = RAGEngine()
    report_gen   = ReportGenerator(model=LLM_MODEL, api_key=ANTHROPIC_API_KEY, base_url=ANTHROPIC_BASE_URL)
    orchestrator = Orchestrator(
        state_api     = state_api,
        event_bus     = event_bus,
        planner       = planner,
        exploit_agent = ExploitAgent(model=LLM_MODEL, api_key=ANTHROPIC_API_KEY, base_url=ANTHROPIC_BASE_URL),
        recon_agent   = ReconAgent(model=LLM_MODEL, api_key=ANTHROPIC_API_KEY, base_url=ANTHROPIC_BASE_URL),
        critic_agent  = CriticAgent(model=LLM_MODEL, api_key=ANTHROPIC_API_KEY, base_url=ANTHROPIC_BASE_URL),
        cleanup_agent = CleanupAgent(api_key=ANTHROPIC_API_KEY, base_url=ANTHROPIC_BASE_URL),
        executor      = executor,
        rag_engine    = rag_engine,
        report_generator = report_gen,
    )
    return orchestrator, event_bus, report_gen


# ── 并发启动 ─────────────────────────────────────────────────



def _parse_args():
    parser = argparse.ArgumentParser(description="Agentic Pentest Framework")
    parser.add_argument(
        "--clean", action="store_true",
        help="启动前清空所有历史数据（Redis/Neo4j/ClickHouse）"
    )
    parser.add_argument(
        "--mission", type=str, default=None,
        help="指定 mission 配置文件路径（覆盖环境变量 MISSION_FILE）"
    )
    parser.add_argument(
        "--check-tools", action="store_true", dest="check_tools",
        help="检查所有已注册工具的可用性，然后退出"
    )
    return parser.parse_args()


def _check_tools():
    """检查所有已注册工具的二进制可用性"""
    import shutil

    # 工具名 → 需要的二进制列表
    _TOOL_BINARIES = {
        "nmap / port_scan / service_enum":  ["nmap"],
        "nuclei / vuln_scan":               ["nuclei"],
        "banner_grab":                      ["ncat", "nc"],  # 任一即可
        "http_probe (httpx)":               ["httpx"],
        "screenshot (playwright)":          ["playwright"],
        "dir_enum (feroxbuster)":           ["feroxbuster"],
        "smb_enum (enum4linux-ng)":         ["enum4linux-ng"],
        "ldap_enum (ldapsearch)":           ["ldapsearch"],
        "cred_spray (hydra)":              ["hydra"],
        "msf / metasploit":                 ["msfrpcd"],
        "codeql / code_audit":              ["codeql"],
    }

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║             Agentic Pentest — 工具可用性检查               ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ {'工具名':<30} {'状态':<8} {'路径':<22}║")
    print("╠══════════════════════════════════════════════════════════════╣")

    available = 0
    total = len(_TOOL_BINARIES)

    for tool_name, binaries in _TOOL_BINARIES.items():
        found_path = None
        for b in binaries:
            path = shutil.which(b)
            if path:
                found_path = path
                break

        if found_path:
            status = "✅ 可用"
            path_str = found_path
            if len(path_str) > 20:
                path_str = "..." + path_str[-17:]
            available += 1
        else:
            status = "❌ 缺失"
            path_str = f"需要: {binaries[0]}"
            if len(path_str) > 20:
                path_str = path_str[:20]

        print(f"║ {tool_name:<30} {status:<8} {path_str:<22}║")

    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ 可用: {available}/{total}    "
          f"{'所有工具就绪！' if available == total else f'缺少 {total - available} 个工具（运行时将跳过）':<38}║")
    print("╚══════════════════════════════════════════════════════════════╝\n")


async def main():
    args = _parse_args()

    if args.check_tools:
        _check_tools()
        return

    mission_file = args.mission or MISSION_FILE

    # ── 初始化 ──────────────────────────────────────────────
    logger.info("=== Agentic Pentest Framework starting ===")

    state_api = await _init_state_api()

    # 如果指定了 --clean，先清空所有历史数据
    if args.clean:
        await _clean_all_state(state_api)

    mission = _load_mission(mission_file)
    await _load_mission_into_state(state_api, mission)
    await state_api.verify_vector_counts_consistency()

    orchestrator, _, report_gen = _build_orchestrator(state_api)

    # 注入 StateAPI 到 FastAPI（Human 审批 API 使用）
    register_state_api(state_api)
    register_report_generator(report_gen)

    # ── 优雅关闭（约束⑤：SIGINT/SIGTERM 均处理）─────────────────
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()
    uvicorn_server = None       # 持有引用以便关闭
    signal_count = 0

    def _shutdown():
        nonlocal signal_count
        signal_count += 1
        if signal_count == 1:
            logger.info("Shutdown signal received — stopping gracefully...")
            orchestrator.stop()
            shutdown_event.set()
            if uvicorn_server:
                uvicorn_server.should_exit = True
        else:
            # 第二次 Ctrl+C：强制退出
            logger.warning("Force exit (second signal)")
            import os
            os._exit(1)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)

    # ── 并发运行 Orchestrator + API + 进度报告 ────────────────
    logger.info(f"API server listening on {API_HOST}:{API_PORT}")
    logger.info(f"Mission scope: {mission.get('scope')}")
    logger.info("Type 'status' in API console or curl http://localhost:{}/status for progress".format(API_PORT))

    async def _run_api():
        nonlocal uvicorn_server
        config = uvicorn.Config(
            app=fastapi_app,
            host=API_HOST,
            port=API_PORT,
            log_level="info",
            loop="none",
        )
        uvicorn_server = uvicorn.Server(config)
        await uvicorn_server.serve()

    async def _print_progress_loop():
        """空循环（进度已由 orchestrator._print_progress 输出）"""
        while not shutdown_event.is_set():
            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=30)
                break
            except asyncio.TimeoutError:
                pass

    try:
        await asyncio.gather(
            orchestrator.start(),
            _run_api(),
            _print_progress_loop(),
            return_exceptions=True,
        )
    except Exception:
        pass

    # ── 最终关闭 ──────────────────────────────────────────────
    shutdown_event.set()
    logger.info("Closing connections...")

    try:
        await state_api.redis.aclose()
        state_api.neo4j.close()
    except Exception as e:
        logger.warning(f"Error closing connections: {e}")

    logger.info("=== Agentic Pentest Framework stopped ===")


if __name__ == "__main__":
    asyncio.run(main())

