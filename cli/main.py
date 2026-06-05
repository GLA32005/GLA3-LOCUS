"""
LOCUS — Autonomous Agentic Pentest Framework

统一 CLI 入口，所有操作通过子命令完成。
"""

from __future__ import annotations

import os
import sys

# 确保项目根目录在 sys.path 最前面，防止同名包冲突（如 LLaMA-Factory 的 api.py）
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import asyncio
import json
import shutil
import signal

import click
from rich.console import Console

console = Console()


def _run_async(coro):
    """在 click 命令中运行 async 函数"""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def _get_config():
    from core.config_manager import ConfigManager
    return ConfigManager(project_dir=_PROJECT_ROOT)


def _get_service_manager(config=None):
    from core.service_manager import ServiceManager
    return ServiceManager(project_dir=_PROJECT_ROOT, config=config)


# ═══════════════════════════════════════════════════════════
# 顶层命令组
# ═══════════════════════════════════════════════════════════

class ChineseHelpCommand(click.Command):
    def get_help(self, ctx):
        return super().get_help(ctx).replace("Usage:", "用法:").replace("Options:", "选项:").replace("Commands:", "命令:").replace("Show this message and exit.", "显示此帮助信息并退出。")

class ChineseHelpGroup(click.Group):
    def get_help(self, ctx):
        return super().get_help(ctx).replace("Usage:", "用法:").replace("Options:", "选项:").replace("Commands:", "命令:").replace("Show this message and exit.", "显示此帮助信息并退出。")
    def command(self, *args, **kwargs):
        kwargs.setdefault("cls", ChineseHelpCommand)
        return super().command(*args, **kwargs)
    def group(self, *args, **kwargs):
        kwargs.setdefault("cls", ChineseHelpGroup)
        return super().group(*args, **kwargs)

@click.group(cls=ChineseHelpGroup, invoke_without_command=True)
@click.version_option("0.1.0", prog_name="locus", message="%(prog)s 版本 %(version)s", help="显示版本信息并退出。")
@click.pass_context
def cli(ctx):
    """LOCUS — Autonomous Agentic Pentest Framework

    自主智能体渗透测试框架。输入 locus COMMAND --help 查看子命令帮助。
    """
    if ctx.invoked_subcommand is None:
        from cli.banner import print_banner
        print_banner()
        click.echo(ctx.get_help())


@cli.command("help")
@click.pass_context
def help_cmd(ctx):
    """显示可用命令与帮助信息"""
    click.echo(ctx.parent.get_help())


# ═══════════════════════════════════════════════════════════
# scan — 核心扫描命令
# ═══════════════════════════════════════════════════════════

@cli.command()
@click.argument("targets", nargs=-1)
@click.option("--risk", default=None, type=int, help="风险等级 1-5")
@click.option("--clean", is_flag=True, help="清空历史数据后扫描")
@click.option("--mission", "-m", type=click.Path(exists=True), help="指定 mission YAML 文件")
@click.option("--dry-run", is_flag=True, help="只生成 mission 配置，不执行扫描")
@click.option("-v", "--verbose", is_flag=True, help="详细日志输出")
def scan(targets, risk, clean, mission, dry_run, verbose):
    """扫描目标

    用法:
      locus scan shop.10086.cn
      locus scan 192.168.1.0/24 --risk 4
      locus scan -m config/mission.yaml --clean
    """
    from cli.banner import print_banner
    print_banner()

    if not targets and not mission:
        console.print("[red]❌ 请指定目标或 mission 文件[/]")
        console.print("   [dim]示例: locus scan target.com[/]")
        console.print("   [dim]      locus scan -m config/mission.yaml[/]")
        raise SystemExit(1)

    config = _get_config()

    import logging
    from core.log_config import setup_logging
    log_level = logging.DEBUG if verbose else logging.INFO
    setup_logging(log_level)

    _run_async(_scan_async(targets, risk, clean, mission, dry_run, config))


async def _scan_async(targets, risk, clean, mission_file, dry_run, config):
    """scan 的异步实现"""
    # 1. 确保服务可用
    svc = _get_service_manager(config)
    mode = await svc.ensure_running()

    # 2. 导出配置到环境变量（兼容旧代码）
    config.export_to_env()
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

    # 3. 生成或加载 mission
    if mission_file:
        console.print(f"📋 [cyan]使用 mission 文件: {mission_file}[/]")
        mission = _load_mission_file(mission_file)
    else:
        mission = _generate_mission(list(targets), risk, config)
        console.print(f"🎯 [cyan]目标: {', '.join(targets)}[/]")
        console.print(f"   [dim]风险等级: {mission['risk_level']} | "
                      f"运行模式: {mode}[/]")

    if dry_run:
        console.print("\n[yellow]--dry-run: 生成的 mission 配置:[/]")
        console.print_json(json.dumps(mission, ensure_ascii=False, indent=2))
        return

    # 4. 初始化并运行
    console.print("\n⚡ [green bold]启动扫描...[/]\n")
    await _run_main_loop(mission, clean, mode, config)


def _generate_mission(targets: list[str], risk: int | None, config) -> dict:
    """从命令行参数动态生成 mission"""
    cfg_risk = config.get("scan.risk_level", 3)
    return {
        "goal": f"对 {', '.join(targets)} 进行渗透测试",
        "scope": targets,
        "oob": [],
        "risk_level": risk if risk is not None else cfg_risk,
        "approved_ops": [
            "port_scan", "vulnerability_scan",
            "exploitation", "privilege_escalation", "lateral_movement",
        ],
        "max_noise": config.get("scan.max_noise", 30),
        "context_budget": config.get("scan.context_budget", 8000),
        "max_payload_retry": config.get("scan.max_payload_retry", 3),
        "human_approve_threshold": 4,
        "deadline": 0,
        "max_stall_count": 10,
        "max_think_rounds": config.get("scan.max_think_rounds", 200),
        "max_runtime_seconds": config.get("scan.max_runtime", 7200),
    }


def _load_mission_file(path: str) -> dict:
    """从 YAML 文件加载 mission"""
    import yaml
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("mission", data)


async def _run_main_loop(mission: dict, clean: bool, mode: str, config):
    """启动核心循环（复用 main.py 的逻辑）"""
    import logging
    import uvicorn

    # 静音 Neo4j driver 的 notification 警告（空库查询不存在的关系类型/属性时会刷屏）
    logging.getLogger("neo4j").setLevel(logging.ERROR)
    logging.getLogger("neo4j.notifications").setLevel(logging.ERROR)
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

    logger = logging.getLogger("locus")

    # 读取配置
    llm_model = config.get("llm.model")
    api_key = config.get("llm.api_key")
    base_url = config.get("llm.base_url")
    redis_url = config.get("storage.redis_url")
    neo4j_url = config.get("storage.neo4j_url")
    neo4j_user = config.get("storage.neo4j_user")
    neo4j_pass = config.get("storage.neo4j_password")
    ch_host = config.get("storage.clickhouse_host")
    ch_port = config.get("storage.clickhouse_port")
    ch_db = config.get("storage.clickhouse_db")
    api_host = config.get("api.host")
    api_port = config.get("api.port")

    # ClickHouse
    ch_client = None
    if mode != "lite":
        try:
            from clickhouse_driver import Client
            ch_client = Client(
                host=ch_host, port=ch_port, database=ch_db,
                settings={"max_threads": 8, "max_block_size": 100000},
            )
        except Exception as e:
            logger.warning(f"ClickHouse 连接失败（降级）: {e}")

    # StateAPI
    if mode == "lite":
        import fakeredis.aioredis
        state_api = StateAPI(
            redis_url="redis://localhost:6379",
            neo4j_url=neo4j_url,
            neo4j_auth=(neo4j_user, neo4j_pass),
            clickhouse_client=None,
        )
        state_api.redis = fakeredis.aioredis.FakeRedis()
    else:
        state_api = StateAPI(
            redis_url=redis_url,
            neo4j_url=neo4j_url,
            neo4j_auth=(neo4j_user, neo4j_pass),
            clickhouse_client=ch_client,
        )
        await state_api.redis.ping()

    # Clean
    if clean:
        logger.info("=== 清理历史数据 ===")
        await state_api.redis.flushdb()
        try:
            state_api.neo4j.execute_query("MATCH (n) DETACH DELETE n")
        except Exception:
            pass
        if ch_client:
            try:
                ch_client.execute("TRUNCATE TABLE IF EXISTS tried_vectors")
                ch_client.execute("TRUNCATE TABLE IF EXISTS footprints")
            except Exception:
                pass

    # 加载 mission
    import socket
    scope = mission.get("scope", [])
    resolved = list(scope)
    for entry in scope:
        if "/" not in entry:
            try:
                import ipaddress
                ipaddress.ip_address(entry)
            except ValueError:
                try:
                    _, _, ips = socket.gethostbyname_ex(entry)
                    for ip in ips:
                        if ip not in resolved:
                            resolved.append(ip)
                    logger.info(f"域名解析 {entry} -> {ips}")
                except Exception:
                    pass
    mission["scope_expanded"] = resolved
    await state_api.redis.set("mission", json.dumps(mission))

    # 构建组件
    event_bus = EventBus()
    executor = Executor(state_api=state_api, event_bus=event_bus)
    planner = Planner(model=llm_model, api_key=api_key, base_url=base_url)
    rag_engine = RAGEngine()
    report_gen = ReportGenerator(model=llm_model, api_key=api_key, base_url=base_url)
    orchestrator = Orchestrator(
        state_api=state_api, event_bus=event_bus,
        planner=planner,
        exploit_agent=ExploitAgent(model=llm_model, api_key=api_key, base_url=base_url),
        recon_agent=ReconAgent(model=llm_model, api_key=api_key, base_url=base_url),
        critic_agent=CriticAgent(model=llm_model, api_key=api_key, base_url=base_url),
        cleanup_agent=CleanupAgent(api_key=api_key, base_url=base_url),
        executor=executor, rag_engine=rag_engine, report_generator=report_gen,
    )

    register_state_api(state_api)
    register_report_generator(report_gen)

    # 优雅关闭
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()
    uvicorn_server = None
    signal_count = 0

    def _shutdown():
        nonlocal signal_count
        signal_count += 1
        if signal_count == 1:
            logger.info("收到关闭信号，正在优雅退出...")
            orchestrator.stop()
            shutdown_event.set()
            if uvicorn_server:
                uvicorn_server.should_exit = True
        else:
            os._exit(1)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)

    # 并发运行 — 先检测端口冲突
    import socket as _sock
    import subprocess as _sp
    _test_sock = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    try:
        _test_sock.bind((api_host if api_host != "0.0.0.0" else "127.0.0.1", api_port))
    except OSError:
        # 端口被占用，尝试自动清理残留进程
        try:
            result = _sp.run(["lsof", "-ti", f":{api_port}"],
                             capture_output=True, text=True, timeout=5)
            pids = result.stdout.strip().split("\n")
            for pid in pids:
                if pid.strip():
                    _sp.run(["kill", pid.strip()], timeout=5)
            logger.warning(f"端口 {api_port} 被占用，已清理残留进程: {pids}")
            import time; time.sleep(1)
        except Exception as e:
            console.print(f"[red]❌ 端口 {api_port} 被占用且无法自动清理: {e}[/]")
            console.print(f"   [dim]手动执行: kill $(lsof -ti :{api_port})[/]")
            return
    finally:
        _test_sock.close()

    async def _run_api():
        nonlocal uvicorn_server
        uv_config = uvicorn.Config(
            app=fastapi_app, host=api_host, port=api_port,
            log_level="warning", loop="none",
        )
        uvicorn_server = uvicorn.Server(uv_config)
        await uvicorn_server.serve()

    logger.info(f"API: http://{api_host}:{api_port}")
    logger.info(f"Scope: {mission.get('scope')}")

    try:
        await asyncio.gather(
            orchestrator.start(), _run_api(),
            return_exceptions=True,
        )
    except Exception:
        pass

    shutdown_event.set()
    try:
        await state_api.redis.aclose()
        state_api.neo4j.close()
    except Exception:
        pass
    logger.info("=== LOCUS 已停止 ===")


# ═══════════════════════════════════════════════════════════
# status — 查看进度
# ═══════════════════════════════════════════════════════════

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="JSON 格式输出")
@click.option("--follow", "-f", is_flag=True, help="持续刷新")
def status(as_json, follow):
    """查看扫描进度

    用法:
      locus status           # 快照
      locus status -f        # 持续刷新
      locus status --json    # JSON 输出
    """
    config = _get_config()
    api_port = config.get("api.port", 8086)
    api_url = f"http://localhost:{api_port}"

    from cli.progress_display import ProgressDisplay
    display = ProgressDisplay(api_base=api_url)

    if follow:
        _run_async(display.follow())
    elif as_json:
        data = _run_async(display._fetch_progress())
        if data:
            display.show_json(data)
        else:
            console.print("[red]❌ 无法连接到 LOCUS 服务[/]")
    else:
        _run_async(display.show())


# ═══════════════════════════════════════════════════════════
# stop — 停止扫描
# ═══════════════════════════════════════════════════════════

@cli.command()
def stop():
    """停止当前扫描（保留后台服务）"""
    config = _get_config()
    api_port = config.get("api.port", 8086)

    async def _stop():
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://localhost:{api_port}/stop",
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        console.print("✅ [green]已发送停止信号[/]")
                    else:
                        console.print(f"[yellow]服务响应: {resp.status}[/]")
        except Exception:
            console.print("[red]❌ 无法连接到 LOCUS 服务（可能未在运行）[/]")

    _run_async(_stop())


# ═══════════════════════════════════════════════════════════
# report — 生成报告
# ═══════════════════════════════════════════════════════════

@cli.command()
@click.option("--format", "fmt", type=click.Choice(["md", "json"]), default="md",
              help="报告格式")
def report(fmt):
    """生成渗透测试报告"""
    config = _get_config()
    api_port = config.get("api.port", 8086)

    async def _report():
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://localhost:{api_port}/report",
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    data = await resp.json()
                    if data.get("status") == "ok":
                        path = data.get("path", "")
                        console.print(f"✅ [green]报告已生成: {path}[/]")
                    else:
                        console.print(f"[yellow]{data.get('message', '报告生成中...')}[/]")
        except Exception:
            console.print("[red]❌ 无法连接到 LOCUS 服务[/]")

    _run_async(_report())


# ═══════════════════════════════════════════════════════════
# up / down — 服务管理
# ═══════════════════════════════════════════════════════════

@cli.command()
def up():
    """启动后台服务（Docker Compose）"""
    config = _get_config()
    svc = _get_service_manager(config)
    _run_async(svc.up())


@cli.command()
def down():
    """停止后台服务（Docker Compose）"""
    config = _get_config()
    svc = _get_service_manager(config)
    _run_async(svc.down())


# ═══════════════════════════════════════════════════════════
# db — 数据库管理
# ═══════════════════════════════════════════════════════════

@cli.group()
def db():
    """数据库与状态管理

    用法:
      locus db clean
      locus db info
    """
    pass

@db.command("clean")
@click.option("--force", "-f", is_flag=True, help="跳过确认强制清空")
def db_clean(force):
    """清空所有底层数据 (Redis, Neo4j, ClickHouse)"""
    if not force:
        click.confirm("此操作将永久清空所有扫描状态、资产图谱和历史日志，是否继续？", abort=True)
    
    config = _get_config()
    redis_url = config.get("storage.redis_url")
    neo4j_url = config.get("storage.neo4j_url")
    neo4j_user = config.get("storage.neo4j_user")
    neo4j_pass = config.get("storage.neo4j_password")
    ch_host = config.get("storage.clickhouse_host")
    ch_port = config.get("storage.clickhouse_port")
    ch_db = config.get("storage.clickhouse_db")

    async def _clean():
        import logging
        logging.getLogger("neo4j").setLevel(logging.ERROR)
        from core.state_api import StateAPI
        try:
            from clickhouse_driver import Client
            ch_client = Client(host=ch_host, port=ch_port, database=ch_db)
        except Exception:
            ch_client = None

        state_api = StateAPI(
            redis_url=redis_url,
            neo4j_url=neo4j_url,
            neo4j_auth=(neo4j_user, neo4j_pass),
            clickhouse_client=ch_client
        )

        with console.status("[cyan]正在清空 Redis...[/]"):
            await state_api.redis.flushdb()
            console.print("✅ [green]Redis 已清空[/]")

        with console.status("[cyan]正在清空 Neo4j 图谱...[/]"):
            try:
                state_api.neo4j.execute_query("MATCH (n) DETACH DELETE n")
                console.print("✅ [green]Neo4j 已清空[/]")
            except Exception as e:
                console.print(f"⚠️ [yellow]Neo4j 清理跳过: {e}[/]")

        with console.status("[cyan]正在清空 ClickHouse 表...[/]"):
            if ch_client:
                try:
                    ch_client.execute("TRUNCATE TABLE IF EXISTS tried_vectors")
                    ch_client.execute("TRUNCATE TABLE IF EXISTS footprints")
                    console.print("✅ [green]ClickHouse 已清空[/]")
                except Exception as e:
                    console.print(f"⚠️ [yellow]ClickHouse 清理跳过: {e}[/]")
            else:
                console.print("⚠️ [dim]ClickHouse 客户端未连接，已跳过[/]")

        try:
            await state_api.redis.aclose()
            state_api.neo4j.close()
        except:
            pass

    _run_async(_clean())


@db.command("info")
def db_info():
    """查看数据库状态与数据量"""
    config = _get_config()
    redis_url = config.get("storage.redis_url")
    neo4j_url = config.get("storage.neo4j_url")
    neo4j_user = config.get("storage.neo4j_user")
    neo4j_pass = config.get("storage.neo4j_password")

    async def _info():
        import logging
        logging.getLogger("neo4j").setLevel(logging.ERROR)
        from core.state_api import StateAPI
        state_api = StateAPI(
            redis_url=redis_url,
            neo4j_url=neo4j_url,
            neo4j_auth=(neo4j_user, neo4j_pass),
            clickhouse_client=None
        )

        from rich.table import Table
        table = Table(title="[bold blue]Locus 底层存储状态[/]")
        table.add_column("存储引擎", style="cyan", no_wrap=True)
        table.add_column("状态", style="green")
        table.add_column("核心指标", style="magenta")

        # Redis
        try:
            db_size = await state_api.redis.dbsize()
            q_len = await state_api.redis.llen("queue:mission")
            table.add_row("Redis", "✅ 在线", f"Key总数: {db_size} | 任务队列: {q_len}")
        except Exception as e:
            table.add_row("Redis", f"❌ 离线", str(e))

        # Neo4j
        try:
            res, _, _ = state_api.neo4j.execute_query("MATCH (n) RETURN count(n) as c")
            node_count = res[0]["c"] if res else 0
            table.add_row("Neo4j", "✅ 在线", f"节点总数: {node_count}")
        except Exception as e:
            table.add_row("Neo4j", f"❌ 离线", str(e))

        console.print(table)
        
        try:
            await state_api.redis.aclose()
            state_api.neo4j.close()
        except:
            pass

    _run_async(_info())


# ═══════════════════════════════════════════════════════════
# assets / vulns — 实时看板
# ═══════════════════════════════════════════════════════════

@cli.command("assets")
@click.option("--target", help="按目标域名或IP过滤")
def assets(target):
    """实时查看已收集到的资产 (Hosts & Services)"""
    config = _get_config()
    redis_url = config.get("storage.redis_url")
    neo4j_url = config.get("storage.neo4j_url")
    neo4j_user = config.get("storage.neo4j_user")
    neo4j_pass = config.get("storage.neo4j_password")

    async def _assets():
        import logging
        logging.getLogger("neo4j").setLevel(logging.ERROR)
        from core.state_api import StateAPI
        state_api = StateAPI(redis_url=redis_url, neo4j_url=neo4j_url, neo4j_auth=(neo4j_user, neo4j_pass), clickhouse_client=None)

        query = "MATCH (h:Host) OPTIONAL MATCH (h)-[:RUNS]->(s:Service) "
        if target:
            query += f"WHERE h.ip CONTAINS '{target}' OR h.domain CONTAINS '{target}' "
        query += "RETURN h.ip as ip, h.domain as domain, collect(s.port + '/' + s.proto) as services"

        try:
            records = state_api._run_cypher_sync(query)
            from rich.table import Table
            table = Table(title=f"[bold blue]Locus 资产清单[/]")
            table.add_column("IP地址", style="cyan")
            table.add_column("域名", style="green")
            table.add_column("开放服务", style="magenta")

            for r in records:
                ip = r["ip"] or "-"
                domain = r["domain"] or "-"
                services = ", ".join([str(x) for x in r["services"] if x]) or "-"
                table.add_row(ip, domain, services)

            console.print(table)
        except Exception as e:
            console.print(f"[red]❌ 无法连接到底层数据库: {e}[/]")
        finally:
            try:
                await state_api.redis.aclose()
                state_api.neo4j.close()
            except: pass

    _run_async(_assets())


@cli.command("vulns")
def vulns():
    """实时查看发现的漏洞与凭证"""
    config = _get_config()
    redis_url = config.get("storage.redis_url")
    neo4j_url = config.get("storage.neo4j_url")
    neo4j_user = config.get("storage.neo4j_user")
    neo4j_pass = config.get("storage.neo4j_password")

    async def _vulns():
        import logging
        logging.getLogger("neo4j").setLevel(logging.ERROR)
        from core.state_api import StateAPI
        state_api = StateAPI(redis_url=redis_url, neo4j_url=neo4j_url, neo4j_auth=(neo4j_user, neo4j_pass), clickhouse_client=None)

        try:
            from rich.table import Table
            
            # Credentials
            cred_query = "MATCH (h:Host)-[:HAS_CRED]->(c:Credential) RETURN h.ip as ip, c.username as username, c.password as password"
            cred_records = state_api._run_cypher_sync(cred_query)
            if cred_records:
                table = Table(title="[bold yellow]已获取凭证[/]")
                table.add_column("目标", style="cyan")
                table.add_column("账号", style="green")
                table.add_column("密码", style="red")
                for r in cred_records:
                    table.add_row(r["ip"] or "-", r["username"] or "-", r["password"] or "-")
                console.print(table)

            # Vulnerabilities (from properties on Host/Service)
            vuln_query = "MATCH (n) WHERE any(k IN keys(n) WHERE k STARTS WITH 'vuln_') RETURN labels(n)[0] as type, n.ip as ip, n.port as port, properties(n) as props"
            vuln_records = state_api._run_cypher_sync(vuln_query)
            if vuln_records:
                table2 = Table(title="[bold red]已发现高价值漏洞[/]")
                table2.add_column("目标", style="cyan")
                table2.add_column("漏洞名称", style="red")
                table2.add_column("详情", style="magenta")
                for r in vuln_records:
                    target = str(r.get("ip", "-")) + (f":{r['port']}" if r.get("port") else "")
                    for k, v in r["props"].items():
                        if k.startswith("vuln_"):
                            table2.add_row(target, k.replace("vuln_", ""), str(v))
                console.print(table2)
            elif not cred_records:
                console.print("✅ [green]暂未发现漏洞或凭证[/]")

        except Exception as e:
            console.print(f"[red]❌ 无法连接到底层数据库: {e}[/]")
        finally:
            try:
                await state_api.redis.aclose()
                state_api.neo4j.close()
            except: pass

    _run_async(_vulns())


# ═══════════════════════════════════════════════════════════
# logs — 日志跟踪
# ═══════════════════════════════════════════════════════════

@cli.command("logs")
def logs():
    """实时查看底层扫描日志"""
    import os
    import time
    log_file = os.path.expanduser("~/.locus/logs/locus.log")
    
    if not os.path.exists(log_file):
        console.print(f"[yellow]日志文件暂不存在: {log_file} (可能尚未启动扫描)[/]")
        return
        
    console.print(f"[dim]正在追踪日志: {log_file}... (按 Ctrl+C 退出)[/]")
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            # 默认跳到文件末尾前约 2000 字节，打印最后几行
            f.seek(0, 2)
            size = f.tell()
            if size > 2000:
                f.seek(size - 2000)
                f.readline() # drop partial line
                
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                # 简单高亮处理
                line = line.strip()
                if "ERROR" in line or "CRITICAL" in line:
                    console.print(f"[red]{line}[/]")
                elif "WARNING" in line:
                    console.print(f"[yellow]{line}[/]")
                elif "SUCCESS" in line or "STRONG" in line:
                    console.print(f"[green]{line}[/]")
                else:
                    console.print(line)
    except KeyboardInterrupt:
        console.print("\n[dim]已退出日志追踪。[/]")


# ═══════════════════════════════════════════════════════════
# tools — 第三方工具管理
# ═══════════════════════════════════════════════════════════

@cli.group("tools")
def tools():
    """管理依赖的第三方二进制安全工具"""
    pass

@tools.command("update")
@click.option("--force", "-f", is_flag=True, help="强制重新下载安装")
def tools_update(force):
    """自动下载并安装 Locus 依赖的二进制引擎 (nuclei/httpx/nmap等)"""
    import platform
    import urllib.request
    import zipfile
    import os
    
    bin_dir = os.path.expanduser("~/.locus/bin")
    os.makedirs(bin_dir, exist_ok=True)
    
    # 获取系统架构
    sys_os = platform.system().lower()
    sys_arch = platform.machine().lower()
    
    if sys_arch in ("x86_64", "amd64"):
        arch = "amd64"
    elif sys_arch in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = "amd64"
        
    os_name = "macOS" if sys_os == "darwin" else "linux"
    
    console.print(f"[dim]探测到运行环境: {os_name} {arch}[/]")
    console.print(f"[dim]工具统一安装目录: {bin_dir}[/]")
    
    # Locus 需要的核心外部依赖（仅做框架示例，具体版本和下载链接可以维护在一个 JSON 中）
    tools_map = {
        "nuclei": f"https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_{os_name}_{arch}.zip",
        "httpx":  f"https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_{os_name}_{arch}.zip",
    }
    
    for tname, url in tools_map.items():
        bin_path = os.path.join(bin_dir, tname)
        if os.path.exists(bin_path) and not force:
            console.print(f"✅ [green]{tname} 已经安装完毕。使用 -f 强制覆盖更新。[/]")
            continue
            
        with console.status(f"[cyan]正在从 Github 拉取 {tname} (可能会受网络影响)...[/]"):
            try:
                zip_path = os.path.join(bin_dir, f"{tname}.zip")
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as response, open(zip_path, 'wb') as out_file:
                    out_file.write(response.read())
                    
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(bin_dir)
                    
                os.remove(zip_path)
                
                # 赋权
                if sys_os != "windows":
                    os.chmod(bin_path, 0o755)
                    
                console.print(f"✅ [green]{tname} 下载并解压成功！[/]")
            except Exception as e:
                console.print(f"❌ [red]{tname} 下载失败，请检查网络 (错误: {e})[/]")

    console.print("\n💡 [yellow]提示: 请确保 ~/.locus/bin 已经加入到你的 $PATH 环境变量中。[/]")
    console.print("   [dim]例如在 ~/.zshrc 或 ~/.bashrc 中添加: export PATH=\"$HOME/.locus/bin:$PATH\"[/]")


# ═══════════════════════════════════════════════════════════
# control — 运行控制
# ═══════════════════════════════════════════════════════════

@cli.command("pause")
def pause():
    """将正在运行的扫描任务挂起 (暂停新的漏洞探测)"""
    config = _get_config()
    api_key = config.get("api.api_key", "changeme")
    api_port = config.get("api.port", 8080)
    
    import urllib.request
    import json
    
    req = urllib.request.Request(
        f"http://127.0.0.1:{api_port}/pause",
        method="POST",
        headers={"X-API-Key": api_key}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "paused":
                console.print("⏸️  [yellow]已发送挂起信号！当前正在执行的 payload 会执行完毕，但 Orchestrator 将暂停规划新的动作。[/]")
    except Exception as e:
        console.print(f"[red]❌ 无法连接到 API 服务: {e}[/]")

@cli.command("resume")
def resume():
    """恢复挂起的扫描任务"""
    config = _get_config()
    api_key = config.get("api.api_key", "changeme")
    api_port = config.get("api.port", 8080)
    
    import urllib.request
    import json
    
    req = urllib.request.Request(
        f"http://127.0.0.1:{api_port}/resume",
        method="POST",
        headers={"X-API-Key": api_key}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "resumed":
                console.print("▶️  [green]已发送恢复信号！Orchestrator 将重新接管任务控制权。[/]")
    except Exception as e:
        console.print(f"[red]❌ 无法连接到 API 服务: {e}[/]")

# ═══════════════════════════════════════════════════════════
# config — 配置管理
# ═══════════════════════════════════════════════════════════

@cli.group()
def config():
    """配置管理

    用法:
      locus config show
      locus config set llm.model Qwen3.5-9B-MLX-8bit
    """
    pass


@config.command("show")
def config_show():
    """显示当前配置"""
    cfg = _get_config()
    console.print(Panel(cfg.show(), title="[bold green]LOCUS 配置[/]",
                        border_style="green"))


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """设置配置项

    用法: locus config set llm.model Qwen3.5-9B-MLX-8bit
    """
    cfg = _get_config()
    cfg.set(key, value)
    console.print(f"✅ [green]{key}[/] = [cyan]{value}[/]")


@config.command("init")
def config_init():
    """初始化并引导配置"""
    import os
    cfg = _get_config()
    cfg.ensure_dir()
    
    console.print("[bold cyan]🔧 Locus 初始化向导[/]")
    console.print("Locus 采用“双模型架构”，基础模型用于常规信息收集与轻量决策，")
    console.print("Strong 模型（可选）用于高难度的漏洞利用攻坚。\n")

    # 1. Base Model
    console.print("[bold yellow]【第一步：基础模型配置】[/]")
    base_url = click.prompt("基础推理服务地址", default="http://127.0.0.1:8866")
    api_key = click.prompt("API Key (本地随意填)", default="localkey")
    model = click.prompt("模型名称", default="Qwen3.5-9B-MLX-8bit")
    
    cfg.set("llm.base_url", base_url)
    cfg.set("llm.api_key", api_key)
    cfg.set("llm.model", model)

    # 2. Strong Model
    console.print("\n[bold yellow]【第二步：Strong 模型配置】[/]")
    use_strong = click.confirm("是否配置 Strong 模型（用于 EXPLOIT 阶段提权/利用攻坚）?", default=True)
    if use_strong:
        strong_api_key = click.prompt("API Key")
        strong_base_url = click.prompt("Base URL", default="https://api.deepseek.com")
        strong_model = click.prompt("模型名称", default="deepseek-v4-flash")
        
        cfg.set("llm.strong_api_key", strong_api_key)
        cfg.set("llm.strong_base_url", strong_base_url)
        cfg.set("llm.strong_model", strong_model)
    else:
        cfg.set("llm.strong_api_key", "")

    # 3. Storage
    console.print("\n[bold yellow]【第三步：运行与存储服务配置】[/]")
    console.print("Locus 的后台状态引擎支持三种模式：Docker自动拉起、本地原生端口、单机纯内存模式(Lite)。")
    custom_storage = click.confirm("你是否需要手动修改底层的数据库连接地址（如果你打算让 Locus 自动管理，或使用单机模式，请选 N）?", default=False)
    if custom_storage:
        redis_url = click.prompt("Redis URL", default="redis://localhost:6379")
        neo4j_url = click.prompt("Neo4j URL", default="bolt://localhost:7687")
        ch_host = click.prompt("ClickHouse Host", default="localhost")
        
        cfg.set("storage.redis_url", redis_url)
        cfg.set("storage.neo4j_url", neo4j_url)
        cfg.set("storage.clickhouse_host", ch_host)

    console.print(f"\n✅ [green]配置已成功写入 {cfg.config_file}[/]")

    # Check for .env conflicts
    env_path = os.path.join(os.getcwd(), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            content = f.read()
            if "LLM_" in content or "STRONG_" in content:
                console.print("\n[bold yellow]⚠️ 注意：检测到你的 .env 文件存在且包含 LLM_* 或 STRONG_* 字段。[/]")
                console.print("[yellow]在全新架构下，.env 不再管理 LLM 配置。建议删除 .env 中的这些遗留行，以免产生误解。[/]")


# ── Profile 子命令 ────────────────────────────────────────

@config.group("profile")
def config_profile():
    """Profile 管理"""
    pass


@config_profile.command("save")
@click.argument("name")
def profile_save(name):
    """保存当前配置为 profile"""
    cfg = _get_config()
    cfg.save_profile(name)
    console.print(f"✅ [green]Profile '{name}' 已保存[/]")


@config_profile.command("use")
@click.argument("name")
def profile_use(name):
    """加载 profile"""
    cfg = _get_config()
    try:
        cfg.load_profile(name)
        console.print(f"✅ [green]已切换到 profile '{name}'[/]")
        base_model = cfg.get("llm.model", "None")
        strong_model = cfg.get("llm.strong_model", "None") or "未配置"
        console.print(f"   [dim]▸ Base 模型:[/] [cyan]{base_model}[/]")
        console.print(f"   [dim]▸ Strong 模型:[/] [cyan]{strong_model}[/]")
    except FileNotFoundError as e:
        console.print(f"[red]❌ {e}[/]")


@config_profile.command("list")
def profile_list():
    """列出所有 profile"""
    cfg = _get_config()
    profiles = cfg.list_profiles()
    if profiles:
        for p in profiles:
            console.print(f"  • {p}")
    else:
        console.print("[dim]暂无 profile，使用 locus config profile save NAME 创建[/]")


# ═══════════════════════════════════════════════════════════
# doctor — 环境检查
# ═══════════════════════════════════════════════════════════

@cli.command()
def doctor():
    """环境自检（Docker、存储、工具、LLM）"""
    from cli.banner import print_banner
    print_banner()

    config = _get_config()
    svc = _get_service_manager(config)

    # 服务健康检查
    svc_health = _run_async(svc.health())

    # 工具检查
    _TOOL_BINARIES = {
        "nmap": ["nmap"],
        "nuclei": ["nuclei"],
        "httpx": ["httpx"],
        "feroxbuster": ["feroxbuster"],
        "hydra": ["hydra"],
        "enum4linux-ng": ["enum4linux-ng"],
        "ldapsearch": ["ldapsearch"],
    }

    tools = {}
    for name, bins in _TOOL_BINARIES.items():
        path = None
        for b in bins:
            p = shutil.which(b)
            if p:
                path = p
                break
        tools[name] = (path is not None, path or "")

    from cli.progress_display import ProgressDisplay
    display = ProgressDisplay()
    checks = display.build_doctor_checks(svc_health, tools)

    # LLM 检查
    llm_model = config.get("llm.model", "未配置")
    llm_url = config.get("llm.base_url", "")
    llm_ok = bool(llm_url)
    checks["🤖 LLM"] = [
        ("模型", True, llm_model),
        ("Base URL", llm_ok, llm_url if llm_ok else "未配置"),
    ]

    display.show_doctor(checks)

    # 运行模式建议
    mode = _run_async(svc.detect_mode())
    mode_desc = {"docker": "Docker 全功能", "native": "本地服务", "lite": "Lite 内存模式"}
    console.print(f"\n  推荐运行模式: [bold green]{mode_desc.get(mode, mode)}[/]")


# ═══════════════════════════════════════════════════════════
# 需要 Panel import
# ═══════════════════════════════════════════════════════════

from rich.panel import Panel


# ═══════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    cli()
