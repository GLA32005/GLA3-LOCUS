"""
服务生命周期管理 — 三级启动策略

检测顺序：Docker compose → 本地原生服务 → lite 模式
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

logger = logging.getLogger(__name__)
console = Console()


class ServiceManager:
    """管理后台服务（Redis / Neo4j / ClickHouse）的启停"""

    def __init__(self, project_dir: str = ".", config=None):
        self.project_dir = Path(project_dir).resolve()
        self.config = config
        self._mode: str | None = None  # docker / native / lite

    # ── 模式检测 ─────────────────────────────────────────

    async def detect_mode(self) -> str:
        """检测可用的运行模式"""
        if self._mode:
            return self._mode

        # 1. 检查 Docker compose 是否可用
        if self._has_docker_compose():
            self._mode = "docker"
            return "docker"

        # 2. 检查本地服务是否已在运行
        if await self._check_native_services():
            self._mode = "native"
            return "native"

        # 3. 降级到 lite 模式
        self._mode = "lite"
        return "lite"

    async def ensure_running(self) -> str:
        """确保服务可用，返回运行模式"""
        mode = await self.detect_mode()

        if mode == "docker":
            if not await self._docker_services_healthy():
                console.print("⏳ [yellow]后台服务未运行，正在启动 Docker Compose...[/]")
                await self._compose_up()
                await self._wait_healthy(timeout=90)
                console.print("✅ [green]后台服务已就绪[/]")
            else:
                console.print("✅ [green]Docker 服务运行中[/]")

        elif mode == "native":
            console.print("✅ [green]已检测到本地服务[/]")

        else:  # lite
            console.print(
                "⚡ [yellow]Lite 模式：使用内存存储（无 Docker、无本地服务）[/]\n"
                "   [dim]数据不持久化，重启后丢失。如需完整功能，请安装 Docker。[/]"
            )
            self._setup_lite_env()

        return mode

    # ── 公开命令 ─────────────────────────────────────────

    async def up(self):
        """启动后台服务"""
        if not self._has_docker_compose():
            console.print("❌ [red]未找到 Docker Compose，无法启动服务[/]")
            console.print("   [dim]请安装 Docker Desktop 或使用 locus scan（自动 lite 模式）[/]")
            return False
        console.print("⏳ [yellow]启动 Docker Compose 服务...[/]")
        await self._compose_up()
        await self._wait_healthy(timeout=90)
        console.print("✅ [green]所有服务已启动[/]")
        return True

    async def down(self):
        """停止后台服务"""
        if not self._has_docker_compose():
            console.print("❌ [red]未找到 Docker Compose[/]")
            return False
        console.print("⏳ [yellow]停止 Docker Compose 服务...[/]")
        cmd = self._compose_cmd() + ["down"]
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(self.project_dir),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.wait()
        console.print("✅ [green]服务已停止[/]")
        return True

    async def health(self) -> dict:
        """检查各服务健康状态"""
        results = {}

        # Docker
        results["docker"] = self._has_docker_compose()

        # Redis
        results["redis"] = await self._check_redis()

        # Neo4j
        results["neo4j"] = await self._check_neo4j()

        # ClickHouse
        results["clickhouse"] = await self._check_clickhouse()

        return results

    # ── Docker Compose 操作 ──────────────────────────────

    def _has_docker_compose(self) -> bool:
        """检测 docker compose 或 docker-compose 是否可用"""
        compose_file = self.project_dir / "docker-compose.yml"
        if not compose_file.exists():
            return False
        # docker compose (V2)
        if shutil.which("docker"):
            try:
                r = subprocess.run(
                    ["docker", "compose", "version"],
                    capture_output=True, timeout=5,
                )
                if r.returncode == 0:
                    return True
            except Exception:
                pass
        # docker-compose (V1)
        if shutil.which("docker-compose"):
            return True
        return False

    def _compose_cmd(self) -> list[str]:
        """返回 compose 命令前缀"""
        if shutil.which("docker"):
            try:
                r = subprocess.run(
                    ["docker", "compose", "version"],
                    capture_output=True, timeout=5,
                )
                if r.returncode == 0:
                    return ["docker", "compose"]
            except Exception:
                pass
        return ["docker-compose"]

    async def _compose_up(self):
        cmd = self._compose_cmd() + ["up", "-d"]
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(self.project_dir),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.error(f"Docker Compose 启动失败: {stderr.decode()}")
            raise RuntimeError(f"Docker Compose 启动失败: {stderr.decode()[:200]}")

    async def _docker_services_healthy(self) -> bool:
        """检查 docker compose 服务是否全部健康"""
        try:
            cmd = self._compose_cmd() + ["ps", "--format", "json"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=str(self.project_dir),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return False
            # 简单检查：有输出且 Redis 可连接
            return bool(stdout.strip()) and await self._check_redis()
        except Exception:
            return False

    async def _wait_healthy(self, timeout: int = 90):
        """等待所有服务健康"""
        import time
        start = time.time()
        while time.time() - start < timeout:
            if await self._check_redis():
                # Redis 是最关键的，其他服务可以稍后就绪
                return
            await asyncio.sleep(2)
        raise TimeoutError(f"服务在 {timeout}s 内未就绪")

    # ── 本地服务检测 ─────────────────────────────────────

    async def _check_native_services(self) -> bool:
        """检查本地是否有 Redis 在运行"""
        return await self._check_redis()

    async def _check_redis(self) -> bool:
        redis_url = "redis://localhost:6379"
        if self.config:
            redis_url = self.config.get("storage.redis_url", redis_url)
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url(redis_url, socket_connect_timeout=2)
            await r.ping()
            await r.aclose()
            return True
        except Exception:
            return False

    async def _check_neo4j(self) -> bool:
        neo4j_url = "bolt://localhost:7687"
        if self.config:
            neo4j_url = self.config.get("storage.neo4j_url", neo4j_url)
        try:
            from neo4j import GraphDatabase
            driver = GraphDatabase.driver(
                neo4j_url, auth=("neo4j", "password"),
            )
            driver.verify_connectivity()
            driver.close()
            return True
        except Exception:
            return False

    async def _check_clickhouse(self) -> bool:
        try:
            from clickhouse_driver import Client
            ch_host = "localhost"
            if self.config:
                ch_host = self.config.get("storage.clickhouse_host", ch_host)
            c = Client(host=ch_host, connect_timeout=2)
            c.execute("SELECT 1")
            c.disconnect()
            return True
        except Exception:
            return False

    # ── Lite 模式 ────────────────────────────────────────

    def _setup_lite_env(self):
        """设置环境变量让主程序使用 lite 模式"""
        import os
        os.environ["LOCUS_MODE"] = "lite"
        os.environ["REDIS_URL"] = "lite://memory"
        logger.info("Lite 模式已激活：使用内存存储")
