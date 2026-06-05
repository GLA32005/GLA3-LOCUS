"""终端进度面板 — rich 实时渲染"""

from __future__ import annotations

import asyncio
import shutil
import time
from datetime import timedelta

import aiohttp
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


console = Console()


def _fmt_duration(seconds: int | float) -> str:
    """格式化秒数为 Xh Ym Zs"""
    td = timedelta(seconds=int(seconds))
    parts = []
    h, rem = divmod(td.seconds, 3600)
    m, s = divmod(rem, 60)
    if td.days:
        parts.append(f"{td.days}d")
    if h:
        parts.append(f"{h}h")
    parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def _progress_bar(current: int, total: int, width: int = 20) -> str:
    """简单文本进度条"""
    if total <= 0:
        filled = 0
    else:
        filled = min(int(current / total * width), width)
    return "█" * filled + "░" * (width - filled)


def _build_snapshot_panel(data: dict) -> Panel:
    """从 /progress API 数据构建 rich Panel"""
    phase = data.get("phase", "UNKNOWN")
    runtime = data.get("runtime_seconds", 0)
    think_rounds = data.get("think_rounds", 0)
    stall = data.get("stall_count", 0)
    target = data.get("active_target", "-")
    total_hosts = data.get("total_hosts", 0)
    owned = data.get("owned_hosts", 0)
    services = data.get("total_services", 0)
    tried = data.get("tried_vectors", 0)
    success = data.get("success_vectors", 0)

    llm = data.get("llm_stats", {})
    local_calls = llm.get("local_calls", 0)
    strong_calls = llm.get("strong_calls", 0)
    budget = llm.get("strong_budget", 20)
    budget_used = llm.get("strong_budget_used", 0)

    # 阶段颜色
    phase_colors = {
        "RECON": "cyan", "EXPLOIT": "yellow",
        "CLEANUP": "green", "DONE": "green",
    }
    pc = phase_colors.get(phase, "white")

    lines = []
    lines.append(
        f"  阶段: [{pc} bold]{phase:<14}[/]"
        f"运行: {_fmt_duration(runtime):<12}"
        f"Think: [bold]#{think_rounds}[/]"
    )
    lines.append(
        f"  目标: {target:<16}"
        f"服务: {services} 个{'':<7}"
        f"Stall: {stall}"
    )
    lines.append("")

    # 资产进度
    host_bar = _progress_bar(total_hosts, max(total_hosts, 1))
    lines.append(f"  资产:  {host_bar}  {total_hosts} hosts ({owned} owned)")

    # 向量进度
    vec_bar = _progress_bar(success, max(tried, 1))
    lines.append(f"  向量:  {vec_bar}  {tried} tried, {success} success")

    # LLM 统计
    lines.append(
        f"  LLM:   本地 {local_calls} 次 | "
        f"升级 {strong_calls} 次 | "
        f"预算 {budget_used}/{budget}"
    )

    # 最近事件
    events = data.get("recent_events", [])
    if events:
        lines.append("")
        lines.append("  [dim]最近事件:[/]")
        for ev in events[-5:]:
            t = ev.get("time", "")
            msg = ev.get("msg", "")
            lines.append(f"  [dim]{t}[/]  {msg}")

    content = "\n".join(lines)
    return Panel(
        content,
        title="[bold green]LOCUS[/]",
        border_style="green",
        padding=(1, 1),
    )


class ProgressDisplay:
    """终端进度显示"""

    def __init__(self, api_base: str = "http://localhost:8086"):
        self.api_base = api_base.rstrip("/")

    async def _fetch_progress(self) -> dict | None:
        """从 API 获取进度数据"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.api_base}/progress", timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception:
            return None

    def show_snapshot(self, data: dict):
        """单次快照显示"""
        panel = _build_snapshot_panel(data)
        console.print(panel)

    async def show(self):
        """获取并显示快照"""
        data = await self._fetch_progress()
        if data:
            self.show_snapshot(data)
        else:
            console.print("[red]❌ 无法连接到 LOCUS 服务（端口 {}）[/]".format(
                self.api_base.split(":")[-1]
            ))
            console.print("[dim]请确保 locus scan 正在运行，或先执行 locus up[/]")

    async def follow(self, interval: float = 2.0):
        """持续刷新模式"""
        console.print("[dim]按 Ctrl+C 退出...[/]\n")
        try:
            with Live(console=console, refresh_per_second=1) as live:
                while True:
                    data = await self._fetch_progress()
                    if data:
                        panel = _build_snapshot_panel(data)
                        live.update(panel)
                    else:
                        live.update(
                            Panel("[red]❌ 连接中断，等待重连...[/]",
                                  title="LOCUS", border_style="red")
                        )
                    await asyncio.sleep(interval)
        except KeyboardInterrupt:
            console.print("\n[dim]已停止刷新[/]")

    def show_json(self, data: dict):
        """JSON 格式输出"""
        import json
        console.print_json(json.dumps(data, ensure_ascii=False, indent=2))

    # ── Doctor 显示 ──────────────────────────────────────

    def show_doctor(self, checks: dict):
        """显示环境检查结果"""
        table = Table(title="LOCUS 环境检查", show_header=True,
                      header_style="bold green", border_style="green")
        table.add_column("类别", style="bold", width=10)
        table.add_column("项目", width=28)
        table.add_column("状态", width=8)
        table.add_column("备注", width=30)

        for category, items in checks.items():
            for i, (name, ok, note) in enumerate(items):
                status = "[green]✅[/]" if ok else "[red]❌[/]"
                cat_label = category if i == 0 else ""
                table.add_row(cat_label, name, status, note)

        console.print(table)

    @staticmethod
    def build_doctor_checks(svc_health: dict, tools: dict | None = None) -> dict:
        """构建 doctor 检查数据"""
        checks = {}

        # Docker
        checks["🐳 Docker"] = [
            (
                "Docker Compose",
                svc_health.get("docker", False),
                "docker compose 可用" if svc_health.get("docker") else "未安装或 docker-compose.yml 不存在",
            ),
        ]

        # 存储
        checks["💾 存储"] = [
            ("Redis", svc_health.get("redis", False),
             "连接正常" if svc_health.get("redis") else "未连接"),
            ("Neo4j", svc_health.get("neo4j", False),
             "连接正常" if svc_health.get("neo4j") else "未连接（可降级）"),
            ("ClickHouse", svc_health.get("clickhouse", False),
             "连接正常" if svc_health.get("clickhouse") else "未连接（可降级）"),
        ]

        # 安全工具
        if tools:
            tool_items = []
            for name, (available, path) in tools.items():
                tool_items.append((
                    name, available,
                    path if available else "未安装（运行时跳过）"
                ))
            checks["🔧 工具"] = tool_items

        return checks
