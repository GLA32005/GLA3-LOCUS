"""
Report Generator — 渗透测试报告生成器（L6 输出层）

职责：
  1. 从 tried_vectors / footprints / assets 汇总全量数据
  2. 生成结构化报告（JSON + Markdown）
  3. 由 LLM 生成修复建议摘要
  4. 由 Orchestrator 在 Loop C 完成后调用

报告结构：
  - 执行摘要（scope、时间范围、总体结果）
  - 攻击发现（按严重性排序）
  - 清理验证（每个 footprint 的清理状态）
  - 统计数据（尝试次数、成功率、token 消耗）
  - 修复建议（LLM 生成）
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from anthropic import AsyncAnthropic

logger = logging.getLogger(__name__)

# ── 常量 ─────────────────────────────────────────────────────

_MAX_TOKENS = 4000

_RECOMMENDATIONS_SYSTEM = """\
You are a penetration testing report writer. Given a summary of successful \
attack vectors and compromised assets, produce actionable remediation \
recommendations. Be specific, reference CVE IDs when applicable, and \
prioritize by risk (Critical > High > Medium > Low).\
Output ONLY valid JSON — no markdown fences, no prose.\
"""

_RECOMMENDATIONS_PROMPT = """\
Successful attack vectors:
{findings_json}

Compromised assets:
{assets_json}

Generate a JSON array of remediation recommendations:
[
  {{
    "priority": "CRITICAL|HIGH|MEDIUM|LOW",
    "target": "<ip or service>",
    "finding": "<what was exploited>",
    "recommendation": "<specific fix>",
    "references": ["CVE-XXXX-XXXX or URL"]
  }}
]
"""


class ReportGenerator:
    """
    渗透测试报告生成器。
    从 StateAPI 读取全量数据，输出 JSON 结构化报告 + Markdown 可读报告。
    """

    def __init__(self, model: str = "Qwen3.5-9B-MLX-8bit", 
                 api_key: str = None, base_url: str = None):
        self.api_key = api_key
        self.base_url = base_url or "http://127.0.0.1:8866"
        self._client = AsyncAnthropic(api_key=self.api_key, base_url=self.base_url)
        self._model = model

    async def generate(self, state_api, mission: dict) -> dict:
        """
        主入口。收集数据 → 汇总 → 生成建议 → 输出报告。
        返回完整报告 dict，同时写入文件。
        """
        logger.info("ReportGenerator: 开始生成报告")

        findings = await self._collect_findings(state_api)
        cleanup_status = await self._collect_cleanup_status(state_api)
        stats = await self._collect_statistics(state_api)
        assets_summary = await self._collect_assets(state_api)

        # LLM 生成修复建议（只有有成功发现时才调用）
        recommendations = []
        if findings:
            try:
                recommendations = await self._generate_recommendations(
                    findings, assets_summary
                )
            except Exception as e:
                logger.error(f"ReportGenerator: 修复建议生成失败: {e}")

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mission": {
                "goal": mission.get("goal", ""),
                "scope": mission.get("scope", []),
                "risk_level": mission.get("risk_level", 0),
            },
            "executive_summary": self._build_executive_summary(
                findings, cleanup_status, stats, mission
            ),
            "findings": findings,
            "cleanup_verification": cleanup_status,
            "statistics": stats,
            "assets_summary": assets_summary,
            "recommendations": recommendations,
        }

        # 写入文件
        output_dir = os.environ.get("REPORT_OUTPUT_DIR", "reports")
        md_path = self._save_report(report, output_dir)
        report["report_file"] = md_path

        logger.info(f"ReportGenerator: 报告已生成 → {md_path}")
        return report

    # ── 数据收集 ──────────────────────────────────────────────

    async def _collect_findings(self, state_api) -> list[dict]:
        """从 tried_vectors 提取成功的攻击发现"""
        try:
            result = await state_api._run_ch(
                """
                SELECT id, target, type, payload, result, fail_reason,
                       info_gain, retry_count, ts
                FROM tried_vectors
                WHERE result = 'SUCCESS'
                ORDER BY ts ASC
                """
            )
        except Exception as e:
            logger.error(f"ReportGenerator: ClickHouse 查询失败: {e}")
            return []

        columns = [
            "id", "target", "type", "payload", "result",
            "fail_reason", "info_gain", "retry_count", "ts"
        ]
        findings = []
        for row in (result or []):
            finding = dict(zip(columns, row))
            finding["ts"] = str(finding["ts"])
            finding["id"] = str(finding["id"])
            findings.append(finding)
        return findings

    async def _collect_cleanup_status(self, state_api) -> list[dict]:
        """从 footprints 汇总清理验证状态"""
        footprints = await state_api.get_all_footprints()
        summary = []
        for fp in footprints:
            summary.append({
                "id": str(fp.get("id", "")),
                "type": str(fp.get("type", "")),
                "target": fp.get("target", ""),
                "cleaned": bool(fp.get("cleaned", False)),
                "ts": str(fp.get("ts", "")),
            })
        total = len(summary)
        cleaned = sum(1 for s in summary if s["cleaned"])
        return {
            "total_footprints": total,
            "cleaned": cleaned,
            "uncleaned": total - cleaned,
            "cleanup_rate": f"{cleaned / total * 100:.1f}%" if total else "N/A",
            "details": summary,
        }

    async def _collect_statistics(self, state_api) -> dict:
        """汇总攻击统计数据"""
        vectors = await state_api.get_vectors_summary()
        total_hosts = await state_api.count_hosts()
        owned_hosts = await state_api.count_owned_hosts()
        hallucinations = await state_api.count_hallucinations()

        return {
            "total_vectors": vectors.get("total", 0),
            "success_count": vectors.get("success_count", 0),
            "fail_count": vectors.get("fail_count", 0),
            "blocked_count": vectors.get("blocked_count", 0),
            "abandoned_count": vectors.get("abandoned_count", 0),
            "success_rate": (
                f"{vectors.get('success_count', 0) / vectors.get('total', 1) * 100:.1f}%"
                if vectors.get("total", 0) > 0 else "N/A"
            ),
            "avg_info_gain": round(vectors.get("avg_info_gain", 0), 3),
            "total_hosts": total_hosts,
            "owned_hosts": owned_hosts,
            "hallucination_count": hallucinations,
            "recommendation": vectors.get("recommendation", ""),
        }

    def _collect_assets_sync(self, state_api) -> list[dict]:
        """同步版本，供 run_in_executor 调用。获取所有已发现的主机摘要。"""
        with state_api.neo4j.session() as session:
            result = session.run("""
                MATCH (h:Host)
                OPTIONAL MATCH (h)-[:RUNS]->(s:Service)
                RETURN h.ip as ip,
                       h.access_level as access_level,
                       h.os as os,
                       h.out_of_scope as out_of_scope,
                       collect(DISTINCT s.port) as open_ports
                ORDER BY h.ip ASC
            """)
            return [dict(record) for record in result]

    async def _collect_assets(self, state_api) -> list[dict]:
        """从 Neo4j 获取所有已发现主机的摘要"""
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self._collect_assets_sync(state_api)
            )
        except Exception as e:
            logger.error(f"ReportGenerator: Neo4j 查询失败: {e}")
            return []

    # ── LLM 修复建议 ─────────────────────────────────────────

    async def _generate_recommendations(
        self,
        findings: list[dict],
        assets: list[dict],
    ) -> list[dict]:
        prompt = _RECOMMENDATIONS_PROMPT.format(
            findings_json=json.dumps(findings, default=str, indent=2),
            assets_json=json.dumps(assets, default=str, indent=2),
        )

        try:
            from core.llm_provider import call_llm_anthropic_style
            raw, tokens = await call_llm_anthropic_style(
                api_key=self.api_key,
                base_url=self.base_url,
                model=self._model,
                system=_RECOMMENDATIONS_SYSTEM,
                prompt=prompt,
                max_tokens=2000
            )
            
            if not raw:
                return []
            
            import re
            json_match = re.search(r'(\{.*\}|\[.*\])', raw, re.DOTALL)
            if json_match:
                raw = json_match.group(1).strip()
            
            return json.loads(raw)
        except Exception as e:
            logger.error(f"ReportGenerator: JSON 生成失败: {e}")
            return []

    # ── 执行摘要 ──────────────────────────────────────────────

    def _build_executive_summary(
        self,
        findings: list[dict],
        cleanup: dict,
        stats: dict,
        mission: dict,
    ) -> str:
        scope = ", ".join(mission.get("scope", []))
        total = stats.get("total_vectors", 0)
        success = stats.get("success_count", 0)
        owned = stats.get("owned_hosts", 0)
        total_hosts = stats.get("total_hosts", 0)
        cleanup_rate = cleanup.get("cleanup_rate", "N/A")

        return (
            f"对 {scope} 执行了 {total} 次攻击尝试，"
            f"成功 {success} 次（{stats.get('success_rate', 'N/A')}）。"
            f"共发现 {total_hosts} 台主机，攻破 {owned} 台。"
            f"清理覆盖率：{cleanup_rate}。"
        )

    # ── Markdown 渲染 ────────────────────────────────────────

    def _render_markdown(self, report: dict) -> str:
        lines = [
            "# 渗透测试报告",
            "",
            f"**生成时间**: {report['generated_at']}",
            f"**目标范围**: {', '.join(report['mission']['scope'])}",
            f"**任务目标**: {report['mission']['goal']}",
            f"**风险等级**: {report['mission']['risk_level']}",
            "",
            "---",
            "",
            "## 1. 执行摘要",
            "",
            report["executive_summary"],
            "",
            "---",
            "",
            "## 2. 资产发现",
            "",
        ]

        assets = report.get("assets_summary", [])
        if not assets:
            lines.append("*未发现任何主机资产。*\n")
        else:
            lines.append(
                "| IP 地址 | 权限级别 | 操作系统 | 开放端口 | 范围 |"
            )
            lines.append("|---------|----------|----------|----------|------|")
            for a in assets:
                ports = ", ".join(map(str, a.get("open_ports", []))) or "无"
                scope_mark = "❌ 越界" if a.get("out_of_scope") else "✅ 在内"
                lines.append(
                    f"| {a.get('ip', 'Unknown')} | {a.get('access_level', 'NONE')} "
                    f"| {a.get('os', 'Unknown')} | {ports} | {scope_mark} |"
                )
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 3. 攻击发现",
            "",
        ])

        findings = report.get("findings", [])
        if not findings:
            lines.append("*无成功的攻击发现。*\n")
        else:
            lines.append(
                "| # | 目标 | 攻击类型 | 信息增益 | 时间 |"
            )
            lines.append("|---|------|---------|---------|------|")
            for i, f in enumerate(findings, 1):
                lines.append(
                    f"| {i} | {f.get('target', '')} | {f.get('type', '')} "
                    f"| {float(f.get('info_gain') or 0):.2f} | {f.get('ts', '')} |"
                )
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 4. 清理验证",
            "",
        ])

        cleanup = report.get("cleanup_verification", {})
        lines.append(
            f"- 总痕迹数: {cleanup.get('total_footprints', 0)}"
        )
        lines.append(f"- 已清理: {cleanup.get('cleaned', 0)}")
        lines.append(f"- 未清理: {cleanup.get('uncleaned', 0)}")
        lines.append(f"- 清理覆盖率: {cleanup.get('cleanup_rate', 'N/A')}")
        lines.append("")

        details = cleanup.get("details", [])
        if details:
            lines.append("| ID | 类型 | 目标 | 已清理 |")
            lines.append("|----|------|------|--------|")
            for d in details:
                cleaned_mark = "✅" if d["cleaned"] else "❌"
                lines.append(
                    f"| {d['id'][:8]}… | {d['type']} "
                    f"| {d['target']} | {cleaned_mark} |"
                )
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 5. 统计数据",
            "",
        ])

        stats = report.get("statistics", {})
        lines.append(f"- 总攻击次数: {stats.get('total_vectors', 0)}")
        lines.append(f"- 成功: {stats.get('success_count', 0)}")
        lines.append(f"- 失败: {stats.get('fail_count', 0)}")
        lines.append(f"- 审查拦截: {stats.get('blocked_count', 0)}")
        lines.append(f"- 放弃: {stats.get('abandoned_count', 0)}")
        lines.append(f"- 成功率: {stats.get('success_rate', 'N/A')}")
        lines.append(f"- 幻觉次数: {stats.get('hallucination_count', 0)}")
        lines.append(
            f"- 平均信息增益: {stats.get('avg_info_gain', 0)}"
        )
        lines.append(
            f"- 发现主机: {stats.get('total_hosts', 0)} "
            f"(攻破: {stats.get('owned_hosts', 0)})"
        )
        lines.append("")

        lines.extend([
            "---",
            "",
            "## 6. 修复建议",
            "",
        ])

        recs = report.get("recommendations", [])
        if not recs:
            lines.append("*无修复建议（无成功攻击或 LLM 生成失败）。*\n")
        else:
            for i, r in enumerate(recs, 1):
                prio = r.get("priority", "MEDIUM")
                lines.append(f"### {i}. [{prio}] {r.get('finding', '')}")
                lines.append("")
                lines.append(f"**目标**: {r.get('target', '')}")
                lines.append(f"**建议**: {r.get('recommendation', '')}")
                refs = r.get("references", [])
                if refs:
                    lines.append(
                        f"**参考**: {', '.join(refs)}"
                    )
                lines.append("")

        lines.extend([
            "---",
            "",
            f"*报告由 Agentic Pentest Framework 自动生成*",
        ])

        return "\n".join(lines)

    # ── 保存 ─────────────────────────────────────────────────

    def _save_report(self, report: dict, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Markdown
        md_path = os.path.join(output_dir, f"report_{ts}.md")
        with open(md_path, "w") as f:
            f.write(self._render_markdown(report))

        # JSON（结构化数据）
        json_path = os.path.join(output_dir, f"report_{ts}.json")
        with open(json_path, "w") as f:
            json.dump(report, f, default=str, indent=2, ensure_ascii=False)

        logger.info(f"ReportGenerator: MD → {md_path}, JSON → {json_path}")
        return md_path
