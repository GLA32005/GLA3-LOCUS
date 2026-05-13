"""
Nuclei Tool — 漏洞扫描
对应 Recon Agent 的 tool 类型：vuln_scan / nuclei
"""

from __future__ import annotations

import asyncio
import json
import logging
import time

from . import BaseTool, ToolResult

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 600  # 秒，nuclei 可能很慢


class NucleiTool(BaseTool):
    """
    asyncio 子进程调用 nuclei，解析 JSONL 输出，提取漏洞发现。
    发现物以 Service 节点扩展属性（vuln_*）写入 assets。
    """

    async def run(self, target: str, params: dict) -> ToolResult:
        # 目标格式：ip / ip:port / http://ip:port
        url = self._normalize_target(target, params)
        templates = params.get("templates", "")  # 空 = 默认模板
        severity  = params.get("severity", "medium,high,critical")
        timeout   = int(params.get("timeout_s", _DEFAULT_TIMEOUT))

        cmd = [
            "nuclei",
            "-u", url,
            "-json",
            "-silent",
            "-severity", severity,
            "-timeout", "10",    # 单模板超时
        ]
        if templates:
            cmd += ["-t", templates]

        logger.info(f"NucleiTool: {' '.join(cmd)}")

        t0 = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            duration_ms = int((time.time() - t0) * 1000)

        except asyncio.TimeoutError:
            duration_ms = int((time.time() - t0) * 1000)
            logger.warning(f"NucleiTool 超时 ({timeout}s)")
            return ToolResult(success=False, raw={},
                              error=f"timeout after {timeout}s",
                              duration_ms=duration_ms)
        except FileNotFoundError:
            return ToolResult(success=False, raw={},
                              error="nuclei not found — install nuclei first")

        findings = self._parse_jsonl(stdout.decode(errors="replace"))
        duration_ms = int((time.time() - t0) * 1000)

        # 将漏洞发现附加到对应 IP 的 Service 节点属性上
        assets = self._build_assets(target, findings)

        # 有 critical/high 发现时 info_gain 更高
        severities = {f.get("info", {}).get("severity", "").lower() for f in findings}
        if "critical" in severities or "high" in severities:
            info_gain = 0.9
        elif findings:
            info_gain = 0.6
        else:
            info_gain = 0.1

        return ToolResult(
            success=True,
            raw={"findings_count": len(findings),
                 "sample": findings[:5]},
            assets=assets,
            info_gain=info_gain,
            novelty=0.9 if findings else 0.3,
            duration_ms=duration_ms,
        )

    # ── 解析 ────────────────────────────────────────────────────

    def _parse_jsonl(self, output: str) -> list[dict]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return findings

    def _build_assets(self, target: str, findings: list[dict]) -> list[dict]:
        """
        将漏洞发现附加为 Service 节点的 vuln_* 属性。
        简化：返回含 `vulns` 列表的 Host 资产节点。
        """
        if not findings:
            return []

        ip = target.split(":")[0]
        vulns = []
        for f in findings:
            info = f.get("info", {})
            vulns.append({
                "template_id": f.get("template-id", ""),
                "name":        info.get("name", ""),
                "severity":    info.get("severity", ""),
                "matched_at":  f.get("matched-at", ""),
                "description": info.get("description", "")[:200],
            })

        return [{
            "ip":      ip,
            "vulns":   vulns,          # 额外字段，写入 Host 节点
            "confidence": 0.9,
        }]

    def _normalize_target(self, target: str, params: dict) -> str:
        proto = params.get("protocol", "")
        if proto:
            return f"{proto}://{target}"
        if ":" in target and not target.startswith("http"):
            ip, port = target.split(":", 1)
            proto = "https" if port in ("443", "8443") else "http"
            return f"{proto}://{target}"
        return f"http://{target}"
