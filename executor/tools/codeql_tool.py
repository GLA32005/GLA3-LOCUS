"""
CodeQL Tool — 静态代码审计（白盒漏洞扫描）
适用场景：获得目标源码访问权限后，对 web 应用进行静态分析。
对应 Recon Agent 的 tool 类型：code_audit / codeql

工作模式：
  1. 拉取目标代码（git clone 或挂载路径）
  2. 运行 codeql database create 构建 DB
  3. 运行 codeql database analyze 执行查询包
  4. 解析 SARIF 输出，提取漏洞发现
  5. 写入 assets.vulns（含代码位置）
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import time
from pathlib import Path

from . import BaseTool, ToolResult

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 600   # CodeQL 分析可能需要几分钟
_QUERY_SUITES = {
    "javascript": "javascript-security-extended",
    "python":     "python-security-extended",
    "java":       "java-security-extended",
    "cpp":        "cpp-security-extended",
    "go":         "go-security-extended",
    "csharp":     "csharp-security-extended",
}
_SEVERITY_INFO_GAIN = {
    "error":   0.9,
    "warning": 0.7,
    "note":    0.4,
}


class CodeQLTool(BaseTool):
    """
    CodeQL 静态分析工具。
    params 字段说明：
      repo_path:   本地代码路径（已 clone 到测试机）
      language:    "python" | "javascript" | "java" | "go" | "cpp" | "csharp"
      query_suite: 自定义查询包路径（可选，默认按 language 选安全包）
      timeout_s:   整体超时（默认 600s）
    """

    async def run(self, target: str, params: dict) -> ToolResult:
        repo_path   = params.get("repo_path", "")
        language    = params.get("language", "").lower()
        query_suite = params.get("query_suite", "")
        timeout     = int(params.get("timeout_s", _DEFAULT_TIMEOUT))

        if not repo_path:
            return ToolResult(success=False, raw={},
                              error="params.repo_path is required")
        if not language:
            return ToolResult(success=False, raw={},
                              error="params.language is required")

        if not query_suite:
            query_suite = _QUERY_SUITES.get(language)
            if not query_suite:
                return ToolResult(success=False, raw={},
                                  error=f"Unsupported language: {language}")

        t0 = time.time()
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path   = os.path.join(tmpdir, "codeql-db")
            sarif_out = os.path.join(tmpdir, "results.sarif")

            # Step 1: Create database
            create_result = await self._run_cmd(
                ["codeql", "database", "create",
                 "--language", language,
                 "--source-root", repo_path,
                 db_path],
                timeout=timeout // 2,
            )
            if create_result["exit_code"] != 0:
                # CodeQL not installed or language not supported
                if "not found" in create_result["stderr"].lower() or create_result["exit_code"] == 127:
                    return ToolResult(success=False, raw={},
                                      error="codeql CLI not found — install CodeQL CLI")
                return ToolResult(
                    success=False,
                    raw={"stderr": create_result["stderr"][:500]},
                    error=f"database create failed: exit={create_result['exit_code']}",
                )

            # Step 2: Analyze
            analyze_result = await self._run_cmd(
                ["codeql", "database", "analyze",
                 "--format", "sarifv2.1.0",
                 "--output", sarif_out,
                 db_path, query_suite],
                timeout=timeout // 2,
            )
            if analyze_result["exit_code"] != 0:
                return ToolResult(
                    success=False,
                    raw={"stderr": analyze_result["stderr"][:500]},
                    error=f"database analyze failed: exit={analyze_result['exit_code']}",
                )

            # Step 3: Parse SARIF
            findings = self._parse_sarif(sarif_out)

        duration_ms = int((time.time() - t0) * 1000)
        assets = self._build_assets(target, findings, repo_path)

        severities = {f.get("severity", "note") for f in findings}
        if "error" in severities:
            info_gain = 0.9
        elif "warning" in severities:
            info_gain = 0.7
        elif findings:
            info_gain = 0.4
        else:
            info_gain = 0.1

        logger.info(
            f"CodeQLTool: {len(findings)} findings on {target} "
            f"({language}) in {duration_ms}ms"
        )
        return ToolResult(
            success=True,
            raw={"findings_count": len(findings), "sample": findings[:5]},
            assets=assets,
            info_gain=info_gain,
            novelty=0.9 if findings else 0.3,
            duration_ms=duration_ms,
        )

    # ── 解析 SARIF ────────────────────────────────────────────

    def _parse_sarif(self, sarif_path: str) -> list[dict]:
        findings = []
        try:
            with open(sarif_path) as f:
                sarif = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"CodeQLTool: SARIF parse error: {e}")
            return []

        for run in sarif.get("runs", []):
            rules = {
                r["id"]: r
                for r in run.get("tool", {}).get("driver", {}).get("rules", [])
            }
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule    = rules.get(rule_id, {})
                message = result.get("message", {}).get("text", "")
                severity = result.get("level", "warning")   # error / warning / note

                locations = result.get("locations", [])
                loc = {}
                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    loc = {
                        "file":   phys.get("artifactLocation", {}).get("uri", ""),
                        "line":   phys.get("region", {}).get("startLine", 0),
                        "column": phys.get("region", {}).get("startColumn", 0),
                    }

                findings.append({
                    "rule_id":  rule_id,
                    "name":     rule.get("name", rule_id),
                    "severity": severity,
                    "message":  message[:300],
                    "location": loc,
                    "tags":     rule.get("properties", {}).get("tags", []),
                })

        return findings

    def _build_assets(self, target: str, findings: list[dict],
                       repo_path: str) -> list[dict]:
        if not findings:
            return []

        ip = target.split(":")[0]
        vulns = [
            {
                "rule_id":  f["rule_id"],
                "name":     f["name"],
                "severity": f["severity"],
                "location": f["location"],
                "message":  f["message"],
                "source":   "codeql",
            }
            for f in findings
        ]
        return [{
            "ip":       ip,
            "vulns":    vulns,
            "confidence": 0.95,   # 静态分析结果置信度高
            "meta":     {"repo_path": repo_path},
        }]

    # ── asyncio 子进程 ────────────────────────────────────────

    async def _run_cmd(self, cmd: list[str], timeout: int) -> dict:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return {
                "exit_code": proc.returncode,
                "stdout":    stdout.decode(errors="replace")[:2000],
                "stderr":    stderr.decode(errors="replace")[:2000],
            }
        except asyncio.TimeoutError:
            return {"exit_code": -1, "stdout": "", "stderr": f"timeout {timeout}s"}
        except FileNotFoundError:
            return {"exit_code": 127, "stdout": "", "stderr": "command not found"}
        except Exception as e:
            return {"exit_code": -1, "stdout": "", "stderr": str(e)}
