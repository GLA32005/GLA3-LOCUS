"""
Nmap Tool — 端口扫描 / 服务枚举
支持 Recon Agent 写入的 tool 类型：
  port_scan / port_scan_full / service_enum
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import xml.etree.ElementTree as ET
from typing import Optional

from . import BaseTool, ToolResult

logger = logging.getLogger(__name__)

# nmap 各扫描类型的命令参数
_SCAN_ARGS: dict[str, list[str]] = {
    "port_scan":      ["-sV", "--open", "--top-ports", "1000", "-T4"],
    "port_scan_full": ["-sV", "--open", "-p-", "-T3"],
    "service_enum":   ["-sV", "-sC", "--open", "-T4"],   # 带默认脚本
    "udp_scan":       ["-sU", "-sV", "--open", "--top-ports", "50", "-T4"],
    "default":        ["-sV", "--open", "--top-ports", "1000", "-T4"],
}

_DEFAULT_TIMEOUT = 300  # 秒


class NmapTool(BaseTool):
    """
    asyncio 子进程调用 nmap，解析 XML 输出，提取 Host / Service 资产节点。
    """

    async def run(self, target: str, params: dict) -> ToolResult:
        ip = target.split(":")[0]
        scan_type = params.get("scan_type", params.get("tool", "default"))
        extra_ports = params.get("ports", "")
        timeout = int(params.get("timeout_s", _DEFAULT_TIMEOUT))

        # 归一化端口参数：LLM 可能返回列表 [22, 80, 443] 而非字符串 "22,80,443"
        if isinstance(extra_ports, list):
            extra_ports = ",".join(str(p) for p in extra_ports if isinstance(p, (int, str)))

        args = list(_SCAN_ARGS.get(scan_type, _SCAN_ARGS["default"]))
        if extra_ports:
            # 校验端口格式：只允许数字、逗号、连字符（如 "80,443" 或 "1-1024"）
            if re.match(r'^[\d,\-]+$', str(extra_ports)):
                # 如果指定了端口，覆盖 --top-ports
                args = [a for a in args if a not in ("--top-ports", "1000")]
                args += ["-p", str(extra_ports)]
            else:
                logger.warning(
                    f"NmapTool: 忽略非法端口参数 '{extra_ports}'，使用默认端口范围"
                )

        # 内网加速：LAN 环境下提高扫描速率
        try:
            import ipaddress as _ipa
            if _ipa.ip_address(ip).is_private:
                args += ["--min-rate", "1000", "--max-rtt-timeout", "200ms"]
        except ValueError:
            pass

        cmd = ["nmap", "-oX", "-"] + args + [ip]
        logger.info(f"NmapTool: {' '.join(cmd)}")

        t0 = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            duration_ms = int((time.time() - t0) * 1000)

            if proc.returncode != 0:
                err_msg = stderr.decode(errors="replace").strip()
                if not err_msg:
                    out_snippet = stdout.decode(errors="replace")[:300].strip()
                    err_msg = f"nmap exit {proc.returncode}: {out_snippet[:200]}"
                logger.error(f"NmapTool 失败: {err_msg}")
                return ToolResult(success=False, raw={}, error=err_msg,
                                  duration_ms=duration_ms)

            xml_str = stdout.decode(errors="replace")
            assets = self._parse_xml(xml_str)

            info_gain = 0.7 if assets else 0.1
            return ToolResult(
                success=True,
                raw={"xml_snippet": xml_str[:3000], "scan_type": scan_type},
                assets=assets,
                info_gain=info_gain,
                novelty=0.8,
                duration_ms=duration_ms,
            )

        except asyncio.TimeoutError:
            duration_ms = int((time.time() - t0) * 1000)
            logger.warning(f"NmapTool 超时 ({timeout}s)")
            return ToolResult(success=False, raw={},
                              error=f"timeout after {timeout}s",
                              duration_ms=duration_ms)
        except FileNotFoundError:
            return ToolResult(success=False, raw={},
                              error="nmap not found — install nmap first")

    # ── XML 解析 ────────────────────────────────────────────────

    def _parse_xml(self, xml_str: str) -> list[dict]:
        """
        从 nmap XML 中提取 Host 资产节点（含嵌套 services 列表）。
        每个 Host 对应 assets mutations 中的一条 UPSERT 记录。
        """
        assets: list[dict] = []
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            logger.error(f"NmapTool XML 解析失败: {e}")
            return assets

        for host_el in root.findall("host"):
            # 状态检查（只处理 up 的主机）
            status = host_el.find("status")
            if status is not None and status.get("state") != "up":
                continue

            # IP 地址
            ip = None
            for addr in host_el.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                    break
            if not ip:
                continue

            # OS 探测（取第一条 osmatch）
            os_name = "Unknown"
            osmatches = host_el.findall(".//osmatch")
            if osmatches:
                os_name = osmatches[0].get("name", "Unknown")

            # 开放端口 → Service 节点列表
            services: list[dict] = []
            ports_el = host_el.find("ports")
            if ports_el:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue

                    service_el = port_el.find("service")
                    app     = service_el.get("name", "") if service_el is not None else ""
                    version = _build_version_str(service_el) if service_el is not None else ""
                    banner  = service_el.get("extrainfo", "") if service_el is not None else ""

                    services.append({
                        "port":    int(port_el.get("portid", 0)),
                        "proto":   port_el.get("protocol", "tcp"),
                        "state":   "open",
                        "app":     app,
                        "version": version,
                        "banner":  banner[:200],
                    })

            # ── 蜜罐启发式检测 ────────────────────────────
            honeypot_suspect = False
            honeypot_reasons = []

            if len(services) > 100:
                honeypot_suspect = True
                honeypot_reasons.append(f"开放端口异常多({len(services)}个)")

            if len(services) > 10:
                versions = [s.get("version", "") for s in services if s.get("version")]
                if versions and len(set(versions)) == 1:
                    honeypot_suspect = True
                    honeypot_reasons.append("所有服务版本完全一致")

                apps = [s.get("app", "") for s in services if s.get("app")]
                if len(apps) > 20 and len(set(apps)) <= 3:
                    honeypot_suspect = True
                    honeypot_reasons.append("大量端口使用相同服务名")

            if honeypot_suspect:
                logger.warning(
                    f"NmapTool: {ip} 疑似蜜罐 — {', '.join(honeypot_reasons)}"
                )

            assets.append({
                "ip":               ip,
                "os":               os_name,
                "access_level":     "NONE",
                "confidence":       0.8,
                "services":         services,
                "creds":            [],
                "honeypot_suspect": honeypot_suspect,
                "honeypot_reasons": honeypot_reasons,
            })

        return assets


def _build_version_str(service_el: ET.Element) -> str:
    parts = [
        service_el.get("product", ""),
        service_el.get("version", ""),
        service_el.get("extrainfo", ""),
    ]
    return " ".join(p for p in parts if p).strip()[:100]
