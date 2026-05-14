"""
轻量级 Shell 工具封装。
每个工具都是对外部 CLI 二进制的薄封装，统一实现 BaseTool 接口。
如果对应的二进制未安装，run() 返回 FileNotFoundError 类型的 ToolResult。
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import time

from . import BaseTool, ToolResult

logger = logging.getLogger(__name__)


# ── 工具可用性检查 ────────────────────────────────────────────

def check_binary(name: str) -> str | None:
    """返回二进制路径，不存在则返回 None"""
    return shutil.which(name)


# ── Banner Grab (netcat) ──────────────────────────────────────

class BannerGrabTool(BaseTool):
    """通过 netcat 抓取服务 banner，低噪音。"""

    async def run(self, target: str, params: dict) -> ToolResult:
        parts = target.split(":")
        ip = parts[0]
        port = parts[1] if len(parts) > 1 else params.get("port", "80")
        timeout = int(params.get("timeout_s", 3))

        # 优先用 ncat，其次 nc
        nc = check_binary("ncat") or check_binary("nc")
        if not nc:
            return ToolResult(success=False, raw={},
                              error="nc/ncat not found — install nmap (includes ncat)")

        cmd = [nc, "-w", str(timeout), "-v", ip, str(port)]
        logger.info(f"BannerGrabTool: {' '.join(cmd)}")

        t0 = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # 发送空行触发 banner 响应
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(b"\r\n\r\n"), timeout=timeout + 2
            )
            duration_ms = int((time.time() - t0) * 1000)
            banner = (stdout.decode(errors="replace") +
                      stderr.decode(errors="replace")).strip()[:500]

            return ToolResult(
                success=bool(banner),
                raw={"banner": banner, "port": port},
                assets=[{
                    "ip": ip,
                    "services": [{
                        "port": int(port), "proto": "tcp",
                        "state": "open", "banner": banner[:200],
                        "app": "", "version": "",
                    }],
                }] if banner else [],
                info_gain=0.4 if banner else 0.1,
                duration_ms=duration_ms,
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, raw={},
                              error=f"timeout after {timeout}s",
                              duration_ms=int((time.time() - t0) * 1000))


# ── Directory Enumeration (feroxbuster) ───────────────────────

class DirEnumTool(BaseTool):
    """通过 feroxbuster 进行 Web 目录枚举。"""

    async def run(self, target: str, params: dict) -> ToolResult:
        if not check_binary("feroxbuster"):
            return ToolResult(success=False, raw={},
                              error="feroxbuster not found — cargo install feroxbuster")

        url = self._normalize_url(target, params)
        timeout = int(params.get("timeout_s", 300))
        wordlist = params.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")

        cmd = [
            "feroxbuster", "-u", url,
            "--json", "--quiet",
            "--depth", "2",
            "--threads", "20",
            "--timeout", "10",
            "--no-state",
        ]
        # 仅在 wordlist 存在时添加
        import os
        if os.path.exists(wordlist):
            cmd += ["-w", wordlist]

        logger.info(f"DirEnumTool: {' '.join(cmd)}")
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

            findings = []
            for line in stdout.decode(errors="replace").splitlines():
                try:
                    entry = json.loads(line)
                    if entry.get("status") and entry["status"] < 404:
                        findings.append({
                            "url": entry.get("url", ""),
                            "status": entry.get("status"),
                            "length": entry.get("content_length", 0),
                        })
                except (json.JSONDecodeError, KeyError):
                    pass

            return ToolResult(
                success=True,
                raw={"findings_count": len(findings),
                     "sample": findings[:20]},
                info_gain=0.7 if findings else 0.2,
                duration_ms=duration_ms,
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, raw={},
                              error=f"timeout after {timeout}s",
                              duration_ms=int((time.time() - t0) * 1000))
        except FileNotFoundError:
            return ToolResult(success=False, raw={},
                              error="feroxbuster not found")

    @staticmethod
    def _normalize_url(target: str, params: dict) -> str:
        if target.startswith("http"):
            return target
        port = ""
        if ":" in target:
            ip, port = target.split(":", 1)
        else:
            ip = target
        proto = "https" if port in ("443", "8443") else "http"
        return f"{proto}://{target}"


# ── SMB Enumeration (enum4linux-ng) ───────────────────────────

class SmbEnumTool(BaseTool):
    """通过 enum4linux-ng 枚举 SMB/RPC 信息。"""

    async def run(self, target: str, params: dict) -> ToolResult:
        if not check_binary("enum4linux-ng"):
            return ToolResult(success=False, raw={},
                              error="enum4linux-ng not found — pip install enum4linux-ng")

        ip = target.split(":")[0]
        timeout = int(params.get("timeout_s", 120))

        cmd = ["enum4linux-ng", "-A", "-oJ", "/dev/stdout", ip]
        logger.info(f"SmbEnumTool: {' '.join(cmd)}")

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
            output = stdout.decode(errors="replace")

            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                data = {"raw_output": output[:2000]}

            shares = data.get("shares", {})
            users = data.get("users", {})

            return ToolResult(
                success=True,
                raw={"shares": len(shares), "users": len(users),
                     "data_snippet": str(data)[:1000]},
                info_gain=0.7 if shares or users else 0.3,
                duration_ms=duration_ms,
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, raw={},
                              error=f"timeout after {timeout}s",
                              duration_ms=int((time.time() - t0) * 1000))
        except FileNotFoundError:
            return ToolResult(success=False, raw={},
                              error="enum4linux-ng not found")


# ── LDAP Enumeration (ldapsearch) ─────────────────────────────

class LdapEnumTool(BaseTool):
    """通过 ldapsearch 枚举 LDAP/AD 信息。"""

    async def run(self, target: str, params: dict) -> ToolResult:
        if not check_binary("ldapsearch"):
            return ToolResult(success=False, raw={},
                              error="ldapsearch not found — install openldap")

        ip = target.split(":")[0]
        port = params.get("port", "389")
        base_dn = params.get("base_dn", "")
        timeout = int(params.get("timeout_s", 60))

        cmd = [
            "ldapsearch", "-x",
            "-H", f"ldap://{ip}:{port}",
            "-b", base_dn or "",
            "-s", "base",
            "(objectClass=*)",
        ]
        logger.info(f"LdapEnumTool: {' '.join(cmd)}")

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
            output = stdout.decode(errors="replace")

            entries = output.count("dn:")
            return ToolResult(
                success=proc.returncode == 0,
                raw={"entries": entries,
                     "output_snippet": output[:2000]},
                info_gain=0.6 if entries > 0 else 0.2,
                duration_ms=duration_ms,
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, raw={},
                              error=f"timeout after {timeout}s",
                              duration_ms=int((time.time() - t0) * 1000))
        except FileNotFoundError:
            return ToolResult(success=False, raw={},
                              error="ldapsearch not found")


# ── Credential Spray (hydra) ─────────────────────────────────

class CredSprayTool(BaseTool):
    """通过 hydra 进行凭据喷洒测试。"""

    async def run(self, target: str, params: dict) -> ToolResult:
        if not check_binary("hydra"):
            return ToolResult(success=False, raw={},
                              error="hydra not found — install hydra")

        ip = target.split(":")[0]
        service = params.get("service", "ssh")
        port = params.get("port", "")
        username = params.get("username", "")
        userlist = params.get("userlist", "")
        password = params.get("password", "")
        passlist = params.get("passlist", "")
        timeout = int(params.get("timeout_s", 120))

        cmd = ["hydra", "-t", "4", "-f"]  # 4线程，找到即停

        if username:
            cmd += ["-l", username]
        elif userlist:
            cmd += ["-L", userlist]
        else:
            return ToolResult(success=False, raw={},
                              error="需要 username 或 userlist 参数")

        if password:
            cmd += ["-p", password]
        elif passlist:
            cmd += ["-P", passlist]
        else:
            return ToolResult(success=False, raw={},
                              error="需要 password 或 passlist 参数")

        if port:
            cmd += ["-s", str(port)]

        cmd += [ip, service]
        logger.info(f"CredSprayTool: {' '.join(cmd)}")

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
            output = stdout.decode(errors="replace")

            # 解析 hydra 输出中的成功凭据
            creds = []
            for line in output.splitlines():
                if "login:" in line.lower() and "password:" in line.lower():
                    creds.append(line.strip())

            assets = []
            if creds:
                assets = [{
                    "ip": ip,
                    "creds": [{"raw": c, "service": service} for c in creds],
                }]

            return ToolResult(
                success=bool(creds),
                raw={"output_snippet": output[:1000], "found": len(creds)},
                assets=assets,
                info_gain=0.95 if creds else 0.2,
                duration_ms=duration_ms,
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, raw={},
                              error=f"timeout after {timeout}s",
                              duration_ms=int((time.time() - t0) * 1000))
        except FileNotFoundError:
            return ToolResult(success=False, raw={},
                              error="hydra not found")


# ── HTTP Probe (httpx by ProjectDiscovery) ────────────────────

class HttpxTool(BaseTool):
    """通过 httpx 探测 HTTP 服务指纹。"""

    async def run(self, target: str, params: dict) -> ToolResult:
        if not check_binary("httpx"):
            return ToolResult(success=False, raw={},
                              error="httpx not found — go install github.com/projectdiscovery/httpx")

        ip = target.split(":")[0]
        timeout = int(params.get("timeout_s", 30))

        cmd = [
            "httpx", "-u", target,
            "-json",
            "-silent",
            "-title", "-tech-detect", "-status-code",
            "-follow-redirects",
            "-timeout", str(min(timeout, 15)),
        ]
        logger.info(f"HttpxTool: {' '.join(cmd)}")

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

            results = []
            for line in stdout.decode(errors="replace").splitlines():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

            assets = []
            for r in results:
                port_val = r.get("port", 80)
                assets.append({
                    "ip": ip,
                    "services": [{
                        "port": int(port_val),
                        "proto": "tcp",
                        "state": "open",
                        "app": "http",
                        "version": r.get("title", ""),
                        "banner": json.dumps({
                            "title": r.get("title", ""),
                            "status": r.get("status_code"),
                            "tech": r.get("tech", []),
                            "server": r.get("webserver", ""),
                        })[:200],
                    }],
                })

            return ToolResult(
                success=bool(results),
                raw={"results": results[:5]},
                assets=assets,
                info_gain=0.5 if results else 0.1,
                duration_ms=duration_ms,
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, raw={},
                              error=f"timeout after {timeout}s",
                              duration_ms=int((time.time() - t0) * 1000))
        except FileNotFoundError:
            return ToolResult(success=False, raw={},
                              error="httpx not found")
