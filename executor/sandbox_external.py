"""
外部沙箱（External Sandbox）
防御对象：目标系统（防止 DoS / 破坏性操作被误打出去）。
技术：Docker 容器 + iptables 白名单，完全网络隔离。

正确定位（约束③）：
  - 拦截语法错误和破坏性指令（rm -rf / mkfs / DROP DATABASE）
  - 不验证漏洞是否能打通（Blind SSRF / Kerberoasting 无法在沙箱预演）
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# 沙箱容器配置
_SANDBOX_IMAGE   = os.environ.get("SANDBOX_IMAGE", "ubuntu:22.04")
_CPU_LIMIT       = "1"          # 1 核
_MEM_LIMIT       = "256m"
_TIMEOUT_S       = 30
_NETWORK_MODE    = "none"       # 完全断网（外部沙箱不需要访问目标）

# 破坏性指令的静态模式匹配（Critic 已做一轮，这里是最后防线）
_DESTRUCTIVE_PATTERNS = (
    "rm -rf /",
    "rm -rf /*",
    "mkfs",
    "drop database",
    "drop table",
    "format c:",
    "del /f /s /q c:\\",
    "> /dev/sda",
    "dd if=/dev/zero of=/dev/",
    "shutdown",
    "halt",
    "poweroff",
    "reboot",
    "init 0",
    "init 6",
)

# executor_hint → 容器内执行命令
_EXEC_CMD: dict[str, list[str]] = {
    "bash":       ["bash", "-c"],
    "sh":         ["sh", "-c"],
    "python":     ["python3", "-c"],
    "powershell": ["pwsh", "-Command"],    # PowerShell on Linux
    "cmd":        ["sh", "-c"],            # cmd 语法转 sh 做语法检查
}


@dataclass
class SandboxResult:
    passed:     bool
    reason:     str = ""         # 失败原因（简短）
    stdout:     str = ""
    stderr:     str = ""
    exit_code:  int = -1


class ExternalSandbox:
    """
    在隔离 Docker 容器中做 payload 语法 + 破坏性检查。
    不能访问目标网络，只做本地语法验证。
    """

    def __init__(self):
        self._docker_available = self._check_docker()
        if not self._docker_available:
            logger.warning("❗ 高危警告：未检测到 Docker 沙箱环境！ExternalSandbox 语法验证与破坏性检查将完全降级为基础静态匹配，系统防御力显著受损！")

    @property
    def is_degraded(self) -> bool:
        """C1a 修复：暴露沙箱降级状态"""
        return not self._docker_available

    @property
    def degraded_reason(self) -> str:
        if not self._docker_available:
            return "Docker 不可用，仅执行静态模式匹配"
        return ""

    def _check_docker(self) -> bool:
        import shutil
        return shutil.which("docker") is not None

    async def check(self, content: str, executor_hint: str = "bash") -> SandboxResult:
        """
        对 payload 进行沙箱检查。
        先做静态模式匹配（快速），再做 Docker 语法执行（慢但准确）。
        """
        # ── 静态检查（不需要 Docker）──────────────────────────
        content_lower = content.lower()
        for pattern in _DESTRUCTIVE_PATTERNS:
            if pattern in content_lower:
                logger.warning(f"ExternalSandbox: 静态拦截 '{pattern}'")
                return SandboxResult(
                    passed=False,
                    reason=f"destructive_pattern: {pattern}"
                )

        if not content.strip():
            return SandboxResult(passed=False, reason="empty_payload")

        # ── Docker 语法检查 ──────────────────────────────────
        if not self._docker_available:
            logger.warning("❗ ExternalSandbox: Docker 不可用，跳过容器检查，仅以静态匹配通过 (degraded_security)")
            return SandboxResult(passed=True, reason="static_only: degraded_security")

        return await self._run_in_docker(content, executor_hint)

    async def _run_in_docker(
        self, content: str, executor_hint: str
    ) -> SandboxResult:
        hint = executor_hint.lower() if executor_hint else "bash"
        exec_cmd = _EXEC_CMD.get(hint, _EXEC_CMD["bash"])

        # 使用 --syntax-check / -n 做纯语法检查（不实际执行）
        # bash -n 和 python -m py_compile 不会运行代码
        if hint in ("bash", "sh"):
            check_cmd = ["bash", "-n", "-c", content]
        elif hint == "python":
            # 写临时文件并用 py_compile 检查
            check_cmd = ["python3", "-c",
                         f"import ast; ast.parse({repr(content)})"]
        else:
            # powershell / cmd：降级为静态通过（沙箱无法轻易检查）
            return SandboxResult(passed=True, reason="no_syntax_check_for_hint")

        t0 = time.time()
        try:
            cmd = [
                "docker", "run", "--rm",
                "--network", _NETWORK_MODE,
                "--cpus", _CPU_LIMIT,
                "--memory", _MEM_LIMIT,
                "--read-only",
                "--tmpfs", "/tmp",
                "--security-opt", "no-new-privileges",
                _SANDBOX_IMAGE,
            ] + check_cmd

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_TIMEOUT_S
            )
            duration = time.time() - t0

            stderr_str = stderr.decode(errors="replace")

            # exit ≥ 125 或 Docker 基础设施错误（镜像未拉取等）→ 降级静态通过
            if proc.returncode >= 125 or any(sig in stderr_str for sig in (
                "Unable to find image", "pull access denied",
                "manifest unknown", "no such file or directory: runsc",
                "Cannot connect to the Docker daemon",
            )):
                logger.warning(
                    f"❗ ExternalSandbox: Docker 基础设施验证失败 "
                    f"(exit={proc.returncode}, err={stderr_str[:100]})，沙箱防护降级为静态通过"
                )
                return SandboxResult(
                    passed=True,
                    reason=f"docker_infra_passthrough: exit={proc.returncode} degraded_security",
                )

            passed = proc.returncode == 0
            reason = "" if passed else f"syntax_error: exit={proc.returncode}"
            logger.debug(
                f"ExternalSandbox: passed={passed} "
                f"exit={proc.returncode} duration={duration:.1f}s"
            )
            return SandboxResult(
                passed=passed,
                reason=reason,
                stdout=stdout.decode(errors="replace")[:500],
                stderr=stderr_str[:500],
                exit_code=proc.returncode,
            )

        except asyncio.TimeoutError:
            logger.warning(f"ExternalSandbox: Docker 超时 ({_TIMEOUT_S}s)")
            return SandboxResult(
                passed=False,
                reason=f"sandbox_timeout_{_TIMEOUT_S}s"
            )
        except Exception as e:
            logger.error(f"ExternalSandbox 异常: {e}")
            # Docker 本身异常时降级为静态通过，不阻塞主流程
            return SandboxResult(passed=True, reason=f"docker_error_passthrough: {e}")
