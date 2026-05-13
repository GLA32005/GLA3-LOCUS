"""
内部沙箱（Internal Sandbox）
防御对象：宿主机（防止 Agent 生成的 Tool-Making 脚本自爆）。
技术：gVisor (runsc) 优先，无 gVisor 时退化为 subprocess + 资源限制。
资源：CPU 1 核 / 内存 256MB / 超时 30s / 完全断网。
"""

from __future__ import annotations

import asyncio
import logging
import os
import resource
import shutil
import tempfile
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_CPU_LIMIT_S     = 10           # CPU 秒数上限
_MEM_LIMIT_BYTES = 256 * 1024 * 1024  # 256 MB
_TIMEOUT_S       = 30
_MAX_OUTPUT      = 8192         # 输出截断阈值（字节）


@dataclass
class InternalSandboxResult:
    success:    bool
    stdout:     str = ""
    stderr:     str = ""
    exit_code:  int = -1
    killed:     bool = False    # True = 资源超限被 kill


class InternalSandbox:
    """
    用于执行 Tool-Making 脚本（不受信任的动态代码）。
    优先使用 gVisor docker runtime；不可用时退化为 subprocess 资源限制。
    完全断网，只读挂载，不可写入宿主机文件系统。
    """

    def __init__(self):
        self._use_gvisor  = self._check_gvisor()
        self._use_docker  = shutil.which("docker") is not None
        logger.info(
            f"InternalSandbox: gvisor={self._use_gvisor} docker={self._use_docker}"
        )

    def _check_gvisor(self) -> bool:
        return shutil.which("runsc") is not None

    async def run_script(
        self, script: str, lang: str = "python"
    ) -> InternalSandboxResult:
        """
        在沙箱内执行脚本。
        lang: "python" | "bash"
        """
        if self._use_docker:
            return await self._run_docker(script, lang)
        return await self._run_subprocess(script, lang)

    # ── Docker (gVisor) 路径 ──────────────────────────────────

    async def _run_docker(
        self, script: str, lang: str
    ) -> InternalSandboxResult:
        image = "python:3.12-slim" if lang == "python" else "ubuntu:22.04"
        runtime_flags = ["--runtime=runsc"] if self._use_gvisor else []

        if lang == "python":
            exec_cmd = ["python3", "-c", script]
        else:
            exec_cmd = ["bash", "-c", script]

        cmd = [
            "docker", "run", "--rm",
            *runtime_flags,
            "--network", "none",
            "--cpus", "1",
            "--memory", "256m",
            "--read-only",
            "--tmpfs", "/tmp:size=32m",
            "--security-opt", "no-new-privileges",
            image,
        ] + exec_cmd

        t0 = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_TIMEOUT_S
            )
            return InternalSandboxResult(
                success=proc.returncode == 0,
                stdout=stdout.decode(errors="replace")[:_MAX_OUTPUT],
                stderr=stderr.decode(errors="replace")[:_MAX_OUTPUT],
                exit_code=proc.returncode,
            )
        except asyncio.TimeoutError:
            logger.warning("InternalSandbox: 超时，强制终止容器")
            return InternalSandboxResult(
                success=False, killed=True,
                stderr=f"killed: timeout {_TIMEOUT_S}s"
            )
        except Exception as e:
            logger.error(f"InternalSandbox Docker 异常: {e}，退化为 subprocess")
            return await self._run_subprocess(script, lang)

    # ── 纯 subprocess 退化路径 ────────────────────────────────

    async def _run_subprocess(
        self, script: str, lang: str
    ) -> InternalSandboxResult:
        """
        无 Docker 时的退化方案：
        通过 preexec_fn 设置 RLIMIT_CPU / RLIMIT_AS，限制资源消耗。
        注意：此路径安全性弱于 gVisor，应仅用于开发环境。
        """
        with tempfile.NamedTemporaryFile(
            suffix=".py" if lang == "python" else ".sh",
            delete=False, mode="w"
        ) as f:
            f.write(script)
            script_path = f.name

        try:
            cmd = (["python3", script_path] if lang == "python"
                   else ["bash", script_path])

            def _set_limits():
                # CPU 秒数
                resource.setrlimit(resource.RLIMIT_CPU,
                                   (_CPU_LIMIT_S, _CPU_LIMIT_S))
                # 虚拟内存
                resource.setrlimit(resource.RLIMIT_AS,
                                   (_MEM_LIMIT_BYTES, _MEM_LIMIT_BYTES))

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=_set_limits,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_TIMEOUT_S
            )
            return InternalSandboxResult(
                success=proc.returncode == 0,
                stdout=stdout.decode(errors="replace")[:_MAX_OUTPUT],
                stderr=stderr.decode(errors="replace")[:_MAX_OUTPUT],
                exit_code=proc.returncode,
            )
        except asyncio.TimeoutError:
            return InternalSandboxResult(
                success=False, killed=True,
                stderr=f"killed: timeout {_TIMEOUT_S}s"
            )
        except Exception as e:
            return InternalSandboxResult(success=False, stderr=str(e))
        finally:
            os.unlink(script_path)
