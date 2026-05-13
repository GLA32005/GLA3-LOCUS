"""
Metasploit Tool — 利用框架 RPC 客户端
通过 pymetasploit3 连接 msfrpcd，执行 exploit/auxiliary 模块。
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from . import BaseTool, ToolResult

logger = logging.getLogger(__name__)

# msfrpcd 默认连接参数（可通过环境变量覆盖）
_DEFAULT_HOST     = "127.0.0.1"
_DEFAULT_PORT     = 55553
_DEFAULT_PASSWORD = "msf"
_DEFAULT_TIMEOUT  = 120  # 秒


class MsfTool(BaseTool):
    """
    Metasploit RPC 客户端。
    params 字段说明：
      module:   模块路径，如 "exploit/windows/smb/ms17_010_eternalblue"
      payload:  payload 路径，如 "windows/x64/meterpreter/reverse_tcp"
      options:  模块选项 dict，如 {"RHOSTS": "10.0.0.5", "LHOST": "10.0.0.1"}
      rpc_host / rpc_port / rpc_pass: 连接参数（可覆盖默认值）
    """

    async def run(self, target: str, params: dict) -> ToolResult:
        # 延迟导入，避免未安装 pymetasploit3 时崩溃
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
        except ImportError:
            return ToolResult(
                success=False, raw={},
                error="pymetasploit3 not installed — pip install pymetasploit3"
            )

        module_path  = params.get("module", "")
        payload_path = params.get("payload", "")
        options      = dict(params.get("options", {}))
        rpc_host     = params.get("rpc_host", _DEFAULT_HOST)
        rpc_port     = int(params.get("rpc_port", _DEFAULT_PORT))
        rpc_pass     = params.get("rpc_pass", _DEFAULT_PASSWORD)
        timeout      = int(params.get("timeout_s", _DEFAULT_TIMEOUT))

        if not module_path:
            return ToolResult(success=False, raw={},
                              error="params.module 未指定")

        # 自动注入 RHOSTS（如未在 options 中指定）
        ip = target.split(":")[0]
        options.setdefault("RHOSTS", ip)
        if ":" in target:
            options.setdefault("RPORT", target.split(":")[1])

        t0 = time.time()
        try:
            client = MsfRpcClient(rpc_pass, server=rpc_host,
                                   port=rpc_port, ssl=False)
            module_type = module_path.split("/")[0]   # "exploit" / "auxiliary"

            if module_type == "exploit":
                exploit = client.modules.use("exploit", module_path)
                for k, v in options.items():
                    exploit[k] = v
                if payload_path:
                    p = client.modules.use("payload", payload_path)
                    result = exploit.execute(payload=p)
                else:
                    result = exploit.execute()
            else:
                mod = client.modules.use(module_type, module_path)
                for k, v in options.items():
                    mod[k] = v
                result = mod.execute()

            duration_ms = int((time.time() - t0) * 1000)

            # result 是 {"job_id": ..., "uuid": ...}
            job_id = result.get("job_id")
            success = job_id is not None

            # 检查是否拿到 session（利用成功）
            sessions = self._get_new_sessions(client, target, timeout)

            footprint = None
            if sessions:
                footprint = {
                    "type":   "MSF_SESSION",
                    "target": target,
                    "detail": {"module": module_path, "sessions": sessions},
                }

            return ToolResult(
                success=bool(sessions),
                raw={"job_id": job_id, "sessions": sessions, "module": module_path},
                footprint=footprint,
                info_gain=0.95 if sessions else 0.3,
                novelty=0.9,
                duration_ms=duration_ms,
            )

        except ConnectionRefusedError:
            return ToolResult(success=False, raw={},
                              error=f"无法连接 msfrpcd at {rpc_host}:{rpc_port}")
        except Exception as e:
            duration_ms = int((time.time() - t0) * 1000)
            logger.error(f"MsfTool 异常: {e}")
            return ToolResult(success=False, raw={}, error=str(e),
                              duration_ms=duration_ms)

    def _get_new_sessions(
        self, client, target: str, wait_s: int
    ) -> list[dict]:
        """Poll for new sessions against target, respecting wait_s up to 300s."""
        import time as _time
        ip = target.split(":")[0]
        # Cap at 300s to protect the event loop from indefinite blocking,
        # but always honour the caller's timeout if smaller.
        deadline = _time.time() + min(wait_s, 300)
        poll_interval = 2
        while _time.time() < deadline:
            try:
                sessions = client.sessions.list
                new = [
                    {"id": sid, "info": info}
                    for sid, info in sessions.items()
                    if info.get("target_host") == ip
                ]
                if new:
                    return new
            except Exception:
                pass
            remaining = deadline - _time.time()
            _time.sleep(min(poll_interval, max(remaining, 0)))
        return []
