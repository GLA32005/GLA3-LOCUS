"""
Executor — 唯一触网者
纯代码，不含 LLM。职责：
  1. 轮询 pending_payloads(APPROVED)  → 路由到对应 L4 工具执行
  2. 轮询 pending_recon_tasks(PENDING) → 路由到侦察工具
  3. 执行结果写回 tried_vectors / assets / footprints
  4. 发布 EXPLOIT_SUCCESS / ASSET_DISCOVERED / TASK_COMPLETED 事件
约束⑥：Executor 是系统中唯一可以直接触网的组件。
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from core.protocols import (
    Event, EventPriority, EventType,
    MutationOperation, PayloadStatus, StateDomain, StateMutation,
    TaskStatus, VectorResult, VectorType,
    AccessLevel,
)
from core.state_api import StateAPI
from core.orchestrator import EventBus

from .sandbox_external import ExternalSandbox
from .tools import ToolResult
from .tools.nmap_tool import NmapTool
from .tools.nuclei_tool import NucleiTool
from .tools.msf_tool import MsfTool

logger = logging.getLogger(__name__)

# ── LOTL 执行方式（SSH / WinRM）─────────────────────────────

async def _exec_via_ssh(ip: str, port: int, creds: list[dict],
                        content: str) -> ToolResult:
    """通过 SSH 在目标主机执行 payload（Linux/UNIX 目标）。"""
    try:
        import asyncssh
    except ImportError:
        return ToolResult(success=False, raw={},
                          error="asyncssh not installed — pip install asyncssh")

    for cred in creds:
        username = cred.get("username", "root")
        password = cred.get("password")
        key_path = cred.get("key_path")
        t0 = time.time()
        try:
            connect_kw: dict = dict(
                host=ip, port=port, username=username,
                known_hosts=None,
            )
            if password:
                connect_kw["password"] = password
            if key_path:
                connect_kw["client_keys"] = [key_path]

            async with asyncssh.connect(**connect_kw) as conn:
                result = await asyncio.wait_for(
                    conn.run(content, check=False), timeout=30
                )
            duration_ms = int((time.time() - t0) * 1000)
            success = result.exit_status == 0
            footprint = {
                "type":   "SSH_EXEC",
                "target": f"{ip}:{port}",
                "detail": {
                    "username": username,
                    "command":  content[:200],
                    "exit_status": result.exit_status,
                },
            }
            return ToolResult(
                success=success,
                raw={"stdout": result.stdout[:1000],
                     "stderr": result.stderr[:500],
                     "exit":   result.exit_status},
                footprint=footprint,
                info_gain=0.8 if success else 0.3,
                duration_ms=duration_ms,
            )
        except asyncssh.PermissionDenied:
            continue  # 尝试下一条凭据
        except Exception as e:
            logger.debug(f"SSH 连接 {ip}:{port} 失败: {e}")
            continue

    return ToolResult(success=False, raw={},
                      error="所有凭据均认证失败或连接超时")


async def _exec_via_winrm(ip: str, port: int, creds: list[dict],
                           content: str) -> ToolResult:
    """通过 WinRM 在目标主机执行 payload（Windows 目标）。"""
    try:
        import winrm
    except ImportError:
        return ToolResult(success=False, raw={},
                          error="pywinrm not installed — pip install pywinrm")

    for cred in creds:
        username = cred.get("username", "Administrator")
        password = cred.get("password", "")
        t0 = time.time()
        try:
            session = winrm.Session(
                f"http://{ip}:{port}/wsman",
                auth=(username, password),
                transport="ntlm",
            )
            result = session.run_ps(content)
            duration_ms = int((time.time() - t0) * 1000)
            success = result.status_code == 0
            footprint = {
                "type":   "WINRM_EXEC",
                "target": f"{ip}:{port}",
                "detail": {
                    "username": username,
                    "command":  content[:200],
                    "exit_code": result.status_code,
                },
            }
            return ToolResult(
                success=success,
                raw={"stdout": result.std_out.decode(errors="replace")[:1000],
                     "stderr": result.std_err.decode(errors="replace")[:500]},
                footprint=footprint,
                info_gain=0.8 if success else 0.3,
                duration_ms=duration_ms,
            )
        except Exception as e:
            logger.debug(f"WinRM {ip}:{port} 失败: {e}")
            continue

    return ToolResult(success=False, raw={},
                      error="WinRM 所有凭据均失败")


# ── 侦察工具路由表 ────────────────────────────────────────────

from .tools.shell_tools import (
    BannerGrabTool, DirEnumTool, SmbEnumTool,
    LdapEnumTool, CredSprayTool, HttpxTool,
)
from .tools.msf_tool import MsfTool
from .tools.codeql_tool import CodeQLTool
from .tools.screenshot_tool import ScreenshotTool

_RECON_TOOL_MAP = {
    # Nmap 系列
    "nmap":            NmapTool,
    "port_scan":       NmapTool,
    "port_scan_full":  NmapTool,
    "service_enum":    NmapTool,
    "udp_scan":       NmapTool,
    # Nuclei
    "vuln_scan":       NucleiTool,
    "nuclei":          NucleiTool,
    # 轻量工具
    "banner_grab":     BannerGrabTool,
    "http_probe":      HttpxTool,
    "dir_enum":        DirEnumTool,
    "auth_test_anon":  BannerGrabTool,  # Hallucination mapping: 匿名登录探测映射到 BannerGrab (包含基础测试)
    "smb_enum":        SmbEnumTool,
    "ldap_enum":       LdapEnumTool,
    "cred_spray":      CredSprayTool,
    # 视觉分析
    "screenshot":      ScreenshotTool,
    # 重型框架
    "msf":             MsfTool,
    "metasploit":      MsfTool,
    "code_audit":      CodeQLTool,
    "codeql":          CodeQLTool,
}


# ── Executor ─────────────────────────────────────────────────

class Executor:
    """
    系统唯一触网者。
    直接使用 StateAPI 写结果，不走 Agent mutation 模式。
    """

    def __init__(self, state_api: StateAPI, event_bus: EventBus):
        self.state_api = state_api
        self.event_bus = event_bus
        self.sandbox   = ExternalSandbox()
        self._tools    = {name: cls() for name, cls in _RECON_TOOL_MAP.items()}
        self._discovered_ips: set[str] = set()   # 已发现的 IP，用于事件去重
        self._running_recon: set[str] = set()     # 正在执行的 recon task_id，防止重复分发
        self._mission_scope: list[str] = []       # 缓存 scope，启动时加载
        self._host_timeouts: dict[str, int] = {}  # 追踪目标超时次数

    async def _load_scope(self):
        """从 Redis 加载 mission scope，带缓存"""
        if not getattr(self, '_mission_scope', None):
            mission = await self.state_api.get_mission()
            self._mission_scope = mission.get("scope_expanded", mission.get("scope", []))
        return self._mission_scope

    def _is_in_scope(self, target: str, scope: list[str]) -> bool:
        """硬编码 scope 校验，拒绝所有越界目标（包括域名）"""
        import ipaddress
        if not target or not scope:
            return False
        ip_str = target.split(":")[0]  # 去掉端口
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return any(
                ip_obj in ipaddress.ip_network(cidr, strict=False)
                for cidr in scope
            )
        except ValueError:
            # 域名或 CIDR 网段直接匹配
            if ip_str in scope:
                return True
            return False

    # ════════════════════════════════════════════════════════════
    # 入口一：执行 APPROVED exploit payload
    # ════════════════════════════════════════════════════════════

    async def execute(self, payload: dict):
        """
        执行一个 APPROVED exploit/action payload。
        由 Orchestrator._executor_loop 调度（已扣除 noise_cost 配额）。
        """
        payload_id  = payload.get("id", "")
        content     = payload.get("content", "")
        target      = payload.get("target", "")
        vector_type = payload.get("vector_type", VectorType.LOTL)
        hint        = payload.get("executor_hint", "bash")
        retry_count = int(payload.get("retry_count", 0))
        agent_id    = payload.get("created_by", "executor")
        timeout_ms  = int(payload.get("timeout_ms", 15000))

        # ── 0. Scope 校验（最后一道防线）────────────────────
        scope = await self._load_scope()
        if not self._is_in_scope(target, scope):
            logger.warning(
                f"Executor: 拒绝越界 payload={payload_id} target={target}"
            )
            await self._update_payload_status(payload_id, PayloadStatus.DONE)
            return

        # ── 1. 标记 EXECUTING ────────────────────────────────
        await self._update_payload_status(
            payload_id, PayloadStatus.EXECUTING
        )

        t0 = time.time()

        # ── 2. 外部沙箱安全检查 ───────────────────────────────
        sandbox_result = await self.sandbox.check(content, hint)
        if not sandbox_result.passed:
            duration_ms = int((time.time() - t0) * 1000)
            logger.warning(
                f"Executor: 沙箱拦截 payload={payload_id} "
                f"reason={sandbox_result.reason}"
            )
            await self._record_vector(
                payload=payload,
                result=VectorResult.SANDBOX_FAIL,
                fail_reason="SANDBOX_SYNTAX_ERROR",
                info_gain=0.0,
                duration_ms=duration_ms,
            )
            await self._update_payload_status(payload_id, PayloadStatus.DONE)
            from core.protocols import RejectReason
            await self.event_bus.publish(Event(
                type=EventType.PAYLOAD_REJECTED,
                source="executor",
                payload={
                    "payload_id": payload_id,
                    "target": target,
                    "reject_reason": RejectReason.SYNTAX_ERROR,
                    "detail": sandbox_result.reason
                }
            ))
            return

        # ── 3. 路由并执行 ─────────────────────────────────────
        try:
            tool_result = await asyncio.wait_for(
                self._route_and_execute(payload),
                timeout=timeout_ms / 1000,
            )
        except asyncio.TimeoutError:
            duration_ms = int((time.time() - t0) * 1000)
            await self._record_vector(
                payload=payload,
                result=VectorResult.TIMEOUT,
                fail_reason="UNKNOWN",
                info_gain=0.0,
                duration_ms=duration_ms,
            )
            await self._update_payload_status(payload_id, PayloadStatus.DONE)
            return
        except Exception as e:
            duration_ms = int((time.time() - t0) * 1000)
            logger.error(f"Executor execute 异常: payload={payload_id} {e}")
            await self._record_vector(
                payload=payload,
                result=VectorResult.FAIL,
                fail_reason="UNKNOWN",
                info_gain=0.0,
                duration_ms=duration_ms,
            )
            await self._update_payload_status(payload_id, PayloadStatus.DONE)
            return

        # ── 4. 写回结果 ───────────────────────────────────────
        duration_ms = tool_result.duration_ms or int((time.time() - t0) * 1000)
        vec_result  = (VectorResult.SUCCESS if tool_result.success
                       else VectorResult.FAIL)
                       
        fail_reason = None
        if not tool_result.success:
            err_str = (tool_result.error or str(tool_result.raw.get("stderr", ""))).lower()
            if duration_ms < 50:
                fail_reason = "NETWORK_UNREACHABLE"
            elif "authentication" in err_str or "permission denied" in err_str:
                fail_reason = "AUTH_FAILED"
            elif "refused" in err_str or "not found" in err_str:
                fail_reason = "SERVICE_NOT_FOUND"
            else:
                fail_reason = "EXECUTION_FAILED"

        await self._record_vector(
            payload=payload,
            result=vec_result,
            fail_reason=fail_reason,
            info_gain=tool_result.info_gain,
            duration_ms=duration_ms,
        )

        # 写入发现的新资产
        for asset in tool_result.assets:
            await self._upsert_asset(asset)

        # 写入 footprints（约束⑤：所有写入目标系统的动作必须记录）
        if tool_result.footprint:
            await self._append_footprint(tool_result.footprint)

        # ── 5. 发布事件 ───────────────────────────────────────
        if tool_result.success:
            access_level = self._infer_access_level(tool_result, payload)
            await self.event_bus.publish(
                Event.exploit_success(
                    target=target,
                    access_level=access_level,
                    vector_id=payload_id,
                )
            )

        # 无论成功/失败，都发 TASK_COMPLETED 让 Orchestrator 感知 exploit 结果
        await self.event_bus.publish(
            Event.task_completed(
                task_id=payload_id,
                result={
                    "tool":         hint,
                    "target":       target,
                    "assets_found": len(tool_result.assets),
                    "duration_ms":  duration_ms,
                    "status":       "FAILED" if not tool_result.success else "DONE",
                    "is_exploit":   True,
                },
            )
        )

        await self._update_payload_status(payload_id, PayloadStatus.DONE)
        logger.info(
            f"Executor: payload={payload_id} target={target} "
            f"result={vec_result} duration={duration_ms}ms"
        )

    # ════════════════════════════════════════════════════════════
    # 入口二：执行 PENDING recon task
    # ════════════════════════════════════════════════════════════

    async def execute_recon(self, task: dict):
        """
        执行一个 PENDING 侦察任务（来自 Recon Agent 的 pending_recon_tasks）。
        由 Orchestrator._recon_loop 调度。
        """
        task_id  = task.get("id", "")
        tool_name = task.get("tool", "")
        target   = task.get("target", "")
        params   = dict(task.get("params", {}))
        params["tool"] = tool_name  # 方便 NmapTool 判断 scan_type

        # ── Scope 校验（最后一道防线，拒绝越界目标）─────────
        scope = await self._load_scope()
        if not self._is_in_scope(target, scope):
            logger.warning(
                f"Executor: 拒绝越界 recon task={task_id} target={target}"
            )
            await self._update_recon_status(task_id, TaskStatus.FAILED)
            return

        # ── 标记 RUNNING ─────────────────────────────────────
        await self._update_recon_status(task_id, TaskStatus.RUNNING)

        t0 = time.time()
        tool = self._tools.get(tool_name)
        if tool is None:
            logger.warning(f"Executor: 未知工具 '{tool_name}'，跳过 task={task_id}")
            await self._update_recon_status(task_id, TaskStatus.FAILED)
            return

        try:
            timeout = int(params.get("timeout_s", 300))
            tool_result = await asyncio.wait_for(
                tool.run(target, params), timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"Executor: recon 超时 task={task_id} tool={tool_name}")
            await self._update_recon_status(task_id, TaskStatus.TIMEOUT)
            
            # A2 修复：所有工具超时都计入目标超时计数（不限 nmap）
            # 问题 #7 修复：按纯 IP 聚合超时计数（不同端口的超时应合并计数）
            ip_only = target.split(":")[0]
            self._host_timeouts[ip_only] = self._host_timeouts.get(ip_only, 0) + 1
            if self._host_timeouts[ip_only] >= 3:
                logger.error(f"目标 {ip_only} 连续 3 次扫描超时，标记为 UNREACHABLE")
                await self.event_bus.publish(Event(
                    type=EventType.TARGET_UNREACHABLE,
                    priority=EventPriority.HIGH,
                    source="executor",
                    payload={"target": ip_only, "reason": "Consecutive timeouts"}
                ))

            # A2 修复：超时也发送 TASK_COMPLETED，让 Orchestrator 感知任务结束
            await self.event_bus.publish(
                Event.task_completed(
                    task_id=task_id,
                    result={
                        "tool":        tool_name,
                        "target":      target,
                        "assets_found": 0,
                        "duration_ms":  0,
                        "status":      "TIMEOUT",
                    },
                )
            )
            return
        except Exception as e:
            logger.error(f"Executor: recon 异常 task={task_id} {e}")
            await self._update_recon_status(task_id, TaskStatus.FAILED)
            return

        # ── 写入发现的资产 ────────────────────────────────────
        new_asset_count = 0  # 问题 #6 修复：只计首次发现的新资产
        for asset in tool_result.assets:
            await self._upsert_asset(asset)
            ip = asset.get("ip", "")
            if ip and ip not in self._discovered_ips:
                self._discovered_ips.add(ip)
                new_asset_count += 1
                await self.event_bus.publish(Event(
                    type=EventType.ASSET_DISCOVERED,
                    priority=EventPriority.HIGH,
                    source="executor",
                    payload={"target": ip, "task_id": task_id,
                             "tool": tool_name},
                ))

            # ── 确定性自动派发：发现 HTTP 服务时注入 nuclei + screenshot ──
            if tool_name in ("nmap", "port_scan", "port_scan_full", "service_enum"):
                await self._auto_dispatch_http_tasks(ip, asset.get("services", []))

        # ── 完成 ─────────────────────────────────────────────
        await self._update_recon_status(task_id, TaskStatus.DONE)
        
        # 智能截断 raw 数据，防止日志被 Base64 塞爆
        raw_display = {}
        if isinstance(tool_result.raw, dict):
            for k, v in tool_result.raw.items():
                if isinstance(v, str) and len(v) > 200:
                    raw_display[k] = v[:200] + "... [TRUNCATED]"
                else:
                    raw_display[k] = v
        else:
            raw_display = str(tool_result.raw)[:300]

        await self.event_bus.publish(
            Event.task_completed(
                task_id=task_id,
                result={
                    "tool":          tool_name,
                    "target":        target,
                    "assets_found":  new_asset_count,
                    "info_gain":     tool_result.info_gain,
                    "duration_ms":   tool_result.duration_ms,
                    "status":        str(tool_result.raw.get("status", "")),
                    "raw_summary":   str(raw_display),
                },
            )
        )

        logger.info(
            f"Executor: recon task={task_id} tool={tool_name} target={target} "
            f"assets={new_asset_count} "
            f"duration={tool_result.duration_ms}ms"
        )

    # ════════════════════════════════════════════════════════════
    # 入口三：执行 APPROVED cleanup task（Loop C）
    # ════════════════════════════════════════════════════════════

    async def execute_cleanup(self, task: dict):
        """
        执行一个 APPROVED 清理任务（Human 审批后）。
        逐步验证：每步执行完立即检查清理效果。
        约束⑤：清理动作本身也记录到 footprints（类型 CLEANUP_EXEC）。
        """
        task_id     = task.get("id", "")
        target      = task.get("target", "")
        content     = task.get("content")
        hint        = task.get("executor_hint", "bash").lower()
        timeout_ms  = int(task.get("timeout_ms", 15000))
        footprint_id = task.get("footprint_id", "")

        # 无命令内容 → 手动操作，标记需人工确认
        if not content:
            logger.info(
                f"Executor: cleanup task={task_id} is manual-only, skipping execution"
            )
            await self._update_cleanup_status(task_id, "MANUAL_REQUIRED")
            return

        await self._update_cleanup_status(task_id, "EXECUTING")
        t0 = time.time()

        ip     = target.split(":")[0]
        port_s = target.split(":")[1] if ":" in target else ""
        creds  = await self._get_target_creds(ip)

        try:
            if hint in ("powershell", "cmd"):
                port = int(port_s) if port_s else 5985
                result = await asyncio.wait_for(
                    _exec_via_winrm(ip, port, creds, content),
                    timeout=timeout_ms / 1000,
                )
            else:
                port = int(port_s) if port_s else 22
                result = await asyncio.wait_for(
                    _exec_via_ssh(ip, port, creds, content),
                    timeout=timeout_ms / 1000,
                )
        except asyncio.TimeoutError:
            logger.warning(f"Executor: cleanup 超时 task={task_id}")
            await self._update_cleanup_status(task_id, "FAILED")
            await self._notify_cleanup_failure(task_id, target, "timeout")
            return
        except Exception as e:
            logger.error(f"Executor: cleanup 异常 task={task_id} {e}")
            await self._update_cleanup_status(task_id, "FAILED")
            await self._notify_cleanup_failure(task_id, target, str(e))
            return

        duration_ms = int((time.time() - t0) * 1000)

        # 记录清理动作本身到 footprints（约束⑤）
        await self._append_footprint({
            "type":   "CLEANUP_EXEC",
            "target": target,
            "detail": {
                "task_id":      task_id,
                "footprint_id": footprint_id,
                "command":      content[:200],
                "success":      result.success,
                "duration_ms":  duration_ms,
            },
        })

        if result.success:
            # 标记原始 footprint 已清理
            if footprint_id:
                await self.state_api.mark_footprint_cleaned(footprint_id)
            await self._update_cleanup_status(task_id, "DONE")
            await self.event_bus.publish(Event.task_completed(
                task_id=task_id,
                result={
                    "type":       "cleanup",
                    "target":     target,
                    "success":    True,
                    "duration_ms": duration_ms,
                },
            ))
            logger.info(
                f"Executor: cleanup task={task_id} target={target} "
                f"SUCCESS in {duration_ms}ms"
            )
        else:
            # 验证失败 → 标记 FAILED，通知 Human
            await self._update_cleanup_status(task_id, "FAILED")
            await self._notify_cleanup_failure(
                task_id, target,
                result.error or result.raw.get("stderr", "unknown error")[:200],
            )
            logger.warning(
                f"Executor: cleanup task={task_id} target={target} FAILED"
            )

    async def _update_cleanup_status(self, task_id: str, status: str):
        await self.state_api.apply_mutation(StateMutation(
            operation=MutationOperation.UPDATE_STATUS,
            domain=StateDomain.PENDING_CLEANUP,
            payload={"id": task_id, "status": status,
                     "executed_at": datetime.now(timezone.utc).isoformat()},
        ))

    async def _notify_cleanup_failure(
        self, task_id: str, target: str, reason: str
    ):
        """清理失败时发送 HUMAN_APPROVAL_REQ，要求人工介入。"""
        await self.event_bus.publish(Event(
            type=EventType.HUMAN_APPROVAL_REQ,
            priority=EventPriority.CRITICAL,
            source="executor",
            payload={
                "context":  "cleanup_failure",
                "task_id":  task_id,
                "target":   target,
                "reason":   reason,
                "message":  f"Cleanup task {task_id} failed on {target}: {reason}",
            },
        ))

    # ════════════════════════════════════════════════════════════
    # 内部路由
    # ════════════════════════════════════════════════════════════

    async def _route_and_execute(self, payload: dict) -> ToolResult:
        """按 vector_type 路由到对应执行方式。"""
        vector_type = payload.get("vector_type", VectorType.LOTL)
        target      = payload.get("target", "")
        content     = payload.get("content", "")
        hint        = payload.get("executor_hint", "bash")

        if vector_type == VectorType.LOTL:
            return await self._exec_lotl(payload)

        if vector_type == VectorType.SSRF:
            return await self._exec_http_probe(target, content)

        # 其余向量类型：通过 MsfTool 或占位处理
        if vector_type in (VectorType.SQLI, VectorType.AUTH_BYPASS,
                           VectorType.BRUTE_FORCE, VectorType.CRED_REUSE,
                           VectorType.PRIVESC, VectorType.LATERAL_MOVE):
            msf_params = payload.get("params", {})
            msf_params.setdefault("module", payload.get("technique", ""))
            return await MsfTool().run(target, msf_params)

        # 兜底
        logger.warning(f"Executor: 未知 vector_type={vector_type}，不执行")
        return ToolResult(success=False, raw={},
                          error=f"unsupported vector_type: {vector_type}")

    async def _exec_lotl(self, payload: dict) -> ToolResult:
        """LotL：根据目标 OS 选择 SSH 或 WinRM。"""
        target = payload.get("target", "")
        ip     = target.split(":")[0]
        port_s = target.split(":")[1] if ":" in target else ""
        hint   = payload.get("executor_hint", "bash").lower()
        content = payload.get("content", "")

        # 从 assets 获取凭据
        creds = await self._get_target_creds(ip)

        if hint in ("powershell", "cmd"):
            port = int(port_s) if port_s else 5985
            return await _exec_via_winrm(ip, port, creds, content)
        else:
            port = int(port_s) if port_s else 22
            return await _exec_via_ssh(ip, port, creds, content)

    # SSRF-indicative patterns in response bodies
    _SSRF_PATTERNS = [
        # AWS/GCP/Azure metadata
        b"ami-id", b"instance-id", b"iam/security-credentials",
        b"computeMetadata", b"DOCUMENT_ROOT",
        # Internal credential bleed
        b'"AccessKeyId"', b'"SecretAccessKey"', b"metadata/identity",
        # File system indicators from SSRF-triggered fetches
        b"root:x:0:", b"[boot loader]", b"\\windows\\system32",
        # Error messages exposing internal addresses
        b"169.254.", b"10.0.", b"192.168.", b"172.16.",
    ]

    async def _exec_http_probe(self, target: str, content: str) -> ToolResult:
        """SSRF: HTTP probe supporting GET/POST, custom headers, and SSRF pattern detection."""
        try:
            import aiohttp
        except ImportError:
            return ToolResult(success=False, raw={},
                              error="aiohttp not installed")

        # Parse content: JSON dict → full control; "POST:url" → POST; else GET
        import json as _json
        method = "GET"
        headers: dict = {}
        body_data: str | None = None
        url: str

        try:
            spec = _json.loads(content)
            url         = spec.get("url", f"http://{target}/")
            method      = spec.get("method", "GET").upper()
            headers     = spec.get("headers", {})
            body_data   = spec.get("body")
        except (ValueError, TypeError):
            if content.upper().startswith("POST:"):
                method = "POST"
                url = content[5:].strip()
            elif content.startswith("http"):
                url = content
            else:
                url = f"http://{target}{content}"

        if not url.startswith("http"):
            url = f"http://{target}/{url.lstrip('/')}"

        t0 = time.time()
        try:
            async with aiohttp.ClientSession(headers=headers) as sess:
                kwargs: dict = dict(
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True,
                )
                if method == "POST":
                    kwargs["data"] = body_data or ""

                req = getattr(sess, method.lower())
                async with req(url, **kwargs) as resp:
                    raw_body = await resp.read()
                    body_text = raw_body[:2000].decode("utf-8", errors="replace")
                    duration_ms = int((time.time() - t0) * 1000)

                    # Detect SSRF-indicative content in body
                    ssrf_hit = any(p in raw_body[:2000] for p in self._SSRF_PATTERNS)
                    # Track redirect chain (internal IP exposure)
                    redirect_hosts = [str(h.url.host) for h in resp.history]
                    internal_redirect = any(
                        h.startswith(("10.", "172.", "192.168.", "169.254."))
                        for h in redirect_hosts
                    )
                    ssrf_confirmed = ssrf_hit or internal_redirect

                    info_gain = 0.9 if ssrf_confirmed else (0.6 if resp.status < 400 else 0.2)
                    return ToolResult(
                        success=resp.status < 400 or ssrf_confirmed,
                        raw={
                            "status":           resp.status,
                            "method":           method,
                            "url":              str(resp.url),
                            "body_snippet":     body_text[:500],
                            "ssrf_confirmed":   ssrf_confirmed,
                            "redirect_chain":   redirect_hosts,
                        },
                        info_gain=info_gain,
                        footprint={
                            "type":   "HTTP_PROBE",
                            "target": url,
                            "detail": {
                                "status":         resp.status,
                                "method":         method,
                                "ssrf_confirmed": ssrf_confirmed,
                            },
                        },
                        duration_ms=duration_ms,
                    )
        except Exception as e:
            return ToolResult(success=False, raw={}, error=str(e))

    # ════════════════════════════════════════════════════════════
    # State 写入辅助（Executor 直接调用 StateAPI，不走 mutation 模式）
    # ════════════════════════════════════════════════════════════

    async def _update_payload_status(
        self, payload_id: str, status: PayloadStatus
    ):
        await self.state_api.apply_mutation(StateMutation(
            operation=MutationOperation.UPDATE_STATUS,
            domain=StateDomain.PENDING_PAYLOADS,
            payload={"id": payload_id, "status": status},
        ))

    async def _update_recon_status(self, task_id: str, status: TaskStatus):
        await self.state_api.apply_mutation(StateMutation(
            operation=MutationOperation.UPDATE_STATUS,
            domain=StateDomain.PENDING_RECON,
            payload={"id": task_id, "status": status},
        ))

    async def _record_vector(
        self,
        payload: dict,
        result: VectorResult,
        fail_reason: Optional[str],
        info_gain: float,
        duration_ms: int,
    ):
        """将最终执行结果追加到 tried_vectors（约束②：APPEND only）。"""
        await self.state_api.apply_mutation(StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.TRIED_VECTORS,
            payload={
                "id":          str(uuid.uuid4()),
                "target":      payload.get("target", ""),
                "type":        payload.get("vector_type", "UNKNOWN"),
                "payload":     payload.get("content", "")[:200],
                "result":      result,
                "fail_reason": fail_reason or "UNKNOWN",
                "info_gain":   info_gain,
                "novelty":     0.2 if result == VectorResult.FAIL else 0.8,
                "retry_count": int(payload.get("retry_count", 0)),
                "tokens_used": 0,
                "duration_ms": duration_ms,
                "agent_id":    "executor",
            },
        ))

    async def _upsert_asset(self, asset: dict):
        """将发现的资产写入 Neo4j assets 图谱（含归一化）。"""
        ip_or_domain = asset.get("ip")
        if not ip_or_domain:
            return

        # ── 归一化逻辑 (Issue 3) ──
        # 如果是域名，尝试解析为 IP，确保 Neo4j 中 Host 节点唯一
        resolved_ip = ip_or_domain
        domain_alias = None

        import ipaddress
        try:
            ipaddress.ip_address(ip_or_domain)
        except ValueError:
            # 不是 IP，尝试解析
            domain_alias = ip_or_domain
            import socket
            try:
                # 优先解析为 IP，确保 hosts 计数准确
                resolved_ip = socket.gethostbyname(ip_or_domain)
                logger.debug(f"Executor: 资产归一化 {domain_alias} -> {resolved_ip}")
            except Exception as e:
                logger.warning(f"Executor: 域名解析失败 {domain_alias}: {e}")
                # 解析失败仍保留域名作为 key (不推荐但作为保底)
                resolved_ip = domain_alias

        asset["ip"] = resolved_ip
        if domain_alias and domain_alias != resolved_ip:
            asset["domain"] = domain_alias  # 存入属性

        await self.state_api.apply_mutation(StateMutation(
            operation=MutationOperation.UPSERT,
            domain=StateDomain.ASSETS,
            payload=asset,
        ))

    async def _append_footprint(self, footprint: dict):
        """记录写入目标系统的动作（约束⑤）。"""
        await self.state_api.apply_mutation(StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.FOOTPRINTS,
            payload={
                "id":     str(uuid.uuid4()),
                "type":   footprint.get("type", "UNKNOWN"),
                "target": footprint.get("target", ""),
                "detail": footprint.get("detail", {}),
                "cleaned": False,
            },
        ))

    async def _get_target_creds(self, ip: str) -> list[dict]:
        """从 Neo4j 获取已知凭据，用于 LOTL 执行。"""
        try:
            host = await self.state_api.get_host_full(ip)
            return host.get("creds", []) if host else []
        except Exception:
            return []

    def _infer_access_level(
        self, result: ToolResult, payload: dict
    ) -> str:
        """根据执行成功的向量类型推断获得的访问级别。"""
        vtype = payload.get("vector_type", "")
        if vtype in (VectorType.PRIVESC,):
            return AccessLevel.ROOT
        if vtype in (VectorType.LATERAL_MOVE,):
            return AccessLevel.USER
        # LOTL / SQLI 等默认 SHELL 级别
        return AccessLevel.SHELL

    # ── 确定性自动派发（纯代码，不经 LLM）─────────────────────

    _HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}
    _auto_dispatched: set[str] = set()   # "ip:port:tool" 去重

    async def _auto_dispatch_http_tasks(self, ip: str, services: list[dict]):
        """
        Nmap 发现 HTTP 服务后，自动注入 vuln_scan + screenshot 任务。
        纯代码逻辑，不依赖 LLM 决策，打破 "Planner 想太多" 的僵局。
        """
        if not ip:
            return

        for svc in services:
            port = svc.get("port", 0)
            app = (svc.get("app") or "").lower()

            # 只对 HTTP 类服务自动派发
            if port not in self._HTTP_PORTS and "http" not in app:
                continue

            target = f"{ip}:{port}"

            # 自动注入 vuln_scan (nuclei)
            await self._inject_auto_task(
                target=target,
                tool="vuln_scan",
                rationale=f"自动派发: 发现 HTTP 服务 {app}:{port}，触发漏洞扫描",
                is_async=True,
                noise_cost=3,
            )

            # 自动注入 screenshot (playwright)
            await self._inject_auto_task(
                target=target,
                tool="screenshot",
                rationale=f"自动派发: 发现 HTTP 服务 {app}:{port}，触发截图分析",
                is_async=False,
                noise_cost=1,
            )

            # 自动注入 dir_enum (feroxbuster)
            await self._inject_auto_task(
                target=target,
                tool="dir_enum",
                rationale=f"自动派发: 发现 HTTP 服务 {app}:{port}，触发目录爆破",
                is_async=True,
                noise_cost=2,
            )

    async def _inject_auto_task(
        self, target: str, tool: str, rationale: str,
        is_async: bool = False, noise_cost: int = 1,
    ):
        """注入一个自动派发的侦察任务（去重）"""
        dedup_key = f"{target}:{tool}"
        if dedup_key in self._auto_dispatched:
            return
        self._auto_dispatched.add(dedup_key)

        # 检查工具是否可用
        if tool not in self._tools:
            return

        import uuid
        from datetime import datetime, timezone
        task_id = str(uuid.uuid4())

        task_payload = {
            "id":         task_id,
            "tool":       tool,
            "target":     target,
            "params":     {},
            "priority":   0.8,   # 高优先级
            "noise_cost": noise_cost,
            "rationale":  rationale,
            "status":     TaskStatus.PENDING,
            "created_by": "executor:auto_dispatch",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        await self.state_api.apply_mutation(StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.PENDING_RECON,
            payload=task_payload,
        ))
        logger.info(f"Executor 自动派发: {tool} → {target}")

