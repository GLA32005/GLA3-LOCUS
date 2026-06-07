"""
Orchestrator — 系统调度核心
职责：
  1. 订阅 EventBus，路由事件到对应处理器
  2. 管理 Planner 的 Think 触发时机（防事件风暴）
  3. 管理 Executor 的并发配额
  4. 处理 PAYLOAD_REJECTED 快速修正循环
  5. 判定 CLEANUP_STATE 进入条件
"""

from __future__ import annotations
import asyncio
import json
import time
import logging
from typing import Callable, Optional
from collections import defaultdict

from .protocols import (
    Event, EventType, EventPriority,
    StateMutation, StateDomain, MutationOperation,
    AgentType, RejectReason, PayloadStatus, TaskStatus
)
from .state_api import StateAPI
from .state_pruner import StatePruner

logger = logging.getLogger(__name__)


class EventBus:
    """
    轻量级内存事件总线。
    支持优先级和同类事件合并（防事件风暴）。
    生产环境可替换为 Redis Pub/Sub，接口不变。
    """

    def __init__(self):
        self._queues: dict[EventPriority, asyncio.Queue] = {
            p: asyncio.Queue() for p in EventPriority
        }
        self._handlers: dict[EventType, list[Callable]] = defaultdict(list)

    def subscribe(self, event_type: EventType, handler: Callable):
        self._handlers[event_type].append(handler)

    async def publish(self, event: Event):
        await self._queues[event.priority].put(event)
        logger.debug(f"Event published: {event.type} from {event.source}")

    async def get_next(self) -> Optional[Event]:
        """按优先级取事件，CRITICAL 优先"""
        for priority in EventPriority:
            q = self._queues[priority]
            if not q.empty():
                return await q.get()
        return None


class Orchestrator:
    """
    系统的调度大脑（纯代码，不含 LLM）。
    """

    # Think 触发间隔控制（防事件风暴）
    MIN_THINK_INTERVAL      = 3.0   # 正常情况最少间隔 3 秒
    CRITICAL_THINK_INTERVAL = 0.5   # CRITICAL 事件触发间隔 0.5 秒
    EVENT_MERGE_WINDOW      = 0.1   # 100ms 内同类事件合并

    def __init__(self, state_api: StateAPI, event_bus: EventBus,
                 planner, exploit_agent, recon_agent, critic_agent,
                 cleanup_agent, executor, rag_engine,
                 report_generator=None):
        self.state_api     = state_api
        self.event_bus     = event_bus
        self.planner       = planner
        self.exploit_agent = exploit_agent
        self.recon_agent   = recon_agent
        self.critic_agent  = critic_agent
        self.cleanup_agent = cleanup_agent
        self.executor      = executor
        self.rag           = rag_engine
        self.report_generator = report_generator
        self.pruner        = StatePruner()

        self._last_think_time = 0.0
        self._is_running      = False
        self._in_cleanup      = False
        self._think_count     = 0     # Think 轮次计数
        self._start_time      = 0.0   # 启动时间戳
        self._total_stall_count = 0   # 累计 stall，永不重置
        self._parse_failure_count = 0 # LLM 解析失败次数
        self._active_executor_tasks = 0 # 当前正在运行的 Executor 任务数
        self._recon_sent_keys: set[str] = set()
        self._exploit_sent_keys: set[str] = set()

        self._is_thinking = False
        self._system_hint: Optional[str] = None  # 传给 Planner 的临时提示 (Issue 4)
        self._host_timeouts: dict[str, int] = {}  # 追踪主机的连续超时/失败次数 (Issue 1)
        self._consecutive_recon_rounds = 0      # 连续侦察轮次计数
        self._last_known_hosts = 0          # 上次已知主机数
        self._force_strong_next_think = False  # 下次 Think 强制大模型
        self._force_exploit_override = False    # stall 强制切 EXPLOIT 时跳过服务检查
        self._force_exploit_override_rounds = 0 # 拦截 Planner RECON 的轮次

        # 并发配额追踪
        self._current_noise = 0
        self._max_noise     = 0     # 从 mission 读取后初始化

    async def start(self):
        """启动 Orchestrator，读取配置后进入主循环"""
        mission = await self.state_api.get_mission()
        self._max_noise = mission.get("max_noise", 50)
        self._start_time = time.time()

        self._is_running = True
        logger.info("Orchestrator started")

        self._running_tasks = [
            asyncio.create_task(self._event_loop()),
            asyncio.create_task(self._think_loop()),
            asyncio.create_task(self._executor_loop())
        ]
        await asyncio.gather(*self._running_tasks)

    def stop(self):
        self._is_running = False
        if hasattr(self, '_running_tasks'):
            for task in self._running_tasks:
                task.cancel()

    def _force_stop(self, reason: str):
        """cleanup 硬超时后的强制退出"""
        if not self._is_running:
            return
        logger.error(
            f"Cleanup 超时 (120s)，原因: {reason}，强制停止 Orchestrator"
        )
        self.stop()

    # ── 主事件循环 ────────────────────────────────────────────

    async def _event_loop(self):
        """
        持续消费 EventBus，按优先级路由到对应处理器。
        同类普通事件在 100ms 窗口内合并。
        """
        pending_events: dict[EventType, Event] = {}
        last_flush = time.time()

        while self._is_running:
            event = await self.event_bus.get_next()

            if event is None:
                # 无事件，检查是否需要 flush 合并窗口
                if time.time() - last_flush >= self.EVENT_MERGE_WINDOW:
                    await self._flush_pending_events(pending_events)
                    pending_events.clear()
                    last_flush = time.time()
                await asyncio.sleep(0.05)
                continue

            if event.priority == EventPriority.CRITICAL:
                # CRITICAL 事件立即处理，不合并
                await self._dispatch_event(event)
            else:
                # 普通事件放入合并窗口
                pending_events[event.type] = event  # 同类覆盖 = 合并

            # 定期 flush
            if time.time() - last_flush >= self.EVENT_MERGE_WINDOW:
                await self._flush_pending_events(pending_events)
                pending_events.clear()
                last_flush = time.time()

    async def _flush_pending_events(self, pending: dict[EventType, Event]):
        for event in pending.values():
            await self._dispatch_event(event)

    async def _dispatch_event(self, event: Event):
        """路由事件到处理器"""
        handlers = {
            EventType.PAYLOAD_REJECTED:     self._handle_payload_rejected,
            EventType.TASK_COMPLETED:       self._handle_task_completed,
            EventType.ASSET_DISCOVERED:     self._handle_asset_discovered,
            EventType.OPPORTUNITY_FOUND:    self._handle_opportunity_found,
            EventType.EXPLOIT_SUCCESS:      self._handle_exploit_success,
            EventType.STALL_DETECTED:       self._handle_stall_detected,
            EventType.CLEANUP_STATE:        self._handle_cleanup_state,
            EventType.HUMAN_APPROVAL_REQ:   self._handle_human_approval,
            EventType.PAYLOAD_APPROVED:     self._handle_payload_approved,
            EventType.TARGET_UNREACHABLE:   self._handle_target_unreachable,
        }
        handler = handlers.get(event.type)
        if handler:
            await handler(event)
        else:
            logger.warning(f"未知事件类型: {event.type}")

    # ── Think 触发循环 ────────────────────────────────────────

    async def _think_loop(self):
        """
        定时检查是否需要触发 Planner Think。
        增加绝对上限保护：轮次上限 + 运行时间上限。
        """
        while self._is_running:
            # 绝对保护：轮次上限
            mission = await self.state_api.get_mission()
            max_rounds = mission.get("max_think_rounds", 200)
            if self._think_count >= max_rounds:
                logger.warning(
                    f"达到 Think 轮次上限 ({max_rounds})，强制进入清理阶段"
                )
                await self._force_cleanup("max_think_rounds_reached")
                return

            # 绝对保护：运行时间上限
            max_runtime = mission.get("max_runtime_seconds", 7200)
            elapsed = time.time() - self._start_time
            if elapsed >= max_runtime:
                logger.warning(
                    f"达到运行时间上限 ({max_runtime}s, 已运行 {elapsed:.0f}s)，"
                    f"强制进入清理阶段"
                )
                await self._force_cleanup("max_runtime_reached")
                return

            # 绝对保护：累计 stall 上限（不可被重置）
            max_stall = mission.get("max_stall_count", 10)
            if self._total_stall_count >= max_stall * 2:
                logger.warning(
                    f"累计 stall 达到绝对上限 ({self._total_stall_count}/{max_stall * 2})，"
                    f"强制进入清理阶段"
                )
                await self._force_cleanup("cumulative_stall_exhausted")
                return

            now = time.time()
            if now - self._last_think_time >= self.MIN_THINK_INTERVAL:
                is_paused = await self.state_api.is_paused()
                if not self._in_cleanup and not is_paused:
                    await self._trigger_think()
                    await self.check_cleanup_trigger()
                elif is_paused:
                    logger.debug("Orchestrator paused, skipping Think.")
            await asyncio.sleep(1.0)

    async def _force_cleanup(self, reason: str):
        """强制触发 CLEANUP_STATE 并停止 Orchestrator"""
        if self._in_cleanup:
            return
        # 立即标记为清理中，迅速打断后续可能的 _trigger_think (解决事件队列阻塞导致 120s 强制退出的 Bug)
        self._in_cleanup = True
        await self.event_bus.publish(Event(
            type=EventType.CLEANUP_STATE,
            priority=EventPriority.CRITICAL,
            source="orchestrator",
            payload={"reason": reason}
        ))
        # 问题 #11 修复：硬超时兜底，防止 cleanup 卡死导致进程永不退出
        # 放宽至 900s (15min)，留给 LLM 生成报告和人工审批 Cleanup 任务的时间
        asyncio.get_event_loop().call_later(900, self._force_stop, reason)

    async def _trigger_think(self, force: bool = False):
        """
        触发一次 Planner Think。
        force=True 时忽略间隔限制（CRITICAL 事件使用）。
        """
        now = time.time()
        interval = (self.CRITICAL_THINK_INTERVAL if force
                    else self.MIN_THINK_INTERVAL)

        if not force and now - self._last_think_time < interval:
            return

        if self._is_thinking:
            logger.debug("Orchestrator: Planner is busy, skipping trigger")
            return

        self._is_thinking = True
        self._last_think_time = now
        self._think_count += 1

        try:
            pruned_view = await self.pruner.generate_view(self.state_api)
            focus = pruned_view.get("focus", {})
            active_target = focus.get("active_target")
            if active_target and await self.state_api.is_unreachable(active_target):
                unreach_hint = (
                    f"❗ 极度紧急警告：当前焦点目标 {active_target} 经多次探测确认无法连通 (TARGET_UNREACHABLE)！"
                    "请立刻放弃对该目标的探索，并从范围内选择其他有效目标进行渗透测试，切勿在此目标上浪费任何资源。"
                )
                self._system_hint = f"{unreach_hint}\n\n{self._system_hint or ''}".strip()

            force_strong = self._force_strong_next_think
            self._force_strong_next_think = False

            # 问题 #5 修复：ABANDON_STRATEGY 硬编码策略转换
            # 当 >90% exploit 失败时，强制注入切换指令而非仅靠 LLM 文本建议
            vectors_summary = pruned_view.get("vectors_summary", {})
            if vectors_summary.get("recommendation") == "ABANDON_STRATEGY":
                abandon_hint = (
                    "⚠️ 强制策略转换：当前攻击向量 >90% 失败率，"
                    "vectors_summary.recommendation=ABANDON_STRATEGY。"
                    "你必须：1) 切换到完全不同的 VectorType/attack technique；"
                    "2) 或者切换 active_target 到 scope 内其他主机。"
                    "绝对禁止继续使用已失败的攻击手法。"
                )
                self._system_hint = f"{abandon_hint}\n\n{self._system_hint or ''}".strip()
                force_strong = True  # 关键决策时强制使用大模型
                logger.warning("ABANDON_STRATEGY 触发：注入强制策略转换提示")

            planner_output = await self.planner.think(
                pruned_view,
                system_hint=self._system_hint,
                force_strong=force_strong,
            )
            # 消费完 hint 后清除，避免污染后续正常 Think
            self._system_hint = None
            
            await self._dispatch_planner_output(planner_output)
            await self._print_progress()
            self._parse_failure_count = 0  # 成功则重置解析失败计数
        except Exception as e:
            self._parse_failure_count += 1
            logger.error(f"Planner Think 失败 (连续 {self._parse_failure_count} 次): {e}")
            if self._parse_failure_count >= 5:
                logger.error("LLM 解析连续失败达到 5 次，强制触发清理")
                await self._force_cleanup("llm_parse_failures_exhausted")
        finally:
            self._is_thinking = False

    async def _dispatch_planner_output(self, output: dict):
        """处理 Planner 的 Act 指令"""

        # RAG 查询优先处理
        if output.get("rag_query"):
            await self._handle_rag_query(output["rag_query"])
            # RAG 结果上黑板后，触发下一轮 Think
            await asyncio.sleep(0.5)
            asyncio.create_task(self._trigger_think(force=True))
            return

        # 异步任务挂起（非阻塞）
        async_task = output.get("async_task")
        if async_task and isinstance(async_task, dict):
            await self._submit_async_task(async_task)
        elif async_task and isinstance(async_task, str):
            # LLM 有时返回字符串而非 dict，尝试 JSON 解析
            try:
                parsed = json.loads(async_task)
                if isinstance(parsed, dict):
                    await self._submit_async_task(parsed)
                else:
                    logger.debug(f"Planner async_task 解析后不是 dict，忽略")
            except (json.JSONDecodeError, ValueError):
                logger.debug(f"Planner async_task 是无法解析的字符串，忽略: {async_task[:80]}")

        # 清理当前轮的 context_retrievals
        await self.state_api.clear_context_retrievals()

        # 将 Planner 的 focus_update 写回 State（Planner 无副作用，由此处代劳）
        # 同时消费掉 opportunity_flag，使其不再保持 True
        focus_update = output.get("focus_update") or {}
        if not isinstance(focus_update, dict):
             focus_update = {}
             
        # 提取核心评估指标
        ext_update = {
            "confidence": output.get("confidence", 0.5),
            "hypothesis": output.get("hypothesis", "")
        }
        
        # 合并基本信息 (排除 LLM 可能返回的 stall_count，且过滤掉 null 以防覆盖有效 IP)
        llm_focus = {k: v for k, v in focus_update.items() 
                     if k != "stall_count" and v is not None}
        
        # 原子获取旧状态以计算 stall_count
        current_focus = await self.state_api.get_focus()
        old_goal = current_focus.get("current_goal", "RECON")
        new_goal = llm_focus.get("current_goal", old_goal)
        active_target = llm_focus.get("active_target") or current_focus.get("active_target")

        # B1 修复：校验 LLM 返回的 active_target 是否在 scope 内
        if active_target and "active_target" in llm_focus:
            mission = await self.state_api.get_mission()
            scope = mission.get("scope_expanded", mission.get("scope", []))
            if scope and not self._is_target_in_scope(active_target, scope):
                logger.warning(f"Orchestrator: LLM 返回的 active_target={active_target} 越界，回退至当前目标")
                active_target = current_focus.get("active_target")
                llm_focus["active_target"] = active_target

        # 增加 EXPLOIT 强制覆盖：如果 stall 触发了 EXPLOIT 强制跳转，拦截 Planner 返回的 RECON
        was_overridden = False
        if getattr(self, "_force_exploit_override_rounds", 0) > 0:
            self._force_exploit_override_rounds -= 1
            if new_goal == "RECON":
                logger.warning(f"Orchestrator: 强行覆盖 Planner 的 RECON 决定，保持在 EXPLOIT 阶段 (剩余强制轮数: {self._force_exploit_override_rounds})")
                new_goal = "EXPLOIT"
                llm_focus["current_goal"] = "EXPLOIT"
                was_overridden = True

        # 增加 EXPLOIT 硬拦截：如果没有服务信息，禁止进入 EXPLOIT 阶段 (Issue 2)
        if new_goal == "EXPLOIT" and active_target:
            host_info = await self.state_api.get_host_full(active_target)
            services = host_info.get("services", []) if host_info else []
            
            # 优化：如果是由 stall 强制切换的（flag 标记），或者已有服务，则允许进入
            if not services:
                if self._force_exploit_override or was_overridden or getattr(self, "_force_exploit_override_rounds", 0) > 0:
                    # flag 放行：允许无服务也进入 EXPLOIT
                    self._force_exploit_override = False
                    logger.info(f"Orchestrator: 目标 {active_target} 无服务但由 stall 强制切换，放行 EXPLOIT")
                else:
                    logger.warning(f"Orchestrator: 目标 {active_target} 尚无服务信息且非强制切换，拦截 EXPLOIT 切换，回退至 RECON")
                    new_goal = "RECON"
                    llm_focus["current_goal"] = "RECON"
                    
                    # 注入系统提示，破除死锁 (Issue 4)
                    if self._host_timeouts.get(active_target, 0) >= 1:
                        self._system_hint = (
                            f"警告：目标 {active_target} 无开放服务且之前的侦察任务多次超时。 "
                            "请重新评估该目标的可达性，考虑使用更隐蔽的扫描手段或切换攻击目标，不要在原地空转。"
                        )

        # 增加 LATERAL 硬拦截：如果没有拿到任何机器权限，禁止进入 LATERAL 阶段
        if new_goal == "LATERAL":
            owned_count = await self.state_api.count_owned_hosts()
            if owned_count == 0:
                logger.warning(f"Orchestrator: 当前没有任何已控制的主机 (owned=0)，拦截 LATERAL 切换，回退至 EXPLOIT/RECON")
                # 如果有目标且有服务，回退到 EXPLOIT，否则 RECON
                if active_target:
                    host_info = await self.state_api.get_host_full(active_target)
                    services = host_info.get("services", []) if host_info else []
                    new_goal = "EXPLOIT" if services else "RECON"
                else:
                    new_goal = "RECON"
                llm_focus["current_goal"] = new_goal
                
                self._system_hint = (
                    "警告：你试图进入 LATERAL (横向移动) 阶段，但当前没有任何已获取权限的主机 (owned=0)。"
                    "横向移动必须在取得至少一台主机的控制权之后才能进行。请先继续对目标进行 RECON 或 EXPLOIT。"
                )

        updates = {**ext_update, **llm_focus}
        updates["opportunity_flag"] = False # 强制清理机会标志
        updates["opportunity_target"] = None
        
        # B2 修复：移除重复的 stall_count 递增
        # stall_count 的唯一递增点在 _apply_node_output 中，当 Agent 未生成有效任务时才递增
            
        await self.state_api.update_focus_atomic(updates)
        # 读取真实 stall 值用于日志（updates 中可能不含 stall_count）
        real_stall = updates.get('stall_count', current_focus.get('stall_count', 0))
        logger.info(
            f"Focus updated: goal={updates.get('current_goal')} "
            f"target={updates.get('active_target', current_focus.get('active_target'))} "
            f"conf={float(updates.get('confidence') or 0):.2f} "
            f"stall={real_stall}"
        )

        # 路由到对应 Agent
        act = output.get("act")
        if not act or not isinstance(act, dict):
            if act:
                logger.warning(f"Planner act 不是 dict，跳过: {type(act).__name__}")
            return

        agent_map = {
            AgentType.RECON:   self._invoke_recon,
            AgentType.EXPLOIT: self._invoke_exploit,
            AgentType.CRITIC:  self._invoke_critic,
            AgentType.CLEANUP: self._invoke_cleanup,
        }

        try:
            agent_type = AgentType(act.get("agent", "recon"))
        except ValueError:
            logger.error(f"Planner 输出非法 AgentType: {act.get('agent')}，安全降级至 RECON")
            agent_type = AgentType.RECON

        # 问题 #2 修复：Goal-Agent 一致性保护
        # 如果当前 goal 是 EXPLOIT，但 Planner 返回 agent=recon，强制纠正
        if agent_type == AgentType.RECON and new_goal == "EXPLOIT":
            logger.warning(
                f"Planner 在 EXPLOIT 阶段返回 recon，强制纠正为 exploit"
            )
            agent_type = AgentType.EXPLOIT

        handler = agent_map.get(agent_type)
        if handler:
            # 连续 RECON 轮次检测：无新主机时累积计数
            if agent_type == AgentType.RECON:
                current_hosts = await self.state_api.count_hosts()
                if current_hosts > self._last_known_hosts:
                    self._consecutive_recon_rounds = 0
                    self._last_known_hosts = current_hosts
                else:
                    self._consecutive_recon_rounds += 1

                RECON_ROUND_LIMIT = 10
                if self._consecutive_recon_rounds >= RECON_ROUND_LIMIT:
                    logger.warning(
                        f"连续 {self._consecutive_recon_rounds} 轮 RECON 无新主机发现，"
                        f"强制切换到 EXPLOIT"
                    )
                    self._consecutive_recon_rounds = 0
                    await self.state_api.update_focus_atomic({
                        "current_goal": "EXPLOIT",
                        "stall_count": 0,
                        "hypothesis": f"RECON 阶段连续 {RECON_ROUND_LIMIT} 轮无新发现，强制进入 EXPLOIT",
                    })
                    self._force_exploit_override = True
                    self._force_exploit_override_rounds = 2
                    self._force_strong_next_think = True
                    
                    self._system_hint = (
                        "重要：侦察阶段已连续多轮无进展，强制进入 EXPLOIT 阶段尝试突破。绝对禁止切换回 RECON 阶段！"
                        "请尽最大努力利用已知服务，如果确认无开放服务或无法利用，请直接请求放弃目标或切换目标 (ABANDON_STRATEGY)。"
                    )
                    asyncio.create_task(self._trigger_think(force=True))
                    return
            else:
                # 非 RECON 重置计数
                self._consecutive_recon_rounds = 0

            await handler(act, output)

    # ── 事件处理器 ────────────────────────────────────────────

    async def _handle_payload_approved(self, event: Event):
        """
        处理 Critic 审批通过的 Payload。
        此处仅打印日志，Executor 会通过轮询机制消费 PENDING_PAYLOADS。
        """
        payload_id = event.payload.get("payload_id")
        logger.info(f"Orchestrator: 收到 PAYLOAD_APPROVED 事件 (payload_id={payload_id})")

    async def _handle_payload_rejected(self, event: Event):
        """
        PAYLOAD_REJECTED 快速修正循环。
        绕过完整 Planner Think，直接触发 Exploit Agent 修正。
        """
        p = event.payload
        retry_count = p.get("retry_count", 0)

        # 读取 mission 配置的最大重试次数
        mission = await self.state_api.get_mission()
        max_retry = mission.get("max_payload_retry", 3)

        # B5a 修复：OUT_OF_SCOPE 是结构性问题，最多重试 1 次
        if p.get("reject_reason") == RejectReason.OUT_OF_SCOPE and retry_count >= 1:
            logger.info(f"Payload {p['payload_id']} 因 OUT_OF_SCOPE 超限 (max=1)，标记 ABANDONED")
            mutation = StateMutation(
                operation=MutationOperation.APPEND,
                domain=StateDomain.TRIED_VECTORS,
                payload={
                    "id":          p["payload_id"],
                    "result":      "ABANDONED",
                    "fail_reason": "OUT_OF_SCOPE_MAX_RETRY",
                    "retry_count": retry_count,
                }
            )
            await self.state_api.apply_mutation(mutation)
            asyncio.create_task(self._trigger_think(force=True))
            return

        if retry_count >= max_retry:
            # 超过重试上限，标记 ABANDONED，让 Planner 换策略
            logger.info(f"Payload {p['payload_id']} 超过重试上限，标记 ABANDONED")
            mutation = StateMutation(
                operation=MutationOperation.APPEND,
                domain=StateDomain.TRIED_VECTORS,
                payload={
                    "id":          p["payload_id"],
                    "result":      "ABANDONED",
                    "fail_reason": "MAX_RETRY",
                    "retry_count": retry_count,
                }
            )
            await self.state_api.apply_mutation(mutation)
            # 触发 Planner 感知，换 VectorType
            asyncio.create_task(self._trigger_think(force=True))
            return

        if p.get("reject_reason") == RejectReason.REQUIRES_APPROVAL:
            # 需要人工审批，不走快速循环
            await self._request_human_approval(p)
            return

        # 直接触发 Exploit Agent 快速修正（绕过 Planner）
        logger.info(f"触发 Payload 快速修正，原因: {p['reject_reason']}")
        await self._invoke_exploit_fixup(
            payload_id=p["payload_id"],
            reject_reason=p["reject_reason"],
            original_payload=p["original_payload"],
            retry_count=retry_count + 1,
        )

    async def _handle_task_completed(self, event: Event):
        """异步任务完成，标记已处理，触发 Planner 重评估"""
        task_id = event.payload.get("task_id")
        result = event.payload.get("result", {})
        tool = result.get("tool", "?")
        target = result.get("target", "?")
        assets_found = result.get("assets_found", 0)
        duration = result.get("duration_ms", 0)
        raw_summary = str(result.get("raw_summary", ""))
        if len(raw_summary) > 100:
            raw_summary = raw_summary[:100] + "... [TRUNCATED]"
            
        logger.info(
            f"[DONE] Tool: {tool} | Target: {target} | "
            f"Assets: {assets_found} | {duration}ms | {raw_summary}"
        )

        # 标记任务已处理
        mutation = StateMutation(
            operation=MutationOperation.UPDATE_STATUS,
            domain=StateDomain.ASYNC_TASKS,
            payload={"id": task_id, "status": "DONE", "processed": True}
        )
        await self.state_api.apply_mutation(mutation)
        
        # ── 超时与失败追踪 ──
        # 注意：TARGET_UNREACHABLE 事件由 Executor 侧 _host_timeouts 统一触发，
        # Orchestrator 不再重复追踪，避免双重计数。
        status = result.get("status", "DONE")
        if status not in ("TIMEOUT", "FAILED"):
            # 任务成功完成，重置该目标的超时计数
            self._host_timeouts[target] = 0
            # 仅在发现新资产时重置 stall，避免无意义任务抹除 stall 信号
            if assets_found > 0:
                await self.state_api.update_focus_atomic({"stall_count": 0})
        else:
            # 问题 #4 修复：exploit payload 执行 FAIL/TIMEOUT 也递增 stall
            # 防止 exploit 连续失败但 stall 不动的无效循环
            is_exploit = result.get("is_exploit", False) or tool in (
                "exploit", "payload", "web_shell", "sqli", "rce"
            )
            if is_exploit:
                current_focus = await self.state_api.get_focus()
                new_stall = int(current_focus.get("stall_count", 0)) + 1
                self._total_stall_count += 1
                await self.state_api.update_focus_atomic({"stall_count": new_stall})
                logger.warning(
                    f"Exploit payload FAIL/TIMEOUT (tool={tool}), stall 递增至 {new_stall}"
                )

        if target and target != "?" and tool and tool != "?":
            params_str = json.dumps(result.get("params", {}), sort_keys=True)
            import hashlib
            cmd_hash = hashlib.md5(f"{tool}:{target}:{params_str}".encode()).hexdigest()[:12]
            dedup_key = f"sent_recon:{cmd_hash}"
            if status in ("TIMEOUT", "FAILED"):
                logger.debug(f"Recon: 任务超时/失败，主动删除冷却锁 {dedup_key}")
                await self.state_api.redis.delete(dedup_key)
            else:
                logger.debug(f"Recon: 任务成功完成，续期冷却锁 {dedup_key} (1800s)")
                await self.state_api.redis.setex(dedup_key, 1800, "1")

        # 启发式决策：Web 探测返回 403 Forbidden 时，自动追加 Bypass 侦察
        status_code = str(result.get("status", ""))
        if tool in ("screenshot", "http_probe", "banner_grab") and "403" in status_code:
            logger.info(f"Orchestrator: 检测到 {target} 403 Forbidden，自动注入 Bypass 侦察")
            await self._inject_bypass_task(target)

        # 新资产进来，触发 Planner 重算优先级队列
        asyncio.create_task(self._trigger_think(force=True))

    async def _handle_asset_discovered(self, event: Event):
        """发现新资产，可能触发 opportunity_flag"""
        target = event.payload.get("target")
        logger.info(f"新资产发现: {target}")

        # 重置 stall_count 并查横向移动路径
        await self.state_api.update_focus_atomic({"stall_count": 0})

        if target:
            paths = await self.state_api.find_lateral_paths(target)
            if paths:
                opp_event = Event.opportunity_found(
                    target=paths[0]["target"],
                    reason=f"距已控主机 {paths[0]['hops']} 跳，无需额外漏洞"
                )
                await self.event_bus.publish(opp_event)

    async def _handle_opportunity_found(self, event: Event):
        """机会主义跳转：立即更新 focus，强制 Think"""
        p = event.payload
        focus = await self.state_api.get_focus()
        focus["opportunity_flag"]  = True
        focus["opportunity_target"] = p["target"]
        focus["opportunity_reason"] = p["reason"]

        mutation = StateMutation(
            operation=MutationOperation.WRITE,
            domain=StateDomain.FOCUS,
            payload=focus
        )
        await self.state_api.apply_mutation(mutation)
        asyncio.create_task(self._trigger_think(force=True))

    async def _handle_exploit_success(self, event: Event):
        """利用成功：更新 assets 中的 access_level"""
        p = event.payload
        logger.info(f"利用成功: {p['target']} -> {p['access_level']}")

        mutation = StateMutation(
            operation=MutationOperation.UPSERT,
            domain=StateDomain.ASSETS,
            payload={"ip": p["target"], "access_level": p["access_level"]}
        )
        await self.state_api.apply_mutation(mutation)

        # 重置 stall_count
        await self.state_api.update_focus_atomic({"stall_count": 0})

        asyncio.create_task(self._trigger_think(force=True))

    async def _handle_stall_detected(self, event: Event):
        """陷入僵局：通知 Planner，可能需要人工介入"""
        logger.warning(f"检测到僵局: {event.payload}")
        mission = await self.state_api.get_mission()
        risk_threshold = mission.get("human_approve_threshold", 4)

        focus = await self.state_api.get_focus()
        if focus.get("stall_count", 0) >= risk_threshold:
            await self._request_human_approval({
                "type":   "STALL",
                "reason": "Agent 多次无进展，需要人工研判方向",
                "focus":  focus,
            })
        else:
            asyncio.create_task(self._trigger_think(force=True))

    async def _handle_cleanup_state(self, event: Event):
        """进入清理阶段"""
        if getattr(self, "_cleanup_handled", False):
            return  # 防止重复触发
        self._cleanup_handled = True
        self._in_cleanup = True
        logger.info("进入 CLEANUP_STATE，暂停所有 Exploit 调度")

        # 将长耗时的报告生成和清理流程放入后台任务，防止阻塞事件循环
        asyncio.create_task(self._run_cleanup_sequence())

    async def _run_cleanup_sequence(self):
        """执行实际的清理序列并等待完成"""
        # 1. 先生成报告（不依赖 cleanup agent 成功返回）
        if self.report_generator:
            try:
                mission = await self.state_api.get_mission()
                report = await self.report_generator.generate(
                    self.state_api, mission
                )
                logger.info(
                    f"Final report generated: {report.get('report_file', 'N/A')}"
                )
            except Exception as e:
                logger.error(f"Report generation failed: {e}")

        # 2. 执行 cleanup agent 生成清理任务
        logger.info("开始生成清理任务...")
        await self._invoke_cleanup({}, {})

        # 3. 等待所有清理任务执行完毕
        logger.info("等待清理任务执行完毕...")
        wait_start = time.time()
        while self._is_running:
            try:
                tasks = await self.state_api.get_pending_cleanup_tasks()
                # 检查是否还有未决的清理任务
                active_tasks = [
                    t for t in tasks 
                    if t.get("status") in ("PENDING", "PENDING_HUMAN", "APPROVED", "EXECUTING")
                ]
                
                if not active_tasks and self._active_executor_tasks == 0:
                    logger.info("所有清理任务执行完毕，准备退出。")
                    break
                    
                # 兜底超时: 10分钟
                if time.time() - wait_start > 600:
                    logger.error("等待清理任务完成超时 (600s)，强制退出。")
                    break
            except Exception as e:
                logger.error(f"检查清理任务状态时出错: {e}")
                
            await asyncio.sleep(2.0)

        self.stop()

    async def _handle_human_approval(self, event: Event):
        """
        HUMAN_APPROVAL_REQ 处理器。
        两种上下文：
          context="cleanup"         → Cleanup Agent 发出，等待人工批准 pending_cleanup_tasks
          context="cleanup_failure" → Executor 发出，清理步骤失败需人工介入
          context="payload"         → Critic 发出 REQUIRES_APPROVAL，等待人工批准 payload

        机制：
          - 将请求写入 Redis 的 "approval_requests" 列表（FastAPI 端点轮询此列表）
          - Orchestrator 本身不阻塞：人工通过 POST /payloads/{id}/approve
            或 POST /cleanup/approve 写回 APPROVED 状态后，Executor loop 自动消费
        """
        ctx     = event.payload.get("context", "unknown")
        message = event.payload.get("message", "Human approval required")

        logger.warning(f"[HUMAN APPROVAL REQUIRED] context={ctx}: {message}")

        # 将审批请求持久化到 Redis，供 API/运营人员查询
        import json
        from datetime import datetime, timezone
        request_record = {
            "id":         event.id,
            "context":    ctx,
            "message":    message,
            "payload":    event.payload,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status":     "PENDING",
        }
        await self.state_api.redis.lpush(
            "approval_requests",
            json.dumps(request_record),
        )
        # 保留最近 100 条，防止列表无限增长
        await self.state_api.redis.ltrim("approval_requests", 0, 99)

        # 对于 cleanup_failure：暂停剩余清理任务，避免雪崩
        if ctx == "cleanup_failure":
            logger.warning(
                "Cleanup failure detected — pausing further cleanup execution. "
                "Resolve via GET /cleanup/tasks and POST /cleanup/approve."
            )

    async def _handle_target_unreachable(self, event: Event):
        """处理目标不可达事件，记入黑板并清理 dedup 锁，检测全 scope 不可达"""
        target = event.payload.get("target")
        if not target:
            return
        logger.error(f"Orchestrator: 处理不可达事件，目标 {target} 记录至黑板")
        await self.state_api.add_unreachable_target(target)

        # 同时标记关联的域名/IP为不可达（IP 和域名是同一目标的不同表示）
        focus = await self.state_api.get_focus()
        active_target = focus.get("active_target", "")
        if active_target and active_target != target:
            # 如果 active_target 是域名而 target 是 IP，反向关联
            try:
                import socket
                resolved_ips = {r[4][0] for r in socket.getaddrinfo(active_target, None, socket.AF_INET)}
                if target in resolved_ips:
                    logger.warning(f"Orchestrator: 域名 {active_target} 解析到不可达 IP {target}，同时标记域名不可达")
                    await self.state_api.add_unreachable_target(active_target)
            except (socket.gaierror, OSError):
                pass  # DNS 解析失败，不关联

        # 同时检查 scope 中的域名是否解析到该 IP
        mission = await self.state_api.get_mission()
        scope = mission.get("scope_expanded", mission.get("scope", []))
        for scope_target in scope:
            if scope_target != target and not await self.state_api.is_unreachable(scope_target):
                try:
                    import socket
                    resolved = {r[4][0] for r in socket.getaddrinfo(scope_target, None, socket.AF_INET)}
                    if target in resolved:
                        logger.warning(f"Orchestrator: scope 域名 {scope_target} 解析到不可达 IP {target}，标记域名不可达")
                        await self.state_api.add_unreachable_target(scope_target)
                except (socket.gaierror, OSError):
                    pass

        # A3 修复：清理该目标相关的 recon dedup 锁，防止锁残留阻塞后续任务
        cursor = b"0"
        cleaned = 0
        while True:
            cursor, keys = await self.state_api.redis.scan(
                cursor=cursor, match="sent_recon:*", count=100
            )
            if keys:
                await self.state_api.redis.delete(*keys)
                cleaned += len(keys)
            if cursor == 0 or cursor == b"0":
                break
        if cleaned:
            logger.info(f"Orchestrator: 已清理 {cleaned} 个 recon dedup 锁")

        # 检测是否所有 scope 目标都不可达 → 强制切换 EXPLOIT 或终止
        mission = await self.state_api.get_mission()
        scope = mission.get("scope_expanded", mission.get("scope", []))
        unreachable = await self.state_api.get_unreachable_targets()
        all_unreachable = scope and all(
            t in unreachable for t in scope
        )
        if all_unreachable:
            # 检查是否已有可利用的服务信息
            owned = await self.state_api.count_owned_hosts()
            focus = await self.state_api.get_focus()
            active_target = focus.get("active_target", "")
            host_info = await self.state_api.get_host_full(active_target) if active_target else None
            services = host_info.get("services", []) if host_info else []

            if services:
                logger.warning(
                    f"Orchestrator: 所有 scope 目标均不可达，但 {active_target} 已有 {len(services)} 个服务信息，强制切换到 EXPLOIT"
                )
                await self.state_api.update_focus_atomic({
                    "current_goal": "EXPLOIT",
                    "stall_count": 0,
                })
                self._system_hint = (
                    f"重要：所有目标的侦察扫描均已超时，但我们已发现 {active_target} 上的 {len(services)} 个服务。"
                    "请立即基于已有服务信息生成利用方案，不要再请求侦察任务。"
                )
            else:
                logger.error(
                    "Orchestrator: 所有 scope 目标均不可达且无服务信息，强制进入清理阶段"
                )
                await self._force_cleanup("all_targets_unreachable")

    # ── Agent 调用方法 ────────────────────────────────────────

    async def _invoke_recon(self, act: dict, planner_output: dict):
        from .protocols import NodeInput
        pruned = await self.pruner.generate_view(self.state_api)
        focus = pruned.get("focus", {})
        active_target = focus.get("active_target")
        if active_target and await self.state_api.is_unreachable(active_target):
            logger.warning(f"Recon: 目标 {active_target} 已被标记为不可达，拒绝下发探测任务")
            # 累积 stall，避免死锁
            current_focus = await self.state_api.get_focus()
            new_stall = int(current_focus.get("stall_count", 0)) + 1
            self._total_stall_count += 1
            await self.state_api.update_focus_atomic({"stall_count": new_stall})
            logger.warning(f"Recon 不可达空转，stall={new_stall}")
            return

        # 检查是否已有足够的 pending recon 任务
        pending_recon_list = pruned.get("pending_recon_list", [])
        pending_count = len([t for t in pending_recon_list if t.get("status") in ("PENDING", "RUNNING")])
        if pending_count >= 3:
            logger.debug(f"Recon: 已有 {pending_count} 个 pending/recon 任务，跳过本轮")
            return

        node_input = NodeInput(
            state_view=pruned,
            trigger_event=Event(
                type=EventType.TASK_COMPLETED,
                payload=act, source="orchestrator"
            ),
            agent_id=f"recon_{time.time()}"
        )
        result = await self.recon_agent.run(node_input)
        await self._apply_node_output(result)

    async def _invoke_exploit(self, act: dict, planner_output: dict):
        from .protocols import NodeInput
        pruned = await self.pruner.generate_view(self.state_api)
        focus = pruned.get("focus", {})
        active_target = focus.get("active_target")
        if active_target:
            is_unreachable = await self.state_api.is_unreachable(active_target)
            host_info = await self.state_api.get_host_full(active_target)
            services = host_info.get("services", []) if host_info else []
            
            if is_unreachable or not services:
                reason = "已被标记为不可达" if is_unreachable else "无任何已知服务"
                logger.warning(f"Exploit: 目标 {active_target} {reason}，拒绝生成利用 payload")
                # 累积 stall，避免死锁
                current_focus = await self.state_api.get_focus()
                new_stall = int(current_focus.get("stall_count", 0)) + 1
                self._total_stall_count += 1
                await self.state_api.update_focus_atomic({"stall_count": new_stall})
                return

        node_input = NodeInput(
            state_view=pruned,
            trigger_event=Event(
                type=EventType.TASK_COMPLETED,
                payload=act, source="orchestrator"
            ),
            agent_id=f"exploit_{time.time()}"
        )
        result = await self.exploit_agent.run(node_input)
        await self._apply_node_output(result)

    async def _invoke_exploit_fixup(self, payload_id: str,
                                     reject_reason: str,
                                     original_payload: str,
                                     retry_count: int):
        """快速修正模式：直接注入 reject_reason，绕过 Planner"""
        from .protocols import NodeInput
        # B5a 修复：fixup 模式下也需要 active_target 和 mission 信息
        focus = await self.state_api.get_focus()
        mission = await self.state_api.get_mission()
        fixup_view = {
            "_fixup_mode": True,
            "active_target": focus.get("active_target", ""),
            "mission": mission,
        }
        node_input = NodeInput(
            state_view=fixup_view,
            trigger_event=Event(
                type=EventType.PAYLOAD_REJECTED,
                priority=EventPriority.CRITICAL,
                source="orchestrator",
                payload={
                    "payload_id":       payload_id,
                    "reject_reason":    reject_reason,
                    "original_payload": original_payload,
                    "retry_count":      retry_count,
                }
            ),
            agent_id=f"exploit_fixup_{time.time()}"
        )
        result = await self.exploit_agent.run(node_input)
        await self._apply_node_output(result)

    async def _invoke_critic(self, act: dict, planner_output: dict):
        """通常由 EventBus 监听 pending_payloads 自动触发，这里是手动调用入口"""
        pending = await self.state_api.get_pending_payloads()
        mission = await self.state_api.get_mission()
        for payload in pending:
            from .protocols import NodeInput
            node_input = NodeInput(
                state_view={"payload": payload, "mission": mission},
                trigger_event=Event(
                    type=EventType.TASK_COMPLETED,
                    payload={"payload_id": payload["id"]},
                    source="orchestrator"
                ),
                agent_id=f"critic_{time.time()}"
            )
            result = await self.critic_agent.run(node_input)
            await self._apply_node_output(result)

    async def _invoke_cleanup(self, act: dict, planner_output: dict):
        """清理阶段，需要 Human 审批"""
        from .protocols import NodeInput
        footprints = await self.state_api.get_all_footprints()
        node_input = NodeInput(
            state_view={"footprints": footprints, "_cleanup_mode": True},
            trigger_event=Event(
                type=EventType.CLEANUP_STATE,
                payload={}, source="orchestrator"
            ),
            agent_id=f"cleanup_{time.time()}"
        )
        result = await self.cleanup_agent.run(node_input)

        # Cleanup 的 mutations 需要人工确认后才执行
        await self._request_human_approval({
            "type":      "CLEANUP_EXECUTION",
            "mutations": [m.__dict__ for m in result.mutations],
            "think_log": result.think_log,
        })

        # 报告已在 _handle_cleanup_state 中提前生成，此处不再重复

    # ── RAG 查询 ──────────────────────────────────────────────

    async def _handle_rag_query(self, query: str):
        """执行 RAG 查询，结果写入 context_retrievals"""
        results = await self.rag.query(query, top_k=5)
        # RetrievalResult 是 dataclass，转为 dict 供 JSON 序列化
        from dataclasses import asdict
        items = []
        for r in results:
            try:
                items.append(asdict(r))
            except Exception:
                items.append({
                    "content": getattr(r, "content", str(r)),
                    "source": getattr(r, "source", "unknown"),
                    "relevance": getattr(r, "relevance", 0.0),
                    "metadata": getattr(r, "metadata", {}),
                })
        mutation = StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.CONTEXT_RETRIEVALS,
            payload={"items": items}
        )
        await self.state_api.apply_mutation(mutation)

    # ── Executor 循环 ─────────────────────────────────────────

    async def _executor_loop(self):
        """持续监听 APPROVED payload + PENDING recon tasks，配额内分配给 Executor"""
        running_payloads: set[str] = set()
        running_recon: set[str] = set()

        while self._is_running:
            # ── exploit payload ────────────────────────────
            approved = await self.state_api.get_approved_payloads()
            for payload in approved:
                pid = payload.get("id", "")
                if pid in running_payloads:
                    continue
                noise_cost = payload.get("noise_cost", 1)
                if self._current_noise + noise_cost <= self._max_noise:
                    self._current_noise += noise_cost
                    running_payloads.add(pid)
                    asyncio.create_task(
                        self._execute_payload(payload, noise_cost, running_payloads)
                    )

            # ── recon tasks ────────────────────────────────
            recon_tasks = await self.state_api.get_pending_recon_tasks()
            for task in recon_tasks:
                task_id = task.get("id", "")
                if task_id in running_recon:
                    continue   # 已经在执行了，跳过
                noise_cost = task.get("noise_cost", 1)
                if self._current_noise + noise_cost <= self._max_noise:
                    self._current_noise += noise_cost
                    running_recon.add(task_id)
                    asyncio.create_task(
                        self._execute_recon_task(task, noise_cost, running_recon)
                    )

            # ── approved cleanup tasks (post-human-approval) ──
            if self._in_cleanup:
                cleanup_tasks = await self.state_api.get_approved_cleanup_tasks()
                for task in cleanup_tasks:
                    noise_cost = task.get("noise_cost", 1)
                    if self._current_noise + noise_cost <= self._max_noise:
                        self._current_noise += noise_cost
                        asyncio.create_task(
                            self._execute_cleanup_task(task, noise_cost)
                        )

            await asyncio.sleep(0.5)

    async def _execute_payload(self, payload: dict, noise_cost: int,
                                running_set: set):
        pid = payload.get("id", "")
        self._active_executor_tasks += 1
        try:
            await self.executor.execute(payload)
        except Exception as e:
            logger.error(f"Executor payload {pid} 失败: {e}", exc_info=True)
        finally:
            self._active_executor_tasks -= 1
            self._current_noise -= noise_cost
            running_set.discard(pid)

    async def _execute_recon_task(self, task: dict, noise_cost: int,
                                   running_set: set):
        task_id = task.get("id", "")
        self._active_executor_tasks += 1
        try:
            await self.executor.execute_recon(task)
        except Exception as e:
            logger.error(f"Executor recon task {task_id} 失败: {e}", exc_info=True)
        finally:
            self._active_executor_tasks -= 1
            self._current_noise -= noise_cost
            running_set.discard(task_id)

    async def _execute_cleanup_task(self, task: dict, noise_cost: int):
        try:
            await self.executor.execute_cleanup(task)
        except Exception as e:
            logger.error(f"Executor cleanup task 失败: {e}", exc_info=True)
        finally:
            self._current_noise -= noise_cost

    # ── 进度统计 ──────────────────────────────────────────────

    async def _print_progress(self):
        """每轮 Think 后打印进度摘要（多维度进度条）"""
        try:
            total_hosts = await self.state_api.count_hosts()
            owned_hosts = await self.state_api.count_owned_hosts()
            pending_recon = len(await self.state_api.get_pending_recon_tasks())
            pending_payloads = await self.state_api.count_pending_payloads()
            vectors = await self.state_api.get_vectors_summary()
            focus = await self.state_api.get_focus()
            recon_keys = len(self._recon_sent_keys)

            total_vec = vectors.get("total", 0)
            success_vec = vectors.get("success_count", 0)

            # ── 计算多维度进度百分比 ──
            # 维度 1: 资产发现（已发现主机 / scope 预估主机数）权重 30%
            mission = await self.state_api.get_mission()
            scope = mission.get("scope", [])
            scope_size = 0
            import ipaddress
            for cidr in scope:
                try:
                    scope_size += ipaddress.ip_network(cidr, strict=False).num_addresses
                except ValueError:
                    scope_size += 1
            scope_size = max(scope_size - 2, 1)  # 减去网络地址和广播地址
            discovery_pct = min(total_hosts / scope_size, 1.0)

            # 维度 2: 侦察深度（已完成的侦察任务 / 已派出的任务）权重 40%
            total_tasks = max(recon_keys, 1)
            done_tasks = max(total_tasks - pending_recon, 0)
            recon_pct = done_tasks / total_tasks

            # 维度 3: 利用成功率（已攻破主机 / 发现主机）权重 30%
            exploit_pct = (owned_hosts / max(total_hosts, 1))

            # 加权总进度
            overall = discovery_pct * 0.3 + recon_pct * 0.4 + exploit_pct * 0.3
            bar_len = 20
            filled = int(overall * bar_len)
            bar = f"[#00d4aa]{'█' * filled}[/][#21262d]{'█' * (bar_len - filled)}[/]"

            # 阶段标签
            goal = focus.get("current_goal", "RECON") if isinstance(focus, dict) else "RECON"
            stall = focus.get("stall_count", 0) if isinstance(focus, dict) else 0
            max_stall = mission.get("max_stall_count", 10)
            conf = float(focus.get("confidence") or 0) if isinstance(focus, dict) else 0
            target = focus.get("active_target", "?") if isinstance(focus, dict) else "?"

            logger.info(
                f"[#555555][PROGRESS #{self._think_count}][/] "
                f"[#00d4aa]{overall*100:.0f}%[/] [#1f6feb]│[/]{bar}[#1f6feb]│[/] "
                f"[#6b8cba][{goal}][/] "
                f"hosts=[#c9d1d9]{total_hosts}/{scope_size}[/] owned=[#ff5f5f]{owned_hosts}[/] "
                f"tasks=[#c9d1d9]{done_tasks}/{total_tasks}[/] pending=[#c9d1d9]{pending_recon}[/] "
                f"vectors=[#c9d1d9]{total_vec}[/](ok=[#3fb950]{success_vec}[/]) "
                f"stall=[#00d4aa]{stall}/{max_stall}[/] "
                f"target=[#00d4aa]{target}[/] conf=[#00d4aa]{conf:.2f}[/]"
            )
        except Exception as e:
            logger.debug(f"Progress print failed: {e}")

    # ── 辅助方法 ──────────────────────────────────────────────

    async def _apply_node_output(self, output):
        """统一提交 Agent 的 mutations 和 events，拦截知识查询请求"""
        applied_count = 0
        knowledge_queries = [
            m for m in output.mutations
            if m.domain == StateDomain.KNOWLEDGE_QUERY
        ]
        seen_dedup_keys = set()

        for mutation in output.mutations:
            if mutation.domain == StateDomain.KNOWLEDGE_QUERY:
                continue

            # 侦察任务去重：使用 Redis 维护 30 分钟去重锁
            # 引入参数哈希进行精细去重 (Issue 3)
            if mutation.domain in (StateDomain.PENDING_RECON, StateDomain.ASYNC_TASKS):
                payload = mutation.payload
                target = payload.get("target", "")
                tool = payload.get("tool", "")
                if target and tool:
                    params_str = json.dumps(payload.get("params", {}), sort_keys=True)
                    import hashlib
                    # port_scan/nmap: 按 tool:target 去重（忽略 params 差异）
                    # 防止 LLM 用不同参数（top-1000 vs -p 1-1024 等）绕过去重
                    _TARGET_LEVEL_DEDUP_TOOLS = {"port_scan", "nmap", "port_scan_full"}
                    if tool in _TARGET_LEVEL_DEDUP_TOOLS:
                        cmd_hash = hashlib.md5(f"{tool}:{target}".encode()).hexdigest()[:12]
                    else:
                        cmd_hash = hashlib.md5(f"{tool}:{target}:{params_str}".encode()).hexdigest()[:12]
                    dedup_key = f"sent_recon:{cmd_hash}"
                    
                    if dedup_key in seen_dedup_keys:
                        logger.debug(f"Recon: {dedup_key} 批次内重复，跳过")
                        continue
                    
                    if await self.state_api.redis.exists(dedup_key):
                        logger.debug(f"Recon: {dedup_key} 处于冷却期，跳过重复下发")
                        continue
                    
                    seen_dedup_keys.add(dedup_key)
                    await self.state_api.redis.setex(dedup_key, 600, "1")

            await self.state_api.apply_mutation(mutation)
            applied_count += 1
            
            # 自动触发 Critic 审查 (Issue 7)
            if mutation.domain == StateDomain.PENDING_PAYLOADS:
                logger.info("检测到新 Payload 写入，自动触发 Critic 审查")
                asyncio.create_task(self._invoke_critic({}, {}))

        for event in output.events:
            await self.event_bus.publish(event)

        if knowledge_queries:
            await self._handle_knowledge_queries(knowledge_queries)
            asyncio.create_task(self._trigger_think(force=True))
            
        # 如果 Agent 这一轮没有产生任何实际状态改变（比如任务全被过滤了）
        # 且当前没有任何异步 Executor 任务在运行，才标记为真正的 STALL
        if applied_count == 0 and not knowledge_queries:
            current_focus = await self.state_api.get_focus()
            if isinstance(current_focus, dict):
                if self._active_executor_tasks == 0:
                    new_stall_count = int(current_focus.get("stall_count", 0)) + 1
                    self._total_stall_count += 1
                    # 修复：使用原子更新避免 race condition
                    await self.state_api.update_focus_atomic({"stall_count": new_stall_count})
                    stall_val = new_stall_count
                    logger.warning(f"检测到系统推进停滞 (无有效新任务或全部被去重)，增加 stall={stall_val}")
                    
                    # stall 达到 2 时，标记下次 Think 强制走大模型
                    if stall_val >= 2 and not self._force_strong_next_think:
                        self._force_strong_next_think = True
                        logger.info("🔼 连续空转 ≥2，标记下次 Planner Think 强制使用大模型")
                else:
                    logger.debug(f"Agent 未生成新任务，但当前有 {self._active_executor_tasks} 个任务正在执行，不增加 stall")

    async def _handle_knowledge_queries(self, mutations: list):
        """拦截 Agent 的知识查询请求，调用 RAG Engine"""
        for m in mutations:
            q = m.payload
            logger.info(
                f"Agent {q.get('source_agent')} 请求知识查询: "
                f"type={q.get('type')} query={q.get('query')[:80]}"
            )
            results = await self.rag.query(
                q["query"],
                type_filter=q.get("type"),
                top_k=3,
            )
            state_items = self.rag.results_to_state(results)
            if state_items:
                # 标记为 Agent 主动请求（StatePruner 优先处理）
                for item in state_items:
                    item["requested_by_agent"] = True
                await self.state_api.apply_mutation(StateMutation(
                    operation=MutationOperation.APPEND,
                    domain=StateDomain.CONTEXT_RETRIEVALS,
                    payload={"items": state_items},
                ))

    async def _submit_async_task(self, task: dict):
        """提交长耗时任务到 async_tasks 队列"""
        mutation = StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.ASYNC_TASKS,
            payload={**task, "status": TaskStatus.PENDING}
        )
        await self.state_api.apply_mutation(mutation)

    async def _request_human_approval(self, context: dict):
        """请求人工审批，挂起相关流程"""
        event = Event(
            type=EventType.HUMAN_APPROVAL_REQ,
            priority=EventPriority.CRITICAL,
            source="orchestrator",
            payload=context
        )
        await self.event_bus.publish(event)
        logger.info(f"人工审批请求已发出: {context.get('type')}")

    # ── CLEANUP_STATE 判定 ────────────────────────────────────

    async def check_cleanup_trigger(self):
        """
        由外部定时调用，检查是否应进入清理阶段。
        四种触发条件任一满足即触发。
        """
        import time
        mission = await self.state_api.get_mission()
        focus   = await self.state_api.get_focus()

        # 条件1: deadline
        deadline = mission.get("deadline")
        if deadline and time.time() > deadline:
            await self.event_bus.publish(Event(
                type=EventType.CLEANUP_STATE,
                priority=EventPriority.CRITICAL,
                source="orchestrator",
                payload={"reason": "deadline_reached"}
            ))
            return

        # 条件2: 目标达成
        if focus.get("current_goal") == "REPORT":
            await self.event_bus.publish(Event(
                type=EventType.CLEANUP_STATE,
                priority=EventPriority.CRITICAL,
                source="orchestrator",
                payload={"reason": "goal_achieved"}
            ))
            return

        # 条件3: stall 累积 → 强制阶段转换（RECON → EXPLOIT）
        stall_count = focus.get("stall_count", 0)
        max_stall   = mission.get("max_stall_count", 10)
        current_goal = focus.get("current_goal", "RECON")

        # stall >= 4 且仍在 RECON：强制切换到 EXPLOIT 尝试突破
        FORCE_EXPLOIT_THRESHOLD = 4
        if (stall_count >= FORCE_EXPLOIT_THRESHOLD
                and current_goal in ("RECON", "recon", "SCAN")
                and focus.get("active_target")):
            target = focus["active_target"]
            # 如果 active_target 已不可达，强制切 EXPLOIT 无意义，跳过让 stall 继续累加触发清理
            if await self.state_api.is_unreachable(target):
                logger.warning(
                    f"空转 {stall_count} 次，但目标 {target} 已标记为不可达，"
                    f"跳过 EXPLOIT 强制切换（等待 stall 耗尽触发清理）"
                )
            else:
                logger.warning(
                    f"空转 {stall_count} 次且仍在 {current_goal}，"
                    f"强制切换到 EXPLOIT 阶段（目标: {target}）"
                )
                # 设置 flag，让 _dispatch_planner_output 的 EXPLOIT 拦截逻辑放行
                self._force_exploit_override = True
                self._force_exploit_override_rounds = 2
                self._force_strong_next_think = True
                self._system_hint = (
                    "强制阶段切换警告：侦察阶段已达到空转上限，未发现任何新资产。"
                    "现在强制进入 EXPLOIT 阶段。绝对禁止切换回 RECON 阶段！"
                    "请尽最大努力利用已知服务，如果确认无法利用，请直接请求放弃目标或切换目标 (ABANDON_STRATEGY)。"
                )

                await self.state_api.update_focus_atomic({
                    "current_goal": "EXPLOIT",
                    "hypothesis": f"RECON 阶段空转 {stall_count} 次后强制进入 EXPLOIT，尝试利用"
                })
                
                asyncio.create_task(self._trigger_think(force=True))
                return

        # 条件4: stall 耗尽 → 清理退出
        if stall_count >= max_stall:
            await self.event_bus.publish(Event(
                type=EventType.CLEANUP_STATE,
                priority=EventPriority.CRITICAL,
                source="orchestrator",
                payload={"reason": "stall_exhausted"}
            ))
            return

    async def _inject_bypass_task(self, target: str):
        """自动注入 403 绕过任务"""
        mutation = StateMutation(
            operation=MutationOperation.WRITE,
            domain=StateDomain.PENDING_RECON,
            payload={
                "id":         str(uuid.uuid4()),
                "target":     target,
                "tool":       "dir_enum",
                "params":     {"profile": "bypass", "wordlist": "common_bypass.txt"},
                "priority":   0.9,
                "noise_cost": 3,
                "is_async":   True,
                "rationale":  "自动探测: 检测到 403 Forbidden，尝试目录爆破寻找绕过路径",
                "status":     TaskStatus.PENDING,
            }
        )
        await self.state_api.apply_mutation(mutation)

    def _is_target_in_scope(self, target: str, scope: list[str]) -> bool:
        """检查目标是否在授权 scope 内（IP 和域名均支持）"""
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
            # 域名直接匹配
            return ip_str in scope
