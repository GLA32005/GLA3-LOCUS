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
        self._recon_sent_keys: set[str] = set()
        self._exploit_sent_keys: set[str] = set()

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

        await asyncio.gather(
            self._event_loop(),
            self._think_loop(),
            self._executor_loop(),
        )

    def stop(self):
        self._is_running = False

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
                if not self._in_cleanup:
                    await self._trigger_think()
                    await self.check_cleanup_trigger()
            await asyncio.sleep(1.0)

    async def _force_cleanup(self, reason: str):
        """强制触发 CLEANUP_STATE 并停止 Orchestrator"""
        if self._in_cleanup:
            return
        await self.event_bus.publish(Event(
            type=EventType.CLEANUP_STATE,
            priority=EventPriority.CRITICAL,
            source="orchestrator",
            payload={"reason": reason}
        ))

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

        self._last_think_time = now
        self._think_count += 1

        try:
            pruned_view = await self.pruner.generate_view(self.state_api)
            planner_output = await self.planner.think(pruned_view)
            await self._dispatch_planner_output(planner_output)
            await self._print_progress()
        except Exception as e:
            logger.error(f"Planner Think 失败: {e}")

    async def _dispatch_planner_output(self, output: dict):
        """处理 Planner 的 Act 指令"""

        # RAG 查询优先处理
        if output.get("rag_query"):
            await self._handle_rag_query(output["rag_query"])
            # RAG 结果上黑板后，触发下一轮 Think
            await asyncio.sleep(0.5)
            await self._trigger_think(force=True)
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
        focus_update = output.get("focus_update")
        if focus_update and isinstance(focus_update, dict):
            current_focus = await self.state_api.get_focus()
            if not isinstance(current_focus, dict):
                current_focus = {}
            
            # 提取 Planner 外层的关键评估信息同步到 Focus
            ext_update = {
                "confidence": output.get("confidence", current_focus.get("confidence", 0)),
                "hypothesis": output.get("hypothesis", current_focus.get("hypothesis", ""))
            }
            
            try:
                # 预提取
                old_stall = int(current_focus.get("stall_count", 0))
                
                # 合并基本信息 (排除 LLM 可能返回的 stall_count)
                llm_focus = {k: v for k, v in focus_update.items() if k != "stall_count"}
                merged = {**current_focus, **ext_update, **llm_focus}
                
                # --- 核心逻辑：Orchestrator 严格掌控 stall_count ---
                # 判定是否有阶段性实质进展：目标阶段改变（例如进入了之前未达到的阶段）
                # 注意：置信度波动不再重置 stall_count，防止 LLM 通过改信心来刷掉计数
                goal_changed = merged.get("current_goal") != current_focus.get("current_goal")
                
                if goal_changed:
                    # 只有阶段改变时，才允许重置为 0
                    merged["stall_count"] = 0
                else:
                    # 否则，维持旧值（并在后面视情况加 1）
                    merged["stall_count"] = old_stall
                
                # 如果置信度没有显著提升 (>= 0.15)，则视为本轮思考无进展，计数加 1
                conf_diff = float(merged.get("confidence") or 0) - float(current_focus.get("confidence") or 0)
                if conf_diff < 0.15 and not goal_changed:
                    merged["stall_count"] = old_stall + 1
                    self._total_stall_count += 1

                from .protocols import StateMutation, MutationOperation, StateDomain
                await self.state_api.apply_mutation(StateMutation(
                    operation=MutationOperation.WRITE,
                    domain=StateDomain.FOCUS,
                    payload=merged,
                ))
                logger.info(
                    f"Focus updated: goal={merged.get('current_goal')} "
                    f"target={merged.get('active_target', 'None')} "
                    f"conf={float(merged.get('confidence') or 0):.2f} "
                    f"stall={merged.get('stall_count', 0)}"
                )
            except Exception as e:
                logger.error(f"Focus 同步失败: {e}")

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

        agent_type = AgentType(act.get("agent", "recon"))
        handler = agent_map.get(agent_type)
        if handler:
            await handler(act, output)

    # ── 事件处理器 ────────────────────────────────────────────

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
            await self._trigger_think(force=True)
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
        raw_summary = result.get("raw_summary", "")[:100]
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

        # 新资产进来，触发 Planner 重算优先级队列
        await self._trigger_think(force=True)

    async def _handle_asset_discovered(self, event: Event):
        """发现新资产，可能触发 opportunity_flag"""
        target = event.payload.get("target")
        logger.info(f"新资产发现: {target}")

        # 重置 stall_count 并查横向移动路径
        focus = await self.state_api.get_focus()
        if isinstance(focus, dict):
            focus["stall_count"] = 0
            await self.state_api.apply_mutation(StateMutation(
                operation=MutationOperation.WRITE,
                domain=StateDomain.FOCUS,
                payload=focus
            ))

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
        await self._trigger_think(force=True)

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
        focus = await self.state_api.get_focus()
        if isinstance(focus, dict):
            focus["stall_count"] = 0
            await self.state_api.apply_mutation(StateMutation(
                operation=MutationOperation.WRITE,
                domain=StateDomain.FOCUS,
                payload=focus
            ))

        await self._trigger_think(force=True)

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
            await self._trigger_think(force=True)

    async def _handle_cleanup_state(self, event: Event):
        """进入清理阶段"""
        if self._in_cleanup:
            return  # 防止重复触发
        self._in_cleanup = True
        logger.info("进入 CLEANUP_STATE，暂停所有 Exploit 调度")
        await self._invoke_cleanup({}, {})
        # 清理完成后停止 Orchestrator
        logger.info("CLEANUP_STATE 完成，停止 Orchestrator")
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

    # ── Agent 调用方法 ────────────────────────────────────────

    async def _invoke_recon(self, act: dict, planner_output: dict):
        from .protocols import NodeInput
        pruned = await self.pruner.generate_view(self.state_api)

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
        node_input = NodeInput(
            state_view={"_fixup_mode": True},  # 极简视图，省 token
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

        # Loop C 完成后生成最终报告
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

    # ── RAG 查询 ──────────────────────────────────────────────

    async def _handle_rag_query(self, query: str):
        """执行 RAG 查询，结果写入 context_retrievals"""
        results = await self.rag.query(query, top_k=5)
        mutation = StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.CONTEXT_RETRIEVALS,
            payload={"items": results}
        )
        await self.state_api.apply_mutation(mutation)

    # ── Executor 循环 ─────────────────────────────────────────

    async def _executor_loop(self):
        """持续监听 APPROVED payload + PENDING recon tasks，配额内分配给 Executor"""
        running_recon: set[str] = set()   # 正在执行的 task_id，防重复分发
        running_payloads: set[str] = set()

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
        try:
            await self.executor.execute(payload)
        finally:
            self._current_noise -= noise_cost
            running_set.discard(pid)

    async def _execute_recon_task(self, task: dict, noise_cost: int,
                                   running_set: set):
        task_id = task.get("id", "")
        try:
            await self.executor.execute_recon(task)
        finally:
            self._current_noise -= noise_cost
            running_set.discard(task_id)

    async def _execute_cleanup_task(self, task: dict, noise_cost: int):
        try:
            await self.executor.execute_cleanup(task)
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
            bar = "█" * filled + "░" * (bar_len - filled)

            # 阶段标签
            goal = focus.get("current_goal", "RECON") if isinstance(focus, dict) else "RECON"
            stall = focus.get("stall_count", 0) if isinstance(focus, dict) else 0
            max_stall = mission.get("max_stall_count", 10)
            conf = float(focus.get("confidence") or 0) if isinstance(focus, dict) else 0
            target = focus.get("active_target", "?") if isinstance(focus, dict) else "?"

            logger.info(
                f"[PROGRESS #{self._think_count}] "
                f"{overall*100:.0f}% |{bar}| "
                f"[{goal}] "
                f"hosts={total_hosts}/{scope_size} owned={owned_hosts} "
                f"tasks={done_tasks}/{total_tasks} pending={pending_recon} "
                f"vectors={total_vec}(ok={success_vec}) "
                f"stall={stall}/{max_stall} "
                f"target={target} conf={conf:.2f}"
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
        for mutation in output.mutations:
            if mutation.domain == StateDomain.KNOWLEDGE_QUERY:
                continue

            # 侦察任务去重：无论是同步(PENDING_RECON)还是异步(ASYNC_TASKS)，同一 target+tool 只派一次
            if mutation.domain in (StateDomain.PENDING_RECON, StateDomain.ASYNC_TASKS):
                payload = mutation.payload
                if "tool" in payload and "target" in payload:
                    target = payload.get("target", "")
                    tool = payload.get("tool", "")
                    key = f"{target}:{tool}"
                    if key in self._recon_sent_keys:
                        logger.debug(f"Recon: 已派过 {key}，跳过重复下发")
                        continue
                    self._recon_sent_keys.add(key)

            await self.state_api.apply_mutation(mutation)
            applied_count += 1

        for event in output.events:
            await self.event_bus.publish(event)

        if knowledge_queries:
            await self._handle_knowledge_queries(knowledge_queries)
            await self._trigger_think(force=True)
            
        # 如果 Agent 这一轮没有产生任何实际状态改变（比如任务全被过滤了），标记为 STALL
        if applied_count == 0 and not knowledge_queries:
            current_focus = await self.state_api.get_focus()
            if isinstance(current_focus, dict):
                current_focus["stall_count"] = int(current_focus.get("stall_count", 0)) + 1
                self._total_stall_count += 1
                await self.state_api.apply_mutation(StateMutation(
                    operation=MutationOperation.WRITE,
                    domain=StateDomain.FOCUS,
                    payload=current_focus
                ))
                logger.warning(f"检测到空转（Agent未生成有效任务），强制增加 stall={current_focus['stall_count']}")

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
            logger.warning(
                f"空转 {stall_count} 次且仍在 {current_goal}，"
                f"强制切换到 EXPLOIT 阶段（目标: {focus['active_target']}）"
            )
            focus["current_goal"] = "EXPLOIT"
            focus["stall_count"] = 0
            focus["hypothesis"] = (
                f"RECON 阶段空转 {stall_count} 次后强制进入 EXPLOIT，"
                f"尝试对 {focus['active_target']} 使用默认凭据或已知漏洞"
            )
            await self.state_api.apply_mutation(StateMutation(
                operation=MutationOperation.WRITE,
                domain=StateDomain.FOCUS,
                payload=focus,
            ))
            await self._trigger_think(force=True)
            return

        # stall 耗尽 → 清理退出
        if stall_count >= max_stall:
            await self.event_bus.publish(Event(
                type=EventType.CLEANUP_STATE,
                priority=EventPriority.CRITICAL,
                source="orchestrator",
                payload={"reason": "stall_exhausted"}
            ))
