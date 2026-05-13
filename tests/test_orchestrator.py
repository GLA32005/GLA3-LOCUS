"""
test_orchestrator.py — Orchestrator + EventBus 单元测试

覆盖：
  - EventBus 发收 + 优先级排序
  - Orchestrator 事件合并窗口
  - PAYLOAD_REJECTED 快速修正循环（含超限 ABANDONED）
  - OPPORTUNITY_FOUND → focus 更新 + 强制 Think
  - EXPLOIT_SUCCESS → assets 更新
  - CLEANUP_STATE → _in_cleanup 标志 + cleanup_tasks 仅在清理阶段消费
  - check_cleanup_trigger（deadline / goal / stall）
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.orchestrator import EventBus, Orchestrator
from core.protocols import (
    AgentType,
    Event,
    EventPriority,
    EventType,
    MutationOperation,
    NodeOutput,
    PayloadStatus,
    RejectReason,
    StateDomain,
    StateMutation,
    TaskStatus,
)


# ═══════════════════════════════════════════════════════════════
# EventBus 测试
# ═══════════════════════════════════════════════════════════════

class TestEventBus:

    @pytest.fixture
    def bus(self):
        return EventBus()

    @pytest.mark.asyncio
    async def test_publish_and_get(self, bus):
        e = Event.task_completed("t1", {"found": 3})
        await bus.publish(e)
        got = await bus.get_next()
        assert got is not None
        assert got.type == EventType.TASK_COMPLETED
        assert got.payload["task_id"] == "t1"

    @pytest.mark.asyncio
    async def test_priority_ordering(self, bus):
        """CRITICAL 事件应先于 HIGH / NORMAL 事件被取出"""
        normal = Event(
            type=EventType.STALL_DETECTED,
            priority=EventPriority.NORMAL,
            source="test", payload={"order": 1},
        )
        critical = Event(
            type=EventType.EXPLOIT_SUCCESS,
            priority=EventPriority.CRITICAL,
            source="test", payload={"order": 2},
        )
        # 先发 NORMAL，再发 CRITICAL
        await bus.publish(normal)
        await bus.publish(critical)

        first = await bus.get_next()
        assert first.priority == EventPriority.CRITICAL
        second = await bus.get_next()
        assert second.priority == EventPriority.NORMAL

    @pytest.mark.asyncio
    async def test_empty_returns_none(self, bus):
        got = await bus.get_next()
        assert got is None


# ═══════════════════════════════════════════════════════════════
# Orchestrator mock 工厂
# ═══════════════════════════════════════════════════════════════

def _make_orchestrator(**overrides):
    """构造一个全 mock 的 Orchestrator，用于单元测试。"""
    state_api = AsyncMock()
    state_api.get_mission = AsyncMock(return_value={
        "scope": ["10.0.0.0/24"],
        "max_noise": 50,
        "max_payload_retry": 3,
        "max_stall_count": 10,
    })
    state_api.get_focus = AsyncMock(return_value={
        "active_target": "10.0.0.5",
        "current_goal": "EXPLOIT",
        "stall_count": 0,
    })
    state_api.apply_mutation = AsyncMock(return_value=True)
    state_api.get_approved_payloads = AsyncMock(return_value=[])
    state_api.get_pending_recon_tasks = AsyncMock(return_value=[])
    state_api.get_approved_cleanup_tasks = AsyncMock(return_value=[])
    state_api.redis = AsyncMock()

    event_bus = EventBus()
    planner = AsyncMock()
    planner.think = AsyncMock(return_value={
        "act": {"agent": "recon", "action_type": "port_scan", "params": {}, "priority": 0.5},
        "focus_update": None,
        "rag_query": None,
        "async_task": None,
    })

    exploit_agent = AsyncMock()
    exploit_agent.run = AsyncMock(return_value=NodeOutput(mutations=[], events=[]))

    recon_agent = AsyncMock()
    recon_agent.run = AsyncMock(return_value=NodeOutput(mutations=[], events=[]))

    critic_agent = AsyncMock()
    cleanup_agent = AsyncMock()

    executor = AsyncMock()
    rag_engine = AsyncMock()

    orch = Orchestrator(
        state_api=overrides.get("state_api", state_api),
        event_bus=overrides.get("event_bus", event_bus),
        planner=overrides.get("planner", planner),
        exploit_agent=overrides.get("exploit_agent", exploit_agent),
        recon_agent=overrides.get("recon_agent", recon_agent),
        critic_agent=overrides.get("critic_agent", critic_agent),
        cleanup_agent=overrides.get("cleanup_agent", cleanup_agent),
        executor=overrides.get("executor", executor),
        rag_engine=overrides.get("rag_engine", rag_engine),
    )
    # 初始化内部状态（通常由 start() 执行）
    orch._max_noise = 50
    orch._is_running = True

    return orch


# ═══════════════════════════════════════════════════════════════
# Orchestrator 事件处理测试
# ═══════════════════════════════════════════════════════════════

class TestOrchestratorPayloadRejected:

    @pytest.mark.asyncio
    async def test_normal_rejection_triggers_exploit_fixup(self):
        """正常拒绝 → 直接触发 Exploit Agent 快速修正（绕过 Planner）"""
        orch = _make_orchestrator()

        event = Event.payload_rejected(
            payload_id="p1",
            reject_reason=RejectReason.HIGH_NOISE,
            original_payload="echo test",
            retry_count=1,
        )
        await orch._handle_payload_rejected(event)

        # Exploit Agent 应被调用（快速修正模式）
        orch.exploit_agent.run.assert_called_once()
        call_args = orch.exploit_agent.run.call_args[0][0]
        assert call_args.trigger_event.type == EventType.PAYLOAD_REJECTED
        assert call_args.trigger_event.payload["retry_count"] == 2  # +1

    @pytest.mark.asyncio
    async def test_max_retry_marks_abandoned(self):
        """超过最大重试次数 → 写 ABANDONED，触发 Planner 重评估"""
        orch = _make_orchestrator()

        event = Event.payload_rejected(
            payload_id="p1",
            reject_reason=RejectReason.SYNTAX_ERROR,
            original_payload="broken",
            retry_count=3,  # == max_payload_retry
        )
        await orch._handle_payload_rejected(event)

        # 不应调用 Exploit Agent
        orch.exploit_agent.run.assert_not_called()
        # 应写入 ABANDONED 记录到 tried_vectors
        call = orch.state_api.apply_mutation.call_args_list[0][0][0]
        assert call.domain == StateDomain.TRIED_VECTORS
        assert call.payload["result"] == "ABANDONED"

    @pytest.mark.asyncio
    async def test_requires_approval_goes_to_human(self):
        """REQUIRES_APPROVAL → 请求人工审批，不走快速修正"""
        orch = _make_orchestrator()

        event = Event.payload_rejected(
            payload_id="p1",
            reject_reason=RejectReason.REQUIRES_APPROVAL,
            original_payload="sensitive",
            retry_count=0,
        )
        await orch._handle_payload_rejected(event)

        # Exploit Agent 不应被调用
        orch.exploit_agent.run.assert_not_called()


class TestOrchestratorOpportunity:

    @pytest.mark.asyncio
    async def test_opportunity_updates_focus(self):
        """OPPORTUNITY_FOUND → focus 更新 opportunity_flag"""
        orch = _make_orchestrator()
        orch._last_think_time = 0  # 允许立即 Think

        event = Event.opportunity_found(
            target="10.0.0.20",
            reason="open SMB share"
        )
        await orch._handle_opportunity_found(event)

        # focus 应被写入 opportunity_flag=True
        mutation_call = orch.state_api.apply_mutation.call_args_list[0][0][0]
        assert mutation_call.domain == StateDomain.FOCUS
        assert mutation_call.payload["opportunity_flag"] is True
        assert mutation_call.payload["opportunity_target"] == "10.0.0.20"


class TestOrchestratorExploitSuccess:

    @pytest.mark.asyncio
    async def test_exploit_success_updates_assets(self):
        """EXPLOIT_SUCCESS → assets 更新 access_level"""
        orch = _make_orchestrator()
        orch._last_think_time = 0

        from core.protocols import AccessLevel
        event = Event.exploit_success(
            target="10.0.0.5:445",
            access_level=AccessLevel.ROOT,
            vector_id="v1",
        )
        await orch._handle_exploit_success(event)

        mutation_call = orch.state_api.apply_mutation.call_args_list[0][0][0]
        assert mutation_call.domain == StateDomain.ASSETS
        assert mutation_call.payload["access_level"] == AccessLevel.ROOT


class TestOrchestratorCleanupState:

    @pytest.mark.asyncio
    async def test_cleanup_state_sets_flag(self):
        """CLEANUP_STATE → 设置 _in_cleanup 标志"""
        cleanup_agent = AsyncMock()
        cleanup_agent.run = AsyncMock(return_value=NodeOutput(
            mutations=[], events=[], think_log="test cleanup",
        ))
        orch = _make_orchestrator(cleanup_agent=cleanup_agent)
        orch.state_api.get_all_footprints = AsyncMock(return_value=[])

        event = Event(
            type=EventType.CLEANUP_STATE,
            priority=EventPriority.CRITICAL,
            source="test", payload={"reason": "goal_achieved"},
        )
        await orch._handle_cleanup_state(event)

        assert orch._in_cleanup is True


class TestCheckCleanupTrigger:

    @pytest.mark.asyncio
    async def test_deadline_triggers_cleanup(self):
        """deadline 超时 → 发 CLEANUP_STATE 事件"""
        orch = _make_orchestrator()
        orch.state_api.get_mission.return_value = {
            "deadline": time.time() - 100,  # 100 秒前已过期
            "max_stall_count": 10,
        }

        await orch.check_cleanup_trigger()

        # EventBus 应有 CLEANUP_STATE 事件
        event = await orch.event_bus.get_next()
        assert event is not None
        assert event.type == EventType.CLEANUP_STATE

    @pytest.mark.asyncio
    async def test_goal_report_triggers_cleanup(self):
        """current_goal=REPORT → 发 CLEANUP_STATE"""
        orch = _make_orchestrator()
        orch.state_api.get_focus.return_value = {
            "current_goal": "REPORT",
            "stall_count": 0,
        }

        await orch.check_cleanup_trigger()

        event = await orch.event_bus.get_next()
        assert event is not None
        assert event.type == EventType.CLEANUP_STATE

    @pytest.mark.asyncio
    async def test_stall_exhausted_triggers_cleanup(self):
        """stall_count >= max → 发 CLEANUP_STATE"""
        orch = _make_orchestrator()
        orch.state_api.get_focus.return_value = {
            "current_goal": "EXPLOIT",
            "stall_count": 10,
        }

        await orch.check_cleanup_trigger()

        event = await orch.event_bus.get_next()
        assert event is not None
        assert event.type == EventType.CLEANUP_STATE

    @pytest.mark.asyncio
    async def test_no_trigger_when_healthy(self):
        """正常运行时不触发 CLEANUP_STATE"""
        orch = _make_orchestrator()
        orch.state_api.get_mission.return_value = {
            "deadline": time.time() + 3600,  # 1 小时后
            "max_stall_count": 10,
        }
        orch.state_api.get_focus.return_value = {
            "current_goal": "EXPLOIT",
            "stall_count": 2,
        }

        await orch.check_cleanup_trigger()

        event = await orch.event_bus.get_next()
        assert event is None


# ═══════════════════════════════════════════════════════════════
# Knowledge Query 拦截测试
# ═══════════════════════════════════════════════════════════════

class TestKnowledgeQueryIntercept:

    @pytest.mark.asyncio
    async def test_knowledge_query_triggers_rag_and_think(self):
        """Agent 返回 knowledge_query mutation → Orchestrator 拦截查询 RAG → 触发 Think"""
        from memory.rag_engine import RetrievalResult

        rag = AsyncMock()
        rag.query = AsyncMock(return_value=[
            RetrievalResult(content="CVE-2021-44228 details", source="cve_db", relevance=0.95),
        ])
        rag.results_to_state = MagicMock(return_value=[
            {"content": "CVE-2021-44228 details", "source": "cve_db", "relevance": 0.95},
        ])

        orch = _make_orchestrator(rag_engine=rag)
        orch._last_think_time = 0

        # 模拟 Agent 返回包含 KNOWLEDGE_QUERY 的 output
        output = NodeOutput(
            mutations=[
                StateMutation(
                    operation=MutationOperation.APPEND,
                    domain=StateDomain.KNOWLEDGE_QUERY,
                    payload={
                        "query": "CVE-2021-44228",
                        "type": "CVE",
                        "reason": "found Log4j service",
                        "source_agent": "recon",
                    },
                ),
            ],
            events=[],
            think_log="need CVE details",
        )

        await orch._apply_node_output(output)

        # RAG 应被调用
        rag.query.assert_awaited_once_with("CVE-2021-44228", type_filter="CVE", top_k=3)

        # context_retrievals 应被写入
        retrieval_calls = [
            c for c in orch.state_api.apply_mutation.call_args_list
            if c[0][0].domain == StateDomain.CONTEXT_RETRIEVALS
        ]
        assert len(retrieval_calls) >= 1

    @pytest.mark.asyncio
    async def test_no_knowledge_query_does_not_trigger_rag(self):
        """Agent 无 knowledge_query → 不触发 RAG"""
        rag = AsyncMock()
        orch = _make_orchestrator(rag_engine=rag)

        output = NodeOutput(
            mutations=[
                StateMutation(
                    operation=MutationOperation.APPEND,
                    domain=StateDomain.PENDING_RECON,
                    payload={"tool": "port_scan", "target": "10.0.0.5"},
                ),
            ],
            events=[],
            think_log="normal recon",
        )

        await orch._apply_node_output(output)

        rag.query.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_knowledge_query_with_non_knowledge_mutations(self):
        """同时有 knowledge_query 和普通 mutation 时，普通 mutation 仍被提交"""
        from memory.rag_engine import RetrievalResult

        rag = AsyncMock()
        rag.query = AsyncMock(return_value=[])
        rag.results_to_state = MagicMock(return_value=[])

        orch = _make_orchestrator(rag_engine=rag)
        orch._last_think_time = 0

        output = NodeOutput(
            mutations=[
                StateMutation(
                    operation=MutationOperation.APPEND,
                    domain=StateDomain.KNOWLEDGE_QUERY,
                    payload={"query": "test", "type": "LotL", "reason": "x", "source_agent": "exploit"},
                ),
                StateMutation(
                    operation=MutationOperation.UPSERT,
                    domain=StateDomain.PENDING_PAYLOADS,
                    payload={"id": "p1", "content": "test"},
                ),
            ],
            events=[],
        )

        await orch._apply_node_output(output)

        # PENDING_PAYLOADS mutation 应被提交
        payload_calls = [
            c for c in orch.state_api.apply_mutation.call_args_list
            if c[0][0].domain == StateDomain.PENDING_PAYLOADS
        ]
        assert len(payload_calls) == 1

    @pytest.mark.asyncio
    async def test_agent_request_marks_requested_by_agent(self):
        """Agent 发起的查询结果应标记 requested_by_agent=True"""
        from memory.rag_engine import RetrievalResult

        rag = AsyncMock()
        rag.query = AsyncMock(return_value=[
            RetrievalResult(content="bypass technique", source="edr_bypass", relevance=0.8),
        ])
        rag.results_to_state = MagicMock(return_value=[
            {"content": "bypass technique", "source": "edr_bypass", "relevance": 0.8},
        ])

        orch = _make_orchestrator(rag_engine=rag)
        orch._last_think_time = 0

        output = NodeOutput(
            mutations=[
                StateMutation(
                    operation=MutationOperation.APPEND,
                    domain=StateDomain.KNOWLEDGE_QUERY,
                    payload={"query": "bypass", "type": "Bypass", "reason": "test", "source_agent": "exploit"},
                ),
            ],
            events=[],
        )

        await orch._apply_node_output(output)

        retrieval_calls = [
            c for c in orch.state_api.apply_mutation.call_args_list
            if c[0][0].domain == StateDomain.CONTEXT_RETRIEVALS
        ]
        assert len(retrieval_calls) >= 1
        items = retrieval_calls[0][0][0].payload["items"]
        assert items[0]["requested_by_agent"] is True
