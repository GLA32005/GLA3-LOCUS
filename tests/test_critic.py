"""
test_critic.py — CriticAgent 单元测试（mock LLM）

覆盖：
  - 硬编码检查：DOS_RISK 模式拦截
  - 硬编码检查：OUT_OF_SCOPE 拦截
  - 硬编码检查：空 payload 拦截
  - LLM 四维评分 + 阈值覆盖逻辑
  - LLM 故障降级
  - APPROVED / BLOCKED / REQUIRES_APPROVAL 三种输出路径
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agents.critic_agent import CriticAgent
from core.protocols import (
    Event,
    EventPriority,
    EventType,
    MutationOperation,
    NodeInput,
    NodeOutput,
    PayloadStatus,
    RejectReason,
    StateDomain,
    VectorResult,
)


# ═══════════════════════════════════════════════════════════════
# 辅助
# ═══════════════════════════════════════════════════════════════

def _make_input(content: str, target: str = "10.0.0.5:80",
                scope: list[str] = None, risk_level: int = 3) -> NodeInput:
    """构造 CriticAgent 的 NodeInput"""
    scope = scope or ["10.0.0.0/24"]
    return NodeInput(
        state_view={
            "payload": {
                "id": "test-payload-1",
                "content": content,
                "target": target,
                "vector_type": "LOTL",
                "technique": "certutil download",
                "retry_count": 0,
                "noise_cost": 3,
                "mission_scope": scope,
            },
            "mission": {
                "scope": scope,
                "risk_level": risk_level,
            },
        },
        trigger_event=Event(
            type=EventType.TASK_COMPLETED,
            payload={"payload_id": "test-payload-1"},
            source="orchestrator",
        ),
        agent_id="critic_test_1",
    )


def _mock_llm_response(scores: dict, verdict: str,
                        reject_reason: str = None) -> dict:
    return {
        "think": "test review",
        "scores": scores,
        "verdict": verdict,
        "reject_reason": reject_reason,
    }


# ═══════════════════════════════════════════════════════════════
# 硬编码检查（不调 LLM）
# ═══════════════════════════════════════════════════════════════

class TestHardcodedChecks:

    @pytest.mark.asyncio
    async def test_dos_risk_rm_rf(self):
        """rm -rf / 必须被硬编码拦截"""
        agent = CriticAgent()
        inp = _make_input("rm -rf / && echo done")
        result = await agent.run(inp)

        assert len(result.mutations) == 2  # UPDATE_STATUS + tried_vectors
        status_mut = result.mutations[0]
        assert status_mut.payload["status"] == PayloadStatus.BLOCKED
        assert status_mut.payload["reject_reason"] == RejectReason.DOS_RISK

    @pytest.mark.asyncio
    async def test_dos_risk_drop_database(self):
        """DROP DATABASE 必须被拦截"""
        agent = CriticAgent()
        inp = _make_input("sqlmap -u http://10.0.0.5/login --sql-query='DROP DATABASE prod'")
        result = await agent.run(inp)

        status_mut = result.mutations[0]
        assert status_mut.payload["reject_reason"] == RejectReason.DOS_RISK

    @pytest.mark.asyncio
    async def test_out_of_scope(self):
        """目标不在 scope 内 → OUT_OF_SCOPE"""
        agent = CriticAgent()
        inp = _make_input(
            "nmap 192.168.1.1",
            target="192.168.1.1:80",
            scope=["10.0.0.0/24"],
        )
        result = await agent.run(inp)

        status_mut = result.mutations[0]
        assert status_mut.payload["reject_reason"] == RejectReason.OUT_OF_SCOPE

    @pytest.mark.asyncio
    async def test_empty_payload(self):
        """空 payload → SYNTAX_ERROR"""
        agent = CriticAgent()
        inp = _make_input("  ")
        result = await agent.run(inp)

        status_mut = result.mutations[0]
        assert status_mut.payload["reject_reason"] == RejectReason.SYNTAX_ERROR

    @pytest.mark.asyncio
    async def test_hardcoded_does_not_call_llm(self):
        """硬编码拦截路径不应调用 LLM"""
        agent = CriticAgent()
        agent._call_llm = AsyncMock()  # 不应被调用
        inp = _make_input("rm -rf /")
        await agent.run(inp)
        agent._call_llm.assert_not_called()


# ═══════════════════════════════════════════════════════════════
# 阈值决策逻辑
# ═══════════════════════════════════════════════════════════════

class TestDecisionLogic:

    def test_high_destructiveness_blocked(self):
        agent = CriticAgent()
        status, reason = agent._apply_decision_logic(
            {"destructiveness": 0.9, "compliance": 1.0, "stability": 1.0, "noise": 0.1},
            "APPROVED", risk_level=3,
        )
        assert status == PayloadStatus.BLOCKED
        assert reason == RejectReason.DOS_RISK

    def test_low_compliance_blocked(self):
        agent = CriticAgent()
        status, reason = agent._apply_decision_logic(
            {"destructiveness": 0.1, "compliance": 0.3, "stability": 1.0, "noise": 0.1},
            "APPROVED", risk_level=3,
        )
        assert status == PayloadStatus.BLOCKED
        assert reason == RejectReason.OUT_OF_SCOPE

    def test_low_stability_blocked(self):
        agent = CriticAgent()
        status, reason = agent._apply_decision_logic(
            {"destructiveness": 0.1, "compliance": 1.0, "stability": 0.5, "noise": 0.1},
            "APPROVED", risk_level=3,
        )
        assert status == PayloadStatus.BLOCKED
        assert reason == RejectReason.SYNTAX_ERROR

    def test_high_noise_blocked_for_low_risk(self):
        agent = CriticAgent()
        status, reason = agent._apply_decision_logic(
            {"destructiveness": 0.1, "compliance": 1.0, "stability": 0.9, "noise": 0.8},
            "APPROVED", risk_level=3,  # < 4
        )
        assert status == PayloadStatus.BLOCKED
        assert reason == RejectReason.HIGH_NOISE

    def test_high_noise_allowed_for_high_risk(self):
        """risk_level >= 4 时不因 HIGH_NOISE 拦截"""
        agent = CriticAgent()
        status, reason = agent._apply_decision_logic(
            {"destructiveness": 0.1, "compliance": 1.0, "stability": 0.9, "noise": 0.8},
            "APPROVED", risk_level=4,
        )
        assert status == PayloadStatus.APPROVED

    def test_all_good_approved(self):
        agent = CriticAgent()
        status, reason = agent._apply_decision_logic(
            {"destructiveness": 0.1, "compliance": 1.0, "stability": 0.95, "noise": 0.3},
            "APPROVED", risk_level=3,
        )
        assert status == PayloadStatus.APPROVED
        assert reason is None

    def test_llm_says_requires_approval(self):
        agent = CriticAgent()
        status, reason = agent._apply_decision_logic(
            {"destructiveness": 0.1, "compliance": 1.0, "stability": 0.95, "noise": 0.3},
            "REQUIRES_APPROVAL", risk_level=3,
        )
        assert status == PayloadStatus.REQUIRES_APPROVAL

    def test_llm_says_blocked_threshold_ok(self):
        """LLM 判 BLOCKED 但所有阈值 OK → 信任 LLM（可能是 HALLUCINATION）"""
        agent = CriticAgent()
        status, reason = agent._apply_decision_logic(
            {"destructiveness": 0.1, "compliance": 1.0, "stability": 0.95, "noise": 0.3},
            "BLOCKED", risk_level=3,
        )
        assert status == PayloadStatus.BLOCKED
        assert reason == RejectReason.HALLUCINATION


# ═══════════════════════════════════════════════════════════════
# LLM 集成（mock）
# ═══════════════════════════════════════════════════════════════

class TestCriticWithMockLLM:

    @pytest.mark.asyncio
    async def test_approved_flow(self):
        """LLM 评分全好 → APPROVED + PAYLOAD_APPROVED 事件"""
        agent = CriticAgent()
        agent._call_llm = AsyncMock(return_value=(
            _mock_llm_response(
                {"noise": 0.2, "stability": 0.95, "destructiveness": 0.1, "compliance": 1.0},
                "APPROVED",
            ),
            200,
        ))

        inp = _make_input("certutil -urlcache -split -f http://10.0.0.5/shell.exe c:\\tmp\\s.exe")
        result = await agent.run(inp)

        # 应该有 APPROVED mutation
        assert any(
            m.payload.get("status") == PayloadStatus.APPROVED
            for m in result.mutations
        )
        # 应该有 PAYLOAD_APPROVED 事件
        assert any(
            e.type == EventType.PAYLOAD_APPROVED
            for e in result.events
        )

    @pytest.mark.asyncio
    async def test_blocked_flow(self):
        """LLM 评分差 → BLOCKED + PAYLOAD_REJECTED 事件"""
        agent = CriticAgent()
        agent._call_llm = AsyncMock(return_value=(
            _mock_llm_response(
                {"noise": 0.9, "stability": 0.5, "destructiveness": 0.1, "compliance": 1.0},
                "BLOCKED",
                "SYNTAX_ERROR",
            ),
            200,
        ))

        inp = _make_input("certutil broken syntax")
        result = await agent.run(inp)

        # stability < 0.8 → BLOCKED/SYNTAX_ERROR
        assert any(
            m.payload.get("status") == PayloadStatus.BLOCKED
            for m in result.mutations
        )
        # 应该有 PAYLOAD_REJECTED 事件
        assert any(
            e.type == EventType.PAYLOAD_REJECTED
            for e in result.events
        )

    @pytest.mark.asyncio
    async def test_llm_failure_degrades_to_blocked(self):
        """LLM 调用失败 → 保守降级为 BLOCKED"""
        agent = CriticAgent()
        agent._call_llm = AsyncMock(return_value=(None, 0))

        inp = _make_input("some valid payload")
        result = await agent.run(inp)

        assert any(
            m.payload.get("status") == PayloadStatus.BLOCKED
            for m in result.mutations
        )


# ═══════════════════════════════════════════════════════════════
# 输出结构完整性
# ═══════════════════════════════════════════════════════════════

class TestOutputStructure:

    @pytest.mark.asyncio
    async def test_blocked_output_has_tried_vectors(self):
        """BLOCKED 输出必须同时写 tried_vectors（审计）"""
        agent = CriticAgent()
        inp = _make_input("rm -rf /")
        result = await agent.run(inp)

        vector_mutations = [
            m for m in result.mutations
            if m.domain == StateDomain.TRIED_VECTORS
        ]
        assert len(vector_mutations) == 1
        assert vector_mutations[0].operation == MutationOperation.APPEND
        assert vector_mutations[0].payload["result"] == VectorResult.CRITIC_BLOCKED

    @pytest.mark.asyncio
    async def test_no_payload_returns_empty(self):
        """state_view 中没有 payload → 空输出"""
        agent = CriticAgent()
        inp = NodeInput(
            state_view={"payload": {}, "mission": {}},
            trigger_event=Event(
                type=EventType.TASK_COMPLETED,
                payload={}, source="test",
            ),
            agent_id="test",
        )
        result = await agent.run(inp)
        assert result.mutations == []
        assert result.events == []
