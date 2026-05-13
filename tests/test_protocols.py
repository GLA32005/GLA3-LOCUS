"""
test_protocols.py — 核心协议约束验证

覆盖：
  - 宪法约束②：tried_vectors / footprints 只允许 APPEND
  - 宪法约束（focus）：只允许 WRITE
  - Event 工厂方法返回值正确
  - NodeOutput 默认字段
  - StateDomain 枚举完整性
"""

import pytest
from core.protocols import (
    AgentType,
    Event,
    EventPriority,
    EventType,
    FailReason,
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


# ── StateMutation 约束 ────────────────────────────────────────

class TestStateMutationConstraints:

    def test_tried_vectors_only_allows_append(self):
        m = StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.TRIED_VECTORS,
            payload={"id": "abc"},
        )
        assert m.validate() is True

    def test_tried_vectors_rejects_upsert(self):
        m = StateMutation(
            operation=MutationOperation.UPSERT,
            domain=StateDomain.TRIED_VECTORS,
            payload={"id": "abc"},
        )
        with pytest.raises(ValueError, match="只允许 APPEND"):
            m.validate()

    def test_tried_vectors_rejects_delete(self):
        m = StateMutation(
            operation=MutationOperation.DELETE,
            domain=StateDomain.TRIED_VECTORS,
            payload={"id": "abc"},
        )
        with pytest.raises(ValueError, match="只允许 APPEND"):
            m.validate()

    def test_footprints_only_allows_append(self):
        m = StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.FOOTPRINTS,
            payload={"id": "xyz"},
        )
        assert m.validate() is True

    def test_footprints_rejects_update_status(self):
        m = StateMutation(
            operation=MutationOperation.UPDATE_STATUS,
            domain=StateDomain.FOOTPRINTS,
            payload={"id": "xyz"},
        )
        with pytest.raises(ValueError, match="只允许 APPEND"):
            m.validate()

    def test_focus_only_allows_write(self):
        m = StateMutation(
            operation=MutationOperation.WRITE,
            domain=StateDomain.FOCUS,
            payload={"active_target": "10.0.0.1"},
        )
        assert m.validate() is True

    def test_focus_rejects_upsert(self):
        m = StateMutation(
            operation=MutationOperation.UPSERT,
            domain=StateDomain.FOCUS,
            payload={"active_target": "10.0.0.1"},
        )
        with pytest.raises(ValueError, match="全量 WRITE"):
            m.validate()

    def test_assets_allows_upsert(self):
        m = StateMutation(
            operation=MutationOperation.UPSERT,
            domain=StateDomain.ASSETS,
            payload={"ip": "10.0.0.5"},
        )
        assert m.validate() is True

    def test_pending_payloads_allows_upsert(self):
        m = StateMutation(
            operation=MutationOperation.UPSERT,
            domain=StateDomain.PENDING_PAYLOADS,
            payload={"id": "p1", "status": "PENDING"},
        )
        assert m.validate() is True

    def test_pending_payloads_allows_update_status(self):
        m = StateMutation(
            operation=MutationOperation.UPDATE_STATUS,
            domain=StateDomain.PENDING_PAYLOADS,
            payload={"id": "p1", "status": "APPROVED"},
        )
        assert m.validate() is True

    def test_mutation_has_auto_uuid(self):
        m1 = StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.TRIED_VECTORS,
            payload={},
        )
        m2 = StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.TRIED_VECTORS,
            payload={},
        )
        assert m1.id != m2.id


# ── Event 工厂方法 ────────────────────────────────────────────

class TestEventFactories:

    def test_payload_rejected_event(self):
        e = Event.payload_rejected(
            payload_id="p1",
            reject_reason=RejectReason.HIGH_NOISE,
            original_payload="echo test",
            retry_count=1,
        )
        assert e.type == EventType.PAYLOAD_REJECTED
        assert e.priority == EventPriority.CRITICAL
        assert e.payload["payload_id"] == "p1"
        assert e.payload["reject_reason"] == RejectReason.HIGH_NOISE
        assert e.payload["retry_count"] == 1

    def test_exploit_success_event(self):
        from core.protocols import AccessLevel
        e = Event.exploit_success(
            target="10.0.0.5:445",
            access_level=AccessLevel.ROOT,
            vector_id="v1",
        )
        assert e.type == EventType.EXPLOIT_SUCCESS
        assert e.priority == EventPriority.CRITICAL
        assert e.payload["target"] == "10.0.0.5:445"

    def test_task_completed_event(self):
        e = Event.task_completed(task_id="t1", result={"found": 3})
        assert e.type == EventType.TASK_COMPLETED
        assert e.priority == EventPriority.HIGH
        assert e.payload["task_id"] == "t1"

    def test_opportunity_found_event(self):
        e = Event.opportunity_found(target="10.0.0.5", reason="open SMB")
        assert e.type == EventType.OPPORTUNITY_FOUND
        assert e.priority == EventPriority.CRITICAL

    def test_event_has_auto_id_and_ts(self):
        e1 = Event.task_completed("t1", {})
        e2 = Event.task_completed("t2", {})
        assert e1.id != e2.id
        assert e1.ts > 0


# ── NodeOutput 默认值 ─────────────────────────────────────────

class TestNodeOutput:

    def test_empty_output(self):
        out = NodeOutput(mutations=[], events=[])
        assert out.mutations == []
        assert out.events == []
        assert out.next_hint is None
        assert out.think_log == ""
        assert out.tokens_used == 0

    def test_output_with_mutations_and_events(self):
        m = StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.TRIED_VECTORS,
            payload={"id": "v1"},
        )
        e = Event.task_completed("t1", {})
        out = NodeOutput(mutations=[m], events=[e], tokens_used=150)
        assert len(out.mutations) == 1
        assert len(out.events) == 1
        assert out.tokens_used == 150


# ── StateDomain 完整性 ────────────────────────────────────────

class TestStateDomainCompleteness:

    def test_all_required_domains_present(self):
        required = {
            "ASSETS", "TRIED_VECTORS", "FOCUS",
            "PENDING_PAYLOADS", "PENDING_RECON",
            "ASYNC_TASKS", "FOOTPRINTS",
            "CONTEXT_RETRIEVALS", "PENDING_CLEANUP",
        }
        existing = {d.name for d in StateDomain}
        missing = required - existing
        assert not missing, f"Missing StateDomain entries: {missing}"


# ── 枚举值不可重复 ────────────────────────────────────────────

class TestEnumUniqueness:

    def test_vector_type_values_unique(self):
        vals = [v.value for v in VectorType]
        assert len(vals) == len(set(vals))

    def test_reject_reason_values_unique(self):
        vals = [v.value for v in RejectReason]
        assert len(vals) == len(set(vals))

    def test_event_type_values_unique(self):
        vals = [v.value for v in EventType]
        assert len(vals) == len(set(vals))
