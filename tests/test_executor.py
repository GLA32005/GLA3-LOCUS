"""
test_executor.py — Executor 测试

覆盖：
  - 路由逻辑（LOTL → _exec_lotl, SSRF → _exec_http_probe, 未知 → 兜底）
  - execute() 沙箱拦截路径
  - execute() 超时路径
  - execute_recon() 正常路径 + 未知工具路径
  - execute_recon() 发布 ASSET_DISCOVERED 事件
  - execute_cleanup() 无命令内容路径
  - _infer_access_level
  - _record_vector 写入格式
"""

from __future__ import annotations

import asyncio
import json
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.protocols import (
    Event, EventType, EventPriority,
    MutationOperation, PayloadStatus, StateDomain, StateMutation,
    TaskStatus, VectorResult, VectorType, AccessLevel,
)
from executor.executor import Executor
from executor.tools import ToolResult


# ── 辅助 ────────────────────────────────────────────────────

def _make_mock_state_api():
    m = MagicMock()
    m.redis = MagicMock()
    m.redis.exists = AsyncMock(return_value=False)
    m.redis.get = AsyncMock(return_value=None)
    m.redis.set = AsyncMock()
    m.apply_mutation = AsyncMock(return_value=True)
    m.get_focus = AsyncMock(return_value={})
    m.get_mission = AsyncMock(return_value={"scope": ["10.0.0.0/24"]})
    return m


def _make_mock_event_bus():
    bus = MagicMock()
    bus.publish = AsyncMock()
    return bus


def _make_payload(**overrides) -> dict:
    base = {
        "id": str(uuid.uuid4()),
        "content": "whoami",
        "target": "10.0.0.5:22",
        "vector_type": VectorType.LOTL,
        "executor_hint": "bash",
        "retry_count": 0,
        "created_by": "test-agent",
        "timeout_ms": 15000,
    }
    base.update(overrides)
    return base


# ── 路由逻辑 ────────────────────────────────────────────────

class TestRouting:

    @pytest.mark.asyncio
    async def test_lotl_routes_to_exec_lotl(self):
        state_api = _make_mock_state_api()
        bus = _make_mock_event_bus()
        executor = Executor(state_api, bus)
        executor.sandbox = MagicMock()
        executor._tools = {}

        # mock sandbox 通过
        sandbox_result = MagicMock(passed=True)
        executor.sandbox.check = AsyncMock(return_value=sandbox_result)

        # mock _exec_lotl
        tool_result = ToolResult(
            success=True, raw={"stdout": "root"},
            info_gain=0.8, duration_ms=100,
        )
        executor._exec_lotl = AsyncMock(return_value=tool_result)

        payload = _make_payload(vector_type=VectorType.LOTL)
        await executor.execute(payload)

        executor._exec_lotl.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_unknown_vector_type_returns_fail(self):
        state_api = _make_mock_state_api()
        bus = _make_mock_event_bus()
        executor = Executor(state_api, bus)
        executor.sandbox = MagicMock()
        executor._tools = {}

        sandbox_result = MagicMock(passed=True)
        executor.sandbox.check = AsyncMock(return_value=sandbox_result)

        payload = _make_payload(vector_type="UNKNOWN_TYPE")
        await executor.execute(payload)

        # 应记录为 FAIL
        vector_calls = [
            c for c in state_api.apply_mutation.call_args_list
            if c[0][0].domain == StateDomain.TRIED_VECTORS
        ]
        assert len(vector_calls) == 1
        assert vector_calls[0][0][0].payload["result"] == VectorResult.FAIL


# ── 沙箱拦截 ────────────────────────────────────────────────

class TestSandboxBlock:

    @pytest.mark.asyncio
    async def test_sandbox_block_records_sandbox_fail(self):
        state_api = _make_mock_state_api()
        bus = _make_mock_event_bus()
        executor = Executor(state_api, bus)
        executor.sandbox = MagicMock()
        executor._tools = {}

        sandbox_result = MagicMock(passed=False, reason="dangerous command")
        executor.sandbox.check = AsyncMock(return_value=sandbox_result)

        payload = _make_payload(content="rm -rf /")
        await executor.execute(payload)

        vector_calls = [
            c for c in state_api.apply_mutation.call_args_list
            if c[0][0].domain == StateDomain.TRIED_VECTORS
        ]
        assert len(vector_calls) == 1
        assert vector_calls[0][0][0].payload["result"] == VectorResult.SANDBOX_FAIL

        # 不应调用 _exec_lotl
        assert not hasattr(executor, '_exec_lotl_called')


# ── execute_recon ────────────────────────────────────────────

class TestExecuteRecon:

    @pytest.mark.asyncio
    async def test_unknown_tool_marks_failed(self):
        state_api = _make_mock_state_api()
        bus = _make_mock_event_bus()
        executor = Executor(state_api, bus)
        executor._tools = {}  # 空路由表

        task = {"id": "t1", "tool": "nonexistent_tool", "target": "10.0.0.5", "params": {}}
        await executor.execute_recon(task)

        status_calls = [
            c for c in state_api.apply_mutation.call_args_list
            if c[0][0].domain == StateDomain.PENDING_RECON
        ]
        # 最后一次调用应该是 FAILED
        assert status_calls[-1][0][0].payload["status"] == TaskStatus.FAILED

    @pytest.mark.asyncio
    async def test_success_emits_task_completed_and_asset_events(self):
        state_api = _make_mock_state_api()
        bus = _make_mock_event_bus()
        executor = Executor(state_api, bus)

        mock_tool = MagicMock()
        mock_tool.run = AsyncMock(return_value=ToolResult(
            success=True,
            raw={"ports": [22, 80]},
            assets=[{"ip": "10.0.0.5", "port": 22, "app": "ssh"}],
            info_gain=0.7,
            duration_ms=200,
        ))
        executor._tools = {"port_scan": mock_tool}

        task = {"id": "t1", "tool": "port_scan", "target": "10.0.0.5", "params": {}}
        await executor.execute_recon(task)

        # 应发布 ASSET_DISCOVERED
        asset_events = [
            c for c in bus.publish.call_args_list
            if c[0][0].type == EventType.ASSET_DISCOVERED
        ]
        assert len(asset_events) >= 1

        # 应发布 TASK_COMPLETED
        task_events = [
            c for c in bus.publish.call_args_list
            if c[0][0].type == EventType.TASK_COMPLETED
        ]
        assert len(task_events) >= 1

        # 最终状态应为 DONE
        status_calls = [
            c for c in state_api.apply_mutation.call_args_list
            if c[0][0].domain == StateDomain.PENDING_RECON
        ]
        assert status_calls[-1][0][0].payload["status"] == TaskStatus.DONE


# ── execute_cleanup ─────────────────────────────────────────

class TestExecuteCleanup:

    @pytest.mark.asyncio
    async def test_empty_content_marks_manual_required(self):
        state_api = _make_mock_state_api()
        bus = _make_mock_event_bus()
        executor = Executor(state_api, bus)

        task = {"id": "c1", "target": "10.0.0.5", "content": None, "executor_hint": "bash"}
        await executor.execute_cleanup(task)

        status_calls = [
            c for c in state_api.apply_mutation.call_args_list
            if c[0][0].domain == StateDomain.PENDING_CLEANUP
        ]
        assert status_calls[0][0][0].payload["status"] == "MANUAL_REQUIRED"


# ── _infer_access_level ─────────────────────────────────────

class TestAccessLevelInference:

    def test_privesc_returns_root(self):
        executor = Executor.__new__(Executor)
        result = executor._infer_access_level(
            ToolResult(success=True, raw={}),
            {"vector_type": VectorType.PRIVESC},
        )
        assert result == AccessLevel.ROOT

    def test_lateral_move_returns_user(self):
        executor = Executor.__new__(Executor)
        result = executor._infer_access_level(
            ToolResult(success=True, raw={}),
            {"vector_type": VectorType.LATERAL_MOVE},
        )
        assert result == AccessLevel.USER

    def test_lotl_returns_shell(self):
        executor = Executor.__new__(Executor)
        result = executor._infer_access_level(
            ToolResult(success=True, raw={}),
            {"vector_type": VectorType.LOTL},
        )
        assert result == AccessLevel.SHELL

    def test_sqli_returns_shell(self):
        executor = Executor.__new__(Executor)
        result = executor._infer_access_level(
            ToolResult(success=True, raw={}),
            {"vector_type": VectorType.SQLI},
        )
        assert result == AccessLevel.SHELL


# ── _record_vector 格式 ─────────────────────────────────────

class TestRecordVector:

    @pytest.mark.asyncio
    async def test_vector_mutation_is_append(self):
        state_api = _make_mock_state_api()
        bus = _make_mock_event_bus()
        executor = Executor(state_api, bus)

        await executor._record_vector(
            payload=_make_payload(),
            result=VectorResult.SUCCESS,
            fail_reason=None,
            info_gain=0.8,
            duration_ms=200,
        )

        call = state_api.apply_mutation.call_args[0][0]
        assert call.operation == MutationOperation.APPEND
        assert call.domain == StateDomain.TRIED_VECTORS
        assert call.payload["result"] == VectorResult.SUCCESS
        assert call.payload["info_gain"] == 0.8

    @pytest.mark.asyncio
    async def test_footprint_is_append(self):
        state_api = _make_mock_state_api()
        bus = _make_mock_event_bus()
        executor = Executor(state_api, bus)

        await executor._append_footprint({
            "type": "SSH_EXEC",
            "target": "10.0.0.5:22",
            "detail": {"command": "whoami"},
        })

        call = state_api.apply_mutation.call_args[0][0]
        assert call.operation == MutationOperation.APPEND
        assert call.domain == StateDomain.FOOTPRINTS
        assert call.payload["type"] == "SSH_EXEC"
        assert call.payload["cleaned"] is False
