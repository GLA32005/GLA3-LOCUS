import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from core.orchestrator import EventBus, Orchestrator
from core.protocols import (
    Event, EventType, StateMutation, StateDomain, 
    MutationOperation, AgentType, NodeOutput, TaskStatus
)
from executor.executor import Executor
from executor.tools.shell_tools import BannerGrabTool

def _make_mock_orchestrator():
    state_api = AsyncMock()
    state_api.get_mission = AsyncMock(return_value={"max_noise": 50})
    state_api.get_focus = AsyncMock(return_value={
        "active_target": "1.1.1.1",
        "current_goal": "RECON",
        "stall_count": 0
    })
    state_api.update_focus_atomic = AsyncMock()
    state_api.apply_mutation = AsyncMock(return_value=True)
    state_api.redis = AsyncMock()
    
    event_bus = EventBus()
    planner = AsyncMock()
    exploit_agent = AsyncMock()
    recon_agent = AsyncMock()
    critic_agent = AsyncMock()
    cleanup_agent = AsyncMock()
    executor = AsyncMock()
    rag = AsyncMock()

    orch = Orchestrator(
        state_api, event_bus, planner, exploit_agent, recon_agent,
        critic_agent, cleanup_agent, executor, rag
    )
    return orch

@pytest.mark.asyncio
async def test_target_unreachable_trigger():
    """验证 Issue 1 & 6: 连续 3 次超时触发 TARGET_UNREACHABLE"""
    orch = _make_mock_orchestrator()
    target = "1.1.1.1"
    
    # 模拟 3 次超时
    for i in range(3):
        event = Event(
            type=EventType.TASK_COMPLETED,
            source="executor",
            payload={
                "task_id": f"task_{i}",
                "result": {"target": target, "tool": "nmap", "status": "TIMEOUT"}
            }
        )
        await orch._handle_task_completed(event)
    
    # 验证是否发布了 TARGET_UNREACHABLE 事件
    # 注意：EventBus.publish 是异步的，这里直接检查是否调用了 apply_mutation (标记不可达)
    calls = [c for c in orch.state_api.apply_mutation.call_args_list 
             if c[0][0].domain == StateDomain.ASSETS and c[0][0].payload.get("unreachable")]
    assert len(calls) >= 1
    assert calls[0][0][0].payload["ip"] == target

@pytest.mark.asyncio
async def test_banner_grab_filtering():
    """验证 Issue 2: 过滤 Ncat: TIMEOUT 等无效 Banner"""
    tool = BannerGrabTool()
    
    # 模拟 ncat 返回超时信息
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"Ncat: Version 7.95 ( https://nmap.org/ncat )\nNcat: TIMEOUT.")
        mock_exec.return_value = mock_proc
        
        result = await tool.run("1.1.1.1:80", {"timeout_s": 1})
        
        # 验证 success 为 False 且没有资产生成
        assert result.success is False
        assert len(result.assets) == 0

@pytest.mark.asyncio
async def test_asset_canonicalization():
    """验证 Issue 3: 域名自动解析归一化"""
    state_api = AsyncMock()
    event_bus = EventBus()
    executor = Executor(state_api, event_bus)
    
    asset = {"ip": "localhost", "services": [{"port": 80}]}
    
    # 模拟解析 localhost -> 127.0.0.1
    with patch("socket.gethostbyname", return_value="127.0.0.1"):
        await executor._upsert_asset(asset)
        
    # 验证写入 state_api 时使用的是 127.0.0.1
    call_payload = state_api.apply_mutation.call_args[0][0].payload
    assert call_payload["ip"] == "127.0.0.1"
    assert call_payload["domain"] == "localhost"

@pytest.mark.asyncio
async def test_deadlock_hint_injection():
    """验证 Issue 4: EXPLOIT 拦截时注入 Hint"""
    orch = _make_mock_orchestrator()
    target = "1.1.1.1"
    
    # 先设置一次超时，让计数器 > 0
    orch._host_timeouts[target] = 1
    
    # 模拟 Planner 尝试切换到 EXPLOIT
    planner_output = {
        "focus_update": {"current_goal": "EXPLOIT", "active_target": target},
        "act": {"agent": "exploit"}
    }
    
    # 模拟目标无服务信息
    orch.state_api.get_host_full.return_value = {"services": []}
    
    await orch._dispatch_planner_output(planner_output)
    
    # 验证 goal 被回退且注入了 hint
    assert orch._system_hint is not None
    assert "重新评估该目标的可达性" in orch._system_hint
