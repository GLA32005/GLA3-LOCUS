"""
test_planner.py — StatePruner + Planner 逻辑验证

策略：mock StateAPI 的所有查询方法，只测裁剪行为和 Planner 输出解析。
覆盖：
  - StatePruner: context_retrievals 按 relevance 过滤 + token 截断
  - StatePruner: pending_summary 只传计数
  - StatePruner: knowledge 列表格式正确
  - Planner: _build_prompt 包含关键 section
  - Planner: _fallback_output 结构合法
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock

from core.state_pruner import StatePruner


# ── StatePruner mock helpers ──────────────────────────────────

def _make_state_api(
    *,
    mission: dict | None = None,
    focus: dict | None = None,
    context_retrievals: list | None = None,
    vectors_summary: dict | None = None,
    hallucinations: int = 0,
    pending_count: int = 0,
    running_recon: int = 0,
    done_tasks: list | None = None,
    host_full: dict | None = None,
    subnet_summary: dict | None = None,
    lateral_paths: list | None = None,
    cred_reuse: list | None = None,
    total_hosts: int = 5,
    owned_hosts: int = 1,
):
    api = AsyncMock()
    api.get_mission           = AsyncMock(return_value=mission or {"scope": ["10.0.0.0/24"]})
    api.get_focus             = AsyncMock(return_value=focus or {"active_target": "10.0.0.5", "current_goal": "RECON"})
    api.get_vectors_summary   = AsyncMock(return_value=vectors_summary or {"total": 0})
    api.count_hallucinations  = AsyncMock(return_value=hallucinations)
    api.count_pending_payloads = AsyncMock(return_value=pending_count)
    api.count_running_recon   = AsyncMock(return_value=running_recon)
    api.get_done_tasks        = AsyncMock(return_value=done_tasks or [])
    api.get_host_full         = AsyncMock(return_value=host_full or {"host": {"ip": "10.0.0.5", "os": "Unknown", "access_level": "NONE"}, "services": [], "creds": []})
    api.get_subnet_summary    = AsyncMock(return_value=subnet_summary or [])
    api.find_lateral_paths    = AsyncMock(return_value=lateral_paths or [])
    api.find_credential_reuse = AsyncMock(return_value=cred_reuse or [])
    api.get_context_retrievals = AsyncMock(return_value=context_retrievals or [])
    api.count_hosts           = AsyncMock(return_value=total_hosts)
    api.count_owned_hosts     = AsyncMock(return_value=owned_hosts)
    return api


# ── StatePruner tests ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_pruner_returns_required_top_level_keys():
    api = _make_state_api()
    pruner = StatePruner(context_budget=8000)
    view = await pruner.generate_view(api)

    required = {"mission", "focus", "vectors_summary", "assets", "knowledge",
                "pending_summary", "_meta"}
    assert required.issubset(view.keys())


@pytest.mark.asyncio
async def test_pruner_meta_tracks_budget():
    api = _make_state_api()
    pruner = StatePruner(context_budget=8000)
    view = await pruner.generate_view(api)

    meta = view["_meta"]
    assert meta["budget"] == 8000
    assert meta["estimated_tokens"] <= 8000
    assert meta["active_target"] == "10.0.0.5"


@pytest.mark.asyncio
async def test_pruner_filters_low_relevance_retrievals():
    retrievals = [
        {"content": "low",  "relevance": 0.4, "source": "cve_db", "summary": "low"},
        {"content": "mid",  "relevance": 0.65, "source": "cve_db", "summary": "mid"},
        {"content": "high", "relevance": 0.9, "source": "lotl_db", "summary": "high"},
    ]
    api = _make_state_api(context_retrievals=retrievals)
    pruner = StatePruner(context_budget=8000)
    view = await pruner.generate_view(api)

    knowledge = view["knowledge"]
    # only relevance >= 0.6 should pass
    assert all(k["relevance"] >= 0.6 for k in knowledge)
    assert len(knowledge) == 2   # mid(0.65) and high(0.9)


@pytest.mark.asyncio
async def test_pruner_respects_token_budget_for_retrievals():
    # Fill retrievals to exceed budget
    retrievals = [
        {"content": f"item{i}", "relevance": 0.9, "source": "x", "summary": "s" * 10}
        for i in range(100)
    ]
    api = _make_state_api(context_retrievals=retrievals)
    pruner = StatePruner(context_budget=3000)   # tight budget
    view = await pruner.generate_view(api)

    # retrieval budget = 20% of (3000 - fixed) ≈ small
    # each item costs 150 tokens → should be truncated
    assert len(view["knowledge"]) < 100


@pytest.mark.asyncio
async def test_pruner_pending_summary_contains_counts():
    api = _make_state_api(pending_count=3, running_recon=2)
    pruner = StatePruner()
    view = await pruner.generate_view(api)

    ps = view["pending_summary"]
    assert ps["payloads_pending"] == 3
    assert ps["recon_running"] == 2


@pytest.mark.asyncio
async def test_pruner_lateral_opportunities_included_when_present():
    paths = [{"from": "A", "to": "B"}, {"from": "B", "to": "C"}]
    api = _make_state_api(lateral_paths=paths)
    pruner = StatePruner()
    view = await pruner.generate_view(api)

    assert "lateral_opportunities" in view
    assert len(view["lateral_opportunities"]) == 2


@pytest.mark.asyncio
async def test_pruner_no_lateral_key_when_empty():
    api = _make_state_api(lateral_paths=[])
    pruner = StatePruner()
    view = await pruner.generate_view(api)

    assert "lateral_opportunities" not in view


@pytest.mark.asyncio
async def test_pruner_banner_truncated_at_200_chars():
    long_banner = "X" * 500
    host = {"ip": "10.0.0.5", "services": [{"port": 80, "banner": long_banner}]}
    api = _make_state_api(host_full=host)
    pruner = StatePruner()
    view = await pruner.generate_view(api)

    svc = view["assets"]["active_host"]["services"][0]
    assert len(svc["banner"]) <= 203   # 200 chars + "..."


@pytest.mark.asyncio
async def test_pruner_no_active_host_when_no_focus_target():
    api = _make_state_api(focus={"active_target": None, "current_goal": "RECON"})
    pruner = StatePruner()
    view = await pruner.generate_view(api)

    assert "active_host" not in view.get("assets", {})


# ── Planner tests ─────────────────────────────────────────────

class TestPlannerBuildPrompt:

    def setup_method(self):
        from core.planner import Planner
        self.planner = Planner.__new__(Planner)

    def _make_view(self, **overrides):
        base = {
            "mission":   {"scope": ["10.0.0.0/24"], "risk_level": 3, "max_noise": 8},
            "focus":     {"active_target": "10.0.0.5", "current_goal": "RECON",
                          "hypothesis": "SMB open", "confidence": 0.6, "stall_count": 0},
            "vectors_summary": {"total": 2, "hallucination_count": 0},
            "assets":    {"active_host": {
                "host": {"ip": "10.0.0.5", "os": "Linux", "access_level": "NONE"},
                "services": [],
            }},
            "knowledge": [],
            "pending_summary": {"payloads_pending": 0, "recon_running": 1, "async_tasks_done": 0},
            "_meta":     {"estimated_tokens": 1500, "budget": 8000, "active_target": "10.0.0.5"},
        }
        base.update(overrides)
        return base

    def test_prompt_contains_scope(self):
        prompt = self.planner._build_prompt(self._make_view())
        assert "10.0.0.0/24" in prompt

    def test_prompt_contains_active_target(self):
        prompt = self.planner._build_prompt(self._make_view())
        assert "10.0.0.5" in prompt

    def test_prompt_contains_goal(self):
        prompt = self.planner._build_prompt(self._make_view())
        assert "RECON" in prompt

    def test_prompt_contains_current_goal(self):
        prompt = self.planner._build_prompt(self._make_view())
        # current_goal is rendered as "当前目标: RECON"
        assert "RECON" in prompt

    def test_prompt_contains_stall_count(self):
        view = self._make_view()
        view["focus"]["stall_count"] = 3
        prompt = self.planner._build_prompt(view)
        assert "3" in prompt


class TestPlannerFallbackOutput:

    def setup_method(self):
        from core.planner import Planner
        self.planner = Planner.__new__(Planner)

    def test_fallback_has_required_keys(self):
        out = self.planner._fallback_output()
        # top-level keys
        assert "act" in out
        assert "rag_query" in out
        # act sub-keys
        assert "agent" in out["act"]
        assert "action_type" in out["act"]

    def test_fallback_agent_is_recon(self):
        out = self.planner._fallback_output()
        assert out["act"]["agent"] == "recon"
