"""
test_report_generator.py — Report Generator 测试

覆盖：
  - _build_executive_summary 格式
  - _render_markdown 基本结构
  - _render_markdown 无发现时的降级文本
  - _render_markdown 带修复建议
  - _save_report 文件写入
  - generate 完整流程（mock state_api + LLM）
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.report_generator import ReportGenerator


# ── Fixtures ────────────────────────────────────────────────

@pytest.fixture
def generator():
    """创建不连 LLM 的 ReportGenerator"""
    g = ReportGenerator.__new__(ReportGenerator)
    g.api_key = "test-key"
    g.base_url = "http://test-url"
    g._client = MagicMock()
    g._model = "test-model"
    return g


@pytest.fixture
def sample_findings():
    return [
        {
            "id": "f1",
            "target": "10.0.0.5:445",
            "type": "LOTL",
            "payload": "certutil",
            "result": "SUCCESS",
            "fail_reason": None,
            "info_gain": 0.8,
            "retry_count": 0,
            "ts": "2025-01-01T10:00:00",
        },
    ]


@pytest.fixture
def sample_cleanup():
    return {
        "total_footprints": 3,
        "cleaned": 2,
        "uncleaned": 1,
        "cleanup_rate": "66.7%",
        "details": [
            {"id": "fp1", "type": "FILE_WRITE", "target": "10.0.0.5", "cleaned": True, "ts": ""},
            {"id": "fp2", "type": "SSH_EXEC", "target": "10.0.0.5", "cleaned": True, "ts": ""},
            {"id": "fp3", "type": "WEBSHELL", "target": "10.0.0.6", "cleaned": False, "ts": ""},
        ],
    }


@pytest.fixture
def sample_stats():
    return {
        "total_vectors": 10,
        "success_count": 2,
        "fail_count": 6,
        "blocked_count": 1,
        "abandoned_count": 1,
        "success_rate": "20.0%",
        "avg_info_gain": 0.45,
        "total_hosts": 5,
        "owned_hosts": 2,
        "hallucination_count": 1,
    }


@pytest.fixture
def sample_mission():
    return {
        "goal": "全面渗透测试",
        "scope": ["10.0.0.0/24"],
        "risk_level": 3,
    }


# ── Executive Summary ───────────────────────────────────────

class TestExecutiveSummary:

    def test_contains_key_metrics(
        self, generator, sample_findings, sample_cleanup, sample_stats, sample_mission
    ):
        summary = generator._build_executive_summary(
            sample_findings, sample_cleanup, sample_stats, sample_mission
        )
        assert "10.0.0.0/24" in summary
        assert "10" in summary        # total_vectors
        assert "2" in summary         # success_count
        assert "66.7%" in summary     # cleanup_rate

    def test_empty_findings(
        self, generator, sample_cleanup, sample_stats, sample_mission
    ):
        summary = generator._build_executive_summary(
            [], sample_cleanup, sample_stats, sample_mission
        )
        assert "0 次" in summary or "0" in summary


# ── Markdown Rendering ──────────────────────────────────────

class TestMarkdownRendering:

    def test_contains_report_sections(self, generator, sample_mission):
        report = {
            "generated_at": "2025-01-01T00:00:00",
            "mission": sample_mission,
            "executive_summary": "测试摘要",
            "findings": [],
            "assets_summary": [],
            "cleanup_verification": {"total_footprints": 0, "cleaned": 0,
                                      "uncleaned": 0, "cleanup_rate": "N/A", "details": []},
            "statistics": {"total_vectors": 0, "success_count": 0},
            "recommendations": [],
        }
        md = generator._render_markdown(report)
        assert "# 渗透测试报告" in md
        assert "## 1. 执行摘要" in md
        assert "## 2. 资产发现" in md
        assert "## 3. 攻击发现" in md
        assert "## 4. 清理验证" in md
        assert "## 5. 统计数据" in md
        assert "## 6. 修复建议" in md

    def test_no_findings_shows_placeholder(self, generator, sample_mission):
        report = {
            "generated_at": "2025-01-01",
            "mission": sample_mission,
            "executive_summary": "test",
            "findings": [],
            "cleanup_verification": {"total_footprints": 0, "cleaned": 0,
                                      "uncleaned": 0, "cleanup_rate": "N/A", "details": []},
            "statistics": {},
            "recommendations": [],
        }
        md = generator._render_markdown(report)
        assert "无成功的攻击发现" in md

    def test_findings_rendered_as_table(
        self, generator, sample_findings, sample_cleanup, sample_mission
    ):
        report = {
            "generated_at": "2025-01-01",
            "mission": sample_mission,
            "executive_summary": "test",
            "findings": sample_findings,
            "cleanup_verification": sample_cleanup,
            "statistics": {},
            "recommendations": [],
        }
        md = generator._render_markdown(report)
        assert "10.0.0.5:445" in md
        assert "LOTL" in md
        assert "| #" in md  # table header

    def test_recommendations_rendered(
        self, generator, sample_mission
    ):
        report = {
            "generated_at": "2025-01-01",
            "mission": sample_mission,
            "executive_summary": "test",
            "findings": [],
            "cleanup_verification": {"total_footprints": 0, "cleaned": 0,
                                      "uncleaned": 0, "cleanup_rate": "N/A", "details": []},
            "statistics": {},
            "recommendations": [
                {
                    "priority": "CRITICAL",
                    "target": "10.0.0.5",
                    "finding": "Log4Shell",
                    "recommendation": "Upgrade to 2.15.0+",
                    "references": ["CVE-2021-44228"],
                }
            ],
        }
        md = generator._render_markdown(report)
        assert "CRITICAL" in md
        assert "Log4Shell" in md
        assert "CVE-2021-44228" in md


# ── Save Report ─────────────────────────────────────────────

class TestSaveReport:

    def test_creates_md_and_json(self, generator, sample_mission):
        report = {
            "generated_at": "2025-01-01T00:00:00",
            "mission": sample_mission,
            "executive_summary": "test summary",
            "findings": [],
            "cleanup_verification": {},
            "statistics": {},
            "recommendations": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = generator._save_report(report, tmpdir)
            assert os.path.exists(md_path)
            assert md_path.endswith(".md")

            # JSON 文件也应存在
            json_path = md_path.replace(".md", ".json")
            assert os.path.exists(json_path)

            with open(json_path) as f:
                loaded = json.load(f)
            assert loaded["mission"]["scope"] == ["10.0.0.0/24"]

    def test_creates_output_dir(self, generator, sample_mission):
        report = {
            "generated_at": "2025-01-01",
            "mission": sample_mission,
            "executive_summary": "test",
            "findings": [],
            "cleanup_verification": {},
            "statistics": {},
            "recommendations": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            nested = os.path.join(tmpdir, "sub", "reports")
            md_path = generator._save_report(report, nested)
            assert os.path.exists(md_path)


# ── Generate 完整流程 ──────────────────────────────────────

class TestGenerate:

    @pytest.mark.asyncio
    async def test_generate_with_no_findings_skips_llm(self, generator):
        """无成功发现时，不调用 LLM 生成建议"""
        state_api = MagicMock()
        state_api.ch = MagicMock()
        state_api.ch.execute = MagicMock(return_value=[])  # ClickHouse 无成功记录
        state_api.get_all_footprints = AsyncMock(return_value=[])
        state_api.get_vectors_summary = AsyncMock(return_value={"total": 0})
        state_api.count_hosts = AsyncMock(return_value=0)
        state_api.count_owned_hosts = AsyncMock(return_value=0)
        state_api.count_hallucinations = AsyncMock(return_value=0)
        state_api.neo4j = MagicMock()

        mission = {"goal": "test", "scope": ["10.0.0.0/24"], "risk_level": 3}

        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["REPORT_OUTPUT_DIR"] = tmpdir
            try:
                report = await generator.generate(state_api, mission)
            finally:
                del os.environ["REPORT_OUTPUT_DIR"]

        assert "executive_summary" in report
        assert report["findings"] == []
        assert report["recommendations"] == []

    @pytest.mark.asyncio
    async def test_generate_calls_llm_with_findings(self, generator):
        """有成功发现时，调用 LLM 生成建议"""
        state_api = MagicMock()
        # mock ClickHouse execute 返回成功记录
        mock_result = [("f1", "10.0.0.5:445", "LOTL", "certutil", "SUCCESS",
                        "UNKNOWN", 0.8, 0, "2025-01-01T10:00:00")]
        state_api.ch = MagicMock()
        state_api.ch.execute = MagicMock(return_value=mock_result)
        state_api.get_all_footprints = AsyncMock(return_value=[])
        state_api.get_vectors_summary = AsyncMock(return_value={"total": 1, "success_count": 1})
        state_api.count_hosts = AsyncMock(return_value=1)
        state_api.count_owned_hosts = AsyncMock(return_value=1)
        state_api.count_hallucinations = AsyncMock(return_value=0)
        # mock Neo4j
        state_api.neo4j = MagicMock()

        # mock LLM 返回修复建议
        recs = [{"priority": "HIGH", "target": "10.0.0.5",
                 "finding": "Log4Shell", "recommendation": "upgrade", "references": []}]
        
        # mock assets
        state_api.neo4j.session.return_value.__enter__.return_value.run.return_value = [
            {"ip": "10.0.0.5", "access_level": "ROOT", "os": "Linux", "out_of_scope": False, "open_ports": [22, 80]}
        ]

        with patch("core.report_generator.call_llm_anthropic_style", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = (json.dumps(recs), 100)

        mission = {"goal": "test", "scope": ["10.0.0.0/24"], "risk_level": 3}

        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["REPORT_OUTPUT_DIR"] = tmpdir
            try:
                report = await generator.generate(state_api, mission)
            finally:
                del os.environ["REPORT_OUTPUT_DIR"]

        assert len(report["findings"]) == 1
        assert len(report["recommendations"]) == 1
        assert "10.0.0.5" in report["executive_summary"]
        mock_llm.assert_awaited_once()
