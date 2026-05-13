"""
test_rag_engine.py — RAG Engine 测试

覆盖：
  - keyword_fallback 正常检索
  - type_filter 过滤
  - CVE 精确匹配
  - CVE + 语义混合查询
  - 空查询处理
  - results_to_state 转换
  - relevance 阈值过滤
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from memory.rag_engine import RAGEngine, RetrievalResult, _BUILTIN_KNOWLEDGE


# ── Fixtures ────────────────────────────────────────────────

@pytest.fixture
def engine_no_chroma(monkeypatch):
    """强制禁用 ChromaDB，走 keyword_fallback 路径"""
    e = RAGEngine.__new__(RAGEngine)
    e._chroma = None
    return e


# ── Keyword Fallback ────────────────────────────────────────

class TestKeywordFallback:

    @pytest.mark.asyncio
    async def test_basic_query_returns_results(self, engine_no_chroma):
        results = await engine_no_chroma.query("certutil download payload", top_k=3)
        assert len(results) > 0
        assert all(isinstance(r, RetrievalResult) for r in results)

    @pytest.mark.asyncio
    async def test_results_sorted_by_relevance_desc(self, engine_no_chroma):
        results = await engine_no_chroma.query("certutil download", top_k=5)
        relevances = [r.relevance for r in results]
        assert relevances == sorted(relevances, reverse=True)

    @pytest.mark.asyncio
    async def test_empty_query_returns_empty(self, engine_no_chroma):
        results = await engine_no_chroma.query("", top_k=5)
        assert results == []

    @pytest.mark.asyncio
    async def test_whitespace_query_returns_empty(self, engine_no_chroma):
        results = await engine_no_chroma.query("   ", top_k=5)
        assert results == []


# ── Type Filter ─────────────────────────────────────────────

class TestTypeFilter:

    @pytest.mark.asyncio
    async def test_filter_cve_only(self, engine_no_chroma):
        results = await engine_no_chroma.query(
            "vulnerability exploit", top_k=10, type_filter="CVE"
        )
        assert all(r.source == "cve_db" for r in results)

    @pytest.mark.asyncio
    async def test_filter_lotl_only(self, engine_no_chroma):
        results = await engine_no_chroma.query(
            "certutil download execution", top_k=10, type_filter="LotL"
        )
        assert all(r.source == "lotl_db" for r in results)

    @pytest.mark.asyncio
    async def test_filter_bypass_only(self, engine_no_chroma):
        results = await engine_no_chroma.query(
            "CrowdStrike evasion", top_k=10, type_filter="Bypass"
        )
        assert all(r.source == "edr_bypass" for r in results)

    @pytest.mark.asyncio
    async def test_filter_methodology_only(self, engine_no_chroma):
        results = await engine_no_chroma.query(
            "Kerberoasting hash cracking", top_k=10, type_filter="Methodology"
        )
        assert all(r.source == "methodology" for r in results)

    @pytest.mark.asyncio
    async def test_no_filter_returns_mixed_sources(self, engine_no_chroma):
        results = await engine_no_chroma.query(
            "certutil powershell CrowdStrike Kerberoasting", top_k=10
        )
        sources = {r.source for r in results}
        assert len(sources) > 1


# ── CVE Exact Match ─────────────────────────────────────────

class TestCVEExactMatch:

    @pytest.mark.asyncio
    async def test_exact_cve_match_returns_099_relevance(self, engine_no_chroma):
        results = await engine_no_chroma.query("CVE-2021-44228 Log4Shell")
        assert any(r.relevance == 0.99 for r in results)
        assert any("Log4Shell" in r.content or "Log4j" in r.content for r in results)

    @pytest.mark.asyncio
    async def test_exact_cve_match_proxylogon(self, engine_no_chroma):
        results = await engine_no_chroma.query("check CVE-2021-26855")
        assert len(results) >= 1
        assert any("ProxyLogon" in r.content for r in results)

    @pytest.mark.asyncio
    async def test_exact_cve_match_deduplicates(self, engine_no_chroma):
        """同一 CVE 不应出现重复条目"""
        results = await engine_no_chroma.query("CVE-2021-44228")
        contents = [r.content[:80] for r in results]
        assert len(contents) == len(set(contents))

    @pytest.mark.asyncio
    async def test_nonexistent_cve_falls_to_semantic(self, engine_no_chroma):
        results = await engine_no_chroma.query("CVE-9999-99999")
        # 不应返回 0.99 精确匹配
        for r in results:
            assert r.relevance < 0.99


# ── results_to_state ────────────────────────────────────────

class TestResultsToState:

    def test_filters_below_min_relevance(self, engine_no_chroma):
        results = [
            RetrievalResult(content="high", source="test", relevance=0.8),
            RetrievalResult(content="low", source="test", relevance=0.3),
            RetrievalResult(content="border", source="test", relevance=0.6),
        ]
        state = engine_no_chroma.results_to_state(results)
        assert len(state) == 2
        assert all(s["relevance"] >= 0.6 for s in state)

    def test_output_format(self, engine_no_chroma):
        results = [
            RetrievalResult(
                content="test content",
                source="cve_db",
                relevance=0.9,
                metadata={"cve": "CVE-2021-44228"},
            ),
        ]
        state = engine_no_chroma.results_to_state(results)
        assert state[0]["content"] == "test content"
        assert state[0]["source"] == "cve_db"
        assert state[0]["relevance"] == 0.9
        assert state[0]["metadata"]["cve"] == "CVE-2021-44228"

    def test_empty_results(self, engine_no_chroma):
        assert engine_no_chroma.results_to_state([]) == []


# ── Top-K 限制 ──────────────────────────────────────────────

class TestTopK:

    @pytest.mark.asyncio
    async def test_top_k_limits_results(self, engine_no_chroma):
        results = await engine_no_chroma.query("attack", top_k=2)
        assert len(results) <= 2

    @pytest.mark.asyncio
    async def test_top_k_1(self, engine_no_chroma):
        results = await engine_no_chroma.query("attack", top_k=1)
        assert len(results) <= 1
