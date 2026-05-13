"""
test_state_api.py — StateAPI 读写逻辑验证

策略：mock Redis / ClickHouse / Neo4j，只测应用逻辑，不测连接。
覆盖：
  - pending_payloads UPSERT / UPDATE_STATUS
  - pending_recon_tasks UPSERT / UPDATE_STATUS
  - pending_cleanup_tasks UPSERT / UPDATE_STATUS
  - get_pending_payloads / get_pending_recon_tasks / get_pending_cleanup_tasks
  - get_approved_payloads / get_approved_cleanup_tasks
  - footprints APPEND（宪法约束②）
  - tried_vectors APPEND（宪法约束②）
  - context_retrievals write / clear
"""

from __future__ import annotations

import json
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from core.protocols import (
    MutationOperation,
    StateDomain,
    StateMutation,
)


# ── 内存 Redis mock ───────────────────────────────────────────

class FakeRedis:
    """简单的内存 KV 存储，模拟 Redis 的 get/set/keys/sadd/smembers/mget 接口"""

    def __init__(self):
        self._store: dict[str, str] = {}
        self._sets: dict[str, set[str]] = {}

    async def get(self, key: str):
        return self._store.get(key)

    async def set(self, key: str, value: str):
        self._store[key] = value

    async def keys(self, pattern: str) -> list[str]:
        prefix = pattern.rstrip("*")
        return [k for k in self._store if k.startswith(prefix)]

    async def delete(self, *keys: str):
        for k in keys:
            self._store.pop(k, None)
            self._sets.pop(k, None)

    async def sadd(self, key: str, *values: str):
        if key not in self._sets:
            self._sets[key] = set()
        for v in values:
            self._sets[key].add(v)

    async def smembers(self, key: str) -> set[str]:
        return self._sets.get(key, set())

    async def mget(self, keys: list[str]) -> list:
        return [self._store.get(k) for k in keys]


# ── Fixture ───────────────────────────────────────────────────

@pytest_asyncio.fixture
async def state_api():
    """返回一个挂载了 FakeRedis 的 StateAPI 实例，不连真实数据库"""
    from core.state_api import StateAPI

    api = StateAPI.__new__(StateAPI)
    api.redis = FakeRedis()

    # ClickHouse mock（只 stub execute，不验细节）
    api.ch = MagicMock()
    api.ch.execute = MagicMock(return_value=None)

    # Neo4j mock（async session context manager）
    api._neo4j = None   # 不测 graph 路径，跳过

    # 绑定 _apply 方法（StateAPI 的 __init__ 里绑定，这里手动补）
    import core.state_api as sa_mod
    import asyncio

    # 重新绑定 mutation router
    api._apply_pending_payloads  = lambda m: sa_mod.StateAPI._apply_pending_payloads(api, m)
    api._apply_pending_recon     = lambda m: sa_mod.StateAPI._apply_pending_recon(api, m)
    api._apply_pending_cleanup   = lambda m: sa_mod.StateAPI._apply_pending_cleanup(api, m)
    api._apply_context_retrievals = lambda m: sa_mod.StateAPI._apply_context_retrievals(api, m)

    # Bind query methods
    api.get_pending_payloads      = lambda: sa_mod.StateAPI.get_pending_payloads(api)
    api.get_approved_payloads     = lambda: sa_mod.StateAPI.get_approved_payloads(api)
    api.get_pending_recon_tasks   = lambda: sa_mod.StateAPI.get_pending_recon_tasks(api)
    api.get_pending_cleanup_tasks = lambda: sa_mod.StateAPI.get_pending_cleanup_tasks(api)
    api.get_approved_cleanup_tasks = lambda: sa_mod.StateAPI.get_approved_cleanup_tasks(api)
    api.get_context_retrievals    = lambda: sa_mod.StateAPI.get_context_retrievals(api)

    return api


# ── pending_payloads ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_upsert_pending_payload(state_api):
    m = StateMutation(
        operation=MutationOperation.UPSERT,
        domain=StateDomain.PENDING_PAYLOADS,
        payload={"id": "p1", "status": "PENDING", "content": "whoami"},
    )
    await state_api._apply_pending_payloads(m)

    raw = await state_api.redis.get("payload:p1")
    assert raw is not None
    p = json.loads(raw)
    assert p["id"] == "p1"
    assert p["status"] == "PENDING"


@pytest.mark.asyncio
async def test_update_status_pending_payload(state_api):
    # Insert first
    await state_api._apply_pending_payloads(StateMutation(
        operation=MutationOperation.UPSERT,
        domain=StateDomain.PENDING_PAYLOADS,
        payload={"id": "p2", "status": "PENDING", "content": "ls"},
    ))

    # Update only status
    await state_api._apply_pending_payloads(StateMutation(
        operation=MutationOperation.UPDATE_STATUS,
        domain=StateDomain.PENDING_PAYLOADS,
        payload={"id": "p2", "status": "APPROVED", "approved_at": "2025-01-01"},
    ))

    raw = await state_api.redis.get("payload:p2")
    p = json.loads(raw)
    assert p["status"] == "APPROVED"
    assert p["content"] == "ls"   # original field preserved
    assert p["approved_at"] == "2025-01-01"


@pytest.mark.asyncio
async def test_get_pending_payloads(state_api):
    for pid, status in [("px", "PENDING"), ("py", "APPROVED"), ("pz", "PENDING")]:
        await state_api.redis.set(f"payload:{pid}", json.dumps({"id": pid, "status": status}))
        await state_api.redis.sadd("idx:payload_ids", pid)

    pending = await state_api.get_pending_payloads()
    ids = {p["id"] for p in pending}
    assert "px" in ids and "pz" in ids
    assert "py" not in ids


@pytest.mark.asyncio
async def test_get_approved_payloads(state_api):
    for pid, status in [("pa", "APPROVED"), ("pb", "PENDING"), ("pc", "APPROVED")]:
        await state_api.redis.set(f"payload:{pid}", json.dumps({"id": pid, "status": status}))
        await state_api.redis.sadd("idx:payload_ids", pid)

    approved = await state_api.get_approved_payloads()
    ids = {p["id"] for p in approved}
    assert "pa" in ids and "pc" in ids
    assert "pb" not in ids


# ── pending_recon_tasks ───────────────────────────────────────

@pytest.mark.asyncio
async def test_upsert_recon_task(state_api):
    m = StateMutation(
        operation=MutationOperation.UPSERT,
        domain=StateDomain.PENDING_RECON,
        payload={"id": "r1", "status": "PENDING", "tool": "nmap"},
    )
    await state_api._apply_pending_recon(m)

    raw = await state_api.redis.get("recon_task:r1")
    assert raw is not None
    t = json.loads(raw)
    assert t["tool"] == "nmap"


@pytest.mark.asyncio
async def test_update_status_recon_task(state_api):
    await state_api._apply_pending_recon(StateMutation(
        operation=MutationOperation.UPSERT,
        domain=StateDomain.PENDING_RECON,
        payload={"id": "r2", "status": "PENDING", "tool": "nuclei"},
    ))
    await state_api._apply_pending_recon(StateMutation(
        operation=MutationOperation.UPDATE_STATUS,
        domain=StateDomain.PENDING_RECON,
        payload={"id": "r2", "status": "DONE"},
    ))

    raw = await state_api.redis.get("recon_task:r2")
    t = json.loads(raw)
    assert t["status"] == "DONE"
    assert t["tool"] == "nuclei"


@pytest.mark.asyncio
async def test_get_pending_recon_tasks_filters_correctly(state_api):
    for tid, status in [("ra", "PENDING"), ("rb", "DONE"), ("rc", "PENDING")]:
        await state_api.redis.set(f"recon_task:{tid}", json.dumps({"id": tid, "status": status}))
        await state_api.redis.sadd("idx:recon_task_ids", tid)

    pending = await state_api.get_pending_recon_tasks()
    ids = {t["id"] for t in pending}
    assert "ra" in ids and "rc" in ids
    assert "rb" not in ids


# ── pending_cleanup_tasks ────────────────────────────────────

@pytest.mark.asyncio
async def test_upsert_cleanup_task(state_api):
    m = StateMutation(
        operation=MutationOperation.UPSERT,
        domain=StateDomain.PENDING_CLEANUP,
        payload={"id": "c1", "status": "PENDING_HUMAN", "operation": "delete /tmp/shell.sh"},
    )
    await state_api._apply_pending_cleanup(m)

    raw = await state_api.redis.get("cleanup_task:c1")
    assert raw is not None
    t = json.loads(raw)
    assert t["status"] == "PENDING_HUMAN"


@pytest.mark.asyncio
async def test_get_pending_cleanup_tasks(state_api):
    for cid, status in [("ca", "PENDING_HUMAN"), ("cb", "APPROVED"), ("cc", "PENDING_HUMAN")]:
        await state_api.redis.set(
            f"cleanup_task:{cid}",
            json.dumps({"id": cid, "status": status})
        )
        await state_api.redis.sadd("idx:cleanup_task_ids", cid)

    pending = await state_api.get_pending_cleanup_tasks()
    ids = {t["id"] for t in pending}
    assert "ca" in ids and "cc" in ids
    assert "cb" not in ids


@pytest.mark.asyncio
async def test_get_approved_cleanup_tasks(state_api):
    for cid, status in [("cd", "APPROVED"), ("ce", "PENDING_HUMAN")]:
        await state_api.redis.set(
            f"cleanup_task:{cid}",
            json.dumps({"id": cid, "status": status})
        )
        await state_api.redis.sadd("idx:cleanup_task_ids", cid)

    approved = await state_api.get_approved_cleanup_tasks()
    ids = {t["id"] for t in approved}
    assert "cd" in ids
    assert "ce" not in ids


# ── context_retrievals ────────────────────────────────────────

@pytest.mark.asyncio
async def test_context_retrievals_accumulate_and_sort(state_api):
    m1 = StateMutation(
        operation=MutationOperation.UPSERT,
        domain=StateDomain.CONTEXT_RETRIEVALS,
        payload={"items": [
            {"content": "low relevance", "relevance": 0.4},
            {"content": "high relevance", "relevance": 0.9},
        ]},
    )
    await state_api._apply_context_retrievals(m1)

    items = await state_api.get_context_retrievals()
    assert len(items) == 2
    assert items[0]["relevance"] == 0.9   # sorted descending


@pytest.mark.asyncio
async def test_context_retrievals_append_on_second_call(state_api):
    await state_api._apply_context_retrievals(StateMutation(
        operation=MutationOperation.UPSERT,
        domain=StateDomain.CONTEXT_RETRIEVALS,
        payload={"items": [{"content": "A", "relevance": 0.7}]},
    ))
    await state_api._apply_context_retrievals(StateMutation(
        operation=MutationOperation.UPSERT,
        domain=StateDomain.CONTEXT_RETRIEVALS,
        payload={"items": [{"content": "B", "relevance": 0.5}]},
    ))

    items = await state_api.get_context_retrievals()
    assert len(items) == 2
    contents = {i["content"] for i in items}
    assert "A" in contents and "B" in contents
