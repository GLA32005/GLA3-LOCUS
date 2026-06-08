"""
State API — Blackboard 访问层
所有组件通过此层读写 State，不直接操作 Redis/Neo4j/ClickHouse
"""

from __future__ import annotations
from typing import Optional, Any
from datetime import datetime, timezone
import json
from enum import Enum
import redis.asyncio as redis
from neo4j import GraphDatabase
import asyncio
import logging

logger = logging.getLogger("StateAPI")

from .protocols import (
    StateMutation, StateDomain, MutationOperation,
    AccessLevel, TaskStatus, PayloadStatus
)

# ── 辅助：支持 Enum 的 JSON 序列化 ───────────────────────────

class EnumEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)

def json_dumps(obj):
    return json.dumps(obj, cls=EnumEncoder)


class StateAPI:
    """
    Blackboard 的统一访问接口。
    三组存储后端对调用方完全透明：
      - Redis:      focus / pending_* / async_tasks / context_retrievals
      - Neo4j:      assets 图谱
      - ClickHouse: tried_vectors / footprints（追加只写）
    """

    def __init__(self, redis_url: str, neo4j_url: str, neo4j_auth: tuple,
                 clickhouse_client):
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.neo4j = GraphDatabase.driver(neo4j_url, auth=neo4j_auth)
        self.ch = clickhouse_client
        self._ch_lock = asyncio.Lock()  # ClickHouse 驱动非线程安全，必须加锁

        # Lua script for atomic FOCUS update (Read-Modify-Write protection)
        self._focus_update_lua = self.redis.register_script("""
            local key = KEYS[1]
            local updates_json = ARGV[1]
            local updates = cjson.decode(updates_json)
            
            local current_raw = redis.call('get', key)
            local current = {}
            if current_raw then
                current = cjson.decode(current_raw)
            end
            
            for k, v in pairs(updates) do
                current[k] = v
            end
            
            local result_raw = cjson.encode(current)
            redis.call('set', key, result_raw)
            return result_raw
        """)

    async def _run_ch(self, query: str, params: dict = None) -> list:
        """封装同步 ClickHouse 执行为异步，并带锁防止并发冲突"""
        async with self._ch_lock:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self.ch.execute(query, params or {})
            )

    # ── 统一提交入口 ──────────────────────────────────────────

    async def apply_mutation(self, mutation: StateMutation) -> bool:
        """
        Orchestrator 调用此方法提交 Agent 声明的变更。
        先校验，再路由到对应后端。
        """
        try:
            mutation.validate()
        except ValueError as e:
            # 违反宪法约束，拒绝执行，写告警
            await self._write_violation_alert(mutation, str(e))
            return False

        router = {
            StateDomain.ASSETS:             self._apply_assets,
            StateDomain.TRIED_VECTORS:      self._apply_tried_vectors,
            StateDomain.FOCUS:              self._apply_focus,
            StateDomain.PENDING_PAYLOADS:   self._apply_pending_payloads,
            StateDomain.PENDING_RECON:      self._apply_pending_recon,
            StateDomain.ASYNC_TASKS:        self._apply_async_tasks,
            StateDomain.FOOTPRINTS:         self._apply_footprints,
            StateDomain.CONTEXT_RETRIEVALS: self._apply_context_retrievals,
            StateDomain.PENDING_CLEANUP:    self._apply_pending_cleanup,
        }

        handler = router.get(mutation.domain)
        if not handler:
            raise ValueError(f"未知 domain: {mutation.domain}")

        await handler(mutation)
        return True

    async def apply_mutations(self, mutations: list[StateMutation]) -> list[bool]:
        """批量提交，顺序执行"""
        results = []
        for m in mutations:
            results.append(await self.apply_mutation(m))
        return results

    # ── mission 读取（只读）────────────────────────────────────

    async def get_mission(self) -> dict:
        """mission 从启动时加载的 YAML，通过 Redis 缓存"""
        raw = await self.redis.get("mission")
        return json.loads(raw) if raw else {}

    # set_mission 被移除以强制执行“约束①：mission 运行时只读”

    async def extend_deadline(self, extra_seconds: int):
        """允许延长任务执行的绝对时间限制，但不允许修改目标"""
        mission = await self.get_mission()
        if mission:
            mission["max_runtime_seconds"] = mission.get("max_runtime_seconds", 7200) + extra_seconds
            await self.redis.set("mission", json_dumps(mission))

    async def load_mission(self, mission: dict):
        """仅启动时调用一次，后续不可修改"""
        if await self.redis.exists("mission"):
            raise PermissionError("mission 已加载，运行时不可修改（约束①）")
        await self.redis.set("mission", json_dumps(mission))
        
    async def close(self):
        """关闭所有外部连接"""
        if hasattr(self, 'redis'):
            await self.redis.aclose()
        if hasattr(self, 'neo4j'):
            self.neo4j.close()
            
    # ── Orchestrator 控制状态 ─────────────────────────────────

    async def is_paused(self) -> bool:
        val = await self.redis.get("system:paused")
        return val == "1"

    async def set_paused(self, paused: bool):
        await self.redis.set("system:paused", "1" if paused else "0")

    # ── focus 读写 ────────────────────────────────────────────

    async def get_focus(self) -> dict:
        raw = await self.redis.get("focus")
        return json.loads(raw) if raw else {}

    # focus 写入通过 apply_mutation，不提供直接写方法

    # ── assets 读取 ───────────────────────────────────────────

    def _run_cypher_sync(self, query: str, **params):
        """同步执行 Cypher，Session 管理同步版本"""
        with self.neo4j.session() as session:
            result = session.run(query, **params)
            return list(result)  # 同步读取所有记录

    async def _run_cypher(self, query: str, **params) -> list:
        """封装同步 Cypher 为异步，并带 30s 超时保护"""
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, lambda: self._run_cypher_sync(query, **params)),
                timeout=30.0
            )
        except asyncio.TimeoutError:
            logger.error(f"Neo4j 查询超时 (30s): {query[:100]}")
            return []

    async def get_host_full(self, ip: str) -> Optional[dict]:
        """获取某主机的完整信息，包括所有关联 Service 和 Credential"""
        records = await self._run_cypher("""
            MATCH (h:Host {ip: $ip})
            OPTIONAL MATCH (h)-[:RUNS]->(s:Service)
            OPTIONAL MATCH (h)-[:HAS_CRED]->(c:Credential)
            RETURN h, collect(distinct s) as services,
                   collect(distinct c) as creds
        """, ip=ip)
        if not records:
            return None
        record = records[0]
        return {
            "host":     dict(record["h"]),
            "services": [dict(s) for s in record["services"] if s],
            "creds":    [dict(c) for c in record["creds"] if c],
        }

    async def get_subnet_summary(self, ip: str) -> list[dict]:
        """同网段主机摘要，只返回 ip + access_level + confidence"""
        subnet = ".".join(ip.split(".")[:3]) + "."
        records = await self._run_cypher("""
            MATCH (h:Host)
            WHERE h.ip STARTS WITH $subnet AND h.ip <> $ip
            RETURN h.ip as ip, h.access_level as access_level,
                   h.confidence as confidence
            LIMIT 50
        """, subnet=subnet, ip=ip)
        return [dict(r) for r in records]

    async def find_lateral_paths(self, from_ip: str,
                                  max_hops: int = 3) -> list[dict]:
        """Cypher查询横向移动路径，驱动 opportunity_flag"""
        max_hops = min(max(1, int(max_hops)), 5)
        records = await self._run_cypher(f"""
            MATCH p = (src:Host {{ip: $ip}})-[:TRUSTS*1..{max_hops}]->(dst:Host)
            WHERE dst.confidence > 0.6
              AND dst.access_level = 'NONE'
            RETURN dst.ip as target, length(p) as hops
            ORDER BY hops ASC
            LIMIT 10
        """, ip=from_ip)
        return [dict(r) for r in records]

    async def find_credential_reuse(self) -> list[dict]:
        """查找可复用凭据，驱动 CRED_REUSE 向量"""
        records = await self._run_cypher("""
            MATCH (h:Host)-[:FOR]->(c:Credential)
            WHERE h.access_level = 'NONE'
              AND c.username IS NOT NULL
            RETURN c.username as username, c.auth_method as type,
                   collect(h.ip) as targets, count(h) as target_count
            ORDER BY target_count DESC
            LIMIT 5
        """)
        return [dict(r) for r in records]

    async def count_hosts(self) -> int:
        """统计 Neo4j 中所有 Host 节点数"""
        records = await self._run_cypher("MATCH (h:Host) RETURN count(h) as cnt")
        return records[0]["cnt"] if records else 0

    async def count_owned_hosts(self) -> int:
        """统计 access_level != NONE 的主机数"""
        records = await self._run_cypher("""
            MATCH (h:Host) WHERE h.access_level IS NOT NULL
              AND h.access_level <> 'NONE'
            RETURN count(h) as cnt
        """)
        return records[0]["cnt"] if records else 0

    async def add_unreachable_target(self, target: str):
        if target:
            await self.redis.sadd("unreachable_targets", target)

    async def is_unreachable(self, target: str) -> bool:
        if not target:
            return False
        return bool(await self.redis.sismember("unreachable_targets", target))

    async def get_unreachable_targets(self) -> set[str]:
        return await self.redis.smembers("unreachable_targets")

    async def set_sandbox_degraded(self, is_degraded: bool, reason: str = ""):
        """C1b 修复：记录沙箱降级状态到 Redis"""
        await self.redis.hset("sandbox_status", mapping={
            "is_degraded": "1" if is_degraded else "0",
            "reason": reason,
        })

    async def get_sandbox_status(self) -> dict:
        """读取沙箱降级状态"""
        raw = await self.redis.hgetall("sandbox_status")
        return {
            "is_degraded": raw.get("is_degraded", "0") == "1",
            "reason": raw.get("reason", ""),
        }

    async def verify_vector_counts_consistency(self):
        """启动自检：核验 ClickHouse 审计表与 Redis 运行时计数的一致性"""
        try:
            # A1 修复：确保 fail_reason 列为 String 类型（兼容旧 Enum8 表）
            try:
                await self._run_ch(
                    "ALTER TABLE tried_vectors MODIFY COLUMN fail_reason String"
                )
                logger.info("ClickHouse: fail_reason 列已迁移为 String 类型")
            except Exception as e:
                if "Nothing to do" not in str(e) and "already" not in str(e).lower():
                    logger.warning(f"ClickHouse fail_reason 迁移跳过: {e}")

            ch_summary = await self.get_vectors_summary()
            ch_total = ch_summary.get("total", 0)
            redis_payloads = await self.redis.scard("idx:payload_ids")
            redis_recon = await self.redis.scard("idx:recon_task_ids")
            redis_total = redis_payloads + redis_recon
            
            logger.info(f"StateAPI 一致性自检: ClickHouse 历史记录总计={ch_total} 条, Redis 队列总计={redis_total} 项 (payloads={redis_payloads}, recon={redis_recon})")
            
            if redis_total > 0 and ch_total == 0:
                logger.warning("❗ 异常状态警告：Redis 中存有活动任务队列，但 ClickHouse 的 tried_vectors 审计表为空！历史执行数据可能已丢失或未同步。")
        except Exception as e:
            logger.error(f"StateAPI 一致性自检异常: {e}")

    def _write_cypher_sync(self, query: str, **params):
        with self.neo4j.session() as session:
            session.run(query, **params)
            return True

    async def _write_cypher(self, query: str, **params) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self._write_cypher_sync(query, **params)
        )

    # ── tried_vectors 读取（聚合摘要）────────────────────────

    async def get_vectors_summary(self, target: Optional[str] = None) -> dict:
        """
        给 StatePruner 用的聚合摘要。
        直接在 ClickHouse 聚合，不加载原始数据。
        """
        where = "WHERE target = %(target)s" if target else ""
        params = {"target": target} if target else {}
        query = f"""
            SELECT
                count()                                    as total,
                countIf(result = 'SUCCESS')                as success_count,
                countIf(result = 'FAIL')                   as fail_count,
                countIf(result = 'CRITIC_BLOCKED')         as blocked_count,
                countIf(result = 'ABANDONED')              as abandoned_count,
                avg(info_gain)                             as avg_info_gain,
                max(info_gain)                             as max_info_gain,
                groupArray(10)(type)                       as recent_types,
                max(ts)                                    as last_attempt_ts
            FROM tried_vectors
            {where}
        """
        result = await self._run_ch(query, params)
        if not result:
            return {"total": 0, "recommendation": "EXPLORE"}

        row = result[0]
        recommendation = self._compute_recommendation(row)
        return {**dict(zip([
            "total", "success_count", "fail_count", "blocked_count",
            "abandoned_count", "avg_info_gain", "max_info_gain",
            "recent_types", "last_attempt_ts"
        ], row)), "recommendation": recommendation}

    def _compute_recommendation(self, row: tuple) -> str:
        total, success, fail = row[0], row[1], row[2]
        if total == 0:
            return "EXPLORE"
        if success > 0:
            return "DEEPEN"             # 已有成功，继续深挖
        if fail > 0 and fail / total > 0.9:
            return "ABANDON_STRATEGY"   # 90%以上失败，换策略
        return "CONTINUE"

    async def count_hallucinations(self, target: Optional[str] = None) -> int:
        where_parts = ["fail_reason = 'HALLUCINATION'"]
        params = {}
        if target:
            where_parts.append("target = %(target)s")
            params["target"] = target
        where = "WHERE " + " AND ".join(where_parts)
        result = await self._run_ch(f"SELECT count() FROM tried_vectors {where}", params)
        return result[0][0] if result else 0

    # ── pending_payloads ──────────────────────────────────────

    async def _get_items_by_index(
        self, index_key: str, prefix: str
    ) -> list[dict]:
        """通用：从 Set 索引获取所有记录，替代 KEYS 全库扫描"""
        ids = await self.redis.smembers(index_key)
        if not ids:
            return []
        keys = [f"{prefix}{id_}" for id_ in ids]
        values = await self.redis.mget(keys)
        items = []
        for raw in values:
            if raw:
                items.append(json.loads(raw))
        return items

    async def get_approved_payloads(self) -> list[dict]:
        """Executor 轮询此接口获取待执行 payload"""
        items = await self._get_items_by_index("idx:payload_ids", "payload:")
        return [p for p in items if p.get("status") == PayloadStatus.APPROVED]

    async def get_pending_payloads(self) -> list[dict]:
        """Critic 轮询此接口获取待审查 payload"""
        items = await self._get_items_by_index("idx:payload_ids", "payload:")
        return [p for p in items if p.get("status") == PayloadStatus.PENDING]

    async def count_pending_payloads(self) -> int:
        items = await self._get_items_by_index("idx:payload_ids", "payload:")
        return sum(1 for p in items if p.get("status") == PayloadStatus.PENDING)

    # ── async_tasks ───────────────────────────────────────────

    async def get_done_tasks(self) -> list[dict]:
        """获取已完成但未处理的异步任务"""
        items = await self._get_items_by_index("idx:async_task_ids", "async_task:")
        return [t for t in items
                if t.get("status") == TaskStatus.DONE and not t.get("processed")]

    async def count_running_recon(self) -> int:
        items = await self._get_items_by_index("idx:recon_task_ids", "recon_task:")
        return sum(1 for t in items if t.get("status") == TaskStatus.RUNNING)

    async def get_pending_recon_tasks(self) -> list[dict]:
        """Executor 轮询此接口获取待执行的侦察任务"""
        items = await self._get_items_by_index("idx:recon_task_ids", "recon_task:")
        return [t for t in items if t.get("status") == TaskStatus.PENDING]

    # ── context_retrievals ────────────────────────────────────

    async def get_context_retrievals(self) -> list[dict]:
        raw = await self.redis.get("context_retrievals")
        return json.loads(raw) if raw else []

    async def clear_context_retrievals(self):
        """每轮 Think 结束后由 Orchestrator 调用"""
        await self.redis.delete("context_retrievals")

    # ── footprints 读取（Cleanup 用）─────────────────────────

    async def get_all_footprints(self) -> list[dict]:
        """Cleanup Agent 读取全量 footprints，不经 StatePruner"""
        result = await self._run_ch("SELECT * FROM footprints ORDER BY ts ASC")
        columns = ["id", "type", "target", "detail", "cleaned", "ts"]
        return [dict(zip(columns, row)) for row in (result or [])]

    async def mark_footprint_cleaned(self, footprint_id: str):
        """遵循约束②：不修改原 footprints 表，而是向清理日志表追加记录"""
        await self._run_ch(
            "INSERT INTO cleaned_footprints (id) VALUES",
            [(footprint_id,)]
        )

    # ── 内部写入方法 ──────────────────────────────────────────

    def _is_ip(self, text: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(text)
            return True
        except ValueError:
            return False

    async def _resolve_to_ip(self, domain: str) -> Optional[str]:
        import socket
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(None, socket.gethostbyname, domain)
        except Exception:
            return None

    async def _apply_assets(self, mutation: StateMutation):
        p = dict(mutation.payload)  # 浅拷贝，避免修改调用方的 dict
        
        # 如果是域名，尝试解析成 IP 以合并资产
        original_ip = p.get("ip", "")
        if original_ip and not self._is_ip(original_ip):
            resolved = await self._resolve_to_ip(original_ip)
            if resolved:
                existing = await self.get_host_full(resolved)
                if existing:
                    # 合并别名
                    aliases = set(existing["host"].get("aliases", []))
                    aliases.add(original_ip)
                    p["aliases"] = list(aliases)
                else:
                    p["aliases"] = [original_ip]
                p["ip"] = resolved
        if mutation.operation == MutationOperation.UPSERT:
            # 将嵌套列表从 Host props 中分离出来（Neo4j 不支持嵌套 list）
            services = p.pop("services", [])
            creds    = p.pop("creds", [])

            # 检查 scope（约束⑥：越界节点标记 OUT_OF_SCOPE）
            mission = await self.get_mission()
            if not self._is_in_scope(p.get("ip", ""), mission):
                p["out_of_scope"] = True

            # Upsert Host 节点
            await self._write_cypher("""
                MERGE (h:Host {ip: $ip})
                SET h += $props
            """, ip=p["ip"], props=p)

            # Upsert Service 节点 + RUNS 边
            for svc in services:
                svc_props = {k: v for k, v in svc.items()
                             if not isinstance(v, (list, dict))}
                await self._write_cypher("""
                    MATCH (h:Host {ip: $ip})
                    MERGE (s:Service {port: $port, proto: $proto, host_ip: $ip})
                    SET s += $props
                    MERGE (h)-[:RUNS]->(s)
                """, ip=p["ip"],
                     port=int(svc.get("port", 0)),
                     proto=svc.get("proto", "tcp"),
                     props=svc_props)

            # Upsert Credential 节点 + HAS_CRED 边
            for cred in creds:
                cred_props = {k: v for k, v in cred.items()
                              if not isinstance(v, (list, dict))}
                await self._write_cypher("""
                    MATCH (h:Host {ip: $ip})
                    MERGE (c:Credential {username: $username, host_ip: $ip})
                    SET c += $props
                    MERGE (h)-[:HAS_CRED]->(c)
                """, ip=p["ip"],
                     username=cred.get("username", "unknown"),
                     props=cred_props)

        elif mutation.operation == MutationOperation.ADD_EDGE:
            await self._write_cypher("""
                MATCH (src:Host {ip: $src}), (dst:Host {ip: $dst})
                MERGE (src)-[r:TRUSTS {type: $type}]->(dst)
                SET r.port = $port, r.discovered_at = $ts
            """, src=p["src"], dst=p["dst"],
                 type=p.get("type", "UNKNOWN"),
                 port=p.get("port"), ts=datetime.now(timezone.utc).isoformat())

    async def _apply_tried_vectors(self, mutation: StateMutation):
        """只追加，永不修改（约束②）"""
        p = mutation.payload
        v_type = p.get("type", "UNKNOWN")
        if hasattr(v_type, "value"): v_type = v_type.value
        v_result = p.get("result", "UNKNOWN")
        if hasattr(v_result, "value"): v_result = v_result.value
        v_fail = p.get("fail_reason", "UNKNOWN")
        if hasattr(v_fail, "value"): v_fail = v_fail.value
        elif not v_fail: v_fail = "UNKNOWN"
        else: v_fail = str(v_fail)

        await self._run_ch(
            "INSERT INTO tried_vectors VALUES",
            [(
                p.get("id", str(__import__("uuid").uuid4())),
                p.get("target", ""),
                v_type,
                p.get("payload", ""),
                v_result,
                v_fail,
                p.get("info_gain", 0.0),
                p.get("novelty", 1.0),
                p.get("retry_count", 0),
                p.get("tokens_used", 0),
                p.get("duration_ms", 0),
                p.get("agent_id", ""),
                datetime.now(timezone.utc)
            )]
        )

    async def _apply_focus(self, mutation: StateMutation):
        await self.redis.set("focus", json_dumps(mutation.payload))

    async def update_focus_atomic(self, updates: dict):
        """原子级更新 focus，防止竞态冲突"""
        await self._focus_update_lua(keys=["focus"], args=[json.dumps(updates)])

    async def _apply_pending_payloads(self, mutation: StateMutation):
        p = mutation.payload
        pid = p.get("id", str(__import__("uuid").uuid4()))
        key = f"payload:{pid}"

        if mutation.operation == MutationOperation.UPDATE_STATUS:
            existing_raw = await self.redis.get(key)
            if existing_raw:
                existing = json.loads(existing_raw)
                existing.update(p)
                await self.redis.set(key, json_dumps(existing))
        else:
            p["id"] = pid
            await self.redis.set(key, json_dumps(p))
            await self.redis.sadd("idx:payload_ids", pid)

    async def _apply_pending_recon(self, mutation: StateMutation):
        p = mutation.payload
        tid = p.get("id", str(__import__("uuid").uuid4()))
        key = f"recon_task:{tid}"

        if mutation.operation == MutationOperation.UPDATE_STATUS:
            existing_raw = await self.redis.get(key)
            if existing_raw:
                existing = json.loads(existing_raw)
                existing.update(p)
                await self.redis.set(key, json_dumps(existing))
        else:
            p["id"] = tid
            await self.redis.set(key, json_dumps(p))
            await self.redis.sadd("idx:recon_task_ids", tid)

    async def _apply_pending_cleanup(self, mutation: StateMutation):
        p = mutation.payload
        tid = p.get("id", str(__import__("uuid").uuid4()))
        key = f"cleanup_task:{tid}"
        if mutation.operation == MutationOperation.UPDATE_STATUS:
            existing_raw = await self.redis.get(key)
            if existing_raw:
                existing = json.loads(existing_raw)
                existing.update(p)
                await self.redis.set(key, json_dumps(existing))
        else:
            p["id"] = tid
            await self.redis.set(key, json_dumps(p))
            await self.redis.sadd("idx:cleanup_task_ids", tid)

    async def get_pending_cleanup_tasks(self) -> list[dict]:
        """Human 审批队列：返回 status=PENDING_HUMAN 的清理任务"""
        items = await self._get_items_by_index("idx:cleanup_task_ids", "cleanup_task:")
        return [t for t in items if t.get("status") == "PENDING_HUMAN"]

    async def get_approved_cleanup_tasks(self) -> list[dict]:
        """Executor 消费：返回 status=APPROVED 的清理任务"""
        items = await self._get_items_by_index("idx:cleanup_task_ids", "cleanup_task:")
        return [t for t in items if t.get("status") == "APPROVED"]

    async def _apply_async_tasks(self, mutation: StateMutation):
        p = mutation.payload
        tid = p.get("id")
        if not tid:
             tid = str(__import__("uuid").uuid4())
             p["id"] = tid
        
        key = f"async_task:{tid}"
        if mutation.operation == MutationOperation.UPDATE_STATUS:
            existing_raw = await self.redis.get(key)
            if existing_raw:
                existing = json.loads(existing_raw)
                # 仅更新 status，防止污染其他字段
                existing["status"] = p.get("status", existing.get("status"))
                if "processed" in p:
                    existing["processed"] = p["processed"]
                await self.redis.set(key, json_dumps(existing))
        else:
            await self.redis.set(key, json_dumps(p))
            await self.redis.sadd("idx:async_task_ids", tid)

    async def _apply_footprints(self, mutation: StateMutation):
        """只追加（约束②扩展到 footprints）"""
        p = mutation.payload
        await self._run_ch(
            "INSERT INTO footprints VALUES",
            [(
                p.get("id", str(__import__("uuid").uuid4())),
                p.get("type", "UNKNOWN"),
                p.get("target", ""),
                json.dumps(p.get("detail", {})),
                False,      # cleaned = false
                datetime.now(timezone.utc)
            )]
        )

    async def _apply_context_retrievals(self, mutation: StateMutation):
        existing = await self.get_context_retrievals()
        existing.extend(mutation.payload.get("items", []))
        # 按 relevance 降序排列
        existing.sort(key=lambda x: x.get("relevance", 0), reverse=True)
        await self.redis.set("context_retrievals", json_dumps(existing))

    def _is_in_scope(self, ip: str, mission: dict) -> bool:
        """检查 IP 是否在授权 scope 内（约束①）"""
        import ipaddress
        scope = mission.get("scope_expanded", mission.get("scope", []))
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in scope:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            pass
        return False

    async def _write_violation_alert(self, mutation: StateMutation, reason: str):
        """违反约束时写入告警"""
        await self._run_ch(
            "INSERT INTO footprints VALUES",
            [(
                str(__import__("uuid").uuid4()),
                "CONSTRAINT_VIOLATION",
                "",
                json_dumps({
                    "mutation_id": mutation.id,
                    "domain": mutation.domain,
                    "operation": mutation.operation,
                    "reason": reason
                }),
                False,
                datetime.now(timezone.utc)
            )]
        )

    # ── LLM 思维链日志 ───────────────────────────────────────

    async def push_llm_log(self, agent_role: str, text: str):
        """将 Agent 的思考过程推入 Redis 列表，保留最近 50 条。"""
        if not text:
            return
        log_entry = {
            "agent": agent_role,
            "text": text,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        key = "locus:llm_logs"
        await self.redis.rpush(key, json_dumps(log_entry))
        # 裁剪保留最近 50 条 (0-indexed, -50 to -1 is the last 50)
        await self.redis.ltrim(key, -50, -1)

    async def get_llm_logs(self, limit: int = 50) -> list[dict]:
        """获取最近的 LLM 思考日志。"""
        key = "locus:llm_logs"
        raw_logs = await self.redis.lrange(key, -limit, -1)
        logs = []
        for raw in raw_logs:
            try:
                logs.append(json.loads(raw))
            except json.JSONDecodeError:
                pass
        return logs
