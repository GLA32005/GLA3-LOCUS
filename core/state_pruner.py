"""
State Pruner — 视图生成器
在 State 流入 Planner 之前进行裁剪，控制在 token 预算内。
这是防止 token 爆炸的核心组件。
"""

from __future__ import annotations
from typing import Optional
from .state_api import StateAPI
from .protocols import TaskStatus


class StatePruner:
    """
    裁剪规则：
    1. mission + focus：全量，约 700 token
    2. tried_vectors：聚合摘要，约 200 token（不加载原始记录）
    3. assets：只展开 active_target，其余只传摘要
    4. context_retrievals：按 relevance 截断，不超预算 20%
    5. pending 状态：只传计数，不传 payload 内容
    """

    def __init__(self, context_budget: int = 8000):
        self.budget = context_budget
        # 各部分的 token 分配比例
        self.MISSION_TOKENS    = 400
        self.FOCUS_TOKENS      = 400
        self.VECTORS_TOKENS    = 300
        self.ASSETS_RATIO      = 0.45   # 剩余预算的 45%
        self.RETRIEVAL_RATIO   = 0.20   # 剩余预算的 20%

    async def generate_view(self, state_api: StateAPI) -> dict:
        """
        生成 Planner 视图，严格控制总 token 量。
        """
        view = {}
        used = 0

        # ── 1. mission 全量 ──────────────────────────────────
        mission = await state_api.get_mission()
        # 展开 CIDR 为具体 IP 列表，降低 LLM 理解 CIDR 的难度
        mission = dict(mission)  # 避免修改原始数据
        # 混合 pre-resolved IPs (from domains) 和 CIDR 展开
        base_scope = mission.get("scope_expanded", mission.get("scope", []))
        mission["scope_expanded"] = self._expand_scope(base_scope)
        view["mission"] = mission
        used += self.MISSION_TOKENS

        # ── 2. focus 全量 ────────────────────────────────────
        focus = await state_api.get_focus()
        view["focus"] = focus
        used += self.FOCUS_TOKENS

        active_target = focus.get("active_target")

        # ── 3. tried_vectors 聚合摘要 ────────────────────────
        view["vectors_summary"] = await state_api.get_vectors_summary(
            target=active_target
        )
        hallucination_count = await state_api.count_hallucinations(active_target)
        view["vectors_summary"]["hallucination_count"] = hallucination_count
        used += self.VECTORS_TOKENS

        # ── 4. assets 按 focus 裁剪 ──────────────────────────
        remaining = self.budget - used
        assets_budget = int(remaining * self.ASSETS_RATIO)
        view["assets"] = await self._prune_assets(
            active_target, assets_budget, state_api
        )
        used += assets_budget

        # ── 5. context_retrievals 按 relevance 截断 ──────────
        remaining = self.budget - used
        retrieval_budget = int(remaining * self.RETRIEVAL_RATIO)
        view["knowledge"] = await self._prune_retrievals(
            retrieval_budget, state_api
        )
        used += retrieval_budget

        # ── 6. pending 状态摘要（只传计数）──────────────────
        view["pending_summary"] = {
            "payloads_pending":  await state_api.count_pending_payloads(),
            "recon_running":     await state_api.count_running_recon(),
            "async_tasks_done":  len(await state_api.get_done_tasks()),
        }
        view["unreachable_targets"] = list(await state_api.get_unreachable_targets())

        # ── 6b. pending recon 任务列表（精简，供 Recon Agent 去重）──
        pending_recon = await state_api.get_pending_recon_tasks()
        all_recon = await state_api._get_items_by_index("idx:recon_task_ids", "recon_task:")
        all_async = await state_api._get_items_by_index("idx:async_task_ids", "async_task:")
        
        all_tasks = all_recon + all_async
        
        running_recon = [t for t in all_tasks if t.get("status") == TaskStatus.RUNNING]
        pending_and_running = pending_recon + running_recon + [t for t in all_async if t.get("status") == TaskStatus.PENDING]
        
        view["pending_recon_list"] = [
            {"target": t.get("target"), "tool": t.get("tool"), "status": t.get("status")}
            for t in pending_and_running
        ]

        completed_recon = [
            t for t in all_tasks 
            if t.get("status") in (TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.TIMEOUT)
        ]
        completed_recon = sorted(completed_recon, key=lambda x: x.get("updated_at", 0), reverse=True)[:15]
        view["completed_recon_list"] = [
            {"target": t.get("target"), "tool": t.get("tool"), "status": t.get("status"), "assets": t.get("assets_found", 0)}
            for t in completed_recon
        ]

        # ── 7. 横向移动机会（Cypher 查询结果）───────────────
        if active_target:
            lateral_paths = await state_api.find_lateral_paths(active_target)
            if lateral_paths:
                view["lateral_opportunities"] = lateral_paths[:3]  # 最多3条

            cred_reuse = await state_api.find_credential_reuse()
            if cred_reuse:
                view["credential_reuse"] = cred_reuse[:3]

        view["_meta"] = {
            "estimated_tokens": used,
            "budget":           self.budget,
            "active_target":    active_target,
        }

        return view

    async def _prune_assets(self, active_target: Optional[str],
                             budget: int, state_api: StateAPI) -> dict:
        result = {}

        if active_target:
            # active_target 全量展开（约占 assets budget 60%）
            host_detail = await state_api.get_host_full(active_target)
            if host_detail:
                # ── 增强状态感知 (Issue 1 & 6) ──
                # 在视图中显式展示不可达状态及超时统计
                host_props = host_detail.get("host", {})
                if host_props.get("unreachable") or await state_api.is_unreachable(active_target):
                    host_props["_system_note"] = "!! 警告：此目标经多次探测被判定为不可达 (TARGET_UNREACHABLE) !!"
                
                # 截断 banner 等长字段防止超预算
                for svc in host_detail.get("services", []):
                    if len(svc.get("banner", "")) > 200:
                        svc["banner"] = svc["banner"][:200] + "..."
                result["active_host"] = host_detail

            # 同网段摘要（约占 assets budget 30%）
            result["subnet_summary"] = await state_api.get_subnet_summary(
                active_target
            )

        # 其他资产只给统计数（约占 10%）
        result["total_hosts"]    = await state_api.count_hosts()
        result["owned_hosts"]    = await state_api.count_owned_hosts()

        return result

    async def _prune_retrievals(self, budget: int,
                                 state_api: StateAPI) -> list[dict]:
        """
        从 context_retrievals 中按 relevance 截断。
        Agent 主动请求的查询结果优先级更高（requested_by_agent=True）。
        每条召回结果只保留 summary（不超 200 token）。
        """
        retrievals = await state_api.get_context_retrievals()
        if not retrievals:
            return []

        # Agent 主动请求的结果放宽 relevance 阈值（0.4 vs 0.6）
        agent_requested = [r for r in retrievals if r.get("requested_by_agent")]
        planner_requested = [r for r in retrievals if not r.get("requested_by_agent")]

        agent_filtered = [r for r in agent_requested if r.get("relevance", 0) >= 0.4]
        planner_filtered = [r for r in planner_requested if r.get("relevance", 0) >= 0.6]

        # Agent 请求的排前面，然后按 relevance 降序
        combined = sorted(
            agent_filtered + planner_filtered,
            key=lambda x: (
                x.get("requested_by_agent", False),
                x.get("relevance", 0),
            ),
            reverse=True,
        )

        # 估算 token 后截断
        result = []
        used = 0
        per_item_tokens = 150  # 每条召回约 150 token

        for item in combined:
            if used + per_item_tokens > budget:
                break
            entry = {
                "source":    item.get("source"),
                "summary":   (item.get("content") or item.get("summary") or "")[:500],
                "relevance": item.get("relevance"),
            }
            if item.get("requested_by_agent"):
                entry["requested_by_agent"] = True
            result.append(entry)
            used += per_item_tokens

        return result

    @staticmethod
    def _expand_scope(scope: list[str]) -> list[str]:
        """将 CIDR 展开为具体 IP 列表（仅 /24 或更小的网段，防止列表爆炸）"""
        import ipaddress
        expanded = []
        for entry in scope:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                if net.prefixlen >= 24:  # /24 最多 256 个 IP
                    expanded.extend(str(ip) for ip in net.hosts())
                else:
                    # 太大的网段不展开，保持 CIDR 原样
                    expanded.append(entry)
            except ValueError:
                expanded.append(entry)  # 非 CIDR，原样保留
        return expanded

