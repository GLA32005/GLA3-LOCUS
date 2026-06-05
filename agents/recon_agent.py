"""
Recon Agent — 侦察 Agent
职责：分析 State，生成侦察任务意图，写入 pending_recon_tasks。
约束：只写 pending_recon_tasks / async_tasks，不直接调用 Nmap/Nuclei（约束⑥）。
"""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from datetime import datetime, timezone

from core.protocols import (
    AgentType,
    BaseAgent,
    Event,
    KnowledgeQueryType,
    MutationOperation,
    NodeInput,
    NodeOutput,
    StateDomain,
    StateMutation,
    TaskStatus,
)

logger = logging.getLogger(__name__)

# ── 常量 ─────────────────────────────────────────────────────

MAX_TASKS_PER_RUN = 5   # 单轮最多生成的侦察任务数，防过度侦察

# 工具名 → 默认是否为长耗时任务
_ASYNC_DEFAULTS: dict[str, bool] = {
    "port_scan_full":  True,   # /24 全端口扫描，分钟级
    "dir_enum":        True,   # 目录枚举，分钟级
    "vuln_scan":       True,   # nuclei 漏扫，分钟级
    "port_scan":       False,  # 单主机快速扫描
    "service_enum":    False,
    "banner_grab":     False,
    "smb_enum":        False,
    "ldap_enum":       False,
    "cred_spray":      False,
    "http_probe":      False,
}

# ── LLM System Prompt ────────────────────────────────────────

_SYSTEM_PROMPT = """\
你是一个专业的渗透测试侦察专家（Recon Agent）。
你的任务是分析当前攻击状态，决定下一批侦察任务。

## 严格规则
1. 输出必须是合法 JSON，不得包含任何 JSON 以外的文字
2. 所有 target 必须在 mission.scope 的 CIDR 范围内
3. 不生成重复任务（参考 vectors_summary 和已知服务列表）
4. 长耗时工具（port_scan_full / dir_enum / vuln_scan）标记 is_async: true
5. **输出格式：必须输出合法 JSON。请保持 `think` 字段极其简洁（50字以内），优先确保 JSON 结构的完整性，防止因推理过长导致输出截断。**
6. 单轮任务 noise_cost 总和不超过 max_noise 的 20%
7. 已有某端口详细信息时，不要重复端口扫描，改做服务深度探测
8. 没有 active_target 时，优先对 scope 内第一个 IP 做初始 port_scan
9. 蜜罐警觉：如果目标 honeypot_suspect=true（端口数>100 或 banner 全部一致），不再对其投入侦察资源，切换到其他目标

## 工具选项（严禁发明任何不在下表中的工具名）
- port_scan       : nmap 快速端口扫描（单主机，Top-1000 端口）
- port_scan_full  : nmap 全端口扫描（单主机，0-65535）— 标记 is_async
- service_enum    : nmap -sV 服务版本识别（针对已知开放端口，较慢且易被拦截）
- banner_grab     : netcat/telnet 抓取 banner（轻量，低噪音）
- vuln_scan       : nuclei 漏洞扫描（针对已知服务）— 标记 is_async
- dir_enum        : feroxbuster 目录枚举（针对 HTTP/HTTPS）— 标记 is_async
- smb_enum        : enum4linux-ng SMB/RPC 枚举（发现 445 后使用）
- ldap_enum       : ldapsearch AD 枚举（发现 389/636 或域控后使用）
- http_probe      : httpx 探测 HTTP 服务标题和指纹（Web 侦察的首选）
- cred_spray      : 已知凭据对新目标的复用测试

## 侦察方法论
1. **Web 优先**：对于 80/443/8080 等 Web 端口，优先使用 `http_probe` 而非 `service_enum`。
2. **渐进探测**：先 `banner_grab`，再根据返回结果决定是否需要 `vuln_scan`。
3. **绕过 403**：发现 Web 403 时，应尝试 `dir_enum` 寻找非公开路径。

## 输出格式
{
  "think": "推理过程（≤100字，供审计）",
  "tasks": [
    {
      "tool": "工具名（见上方列表）",
      "target": "IP 或 IP:PORT（必须在 scope 内）",
      "params": {"参数名": "参数值"},
      "priority": 0.0到1.0,
      "noise_cost": 1到10的整数,
      "is_async": true或false,
      "rationale": "选择理由（≤50字）"
    }
  ],
  "info_needed": "需要从知识库查询的内容，无则填 null",
  "knowledge_query": {
    "query": "具体查询内容",
    "type": "CVE / Bypass / LotL / Methodology 之一",
    "reason": "为什么需要查（≤30字）"
  }
}

注意: knowledge_query 和 info_needed 的区别：
- info_needed: 仅仅是标记"我需要更多信息"，留给 Planner 决定
- knowledge_query: 直接请求查询知识库，Orchestrator 会立即执行查询并返回结果
- 当你已经明确知道需要查什么时，用 knowledge_query；当只是模糊地感到信息不足时，用 info_needed
"""


# ── ReconAgent ───────────────────────────────────────────────

class ReconAgent(BaseAgent):
    """
    侦察 Agent。

    只写 pending_recon_tasks（短任务）或 async_tasks（长任务）。
    不直接触网，不写 assets，不写 tried_vectors——这些由 Executor 处理。
    """

    def __init__(self, model: str = "Qwen3.5-9B-MLX-8bit", 
                 api_key: str = None, base_url: str = None):
        super().__init__(AgentType.RECON)
        self.api_key = api_key
        self.base_url = base_url or "http://127.0.0.1:8866"
        self._vision_checked = False
        self._vision_supported = False

    async def run(self, input: NodeInput) -> NodeOutput:
        view = input.state_view
        mutations: list[StateMutation] = []
        events: list[Event] = []

        # 1. 尝试启发式规则 (Issue 6)
        stall_count = view.get("focus", {}).get("stall_count", 0)
        if stall_count >= 2:
            heuristic_tasks = []
            logger.info(f"ReconAgent: 处于空转状态 (stall={stall_count})，禁用启发式规则，强制使用大模型推理")
        else:
            heuristic_tasks = self._apply_heuristic_rules(view)
        
        # 如果启发式规则已经生成了足够的任务，且不是关键阶段，可以跳过 LLM 推理以节省时间和 Token
        # 判定标准：启发式任务 >= 3 且没有 active_target 的关键变动请求
        skip_llm = len(heuristic_tasks) >= 3 and not view.get("focus", {}).get("opportunity_flag")
        
        # 问题 #3 修复：启发式任务先自查 dedup 状态
        # 如果全部会被去重过滤，则不跳过 LLM（否则死循环空转）
        if skip_llm:
            existing_tasks = view.get("pending_recon_list", [])
            existing_keys = {
                (t.get("target", ""), t.get("tool", ""))
                for t in existing_tasks
                if t.get("status") in ("PENDING", "RUNNING")
            }
            deduped = [t for t in heuristic_tasks
                       if (t.get("target", ""), t.get("tool", "port_scan")) not in existing_keys]
            if not deduped:
                skip_llm = False
                logger.info("ReconAgent: 启发式任务全部重复，回退到 LLM 推理")
        
        if skip_llm:
            llm_out = {
                "think": "启发式规则已生成足够任务，跳过 LLM 推理以加速流程。",
                "tasks": heuristic_tasks,
                "info_needed": None,
                "knowledge_query": None
            }
            tokens_used = 0
            logger.info(f"ReconAgent [{input.agent_id}]: 触发启发式快路径，跳过 LLM")
        else:
            # LLM 推理
            prompt = self._build_prompt(view, input.trigger_event)
            llm_out, tokens_used = await self._call_llm(prompt, state_view=view)
            # 合并结果
            llm_out["tasks"] = heuristic_tasks + llm_out.get("tasks", [])

        think_log = llm_out.get("think", "")
        raw_tasks = llm_out.get("tasks", [])
        info_needed = llm_out.get("info_needed")
        knowledge_query = llm_out.get("knowledge_query")

        if info_needed:
            # 记录 think_log，让 Planner 感知需要补充知识，由 Planner 发 RAG 查询
            think_log = f"{think_log}\n[INFO_NEEDED] {info_needed}"

        # 如果 Agent 明确请求查知识库，生成 KNOWLEDGE_QUERY mutation
        if knowledge_query and knowledge_query.get("query"):
            kq_type = knowledge_query.get("type", "Methodology")
            # 验证 type 合法性
            try:
                KnowledgeQueryType(kq_type)
            except ValueError:
                kq_type = "Methodology"
            mutations.append(self._make_knowledge_query(
                query=knowledge_query["query"],
                type=kq_type,
                reason=knowledge_query.get("reason", ""),
            ))

        # 限制单轮任务数
        raw_tasks = raw_tasks[:MAX_TASKS_PER_RUN]

        # 清洗 target (Issue 4)
        for t in raw_tasks:
            target = t.get("target", "")
            if isinstance(target, str):
                if target.startswith("http://"): target = target[7:]
                if target.startswith("https://"): target = target[8:]
                target = target.split("/")[0] # strip path
                t["target"] = target

        # 硬编码 scope 验证与不可达拦截（LLM 不可信）
        mission_data = view.get("mission", {})
        scope = mission_data.get("scope_expanded", mission_data.get("scope", []))
        unreachable = set(view.get("unreachable_targets", []))
        valid_tasks = [t for t in raw_tasks
                       if self._is_in_scope(t.get("target", ""), scope) and t.get("target", "").split(":")[0] not in unreachable]

        # CIDR 展开：将网段任务拆解为单 IP 任务（限制最大展开数以防爆炸）
        expanded_tasks = []
        for t in valid_tasks:
            target = t.get("target", "")
            if "/" in target and not target.endswith("/32"):
                try:
                    import ipaddress as _ipa
                    net = _ipa.ip_network(target, strict=False)
                    if net.num_addresses <= 64:  # 只自动展开 /26 或更小的网段
                        logger.info(f"ReconAgent: 展开网段任务 {target} -> {net.num_addresses-2} 个主机")
                        for ip in net.hosts():
                            new_task = dict(t)
                            new_task["target"] = str(ip)
                            expanded_tasks.append(new_task)
                        continue
                    else:
                        logger.warning(f"ReconAgent: 网段 {target} 太大 (>{net.num_addresses})，保持原样下发")
                except Exception as e:
                    logger.debug(f"ReconAgent: CIDR 展开失败 {target}: {e}")
            expanded_tasks.append(t)

        # 去重：检查 view 中已有的 pending/recon 任务，跳过相同 target+tool 的任务
        existing_tasks = view.get("pending_recon_list", [])
        existing_keys = {
            (t.get("target", ""), t.get("tool", ""))
            for t in existing_tasks
            if t.get("status") in ("PENDING", "RUNNING")
        }
        deduped_tasks = []
        for t in expanded_tasks:
            key = (t.get("target", ""), t.get("tool", "port_scan"))
            if key in existing_keys:
                logger.debug(f"ReconAgent: 跳过重复任务 {key}")
                continue
            deduped_tasks.append(t)
            existing_keys.add(key)   # 同一轮内也去重

        dropped = len(raw_tasks) - len(deduped_tasks)
        if dropped:
            logger.warning(
                f"ReconAgent [{input.agent_id}]: 过滤 {dropped} 个重复/越界任务"
            )

        # 生成 mutations
        for task in deduped_tasks:
            task_id = str(uuid.uuid4())
            tool = task.get("tool", "port_scan")
            is_async = task.get("is_async", _ASYNC_DEFAULTS.get(tool, False))

            task_payload = {
                "id":          task_id,
                "tool":        tool,
                "target":      task.get("target"),
                "params":      task.get("params", {}),
                "priority":    task.get("priority", 0.5),
                "noise_cost":  min(max(task.get("noise_cost", 1), 1), 10),
                "rationale":   task.get("rationale", ""),
                "status":      TaskStatus.PENDING,
                "created_by":  input.agent_id,
                "created_at":  datetime.now(timezone.utc).isoformat(),
            }

            if is_async:
                # 长耗时任务挂入 async_tasks，不阻塞主循环
                mutations.append(StateMutation(
                    operation=MutationOperation.APPEND,
                    domain=StateDomain.ASYNC_TASKS,
                    payload={
                        **task_payload,
                        "description": f"[RECON] {tool} @ {task.get('target')}",
                    },
                ))
            else:
                # 短任务直接进 pending_recon_tasks，Executor 统一调度
                mutations.append(self._make_recon_task_mutation(task_payload))

        logger.info(
            f"ReconAgent [{input.agent_id}]: "
            f"生成 {len(deduped_tasks)} 个任务 "
            f"({sum(1 for t in deduped_tasks if not t.get('is_async', False))} 同步 / "
            f"{sum(1 for t in deduped_tasks if t.get('is_async', _ASYNC_DEFAULTS.get(t.get('tool',''), False)))} 异步), "
            f"tokens={tokens_used}"
        )

        # 注：截图/nuclei 任务由 Executor._auto_dispatch_http_tasks 自动注入
        # 不在此处重复注入，避免截图循环

        return NodeOutput(
            mutations=mutations,
            events=events,
            next_hint=None,
            think_log=think_log,
            tokens_used=tokens_used,
        )

    # ── LLM 调用 ─────────────────────────────────────────────

    async def _call_llm(self, prompt: str, state_view: dict = None) -> tuple[dict, int]:
        try:
            from core.llm_provider import call_llm_with_escalation, parse_robust_json

            def _parse(text):
                return parse_robust_json(text)

            _VALID_TOOLS = {"port_scan", "banner_grab", "http_probe", "dir_enum",
                           "vuln_scan", "service_enum", "smb_enum", "ldap_enum",
                           "cred_spray", "screenshot", "nmap", "port_scan_full"}

            def _conf(parsed):
                """客观质量评分：检查任务是否有效可执行"""
                if parsed is None:
                    return None
                tasks = parsed.get("tasks", [])
                if not tasks:
                    return 0.0

                scope = []
                if state_view:
                    mission = state_view.get("mission", {})
                    scope = mission.get("scope_expanded", mission.get("scope", []))

                valid_count = 0
                for t in tasks:
                    tool_ok = t.get("tool") in _VALID_TOOLS
                    target = t.get("target", "")
                    target_ok = (not scope) or any(
                        target == s or target.split(":")[0] == s for s in scope
                    )
                    if tool_ok and target_ok:
                        valid_count += 1

                ratio = valid_count / len(tasks)
                # 奖励多样性
                tool_types = {t.get("tool") for t in tasks}
                diversity = min(len(tool_types) / 3, 0.2)

                return min(1.0, ratio * 0.8 + diversity)

            raw, tokens, escalated = await call_llm_with_escalation(
                system=_SYSTEM_PROMPT,
                prompt=prompt,
                agent_role="recon",
                confidence_fn=_conf,
                parse_fn=_parse,
                max_tokens=4000,
            )

            if not raw:
                return self._fallback_output(), 0

            output = parse_robust_json(raw)
            if not output:
                logger.error(f"ReconAgent 输出非法 JSON 且修复失败: {raw[:200]}...")
                return self._fallback_output(), 0

            if escalated:
                logger.info("ReconAgent: 本次由大模型完成")
            return output, tokens
        except Exception as e:
            logger.error(f"ReconAgent LLM 调用失败: {e}")
            return self._fallback_output(), 0

    # ── Prompt 构建 ──────────────────────────────────────────

    def _build_prompt(self, view: dict, trigger_event: Event) -> str:
        lines: list[str] = ["## 当前状态（侦察决策）\n"]

        # mission 约束
        m = view.get("mission", {})
        lines.append(f"**目标**: {m.get('goal', '未设置')}")
        lines.append(f"**授权范围 (scope)**: {m.get('scope', [])}")
        lines.append(f"**范围内具体 IP（扫描目标必须从这里选）**: {m.get('scope_expanded', m.get('scope', []))}")
        lines.append(f"**禁止目标 (oob)**: {m.get('oob', [])}")
        lines.append(f"**最大噪音配额 (max_noise)**: {m.get('max_noise', 30)}\n")

        # focus 当前意图
        f = view.get("focus", {})
        active_target = f.get("active_target")
        lines.append(f"**焦点目标**: {active_target or '未设置（需要初始侦察）'}")
        lines.append(f"**当前阶段**: {f.get('current_goal', 'RECON')}")
        lines.append(f"**当前假设**: {f.get('hypothesis', '暂无')}")
        lines.append(f"**置信度**: {float(f.get('confidence') or 0):.2f}")
        lines.append(f"**连续无进展**: {f.get('stall_count', 0)} 次\n")

        # Planner 下达的具体指令（来自 trigger_event.payload）
        act = trigger_event.payload if trigger_event else {}
        action_type = act.get("action_type")
        if action_type:
            lines.append(f"**Planner 指令**: action_type={action_type}, "
                         f"params={act.get('params', {})}\n")

        # assets：active_target 详情
        assets = view.get("assets", {})
        active_host = assets.get("active_host")
        if active_host:
            host = active_host.get("host", {})
            services = active_host.get("services", [])
            creds = active_host.get("creds", [])
            lines.append(f"**目标主机 {active_target}**:")
            lines.append(f"  OS: {host.get('os', '未知')}")
            lines.append(f"  access_level: {host.get('access_level', 'NONE')}")
            if services:
                lines.append(f"  已发现服务（{len(services)} 个）:")
                for svc in services[:15]:
                    lines.append(
                        f"    {svc.get('port')}/{svc.get('proto', 'tcp')} "
                        f"{svc.get('app', '?')} {svc.get('version', '')} "
                        f"{'[banner已抓]' if svc.get('banner') else ''}"
                    )
            else:
                lines.append("  尚无已知服务，需要端口扫描")
            if creds:
                lines.append(f"  已获凭据: {len(creds)} 个")
        else:
            lines.append(
                f"**目标主机**: 尚无数据，"
                f"请对 scope 内目标发起初始 port_scan"
            )
        lines.append("")

        # 同网段摘要
        subnet_summary = assets.get("subnet_summary", [])
        if subnet_summary:
            lines.append(f"**同网段主机（{len(subnet_summary)} 个）**:")
            for h in subnet_summary[:5]:
                lines.append(
                    f"  {h.get('ip')} access={h.get('access_level', 'NONE')} "
                    f"confidence={float(h.get('confidence') or 0):.2f}"
                )
            lines.append("")

        # 近期已完成侦察任务
        completed_recon = view.get("completed_recon_list", [])
        if completed_recon:
            lines.append("**近期已完成的侦察任务**:")
            for t in completed_recon:
                lines.append(f"  - 工具: {t.get('tool')} | 目标: {t.get('target')} | 状态: {t.get('status')} | 发现新资产: {t.get('assets', 0)}")
            lines.append("  *注意：绝对不要重复下发已经完成（或超时、失败）且目标和工具相同的侦察任务，否则会导致死循环。*\n")

        # tried_vectors 摘要（避免重复侦察）
        vs = view.get("vectors_summary", {})
        total = vs.get("total", 0)
        if total:
            lines.append(f"**已执行侦察**: {total} 次")
            lines.append(f"  成功: {vs.get('success_count', 0)} | "
                         f"失败: {vs.get('fail_count', 0)} | "
                         f"均衡信息增益: {float(vs.get('avg_info_gain') or 0):.2f}")
            recent = vs.get("recent_types", [])
            if recent:
                lines.append(f"  最近使用工具: {recent}")
            lines.append(f"  建议: {vs.get('recommendation', 'EXPLORE')}\n")
        else:
            lines.append("**已执行侦察**: 无，这是第一次侦察\n")

        # credential_reuse 机会
        if view.get("credential_reuse"):
            lines.append("**可复用凭据**:")
            for cr in view["credential_reuse"]:
                lines.append(
                    f"  {cr.get('username')} ({cr.get('type')}) "
                    f"可用于 {cr.get('target_count')} 个未控主机"
                )
            lines.append("")

        # 知识召回
        if view.get("knowledge"):
            lines.append("**相关知识**:")
            for k in view["knowledge"]:
                lines.append(
                    f"  [{float(k.get('relevance') or 0):.2f}] "
                    f"{k.get('source')}: {k.get('summary', '')[:120]}"
                )
            lines.append("")

        # 任务队列状态
        ps = view.get("pending_summary", {})
        lines.append(
            f"**队列**: 侦察中={ps.get('recon_running', 0)} | "
            f"待审Payload={ps.get('payloads_pending', 0)}"
        )

        lines.append(
            "\n请基于以上状态，生成下一批侦察任务。"
            "优先补全未知攻击面，避免重复已知信息。"
        )
        return "\n".join(lines)

    def _apply_heuristic_rules(self, view: dict) -> list[dict]:
        """
        启发式规则层：对显而易见的探测步骤直接生成任务，无需 LLM 介入。
        """
        tasks = []
        assets = view.get("assets", {})
        active_host = assets.get("active_host")
        if not active_host:
            return []

        # B3 修复：如果 pending 队列已有任务，跳过启发式生成避免重复
        pending_recon_list = view.get("pending_recon_list", [])
        active_pending = [t for t in pending_recon_list if t.get("status") in ("PENDING", "RUNNING")]
        if len(active_pending) >= 2:
            logger.debug(f"启发式规则: pending 队列已有 {len(active_pending)} 个任务，跳过")
            return []
        
        ip = active_host.get("host", {}).get("ip")
        services = active_host.get("services", [])
        
        # 规则 1: 发现新端口但无服务版本 -> service_enum
        for svc in services:
            if not svc.get("app") or svc.get("app") == "unknown":
                tasks.append({
                    "tool": "service_enum",
                    "target": f"{ip}:{svc['port']}",
                    "params": {},
                    "priority": 0.8,
                    "noise_cost": 2,
                    "rationale": "启发式规则：自动探测未知服务的版本信息"
                })
        
        # 规则 2: HTTP 服务发现 -> http_probe + dir_enum
        for svc in services:
            port = svc.get("port")
            app = svc.get("app", "").lower()
            if port in {80, 443, 8080, 8443} or "http" in app:
                target = f"{ip}:{port}"
                tasks.append({
                    "tool": "http_probe",
                    "target": target,
                    "params": {},
                    "priority": 0.7,
                    "noise_cost": 1,
                    "rationale": "启发式规则：发现 Web 端口，自动执行 http_probe"
                })
                # 强制增加异步目录枚举，破除指纹识别失败导致的僵局
                tasks.append({
                    "tool": "dir_enum",
                    "target": target,
                    "params": {},
                    "priority": 0.6,
                    "noise_cost": 2,
                    "is_async": True,
                    "rationale": "启发式规则：Web 目标自动开启深度扫描"
                })
                
        return tasks

    # ── 辅助 ─────────────────────────────────────────────────

    def _is_in_scope(self, target: str, scope: list[str]) -> bool:
        """硬编码 scope 验证，防止 LLM 越界（二次校验）"""
        if not target or not scope:
            return False
        ip_str = target.split(":")[0]   # 去掉端口
        try:
            # 1. 尝试作为单个 IP
            ip_obj = ipaddress.ip_address(ip_str)
            return any(
                ip_obj in ipaddress.ip_network(cidr, strict=False)
                for cidr in scope
            )
        except ValueError:
            # 2. 尝试作为网络 (CIDR)
            try:
                net_obj = ipaddress.ip_network(ip_str, strict=False)
                # 检查该网段是否完全包含在 scope 的某个网段内
                return any(
                    net_obj.subnet_of(ipaddress.ip_network(cidr, strict=False))
                    for cidr in scope
                )
            except Exception:
                # 3. 尝试作为域名直接匹配
                if ip_str in scope:
                    return True
                # 域名目标直接拒绝，不进行 DNS 解析（约束⑥）
                logger.warning(f"ReconAgent: 拒绝非 IP/CIDR/Domain 目标 '{target}'，不在授权范围内")
                return False

    def _fallback_output(self) -> dict:
        """LLM 异常时的安全降级：不生成任何任务，等待 Planner 重新调度"""
        return {
            "think": "LLM 调用失败，安全降级：不生成任务",
            "tasks": [],
            "info_needed": None,
            "knowledge_query": None,
        }

    # ── 视觉直觉：自动截图注入 ────────────────────────────────

    _HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}

    async def _maybe_inject_screenshot_tasks(
        self,
        view: dict,
        mutations: list[StateMutation],
        existing_keys: set,
        agent_id: str,
    ):
        """
        如果模型支持 Vision，自动为发现的 HTTP 服务注入截图任务。
        如果不支持，静默跳过。
        """
        # 惰性检测 Vision 能力（只检测一次）
        if not self._vision_checked:
            self._vision_checked = True
            try:
                from core.llm_provider import check_vision_support
                self._vision_supported = await check_vision_support(
                    self.api_key, self.base_url, self.model
                )
            except Exception:
                self._vision_supported = False

        if not self._vision_supported:
            return

        # 从 active_host 的 services 中找 HTTP 端口
        assets = view.get("assets", {})
        active_host = assets.get("active_host", {})
        host_data = active_host.get("host", {})
        services = active_host.get("services", [])
        ip = host_data.get("ip")
        if not ip:
            return

        for svc in services:
            port = svc.get("port", 0)
            app = svc.get("app", "").lower()
            if port not in self._HTTP_PORTS and "http" not in app:
                continue

            target = f"{ip}:{port}"
            key = (target, "screenshot")
            if key in existing_keys:
                continue
            existing_keys.add(key)

            task_id = str(uuid.uuid4())
            mutations.append(StateMutation(
                operation=MutationOperation.APPEND,
                domain=StateDomain.PENDING_RECON,
                payload={
                    "id":         task_id,
                    "tool":       "screenshot",
                    "target":     target,
                    "params":     {},
                    "priority":   0.3,
                    "noise_cost": 1,
                    "rationale":  "视觉直觉：自动截图 HTTP 服务供 LLM 分析",
                    "status":     TaskStatus.PENDING,
                    "created_by": agent_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            ))
            logger.info(f"ReconAgent: 注入截图任务 target={target}")

