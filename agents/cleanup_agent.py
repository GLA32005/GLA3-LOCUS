"""
Cleanup Agent — 清道夫 Agent（Loop C）
职责：读取全量 footprints，按时间逆序生成逆向清理操作，写入 pending_cleanup_tasks。
约束：
  - 仅在 CLEANUP_STATE 事件触发后执行（所有 Exploit 调度已暂停）
  - 每个清理任务精确对应一条 footprint，不做额外操作
  - 必须生成 HUMAN_APPROVAL_REQ 事件（约束⑦：Cleanup 需 Human 审批）
  - 不执行清理，执行由 Executor 完成
"""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from datetime import datetime, timezone

from anthropic import AsyncAnthropic

from core.protocols import (
    AgentType,
    BaseAgent,
    Event,
    EventPriority,
    EventType,
    MutationOperation,
    NodeInput,
    NodeOutput,
    StateDomain,
    StateMutation,
)

logger = logging.getLogger(__name__)

# ── 常量 ─────────────────────────────────────────────────────

_MAX_TOKENS      = 2000
_MAX_FOOTPRINTS  = 50   # 单轮处理上限，防 prompt 过长

# footprint type → 默认逆向操作模板（供 LLM 参考）
_REVERSE_HINTS: dict[str, str] = {
    "FILE_CREATE":      "delete the created file",
    "FILE_MODIFY":      "restore file to original content",
    "PROCESS_SPAWN":    "kill spawned process if still running",
    "REG_WRITE":        "delete or restore registry key",
    "SERVICE_INSTALL":  "stop and uninstall the service",
    "USER_CREATE":      "delete created user account",
    "CRED_DUMP":        "rotate affected credentials (inform scope owner)",
    "PERSISTENCE":      "remove persistence mechanism",
    "NETWORK_CONNECT":  "close connection, no host-side cleanup needed",
    "MSF_SESSION":      "terminate meterpreter session",
    "SHELL_CMD":        "review impact and undo if reversible",
}

# ── LLM System Prompt ────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a penetration test cleanup specialist. You will be given a list of \
footprints (actions taken against target systems during an authorized pentest). \
Your job is to generate a precise, ordered cleanup plan that:
1. Processes footprints in REVERSE chronological order (undo newest first)
2. For each footprint, proposes exactly ONE reversible operation
3. Marks irreversible operations explicitly (e.g., credential dumps)
4. Never proposes operations outside the original scope
5. Never invents additional cleanup steps not tied to a footprint

Output ONLY valid JSON — no markdown fences, no prose.
"""

_USER_PROMPT_TMPL = """\
Mission scope: {scope}
Trigger reason: {trigger_reason}

Footprints to clean (newest first):
{footprints_json}

Reverse-hint templates (use as guidance only):
{hints_json}

Generate a cleanup plan.

Output JSON schema:
{{
  "think": "<≤100 chars: key risk items and approach>",
  "tasks": [
    {{
      "footprint_id":   "<uuid of the footprint this undoes>",
      "target":         "<ip:port or ip>",
      "operation":      "<human-readable reverse op>",
      "executor_hint":  "bash|powershell|cmd|python|manual",
      "content":        "<exact command or null if manual>",
      "reversible":     true|false,
      "noise_cost":     1,
      "timeout_ms":     10000,
      "rationale":      "<≤60 chars why>"
    }}
  ],
  "irreversible_count": 0,
  "report_summary":    "<≤200 chars overall cleanup summary>"
}}
"""


class CleanupAgent(BaseAgent):
    """
    Loop C 清道夫。
    state_view 必须包含：
      - "footprints": list[dict]   — 来自 state_api.get_all_footprints()
      - "mission":    dict         — 含 scope list
      - "trigger_reason": str      — CLEANUP_STATE 的触发原因
    输出：
      - UPSERT → pending_cleanup_tasks（每个任务一条，status=PENDING_HUMAN）
      - Event(HUMAN_APPROVAL_REQ, CRITICAL) — 约束⑦，不可省略
    """

    def __init__(self, api_key: str = None, base_url: str = None):
        super().__init__(AgentType.CLEANUP)
        self.api_key = api_key or "Ww131421"
        self.base_url = base_url or "http://127.0.0.1:8866"
        self._client = AsyncAnthropic(api_key=self.api_key, base_url=self.base_url)

    async def run(self, input: NodeInput) -> NodeOutput:
        footprints = input.state_view.get("footprints", [])
        mission    = input.state_view.get("mission", {})
        trigger    = input.state_view.get("trigger_reason", "CLEANUP_STATE")

        if not footprints:
            logger.info("CleanupAgent: no footprints, nothing to clean")
            return NodeOutput(mutations=[], events=[])

        # 时间逆序（最新先清）
        sorted_fp = sorted(
            footprints,
            key=lambda x: x.get("ts", ""),
            reverse=True,
        )[:_MAX_FOOTPRINTS]

        try:
            tasks = await self._call_llm(sorted_fp, mission, trigger)
        except Exception as e:
            logger.error(f"CleanupAgent LLM 失败: {e}")
            return NodeOutput(mutations=[], events=[])

        if not tasks:
            return NodeOutput(mutations=[], events=[])

        mutations = self._build_mutations(tasks)
        events    = self._build_events(tasks, mission, trigger)

        logger.info(
            f"CleanupAgent: {len(tasks)} cleanup tasks generated "
            f"({sum(1 for t in tasks if not t.get('reversible', True))} irreversible)"
        )
        return NodeOutput(mutations=mutations, events=events)

    # ── LLM 调用 ──────────────────────────────────────────────

    async def _call_llm(
        self,
        footprints: list[dict],
        mission: dict,
        trigger_reason: str,
    ) -> list[dict]:
        scope  = mission.get("scope", [])
        prompt = _USER_PROMPT_TMPL.format(
            scope=json.dumps(scope),
            trigger_reason=trigger_reason,
            footprints_json=json.dumps(footprints, default=str, indent=2),
            hints_json=json.dumps(_REVERSE_HINTS, indent=2),
        )

        try:
            from core.llm_provider import call_llm_anthropic_style
            raw, tokens = await call_llm_anthropic_style(
                api_key=self.api_key,
                base_url=self.base_url,
                model="Qwen3.5-9B-MLX-8bit",
                system=_SYSTEM_PROMPT,
                prompt=prompt,
                max_tokens=_MAX_TOKENS
            )
            
            if not raw:
                return []
            
            # JSON 提取
            import re
            json_match = re.search(r'(\{.*\}|\[.*\])', raw, re.DOTALL)
            if json_match:
                raw = json_match.group(1).strip()
            
            return json.loads(raw).get("tasks", [])
        except Exception as e:
            logger.error(f"CleanupAgent LLM 失败: {e}")
            return []

        try:
            llm_out = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.error(f"CleanupAgent JSON parse error: {e} — raw: {raw[:200]}")
            return []

        tasks = llm_out.get("tasks", [])
        scope_set = set(mission.get("scope", []))

        validated = []
        for t in tasks:
            if not self._is_in_scope(t.get("target", ""), scope_set):
                logger.warning(
                    f"CleanupAgent: task target {t.get('target')} not in scope, skipping"
                )
                continue
            validated.append(t)

        return validated

    # ── Mutations ─────────────────────────────────────────────

    def _build_mutations(self, tasks: list[dict]) -> list[StateMutation]:
        mutations = []
        now = datetime.now(timezone.utc).isoformat()
        for t in tasks:
            task_id = str(uuid.uuid4())
            payload = {
                "id":             task_id,
                "footprint_id":   t.get("footprint_id"),
                "target":         t.get("target", ""),
                "operation":      t.get("operation", ""),
                "executor_hint":  t.get("executor_hint", "bash"),
                "content":        t.get("content"),
                "reversible":     t.get("reversible", True),
                "noise_cost":     int(t.get("noise_cost", 1)),
                "timeout_ms":     int(t.get("timeout_ms", 10000)),
                "rationale":      t.get("rationale", ""),
                "status":         "PENDING_HUMAN",
                "created_at":     now,
                "approved_at":    None,
                "executed_at":    None,
                "verified":       False,
            }
            mutations.append(StateMutation(
                operation=MutationOperation.UPSERT,
                domain=StateDomain.PENDING_CLEANUP,
                payload=payload,
            ))
        return mutations

    # ── Events ───────────────────────────────────────────────

    def _build_events(
        self,
        tasks: list[dict],
        mission: dict,
        trigger_reason: str,
    ) -> list[Event]:
        irreversible = [t for t in tasks if not t.get("reversible", True)]
        return [
            Event(
                type=EventType.HUMAN_APPROVAL_REQ,
                priority=EventPriority.CRITICAL,
                source="cleanup_agent",
                payload={
                    "context":             "cleanup",
                    "task_count":          len(tasks),
                    "irreversible_count":  len(irreversible),
                    "trigger_reason":      trigger_reason,
                    "mission_id":          mission.get("id", ""),
                    "message": (
                        f"Cleanup plan ready: {len(tasks)} tasks "
                        f"({len(irreversible)} irreversible). "
                        "Human approval required before execution."
                    ),
                },
            )
        ]

    # ── Scope helper ─────────────────────────────────────────

    @staticmethod
    def _is_in_scope(target: str, scope: set[str]) -> bool:
        """IP/CIDR 作用域检查，与 ReconAgent 逻辑相同。"""
        if not target or not scope:
            return False
        ip_str = target.split(":")[0].split("/")[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return target in scope
        for s in scope:
            try:
                if ip in ipaddress.ip_network(s, strict=False):
                    return True
            except ValueError:
                if s == ip_str:
                    return True
        return False

