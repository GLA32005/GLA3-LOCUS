"""
Critic Agent — 审查 Agent
对 pending_payloads 中的 PENDING 条目进行四维评分。
硬编码检查（DOS_RISK / OUT_OF_SCOPE / 空 payload）不过 LLM，直接拦截。
LLM 打分后，阈值决策逻辑覆盖 LLM 判定，防止 LLM 被绕过。
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
    EventPriority,
    EventType,
    MutationOperation,
    NodeInput,
    NodeOutput,
    PayloadStatus,
    RejectReason,
    StateDomain,
    StateMutation,
    VectorResult,
)

logger = logging.getLogger(__name__)

# ── 硬编码危险模式（case-insensitive 子串匹配）────────────────

_DOS_PATTERNS: tuple[str, ...] = (
    "rm -rf /",
    "rm -rf /*",
    "mkfs",
    "drop database",
    "drop table",
    "format c:",
    "del /f /s /q c:\\",
    "del /f /s /q /",
    "shutdown",
    "halt",
    "poweroff",
    "reboot",
    "init 0",
    "init 6",
    "> /dev/sda",
    "dd if=/dev/zero of=/dev/",
)

# ── 评分阈值 ─────────────────────────────────────────────────

_DOS_THRESHOLD         = 0.5
_COMPLIANCE_THRESHOLD  = 0.5
_STABILITY_THRESHOLD   = 0.5
_NOISE_THRESHOLD       = 0.85

# ── LLM System Prompt ────────────────────────────────────────

_CRITIC_SYSTEM = """\
你是一个渗透测试安全审查专家（Critic Agent）。
你的任务是对一个 payload 进行四维安全评分，决定是否允许执行。

## 评分维度（均为 0.0-1.0 的浮点数）
- noise:           EDR 遥测触发量。0=几乎无日志；1=极度嘈杂(如全端口全速扫描、破坏性动作)。常规漏洞扫描和普通利用请给 0.3-0.6。
- stability:       沙箱语法成功率。0=明显语法错误；1=语法完全正确。绝大多数标准命令或常见脚本都应给 0.9-1.0。
- destructiveness: DoS/破坏性风险。0=完全安全；1=会造成数据丢失或服务中断。
    【极度重要】破坏性仅指：永久性数据删除、破坏系统配置、导致系统崩溃或拒绝服务（DoS）。像读取文件、下载工具(curl/wget)、执行爆破(hydra/ssh)等操作，不管有多敏感或非法，其 destructiveness 必须小于 0.3。高噪音不等于高破坏性！
- compliance:      目标合规性。0=目标在 scope 之外；1=目标完全在授权范围内。

## 严格规则
1. 输出必须是合法 JSON，不得包含任何 JSON 以外的文字
2. 任何可能造成数据丢失/服务中断的操作，destructiveness 必须 ≥ 0.8
3. compliance 仅基于 target IP 是否在 mission_scope 内判断
4. verdict 必须是 APPROVED、BLOCKED 或 REQUIRES_APPROVAL 之一
5. 当 verdict=BLOCKED 时，reject_reason 必须填写对应枚举值
6. 当你无法确定某项风险时，宁可评分偏高（保守原则）

## 评分示例（calibration）
- curl 下载文件: destructiveness=0.0（只读操作）
- SSH 暴力破解: destructiveness=0.1（认证尝试，不修改目标状态）
- 写 crontab 反弹 shell: destructiveness=0.3（持久化但可逆）
- rm -rf /: destructiveness=1.0（不可恢复的数据破坏）

## 输出格式
{
  "think":    "评审推理（≤80字）",
  "scores": {
    "noise":           0.0,
    "stability":       0.0,
    "destructiveness": 0.0,
    "compliance":      0.0
  },
  "verdict":       "APPROVED 或 BLOCKED 或 REQUIRES_APPROVAL",
  "reject_reason": "DOS_RISK 或 SYNTAX_ERROR 或 OUT_OF_SCOPE 或 HALLUCINATION 或 HIGH_NOISE 或 REQUIRES_APPROVAL 或 null"
}
"""


# ── CriticAgent ──────────────────────────────────────────────

class CriticAgent(BaseAgent):
    """
    审查 Agent。
    执行流程：
      1. 硬编码检查（不调 LLM）
      2. LLM 四维评分
      3. 阈值决策逻辑覆盖 LLM 判定
      4. 生成 mutations（UPDATE_STATUS on pending_payloads + APPEND on tried_vectors）
         和 events（PAYLOAD_APPROVED / PAYLOAD_REJECTED / HUMAN_APPROVAL_REQ）
    """

    def __init__(self, model: str = "Qwen3.5-9B-MLX-8bit", 
                 api_key: str = None, base_url: str = None):
        super().__init__(AgentType.CRITIC)
        self.api_key = api_key
        self.base_url = base_url or "http://127.0.0.1:8866"

    async def run(self, input: NodeInput) -> NodeOutput:
        payload = input.state_view.get("payload", {})
        mission = input.state_view.get("mission", {})

        payload_id      = payload.get("id", "")
        content         = payload.get("content", "")
        target          = payload.get("target", "")
        vector_type     = payload.get("vector_type", "UNKNOWN")
        retry_count     = int(payload.get("retry_count", 0))
        mission_scope   = mission.get("scope_expanded", mission.get("scope", []))
        risk_level      = int(mission.get("risk_level", 3))

        # C1c 修复：检测沙箱降级状态，动态收紧 stability 阈值
        sandbox_status = input.state_view.get("sandbox_status", {})
        self._sandbox_degraded = sandbox_status.get("is_degraded", False)

        if not payload_id:
            logger.error("CriticAgent: state_view 中无有效 payload，跳过")
            return NodeOutput(mutations=[], events=[], next_hint=None,
                              think_log="no payload in state_view", tokens_used=0)

        # ── Step 1：硬编码检查 ────────────────────────────────
        hard_fail, hard_reason = self._hardcoded_check(content, target, mission_scope)
        if hard_fail:
            logger.info(
                f"CriticAgent [{input.agent_id}]: 硬编码拦截 "
                f"payload={payload_id} reason={hard_reason}"
            )
            return self._make_blocked_output(
                payload=payload,
                reason=hard_reason,
                scores=None,
                think_log=f"硬编码检查拦截: {hard_reason}",
                tokens_used=0,
                agent_id=input.agent_id,
            )

        # ── Step 2：LLM 四维评分 ──────────────────────────────
        prompt = self._build_review_prompt(payload, mission)
        llm_out, tokens_used = await self._call_llm(prompt)

        if llm_out is None:
            # LLM 失败：保守降级为 BLOCKED/SYNTAX_ERROR
            logger.error(f"CriticAgent [{input.agent_id}]: LLM 失败，降级 BLOCKED")
            return self._make_blocked_output(
                payload=payload,
                reason=RejectReason.SYNTAX_ERROR,
                scores=None,
                think_log="LLM 调用失败，保守降级为 BLOCKED",
                tokens_used=0,
                agent_id=input.agent_id,
            )

        scores = llm_out.get("scores", {})
        llm_verdict = llm_out.get("verdict", "BLOCKED")
        think_log = llm_out.get("think", "")

        # ── Step 3：阈值决策逻辑（覆盖 LLM 判定）─────────────
        status, reason = self._apply_decision_logic(
            scores, llm_verdict, risk_level
        )

        logger.info(
            f"CriticAgent [{input.agent_id}]: payload={payload_id} "
            f"verdict={status} reason={reason} "
            f"scores={scores} tokens={tokens_used}"
        )


        if status == PayloadStatus.APPROVED:
            return self._make_approved_output(
                payload=payload, scores=scores,
                think_log=think_log, tokens_used=tokens_used,
            )
        elif status == PayloadStatus.REQUIRES_APPROVAL:
            return self._make_require_approval_output(
                payload=payload, scores=scores,
                think_log=think_log, tokens_used=tokens_used,
            )
        else:
            return self._make_blocked_output(
                payload=payload, reason=reason, scores=scores,
                think_log=think_log, tokens_used=tokens_used,
                agent_id=input.agent_id,
            )

    # ── 硬编码检查 ────────────────────────────────────────────

    def _hardcoded_check(
        self, content: str, target: str, scope: list[str]
    ) -> tuple[bool, RejectReason | None]:
        """
        返回 (blocked, reason)。
        blocked=True 表示直接拦截，不调 LLM。
        """
        # 空 payload
        if not content or len(content.strip()) < 5:
            return True, RejectReason.SYNTAX_ERROR

        # 危险命令模式匹配
        content_lower = content.lower()
        for pattern in _DOS_PATTERNS:
            if pattern in content_lower:
                logger.warning(f"硬编码拦截: 命中危险模式 '{pattern}'")
                return True, RejectReason.DOS_RISK

        # OUT_OF_SCOPE
        if scope:
            ip_str = target.split(":")[0]
            if not self._is_in_scope(ip_str, scope):
                return True, RejectReason.OUT_OF_SCOPE

        return False, None

    # ── LLM 评分 ─────────────────────────────────────────────

    def _build_review_prompt(self, payload: dict, mission: dict) -> str:
        lines = ["## 待审 Payload\n```"]
        lines.append(payload.get("content", "（空）"))
        lines.append("```\n")

        lines.append(f"**目标**: {payload.get('target', '未知')}")
        lines.append(f"**向量类型**: {payload.get('vector_type', '未知')}")
        lines.append(f"**技术**: {payload.get('technique', '未知')}\n")

        scope = mission.get("scope_expanded", mission.get("scope", []))
        lines.append(f"**授权范围 (scope)**: {scope}")
        lines.append(f"**任务风险等级**: {mission.get('risk_level', 3)}/5\n")

        edr = payload.get("edr_profile")
        if edr:
            lines.append(f"**EDR Profile**:")
            lines.append(f"  已检测: {edr.get('detected_products', [])}")
            lines.append(f"  遥测等级: {edr.get('telemetry_level', '未知')}\n")

        lines.append("请对以上 payload 进行四维评分，输出严格 JSON。")
        return "\n".join(lines)

    async def _call_llm(self, prompt: str) -> tuple[dict | None, int]:
        try:
            from core.llm_provider import call_llm_with_escalation, parse_robust_json
            import re

            def _parse(text):
                # critic 用自己的解析逻辑：正则提取 + json.loads
                if not text:
                    return None
                json_match = re.search(r'(\{.*\}|\[.*\])', text, re.DOTALL)
                if json_match:
                    text = json_match.group(1).strip()
                try:
                    return json.loads(text)
                except Exception:
                    return parse_robust_json(text)

            def _conf(parsed):
                """客观质量评分：检查评分结构完整性"""
                if parsed is None:
                    return None
                score = 0.0

                # 1. scores 四维齐全 (0.4)
                scores = parsed.get("scores", {})
                if isinstance(scores, dict):
                    dims = {"noise", "stability", "destructiveness", "compliance"}
                    present = sum(1 for d in dims if d in scores)
                    score += 0.4 * (present / len(dims))

                    # 数值在 0~1 范围内
                    all_valid = all(
                        isinstance(scores.get(d), (int, float)) and 0 <= scores.get(d, -1) <= 1
                        for d in dims if d in scores
                    )
                    if all_valid and present == len(dims):
                        score += 0.2

                # 2. verdict 合法枚举 (0.3)
                verdict = parsed.get("verdict", "")
                if verdict in ("APPROVED", "BLOCKED", "REQUIRES_APPROVAL"):
                    score += 0.3

                # 3. think 非空 (0.1)
                if parsed.get("think"):
                    score += 0.1

                return min(1.0, score)

            raw, tokens, escalated = await call_llm_with_escalation(
                system=_CRITIC_SYSTEM,
                prompt=prompt,
                agent_role="critic",
                confidence_fn=_conf,
                parse_fn=_parse,
                max_tokens=400,
            )

            if not raw:
                return None, 0

            result = _parse(raw)
            if escalated:
                logger.info("CriticAgent: 本次由大模型完成")
            return result, tokens
        except Exception as e:
            logger.error(f"CriticAgent LLM 调用失败: {e}")
            return None, 0

    # ── 阈值决策逻辑 ──────────────────────────────────────────

    def _apply_decision_logic(
        self,
        scores: dict,
        llm_verdict: str,
        risk_level: int,
    ) -> tuple[PayloadStatus, RejectReason | None]:
        """
        硬编码阈值覆盖 LLM 判定。
        顺序有意义：DoS/scope 是绝对否决；stability 优先于 noise。
        """
        dos   = float(scores.get("destructiveness", 0.0))
        comp  = float(scores.get("compliance", 1.0))
        stab  = float(scores.get("stability", 1.0))
        noise = float(scores.get("noise", 0.0))

        # DoS 风险判定：如果 risk_level 较高 (>=4)，对爆破等操作适当放宽阈值
        dos_limit = _DOS_THRESHOLD
        if risk_level >= 3:
            # 即使是中等风险等级，也允许轻量级的 Web 探测 (0.7 左右)
            dos_limit = 0.75
        if risk_level >= 4:
            dos_limit = 0.85  # 高风险任务下允许更具攻击性的操作
            
        if dos > dos_limit:
            return PayloadStatus.BLOCKED, RejectReason.DOS_RISK

        if comp < _COMPLIANCE_THRESHOLD:
            return PayloadStatus.BLOCKED, RejectReason.OUT_OF_SCOPE

        # C1c 修复：沙箱降级时收紧 stability 阈值
        stab_threshold = 0.65 if getattr(self, '_sandbox_degraded', False) else _STABILITY_THRESHOLD
        if stab < stab_threshold:
            return PayloadStatus.BLOCKED, RejectReason.SYNTAX_ERROR

        if noise > _NOISE_THRESHOLD and risk_level < 4:
            return PayloadStatus.BLOCKED, RejectReason.HIGH_NOISE

        if llm_verdict == "REQUIRES_APPROVAL":
            return PayloadStatus.REQUIRES_APPROVAL, None

        # LLM 说 BLOCKED 但未触发阈值：尊重 LLM（可能是 HALLUCINATION 等主观判断）
        if llm_verdict == "BLOCKED":
            return PayloadStatus.BLOCKED, RejectReason.HALLUCINATION

        return PayloadStatus.APPROVED, None

    # ── 输出构建 ─────────────────────────────────────────────

    def _make_approved_output(
        self, payload: dict, scores: dict,
        think_log: str, tokens_used: int,
    ) -> NodeOutput:
        payload_id = payload["id"]
        mutations = [
            StateMutation(
                operation=MutationOperation.UPDATE_STATUS,
                domain=StateDomain.PENDING_PAYLOADS,
                payload={
                    "id":            payload_id,
                    "status":        PayloadStatus.APPROVED,
                    "approved_at":   datetime.now(timezone.utc).isoformat(),
                    "critic_scores": scores,
                },
            ),
        ]
        events = [
            Event(
                type=EventType.PAYLOAD_APPROVED,
                priority=EventPriority.HIGH,
                source="critic_agent",
                payload={
                    "payload_id": payload_id,
                    "noise_cost": payload.get("noise_cost", 1),
                },
            ),
        ]
        return NodeOutput(
            mutations=mutations, events=events,
            next_hint=None, think_log=think_log, tokens_used=tokens_used,
        )

    def _make_blocked_output(
        self,
        payload: dict,
        reason: RejectReason | None,
        scores: dict | None,
        think_log: str,
        tokens_used: int,
        agent_id: str,
    ) -> NodeOutput:
        payload_id   = payload.get("id", "")
        content      = payload.get("content", "")
        target       = payload.get("target", "")
        vector_type  = payload.get("vector_type", "UNKNOWN")
        retry_count  = int(payload.get("retry_count", 0))

        mutations = [
            # pending_payloads：标记 BLOCKED
            StateMutation(
                operation=MutationOperation.UPDATE_STATUS,
                domain=StateDomain.PENDING_PAYLOADS,
                payload={
                    "id":            payload_id,
                    "status":        PayloadStatus.BLOCKED,
                    "reject_reason": reason,
                    "critic_scores": scores,
                },
            ),
            # tried_vectors：CRITIC_BLOCKED 记录（约束②：APPEND only）
            self._make_vector_mutation({
                "id":           str(uuid.uuid4()),
                "target":       target,
                "type":         vector_type,
                "payload":      content[:200],  # 截断，防超长
                "result":       VectorResult.CRITIC_BLOCKED,
                "fail_reason":  reason if reason else "UNKNOWN",
                "info_gain":    0.0,
                "novelty":      0.2,    # 已试过，衰减
                "retry_count":  retry_count,
                "tokens_used":  tokens_used,
                "duration_ms":  0,
                "agent_id":     agent_id,
            }),
        ]

        events = [
            Event.payload_rejected(
                payload_id=payload_id,
                reject_reason=reason if reason else RejectReason.SYNTAX_ERROR,
                original_payload=content,
                retry_count=retry_count,
            ),
        ]

        return NodeOutput(
            mutations=mutations, events=events,
            next_hint=None, think_log=think_log, tokens_used=tokens_used,
        )

    def _make_require_approval_output(
        self, payload: dict, scores: dict,
        think_log: str, tokens_used: int,
    ) -> NodeOutput:
        payload_id = payload["id"]
        mutations = [
            StateMutation(
                operation=MutationOperation.UPDATE_STATUS,
                domain=StateDomain.PENDING_PAYLOADS,
                payload={
                    "id":            payload_id,
                    "status":        PayloadStatus.REQUIRES_APPROVAL,
                    "critic_scores": scores,
                },
            ),
        ]
        # 不发 PAYLOAD_REJECTED（Loop A 不触发），只发人工审批请求
        events = [
            Event(
                type=EventType.HUMAN_APPROVAL_REQ,
                priority=EventPriority.CRITICAL,
                source="critic_agent",
                payload={
                    "payload_id":      payload_id,
                    "payload_content": payload.get("content", ""),
                    "target":          payload.get("target", ""),
                    "scores":          scores,
                    "reason":          "requires_human_review",
                },
            ),
        ]
        return NodeOutput(
            mutations=mutations, events=events,
            next_hint=None, think_log=think_log, tokens_used=tokens_used,
        )

    # ── 辅助 ─────────────────────────────────────────────────

    def _is_in_scope(self, ip_str: str, scope: list[str]) -> bool:
        if not ip_str or not scope:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return any(
                ip_obj in ipaddress.ip_network(cidr, strict=False)
                for cidr in scope
            )
        except ValueError:
            # 域名直接匹配
            if ip_str in scope:
                return True
            return False
