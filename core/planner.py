"""
Planner — 状态机大脑
基于 StatePruner 输出的裁剪视图，通过 LLM 推理生成结构化 Act 指令。
输出严格 JSON，不允许自由文本。
"""

from __future__ import annotations
import json
import logging
from anthropic import AsyncAnthropic

logger = logging.getLogger(__name__)

PLANNER_SYSTEM = """
你是一个渗透测试规划器（Planner）。
你的角色是基于当前攻击状态，决定下一步行动。

## 严格规则
1. 输出必须是合法 JSON，不得包含任何 JSON 以外的内容
2. 不要编造不存在的 CVE 或漏洞（如不确定，设置 rag_query 去查）
3. 如果 vectors_summary.recommendation == "ABANDON_STRATEGY"，必须换 VectorType
4. 如果 vectors_summary.hallucination_count > 0，必须先通过 rag_query 验证版本
5. 如果 focus.opportunity_flag == true，act.agent 必须是 exploit
6. 漏洞链思维：当发现多个低/中危漏洞时，评估它们的组合是否构成高危攻击链（如 信息泄露+弱口令=未授权访问，SSRF+文件读取=RCE，文件上传+路径遍历=WebShell）。hypothesis 应包含组合路径
7. 蜜罐警觉：如果目标 honeypot_suspect=true，立即切换到其他目标

## 输出格式
{
  "think": "推理过程（简洁，供审计）",
  "hypothesis": "当前最可能的攻击路径（一句话）",
  "confidence": 0.0到1.0之间的数字,
  "opportunity_detected": true或false,
  "act": {
    "agent": "recon 或 exploit 或 critic 或 cleanup",
    "action_type": "具体动作，如 port_scan / sqli_test / privesc",
    "params": {},
    "priority": 0.0到1.0
  },
  "rag_query": "需要查知识库时填写，否则填 null",
  "async_task": "需要长耗时任务时填写，否则填 null",
  "stall_assessment": "是否陷入僵局及原因",
  "focus_update": {
    "active_target": "IP或null（不变则填null）",
    "current_goal": "RECON/EXPLOIT/PRIVESC/LATERAL/PERSIST/REPORT 之一",
    "stall_count": "数字（如果本轮无进展则加1，否则置0）"
  }
}
"""


class Planner:

    def __init__(self, model: str = "Qwen3.5-9B-MLX-8bit", 
                 api_key: str = None, base_url: str = None):
        self.api_key = api_key or "Ww131421"
        self.base_url = base_url or "http://127.0.0.1:8866"
        logger.info(f"Planner init: model={model}, base_url={self.base_url}, key_len={len(self.api_key)}")
        self.client = AsyncAnthropic(api_key=self.api_key, base_url=self.base_url)
        self.model  = model

    async def think(self, pruned_view: dict) -> dict:
        """
        执行一次 Think 节拍。
        输入是 StatePruner 生成的裁剪视图，输出是结构化 Act 指令。
        """
        prompt = self._build_prompt(pruned_view)

        try:
            from core.llm_provider import call_llm_anthropic_style
            raw, tokens_used = await call_llm_anthropic_style(
                api_key=self.api_key,
                base_url=self.base_url,
                model=self.model,
                system=PLANNER_SYSTEM,
                prompt=prompt,
                max_tokens=4000
            )

            if not raw.strip():
                return self._fallback_output()

            # 更加鲁棒的 JSON 提取：寻找第一个 { 和最后一个 }
            import re
            json_match = re.search(r'(\{.*\}|\[.*\])', raw, re.DOTALL)
            if json_match:
                raw = json_match.group(1).strip()
            
            try:
                output = json.loads(raw)
            except json.JSONDecodeError:
                # 最后的尝试：尝试补全可能缺失的引号和括号
                try:
                    tmp_raw = raw
                    if tmp_raw.count('"') % 2 != 0: tmp_raw += '"'
                    if tmp_raw.count('{') > tmp_raw.count('}'): 
                        tmp_raw += '}' * (tmp_raw.count('{') - tmp_raw.count('}'))
                    output = json.loads(tmp_raw)
                except:
                    logger.error(f"Planner 输出非法 JSON 且修复失败: {raw[:200]}...")
                    return self._fallback_output()
            
            if not isinstance(output, dict):
                logger.error(f"Planner: JSON 解析结果不是 dict (type={type(output).__name__}), value={str(output)[:100]}")
                return self._fallback_output()

            # 调试：打印 Planner 输出的 focus_update 和 act
            logger.debug(
                f"Planner raw output: "
                f"act={output.get('act')} "
                f"focus_update={output.get('focus_update')} "
                f"type(fu)={type(output.get('focus_update')).__name__}"
            )

            # 处理 focus 更新
            if output.get("focus_update"):
                await self._apply_focus_update(
                    output["focus_update"], pruned_view
                )

            logger.info(
                f"Planner Think完成: agent={output.get('act', {}).get('agent')} "
                f"confidence={output.get('confidence')}"
            )
            return output

        except json.JSONDecodeError as e:
            logger.error(f"Planner 输出非法 JSON: {e}")
            # 返回安全的降级指令：派 Recon 补充情报
            return self._fallback_output()

    def _build_prompt(self, view: dict) -> str:
        """构建 Planner Prompt，突出关键信息"""
        lines = ["## 当前攻击状态\n"]

        # mission 摘要
        m = view.get("mission", {})
        lines.append(f"**目标**: {m.get('goal', '未设置')}")
        lines.append(f"**授权范围**: {m.get('scope', [])}")
        lines.append(f"**范围内具体 IP**: {m.get('scope_expanded', m.get('scope', []))}")
        lines.append(f"**风险等级**: {m.get('risk_level', 3)}/5\n")

        # focus 当前意图
        f = view.get("focus", {})
        lines.append(f"**当前焦点目标**: {f.get('active_target', '未设置')}")
        lines.append(f"**当前目标**: {f.get('current_goal', 'RECON')}")
        lines.append(f"**连续无进展次数**: {f.get('stall_count', 0)}")
        if f.get("opportunity_flag"):
            lines.append(
                f"⚡ **机会发现**: {f.get('opportunity_target')} "
                f"原因: {f.get('opportunity_reason')}"
            )
        lines.append("")

        # vectors 摘要（最关键的决策依据）
        vs = view.get("vectors_summary", {})
        lines.append(f"**已尝试向量**: 总计{vs.get('total', 0)}次")
        lines.append(f"  成功: {vs.get('success_count', 0)} | "
                     f"失败: {vs.get('fail_count', 0)} | "
                     f"拦截: {vs.get('blocked_count', 0)}")
        lines.append(f"  平均信息增益: {float(vs.get('avg_info_gain') or 0):.2f}")
        lines.append(f"  幻觉次数: {vs.get('hallucination_count', 0)}")
        lines.append(f"  **建议**: {vs.get('recommendation', 'EXPLORE')}\n")

        # assets 摘要
        assets = view.get("assets", {})
        if assets.get("active_host"):
            host = assets["active_host"]
            lines.append(f"**当前目标主机**:")
            lines.append(f"  OS: {host['host'].get('os', '未知')}")
            lines.append(f"  权限: {host['host'].get('access_level', 'NONE')}")
            lines.append(
                f"  开放服务: "
                f"{[s.get('app','?')+':'+str(s.get('port','?')) for s in host.get('services', [])]}"
            )
            if host.get("creds"):
                lines.append(f"  已获凭据: {len(host['creds'])}个")
            if host['host'].get("honeypot_suspect"):
                reasons = host['host'].get('honeypot_reasons', [])
                lines.append(f"  ⚠️ **疑似蜜罐**: {', '.join(reasons)}（建议切换目标，避免浪费资源）")
        lines.append("")

        # 横向移动机会
        if view.get("lateral_opportunities"):
            lines.append(f"**横向移动机会**:")
            for opp in view["lateral_opportunities"]:
                lines.append(
                    f"  → {opp['target']} (距离 {opp['hops']} 跳)"
                )
            lines.append("")

        # 知识召回结果
        if view.get("knowledge"):
            lines.append(f"**相关知识**:")
            for k in view["knowledge"]:
                lines.append(
                    f"  [{float(k.get('relevance') or 0):.2f}] "
                    f"{k.get('source')}: {k.get('summary', '')[:100]}"
                )
            lines.append("")

        # pending 状态
        ps = view.get("pending_summary", {})
        lines.append(
            f"**队列状态**: "
            f"待审Payload={ps.get('payloads_pending', 0)} | "
            f"侦察中={ps.get('recon_running', 0)} | "
            f"异步完成={ps.get('async_tasks_done', 0)}\n"
        )

        lines.append("请基于以上状态，决定下一步行动。")
        return "\n".join(lines)

    async def _apply_focus_update(self, update: dict, view: dict):
        """
        Planner 输出中包含 focus_update 时，
        由 Orchestrator 统一提交（这里仅记录，实际写入由 Orchestrator 处理）
        """
        # 实际上由 Orchestrator 调用 state_api 写入
        # Planner 本身不直接写 State（无副作用原则）
        pass

    def _fallback_output(self) -> dict:
        """LLM 输出异常时的安全降级：派 Recon 补充情报"""
        return {
            "think":               "LLM 输出解析失败，降级为 Recon 模式",
            "hypothesis":          "信息不足，需要补充侦察",
            "confidence":          0.1,
            "opportunity_detected": False,
            "act": {
                "agent":       "recon",
                "action_type": "general_recon",
                "params":      {},
                "priority":    0.5,
            },
            "rag_query":       None,
            "async_task":      None,
            "stall_assessment": "Planner 输出异常",
            "focus_update": {
                "active_target": None,
                "current_goal":  "RECON",
                # 不再硬编码 stall_count，由 Orchestrator 维持现状或递增
            }
        }
