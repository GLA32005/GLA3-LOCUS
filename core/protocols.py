"""
Agentic Pentest Framework — 核心协议定义
版本: v4.0
说明: 所有组件必须遵守这三个协议，任何扩展不得破坏接口契约
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid


# ════════════════════════════════════════════════════════════
# 枚举定义 — 所有状态值必须用枚举，禁止魔法字符串
# ════════════════════════════════════════════════════════════

class VectorType(str, Enum):
    SQLI            = "SQLI"
    XSS             = "XSS"
    SSRF            = "SSRF"
    AUTH_BYPASS     = "AUTH_BYPASS"
    BRUTE_FORCE     = "BRUTE_FORCE"
    CRED_REUSE      = "CRED_REUSE"
    PRIVESC         = "PRIVESC"
    LATERAL_MOVE    = "LATERAL_MOVE"
    LOTL            = "LOTL"
    RECON           = "RECON"


class VectorResult(str, Enum):
    SUCCESS         = "SUCCESS"
    FAIL            = "FAIL"
    CRITIC_BLOCKED  = "CRITIC_BLOCKED"
    SANDBOX_FAIL    = "SANDBOX_FAIL"
    ABANDONED       = "ABANDONED"
    UNKNOWN         = "UNKNOWN"
    TIMEOUT         = "TIMEOUT"


class FailReason(str, Enum):
    PATCHED             = "PATCHED"
    WAF_BLOCKED         = "WAF_BLOCKED"
    VERSION_MISMATCH    = "VERSION_MISMATCH"
    HALLUCINATION       = "HALLUCINATION"
    CRITIC_BLOCKED      = "CRITIC_BLOCKED"
    MAX_RETRY           = "MAX_RETRY"
    OUT_OF_SCOPE        = "OUT_OF_SCOPE"
    DOS_RISK            = "DOS_RISK"
    SYNTAX_ERROR        = "SYNTAX_ERROR"
    HIGH_NOISE          = "HIGH_NOISE"
    EXECUTION_FAILED    = "EXECUTION_FAILED"
    NETWORK_UNREACHABLE = "NETWORK_UNREACHABLE"
    AUTH_FAILED         = "AUTH_FAILED"
    SERVICE_NOT_FOUND   = "SERVICE_NOT_FOUND"
    UNKNOWN             = "UNKNOWN"


class PayloadStatus(str, Enum):
    PENDING             = "PENDING"
    APPROVED            = "APPROVED"
    BLOCKED             = "BLOCKED"
    REQUIRES_APPROVAL   = "REQUIRES_APPROVAL"
    EXECUTING           = "EXECUTING"
    DONE                = "DONE"


class RejectReason(str, Enum):
    DOS_RISK            = "DOS_RISK"
    SYNTAX_ERROR        = "SYNTAX_ERROR"
    OUT_OF_SCOPE        = "OUT_OF_SCOPE"
    HALLUCINATION       = "HALLUCINATION"
    HIGH_NOISE          = "HIGH_NOISE"
    REQUIRES_APPROVAL   = "REQUIRES_APPROVAL"


class TaskStatus(str, Enum):
    PENDING     = "PENDING"
    RUNNING     = "RUNNING"
    DONE        = "DONE"
    TIMEOUT     = "TIMEOUT"
    FAILED      = "FAILED"


class AccessLevel(str, Enum):
    NONE    = "NONE"
    SHELL   = "SHELL"
    USER    = "USER"
    ROOT    = "ROOT"
    DA      = "DA"      # Domain Admin


class AgentType(str, Enum):
    RECON   = "recon"
    EXPLOIT = "exploit"
    CRITIC  = "critic"
    CLEANUP = "cleanup"


class EventType(str, Enum):
    TASK_COMPLETED      = "TASK_COMPLETED"
    ASSET_DISCOVERED    = "ASSET_DISCOVERED"
    OPPORTUNITY_FOUND   = "OPPORTUNITY_FOUND"
    PAYLOAD_REJECTED    = "PAYLOAD_REJECTED"
    PAYLOAD_APPROVED    = "PAYLOAD_APPROVED"
    EXPLOIT_SUCCESS     = "EXPLOIT_SUCCESS"
    STALL_DETECTED      = "STALL_DETECTED"
    CLEANUP_STATE       = "CLEANUP_STATE"
    TASK_TIMEOUT        = "TASK_TIMEOUT"
    HUMAN_APPROVAL_REQ  = "HUMAN_APPROVAL_REQ"
    TARGET_UNREACHABLE  = "TARGET_UNREACHABLE"


# ════════════════════════════════════════════════════════════
# 协议一：StateMutation
# Agent 不直接调用 State API，只返回 mutation 列表
# Orchestrator 统一提交，保证事务性和可审计性
# ════════════════════════════════════════════════════════════

class MutationOperation(str, Enum):
    APPEND          = "append"          # 追加（tried_vectors / footprints）
    UPSERT          = "upsert"          # 插入或更新（assets 节点）
    UPDATE_STATUS   = "update_status"   # 只改状态字段
    WRITE           = "write"           # 全量写入（focus 覆写）
    ADD_EDGE        = "add_edge"        # Neo4j 添加关系边
    DELETE          = "delete"          # 仅 cleanup 阶段使用


class StateDomain(str, Enum):
    ASSETS              = "assets"
    TRIED_VECTORS       = "tried_vectors"
    FOCUS               = "focus"
    PENDING_PAYLOADS    = "pending_payloads"
    PENDING_RECON       = "pending_recon_tasks"
    ASYNC_TASKS         = "async_tasks"
    FOOTPRINTS          = "footprints"
    CONTEXT_RETRIEVALS  = "context_retrievals"
    PENDING_CLEANUP     = "pending_cleanup_tasks"
    KNOWLEDGE_QUERY     = "knowledge_query"


@dataclass
class StateMutation:
    """
    Agent 对 State 的一次变更意图。
    Agent 是无副作用的纯函数，只返回 mutation，由 Orchestrator 统一执行。
    """
    operation:  MutationOperation
    domain:     StateDomain
    payload:    dict
    id:         str = field(default_factory=lambda: str(uuid.uuid4()))
    ts:         datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def validate(self) -> bool:
        """基础校验，防止 Agent 发出非法 mutation"""
        # tried_vectors 和 footprints 只允许 APPEND
        if self.domain in (StateDomain.TRIED_VECTORS, StateDomain.FOOTPRINTS):
            if self.operation != MutationOperation.APPEND:
                raise ValueError(
                    f"{self.domain} 只允许 APPEND 操作，"
                    f"收到 {self.operation}（审计完整性约束）"
                )
        # knowledge_query 只允许 APPEND
        if self.domain == StateDomain.KNOWLEDGE_QUERY:
            if self.operation != MutationOperation.APPEND:
                raise ValueError("knowledge_query 只允许 APPEND")
        # focus 只允许 WRITE（全量覆写）
        if self.domain == StateDomain.FOCUS:
            if self.operation != MutationOperation.WRITE:
                raise ValueError("focus 只允许全量 WRITE")
        return True


class KnowledgeQueryType(str, Enum):
    """知识查询类型，提高检索精度"""
    CVE         = "CVE"
    BYPASS      = "Bypass"
    LOTL        = "LotL"
    METHODOLOGY = "Methodology"


@dataclass
class KnowledgeQuery:
    """Agent → Orchestrator 的知识查询请求"""
    query:          str                 # 查询文本
    type:           KnowledgeQueryType  # 知识类型
    reason:         str                 # 为什么需要查（供审计）
    source_agent:   str                 # 哪个 Agent 发起的
    priority:       str = "NORMAL"      # NORMAL / HIGH（快速修正模式下为 HIGH）


# ════════════════════════════════════════════════════════════
# 协议二：Event
# 所有组件通过 Event 通信，不直接调用对方
# ════════════════════════════════════════════════════════════

class EventPriority(int, Enum):
    CRITICAL    = 0     # 立即处理，不合并（PAYLOAD_REJECTED / EXPLOIT_SUCCESS）
    HIGH        = 1     # 100ms 内合并同类
    NORMAL      = 2     # 500ms 内合并同类
    LOW         = 3     # 可延迟，批量处理


@dataclass
class Event:
    """
    系统内所有异步通信的载体。
    优先级决定 Orchestrator 的处理时机。
    """
    type:       EventType
    payload:    dict
    source:     str                 # 发出事件的组件名
    priority:   EventPriority = EventPriority.NORMAL
    id:         str = field(default_factory=lambda: str(uuid.uuid4()))
    ts:         float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())

    @classmethod
    def payload_rejected(cls, payload_id: str, reject_reason: RejectReason,
                          original_payload: str, retry_count: int) -> "Event":
        return cls(
            type=EventType.PAYLOAD_REJECTED,
            priority=EventPriority.CRITICAL,   # 立即处理，触发快速修正循环
            source="critic_agent",
            payload={
                "payload_id":       payload_id,
                "reject_reason":    reject_reason,
                "original_payload": original_payload,
                "retry_count":      retry_count,
            }
        )

    @classmethod
    def task_completed(cls, task_id: str, result: dict) -> "Event":
        return cls(
            type=EventType.TASK_COMPLETED,
            priority=EventPriority.HIGH,
            source="executor",
            payload={"task_id": task_id, "result": result}
        )

    @classmethod
    def exploit_success(cls, target: str, access_level: AccessLevel,
                         vector_id: str) -> "Event":
        return cls(
            type=EventType.EXPLOIT_SUCCESS,
            priority=EventPriority.CRITICAL,
            source="executor",
            payload={
                "target":       target,
                "access_level": access_level,
                "vector_id":    vector_id,
            }
        )

    @classmethod
    def opportunity_found(cls, target: str, reason: str) -> "Event":
        return cls(
            type=EventType.OPPORTUNITY_FOUND,
            priority=EventPriority.CRITICAL,
            source="orchestrator",
            payload={"target": target, "reason": reason}
        )


# ════════════════════════════════════════════════════════════
# 协议三：Node（Agent 基类）
# 所有 Agent 实现此接口
# 输入：裁剪后的 State 视图 + 触发事件
# 输出：mutation 列表 + 待发事件列表
# ════════════════════════════════════════════════════════════

@dataclass
class NodeInput:
    """
    Agent 的统一输入格式。
    state_view 由 StatePruner 生成，已控制在 token 预算内。
    trigger_event 是触发本次调用的原因。
    """
    state_view:     dict            # StatePruner 输出
    trigger_event:  Event           # 触发事件
    agent_id:       str             # 本次调用的唯一标识，用于日志追踪


@dataclass
class NodeOutput:
    """
    Agent 的统一输出格式。
    Agent 是无副作用的纯函数：不直接操作数据库，不直接发事件。
    所有副作用通过 mutations 和 events 声明，由 Orchestrator 执行。
    """
    mutations:      list[StateMutation]     # 要写回 Blackboard 的变更
    events:         list[Event]             # 要抛出的事件
    next_hint:      Optional[AgentType] = None  # 建议调度的下一个 Agent（可忽略）
    think_log:      str = ""                # 推理过程，写入审计日志
    tokens_used:    int = 0                 # 本次 LLM 调用消耗的 token


class BaseAgent(ABC):
    """
    所有 Agent 的基类。
    子类只需实现 run()，不需要关心 State 写入和事件发布。
    """

    def __init__(self, agent_type: AgentType):
        self.agent_type = agent_type

    @abstractmethod
    async def run(self, input: NodeInput) -> NodeOutput:
        """
        核心执行逻辑。
        必须是无副作用的：不直接调用 State API，不直接发 Event。
        所有副作用通过返回的 NodeOutput 声明。
        """
        pass

    def _make_vector_mutation(self, vector_data: dict) -> StateMutation:
        """便捷方法：创建 tried_vectors 追加 mutation"""
        return StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.TRIED_VECTORS,
            payload=vector_data
        )

    def _make_footprint_mutation(self, footprint_data: dict) -> StateMutation:
        """便捷方法：创建 footprints 追加 mutation"""
        return StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.FOOTPRINTS,
            payload=footprint_data
        )

    def _make_payload_mutation(self, payload_data: dict) -> StateMutation:
        """便捷方法：写入 pending_payloads"""
        return StateMutation(
            operation=MutationOperation.UPSERT,
            domain=StateDomain.PENDING_PAYLOADS,
            payload=payload_data
        )

    def _make_recon_task_mutation(self, task_data: dict) -> StateMutation:
        """便捷方法：写入 pending_recon_tasks（Recon Agent专用）"""
        return StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.PENDING_RECON,
            payload=task_data
        )

    def _make_knowledge_query(
        self, query: str, type: str, reason: str, priority: str = "NORMAL"
    ) -> StateMutation:
        """便捷方法：创建知识查询请求（Agent → Orchestrator）"""
        return StateMutation(
            operation=MutationOperation.APPEND,
            domain=StateDomain.KNOWLEDGE_QUERY,
            payload={
                "query":        query,
                "type":         type,
                "reason":       reason,
                "source_agent": self.agent_type.value,
                "priority":     priority,
            }
        )
