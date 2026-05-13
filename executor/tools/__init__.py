"""
L4 工具层基础类型。
所有工具实现 BaseTool 接口，返回统一的 ToolResult。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ToolResult:
    """
    工具执行结果。Executor 根据此结构写回 State。

    assets:    发现的资产列表，每项是 pending_payload schema 中 assets 节点格式
               {"ip": ..., "os": ..., "services": [...], "creds": [...]}
    footprint: 写入目标系统的动作记录（约束⑤：必须记录到 footprints）
    info_gain: 0.0-1.0，用于更新 tried_vectors.info_gain
    novelty:   0.0-1.0，衰减因子
    """
    success:      bool
    raw:          dict                        # 原始工具输出（截断后存 tried_vectors.payload）
    assets:       list[dict] = field(default_factory=list)
    footprint:    dict | None = None          # 非 None → 写 footprints（主动写入目标时）
    info_gain:    float = 0.0
    novelty:      float = 1.0
    error:        str | None = None
    duration_ms:  int = 0


class BaseTool(ABC):
    """所有 L4 工具的基类。"""

    @abstractmethod
    async def run(self, target: str, params: dict) -> ToolResult:
        """
        执行工具，返回 ToolResult。
        target: "ip" 或 "ip:port" 或 "ip:port/path"
        params: 工具特定参数
        """
