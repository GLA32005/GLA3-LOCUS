"""
安全检查共享模块 — 破坏性命令检测
Critic Agent 和 External Sandbox 共用此模块，确保检测逻辑一致且不可绕过。

设计原则：
  - 对输入做多层规范化后再匹配，防止常见混淆绕过
  - deny-list 模式（已知危险模式），作为 Docker 沙箱的补充层
  - 宁可误报也不漏报（保守原则）

P0-1 修复：替代原 critic_agent._DOS_PATTERNS 和 sandbox_external._DESTRUCTIVE_PATTERNS
的 naive 子串匹配，增加对混淆/变形 payload 的检测能力。
"""

from __future__ import annotations

import base64
import re
import logging

logger = logging.getLogger(__name__)

# ── 危险命令模式（在规范化后的内容上做子串匹配）──────────────

_DESTRUCTIVE_PATTERNS: tuple[str, ...] = (
    "rm -rf /",
    "rm -rf /*",
    "mkfs",
    "drop database",
    "drop table",
    "format c:",
    "del /f /s /q c:\\",
    "del /f /s /q /",
    "> /dev/sda",
    "dd if=/dev/zero of=/dev/",
    "shutdown -h",
    "shutdown /s",
    "halt",
    "poweroff",
    "reboot",
    "init 0",
    "init 6",
)

# ── 正则模式（捕获变形写法）─────────────────────────────────

_DESTRUCTIVE_REGEXES: tuple[re.Pattern, ...] = (
    # rm 带任意 flag 组合删除根目录
    re.compile(r'\brm\s+(-[a-zA-Z]+\s+)*/\s*$', re.MULTILINE),
    re.compile(r'\brm\s+(-[a-zA-Z]+\s+)*/\*'),
    # dd 写入块设备
    re.compile(r'\bdd\b.*\bof\s*=\s*/dev/[a-z]'),
    # 重定向截断块设备
    re.compile(r'>\s*/dev/sd[a-z]'),
    re.compile(r'>\s*/dev/nvme'),
    # wipefs / shred 针对设备
    re.compile(r'\b(wipefs|shred)\b.*(/dev/sd|/dev/nvme)'),
    # fork bomb（bash 经典形式及变体）
    re.compile(r':\(\)\s*\{\s*:\|:\s*&\s*\}\s*;?\s*:'),
    re.compile(r'\.\(\)\s*\{\s*\.\|\.\s*&\s*\}\s*;?\s*\.'),
    # Python 破坏性操作
    re.compile(r'shutil\.rmtree\s*\(\s*[\'\"]/'),
    re.compile(r'os\.remove\s*\(\s*[\'\"]/'),
)

# ── Base64 管道执行模式 ──────────────────────────────────────

_B64_PIPE = re.compile(
    r'(?:echo|printf)\s+["\']?([A-Za-z0-9+/=]{8,})["\']?\s*\|\s*'
    r'(?:base64\s+-d|openssl\s+base64\s+-d)',
    re.IGNORECASE,
)
_B64_HEREDOC = re.compile(
    r'base64\s+-d\s*<<<\s*["\']?([A-Za-z0-9+/=]{8,})',
    re.IGNORECASE,
)

# ── eval/exec 包装 ───────────────────────────────────────────

_EVAL_WRAPPERS = re.compile(
    r'\b(eval|exec|source)\s+["\']+(.+?)["\']',
    re.IGNORECASE,
)


def _normalize_shell(content: str) -> str:
    """
    对 shell 命令做规范化，消除常见混淆手法。
    """
    s = content
    # 1. $IFS / ${IFS} → 空格（最常见的分隔符混淆）
    s = re.sub(r'\$\{?IFS\}?', ' ', s)
    # 2. 反斜杠续行
    s = re.sub(r'\\\n', '', s)
    # 3. 去除引号分割拼接：'r'"m"' → rm
    s = re.sub(r"'([^']*)'", r'\1', s)
    s = re.sub(r'"([^"]*)"', r'\1', s)
    # 4. 折叠多余空白
    s = re.sub(r'\s+', ' ', s).strip()
    return s


def _expand_variables(content: str) -> str:
    """
    展开简单的 VAR=value; $VAR 或 VAR=value && $VAR 变量替换模式。
    """
    assignments: dict[str, str] = {}
    for m in re.finditer(r'\b([A-Z_][A-Z0-9_]*)=(\S+)', content, re.IGNORECASE):
        assignments[m.group(1)] = m.group(2)

    if not assignments:
        return content

    expanded = content
    for var, val in assignments.items():
        expanded = expanded.replace(f'${{{var}}}', val)
        expanded = expanded.replace(f'${var}', val)
    return expanded


def _decode_base64_payloads(content: str) -> list[str]:
    """提取并解码 base64 编码的 payload 片段。"""
    decoded = []
    for pattern in (_B64_PIPE, _B64_HEREDOC):
        for m in pattern.finditer(content):
            try:
                raw = base64.b64decode(m.group(1))
                decoded.append(raw.decode('utf-8', errors='replace'))
            except Exception:
                pass
    return decoded


def check_destructive(content: str) -> tuple[bool, str]:
    """
    多层检测 payload 是否包含破坏性命令。

    检测流程：
      1. 原始内容子串匹配
      2. 规范化后子串匹配（消除 $IFS、引号分割等）
      3. 变量展开后匹配（捕获 X=rm; $X -rf /）
      4. Base64 解码后匹配（捕获 echo ...|base64 -d|bash）
      5. eval/exec 内部内容提取后匹配
      6. 正则匹配（捕获灵活的变形写法）

    Returns:
        (is_destructive, matched_pattern_description)
    """
    if not content:
        return False, ""

    # 构建待检测的所有变体
    variants: list[str] = [content]

    normalized = _normalize_shell(content)
    if normalized != content:
        variants.append(normalized)

    expanded = _expand_variables(content)
    if expanded != content:
        variants.append(expanded)
        norm_expanded = _normalize_shell(expanded)
        if norm_expanded != expanded:
            variants.append(norm_expanded)

    # base64 解码结果
    for decoded in _decode_base64_payloads(content):
        variants.append(decoded)
        variants.append(_normalize_shell(decoded))

    # eval/exec 内部内容
    for m in _EVAL_WRAPPERS.finditer(content):
        inner = m.group(2).strip()
        variants.append(inner)
        variants.append(_normalize_shell(inner))

    # 去重，保持顺序
    seen: set[str] = set()
    unique: list[str] = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            unique.append(v)

    # 子串匹配（在每个变体的 lower 上）
    for variant in unique:
        variant_lower = variant.lower()
        for pattern in _DESTRUCTIVE_PATTERNS:
            if pattern in variant_lower:
                logger.warning(
                    f"安全检测: 命中破坏性模式 '{pattern}' "
                    f"(变体: {variant[:80]})"
                )
                return True, f"destructive_pattern: {pattern}"

    # 正则匹配
    for variant in unique:
        for regex in _DESTRUCTIVE_REGEXES:
            if regex.search(variant):
                logger.warning(
                    f"安全检测: 命中破坏性正则 '{regex.pattern}' "
                    f"(变体: {variant[:80]})"
                )
                return True, f"destructive_regex: {regex.pattern}"

    return False, ""
