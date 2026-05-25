"""
LLM Provider — 统一 LLM 访问适配层

双模型架构：
  LOCAL  = 本地小模型（主力，零成本）
  STRONG = 远端大模型（升级通道，按需调用）

升级触发条件：
  1. 置信度 < 阈值
  2. JSON 解析失败（可配置）
  3. 外部强制（force_strong=True）

API 格式自动适配：
  - Anthropic 风格: /v1/messages
  - OpenAI 风格:    /v1/chat/completions
"""

import asyncio
import json
import logging
import os
import re
import httpx

logger = logging.getLogger(__name__)


# ── 双模型配置 ────────────────────────────────────────────────

LOCAL_CONFIG = {
    "base_url":   os.getenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:8866"),
    "api_key":    os.getenv("ANTHROPIC_API_KEY", "local"),
    "model":      os.getenv("LOCAL_MODEL", "Qwen3.5-9B-MLX-8bit"),
    "api_format": os.getenv("LOCAL_API_FORMAT", "anthropic"),  # anthropic | openai
    "max_tokens": 1200,
}

STRONG_CONFIG = {
    "base_url":   os.getenv("STRONG_BASE_URL", ""),
    "api_key":    os.getenv("STRONG_API_KEY", ""),
    "model":      os.getenv("STRONG_MODEL", "deepseek-chat"),
    "api_format": os.getenv("STRONG_API_FORMAT", ""),  # 空=自动检测
    "max_tokens": 2000,
}


# ── 各 Agent 的升级阈值 ──────────────────────────────────────

ESCALATION_CONFIG = {
    "planner": {
        "threshold": 0.6,
        "max_local_retries": 1,
        "escalate_on_parse_fail": True,
    },
    "exploit": {
        "threshold": 0.7,
        "max_local_retries": 1,
        "escalate_on_parse_fail": True,
    },
    "recon": {
        "threshold": 0.4,
        "max_local_retries": 2,
        "escalate_on_parse_fail": False,
    },
    "critic": {
        "threshold": 0.5,
        "max_local_retries": 2,
        "escalate_on_parse_fail": False,
    },
}


# ── 统计计数器 ────────────────────────────────────────────────

_local_calls: int = 0
_escalation_counts: dict[str, int] = {}
_strong_budget = int(os.getenv("STRONG_BUDGET", "20"))
_strong_budget_used: int = 0


def get_llm_stats() -> dict:
    """供 /progress API 暴露统计"""
    total = _local_calls + sum(_escalation_counts.values())
    return {
        "local_calls": _local_calls,
        "escalations": dict(_escalation_counts),
        "strong_budget": f"{_strong_budget_used}/{_strong_budget}",
        "escalation_rate": f"{sum(_escalation_counts.values()) / max(total, 1) * 100:.1f}%",
    }


def reset_llm_stats():
    """每次新任务重置统计"""
    global _local_calls, _escalation_counts, _strong_budget_used
    _local_calls = 0
    _escalation_counts = {}
    _strong_budget_used = 0


# ── API 格式检测 ──────────────────────────────────────────────

def _detect_api_format(config: dict) -> str:
    """通过 base_url 自动检测 API 格式"""
    fmt = config.get("api_format", "").strip()
    if fmt in ("anthropic", "openai"):
        return fmt
    url = config.get("base_url", "").lower()
    if any(k in url for k in ("openai", "deepseek", "together", "groq", "fireworks")):
        return "openai"
    return "anthropic"


# ── 核心调用函数 ──────────────────────────────────────────────

async def call_llm(
    system: str,
    prompt: str,
    agent_role: str = "planner",
    max_tokens: int = 1500,
    force_strong: bool = False,
) -> tuple[str, int, bool]:
    """
    单次 LLM 调用。
    返回 (response_text, tokens_used, was_escalated)
    """
    global _local_calls, _strong_budget_used

    if force_strong and _is_strong_available():
        if _strong_budget_used < _strong_budget:
            _strong_budget_used += 1
            _escalation_counts[agent_role] = _escalation_counts.get(agent_role, 0) + 1
            logger.info(f"[{agent_role}] 🔼 强制升级大模型 (累计第 {_escalation_counts[agent_role]} 次)")
            text, tokens = await _call_single(system, prompt, STRONG_CONFIG, max_tokens)
            return text, tokens, True
        else:
            logger.warning(f"[{agent_role}] 大模型预算已用完 ({_strong_budget_used}/{_strong_budget})，回退本地")

    _local_calls += 1
    text, tokens = await _call_single(system, prompt, LOCAL_CONFIG, max_tokens)
    return text, tokens, False


async def call_llm_with_escalation(
    system: str,
    prompt: str,
    agent_role: str,
    confidence_fn,     # callable(parsed_dict) -> float | None
    parse_fn,           # callable(text) -> dict | None
    max_tokens: int = 1500,
    force_strong: bool = False,
) -> tuple[str, int, bool]:
    """
    带自动升级的 LLM 调用。
    1. 先跑本地小模型
    2. 解析失败 or 置信度不足 → 升级大模型
    返回 (response_text, tokens_used, was_escalated)
    """
    global _local_calls, _strong_budget_used

    # 外部强制升级（如 stall 触发、新资产发现）
    if force_strong:
        return await call_llm(system, prompt, agent_role, max_tokens, force_strong=True)

    cfg = ESCALATION_CONFIG.get(agent_role, ESCALATION_CONFIG["planner"])
    threshold = cfg["threshold"]
    max_retries = cfg["max_local_retries"]

    last_text = ""
    last_tokens = 0
    should_escalate = False
    escalate_reason = ""

    # ── 本地重试 ──
    for attempt in range(max_retries + 1):
        _local_calls += 1
        text, tokens = await _call_single(system, prompt, LOCAL_CONFIG, max_tokens)
        last_text = text
        last_tokens = tokens

        if not text.strip():
            escalate_reason = "空响应"
            should_escalate = cfg["escalate_on_parse_fail"]
            break

        parsed = parse_fn(text)
        if parsed is None:
            if not cfg["escalate_on_parse_fail"]:
                logger.debug(f"[{agent_role}] 解析失败，不升级（兜底策略）")
                return text, tokens, False
            escalate_reason = "解析失败"
            logger.warning(f"[{agent_role}] 本地解析失败 attempt={attempt + 1}")
            if attempt < max_retries:
                continue
            should_escalate = True
            break

        conf = confidence_fn(parsed)
        if conf is not None and conf >= threshold:
            logger.debug(f"[{agent_role}] 本地置信度 {conf:.2f} ≥ {threshold}，无需升级")
            return text, tokens, False

        if conf is not None:
            logger.info(
                f"[{agent_role}] 本地置信度 {conf:.2f} < {threshold}，"
                f"attempt={attempt + 1}/{max_retries + 1}"
            )
            escalate_reason = f"置信度 {conf:.2f} < {threshold}"

        if attempt < max_retries:
            continue
        should_escalate = True

    # ── 升级到大模型 ──
    if should_escalate and _is_strong_available() and _strong_budget_used < _strong_budget:
        _strong_budget_used += 1
        _escalation_counts[agent_role] = _escalation_counts.get(agent_role, 0) + 1
        logger.info(
            f"[{agent_role}] 🔼 升级大模型: {escalate_reason} "
            f"(累计第 {_escalation_counts[agent_role]} 次)"
        )
        text, tokens = await _call_single(system, prompt, STRONG_CONFIG, max_tokens)
        return text, tokens, True

    if should_escalate:
        if not _is_strong_available():
            logger.debug(f"[{agent_role}] 需要升级但 STRONG 未配置，返回本地结果")
        else:
            logger.warning(f"[{agent_role}] 需要升级但预算已用完，返回本地结果")

    return last_text, last_tokens, False


# ── 底层单次调用 ──────────────────────────────────────────────

async def _call_single(
    system: str, prompt: str, config: dict, max_tokens: int
) -> tuple[str, int]:
    """底层单次调用，自动适配 Anthropic / OpenAI 格式"""
    fmt = _detect_api_format(config)
    if fmt == "openai":
        return await _call_openai(system, prompt, config, max_tokens)
    return await _call_anthropic(system, prompt, config, max_tokens)


async def _call_anthropic(
    system: str, prompt: str, config: dict, max_tokens: int
) -> tuple[str, int]:
    """Anthropic 风格 API: /v1/messages"""
    headers = {
        "x-api-key": config["api_key"] or "",
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": config["model"],
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }
    url = f"{config['base_url'].rstrip('/')}/v1/messages"
    return await _do_request(url, headers, payload, _parse_anthropic_response)


async def _call_openai(
    system: str, prompt: str, config: dict, max_tokens: int
) -> tuple[str, int]:
    """OpenAI 风格 API: /v1/chat/completions"""
    headers = {
        "Authorization": f"Bearer {config['api_key'] or ''}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": config["model"],
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    }
    url = f"{config['base_url'].rstrip('/')}/v1/chat/completions"
    return await _do_request(url, headers, payload, _parse_openai_response)


async def _do_request(
    url: str, headers: dict, payload: dict, parse_fn
) -> tuple[str, int]:
    """通用 HTTP 请求，含指数退避重试"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=180.0, trust_env=False) as client:
                resp = await client.post(url, headers=headers, json=payload)
                if resp.status_code == 429:
                    wait = 2 ** attempt
                    logger.warning(f"LLM 速率限制 (429)，等待 {wait}s 后重试...")
                    await asyncio.sleep(wait)
                    continue
                resp.raise_for_status()
                return parse_fn(resp.json())
        except (httpx.HTTPError, KeyError) as e:
            if attempt == max_retries - 1:
                logger.error(f"LLM 调用在 {max_retries} 次重试后失败: {e}")
                return "", 0
            wait = min(60, (2 ** attempt) + 1.0)
            logger.warning(f"LLM 调用失败: {e}，第 {attempt + 1} 次重试 (等待 {wait}s)...")
            await asyncio.sleep(wait)
    return "", 0


def _parse_anthropic_response(data: dict) -> tuple[str, int]:
    text = ""
    thinking = ""
    for block in data.get("content", []):
        if block.get("type") == "text":
            text += block.get("text", "")
        elif block.get("type") == "thinking":
            thinking += block.get("thinking", "")
    if not text.strip() and thinking:
        text = thinking
    tokens = data.get("usage", {}).get("total_tokens", 0)
    return text, tokens


def _parse_openai_response(data: dict) -> tuple[str, int]:
    choices = data.get("choices", [])
    text = choices[0]["message"]["content"] if choices else ""
    tokens = data.get("usage", {}).get("total_tokens", 0)
    return text, tokens


def _is_strong_available() -> bool:
    return bool(STRONG_CONFIG.get("api_key") and STRONG_CONFIG.get("base_url"))


# ── 旧接口兼容（call_llm_anthropic_style）────────────────────
# 保留给尚未迁移的模块（如 report_generator）

async def call_llm_anthropic_style(
    api_key: str,
    base_url: str,
    model: str,
    system: str,
    prompt: str,
    max_tokens: int = 1500,
) -> tuple[str, int]:
    """向后兼容的 Anthropic 风格调用"""
    global _local_calls
    _local_calls += 1
    config = {"api_key": api_key, "base_url": base_url, "model": model, "api_format": "anthropic"}
    return await _call_anthropic(system, prompt, config, max_tokens)


# ── JSON 解析 ─────────────────────────────────────────────────

def parse_robust_json(raw_text: str):
    """
    极度鲁棒的 JSON 提取器：
    1. 处理 Markdown 代码块包裹
    2. 处理前后废话
    3. 启发式修复未闭合括号或引号
    4. 针对 Qwen 等模型在 think 字段包含换行的场景进行了优化
    """
    if not raw_text:
        return None
    
    clean_raw = raw_text.strip()
    
    # 1. 处理 Markdown 代码块
    if "```json" in clean_raw:
        json_match = re.search(r"```json\s*(\{.*\}|\[.*\])\s*```", clean_raw, re.DOTALL)
        if json_match:
            clean_raw = json_match.group(1).strip()
    elif "```" in clean_raw:
        start_idx = clean_raw.find("{") if "{" in clean_raw else clean_raw.find("[")
        end_idx = (
            clean_raw.rfind("}") if "}" in clean_raw else 
            clean_raw.rfind("]") if "]" in clean_raw else -1
        )
        if 0 <= start_idx < end_idx:
            clean_raw = clean_raw[start_idx : end_idx + 1]

    # 2. 基础正则提取（防止前后有废话）
    json_match = re.search(r'(\{.*\}|\[.*\])', clean_raw, re.DOTALL)
    if json_match:
        clean_raw = json_match.group(1).strip()

    try:
        # strict=False 允许字符串包含控制字符（如未转义的换行符）
        return json.loads(clean_raw, strict=False)
    except json.JSONDecodeError:
        # 3. 启发式修复（补齐截断或修复格式错误）
        try:
            # A. 尝试修复字符串中未转义的换行
            tmp = re.sub(r'([^\\])\n', r'\1\\n', clean_raw)
            
            # B. 尝试修复字符串中未转义的双引号 (Issue 4)
            tmp = re.sub(r'("[\w_]+"\s*:\s*")(.*?)("(?=\s*[,\}]))', 
                         lambda m: m.group(1) + m.group(2).replace('"', '\\"') + m.group(3), 
                         tmp, flags=re.DOTALL)

            try:
                return json.loads(tmp, strict=False)
            except:
                pass

            # C. 补齐未闭合引号和括号
            if tmp.count('"') % 2 != 0:
                tmp += '"'
            
            brackets = {"{": "}", "[": "]"}
            stack = []
            in_string = False
            escape = False
            
            for char in tmp:
                if char == '"' and not escape:
                    in_string = not in_string
                elif char == '\\' and in_string:
                    escape = not escape
                    continue
                
                if not in_string:
                    if char in brackets.keys():
                        stack.append(char)
                    elif char in brackets.values():
                        if stack and brackets[stack[-1]] == char:
                            stack.pop()
                
                escape = False
            
            while stack:
                tmp += brackets[stack.pop()]
                
            return json.loads(tmp, strict=False)
        except Exception:
            return None


# ── Vision 能力检测 ──────────────────────────────────────────

async def check_vision_support(
    api_key: str, base_url: str, model: str
) -> bool:
    """探测当前模型是否支持 Vision"""
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    payload = {
        "model": model,
        "max_tokens": 10,
        "messages": [{
            "role": "user", 
            "content": [
                {"type": "text", "text": "Is this an image?"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="}}
            ]
        }]
    }
    
    url = f"{base_url.rstrip('/')}/v1/messages"
    try:
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            resp = await client.post(url, headers=headers, json=payload)
            return resp.status_code == 200
    except:
        return False
