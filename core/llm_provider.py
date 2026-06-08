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
  - OpenAI 风格:    /chat/completions
"""

import asyncio
import json
import logging
import os
import re
import httpx

logger = logging.getLogger(__name__)


from core.config_manager import ConfigManager

# ── 双模型配置（延迟求值，实时从 ConfigManager 获取）──

def _get_local_config() -> dict:
    cfg = ConfigManager().get_all().get("llm", {})
    return {
        "base_url":   cfg.get("base_url", "http://127.0.0.1:8866"),
        "api_key":    cfg.get("api_key", "localkey"),
        "model":      cfg.get("model", "Qwen3.5-9B-MLX-8bit"),
        "api_format": cfg.get("api_format", ""),  # 空 = 自动检测
        "max_tokens": 1200,
    }

def _get_strong_config() -> dict:
    cfg = ConfigManager().get_all().get("llm", {})
    return {
        "base_url":   cfg.get("strong_base_url", ""),
        "api_key":    cfg.get("strong_api_key", ""),
        "model":      cfg.get("strong_model", "deepseek-v4-flash"),
        "api_format": cfg.get("strong_api_format", ""),
        "max_tokens": 2000,
    }


# ── 各 Agent 的升级阈值 ──────────────────────────────────────

ESCALATION_CONFIG = {
    "planner": {
        "threshold": 0.6,
        "garbage_threshold": 0.3,  # 低于此分直接丢弃，不升级
        "max_local_retries": 0,
        "escalate_on_parse_fail": True,
    },
    "exploit": {
        "threshold": 0.7,
        "garbage_threshold": 0.3,
        "max_local_retries": 0,
        "escalate_on_parse_fail": True,
    },
    "recon": {
        "threshold": 0.5,
        "garbage_threshold": 0.2,
        "max_local_retries": 0,
        "escalate_on_parse_fail": False,
    },
    "critic": {
        "threshold": 0.0,          # Critic 有硬编码规则兜底，不需要升级
        "garbage_threshold": 0.0,
        "max_local_retries": 0,
        "escalate_on_parse_fail": False,
    },
}


# ── 统计计数器 ────────────────────────────────────────────────

_local_calls: int = 0
_escalation_counts: dict[str, int] = {}
_strong_budget = int(ConfigManager().get_all().get("llm", {}).get("strong_budget", 20))
_strong_budget_used: int = 0
_total_tokens: int = 0
_total_tokens_base: int = 0
_total_tokens_strong: int = 0


def get_llm_stats() -> dict:
    """供 /progress API 暴露统计"""
    total = _local_calls + sum(_escalation_counts.values())
    return {
        "local_calls": _local_calls,
        "escalations": dict(_escalation_counts),
        "strong_upgrades": _strong_budget_used,
        "strong_budget": f"{_strong_budget - _strong_budget_used}/{_strong_budget}",
        "escalation_rate": f"{sum(_escalation_counts.values()) / max(total, 1) * 100:.1f}%",
        "total_tokens": _total_tokens,
        "total_tokens_base": _total_tokens_base,
        "total_tokens_strong": _total_tokens_strong,
    }


def reset_llm_stats():
    """每次新任务重置统计"""
    global _local_calls, _escalation_counts, _strong_budget_used, _total_tokens, _total_tokens_base, _total_tokens_strong
    _local_calls = 0
    _escalation_counts = {}
    _strong_budget_used = 0
    _total_tokens = 0
    _total_tokens_base = 0
    _total_tokens_strong = 0


# ── API 格式检测 ──────────────────────────────────────────────

def _detect_api_format(config: dict) -> str:
    """通过显式配置或 base_url 自动检测 API 格式"""
    fmt = config.get("api_format", "").strip()
    if fmt in ("anthropic", "openai"):
        return fmt
    # 未显式配置 → 根据 URL 自动判断
    url = config.get("base_url", "").lower()
    if any(k in url for k in ("openai", "deepseek", "together", "groq", "fireworks", "siliconflow")):
        return "openai"
    # 本地服务 (localhost/127.0.0.1) 默认 anthropic（兼容 LM Studio 等）
    if any(k in url for k in ("localhost", "127.0.0.1", "0.0.0.0")):
        return "anthropic"
    return "openai"  # 公网 API 默认 OpenAI 格式（更通用）


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
    global _local_calls, _strong_budget_used, _total_tokens, _total_tokens_base, _total_tokens_strong

    if force_strong and _is_strong_available():
        if _strong_budget_used < _strong_budget:
            _strong_budget_used += 1
            _escalation_counts[agent_role] = _escalation_counts.get(agent_role, 0) + 1
            local_cfg = _get_local_config()
            strong_cfg = _get_strong_config()
            logger.warning(
                f"[{agent_role}] 🔼 强制切换到大模型 | "
                f"模型: {local_cfg['model']} → {strong_cfg['model']} | "
                f"累计升级: {_escalation_counts[agent_role]} 次 "
                f"(预算 {_strong_budget_used}/{_strong_budget})"
            )
            text, tokens = await _call_single(system, prompt, strong_cfg, max_tokens)
            _total_tokens += tokens
            _total_tokens_strong += tokens
            if text.strip():
                logger.warning(
                    f"[{agent_role}] ✅ 大模型已响应 | "
                    f"模型: {strong_cfg['model']} | tokens={tokens}"
                )
            else:
                logger.error(
                    f"[{agent_role}] ❌ 大模型也返回空响应 | "
                    f"模型: {strong_cfg['model']}"
                )
            return text, tokens, True
        else:
            logger.warning(
                f"[{agent_role}] 需要强制升级，但大模型预算已用完 "
                f"({_strong_budget_used}/{_strong_budget})，回退本地"
            )

    _local_calls += 1
    text, tokens = await _call_single(system, prompt, _get_local_config(), max_tokens)
    _total_tokens += tokens
    _total_tokens_base += tokens
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
    global _local_calls, _strong_budget_used, _total_tokens, _total_tokens_base, _total_tokens_strong

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
        text, tokens = await _call_single(system, prompt, _get_local_config(), max_tokens)
        _total_tokens += tokens
        _total_tokens_base += tokens
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
            logger.debug(f"[{agent_role}] 输出质量分 {conf:.2f} ≥ {threshold}，无需升级")
            return text, tokens, False

        if conf is not None:
            logger.info(
                f"[{agent_role}] 输出质量分 {conf:.2f} < {threshold}，"
                f"本地模型能力不足，准备升级大模型 (attempt={attempt + 1}/{max_retries + 1})"
            )
            escalate_reason = f"质量分 {conf:.2f} < {threshold}"

        if attempt < max_retries:
            continue
        should_escalate = True

    # ── 升级到大模型 ──
    if should_escalate and _is_strong_available() and _strong_budget_used < _strong_budget:
        _strong_budget_used += 1
        _escalation_counts[agent_role] = _escalation_counts.get(agent_role, 0) + 1
        strong_cfg = _get_strong_config()
        logger.warning(
            f"[{agent_role}] 🔼 本地模型能力不足，切换到大模型 | "
            f"原因: {escalate_reason} | "
            f"模型: {_get_local_config()['model']} → {strong_cfg['model']} | "
            f"累计升级: {_escalation_counts[agent_role]} 次 "
            f"(预算 {_strong_budget_used}/{_strong_budget})"
        )
        text, tokens = await _call_single(system, prompt, strong_cfg, max_tokens)
        _total_tokens += tokens
        _total_tokens_strong += tokens
        if text.strip():
            logger.warning(
                f"[{agent_role}] ✅ 大模型已响应 | "
                f"模型: {strong_cfg['model']} | tokens={tokens}"
            )
        else:
            logger.error(
                f"[{agent_role}] ❌ 大模型也返回空响应 | "
                f"模型: {strong_cfg['model']}"
            )
        return text, tokens, True

    if should_escalate:
        if not _is_strong_available():
            logger.warning(
                f"[{agent_role}] ⚠️ 本地模型能力不足({escalate_reason})，"
                f"但 STRONG 模型未配置，降级使用本地结果"
            )
        else:
            logger.warning(
                f"[{agent_role}] ⚠️ 本地模型能力不足({escalate_reason})，"
                f"但大模型预算已用完 ({_strong_budget_used}/{_strong_budget})，降级使用本地结果"
            )

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
    base_url = config['base_url'].rstrip('/')
    if base_url.endswith("/v1"):
        url = f"{base_url}/messages"
    else:
        url = f"{base_url}/v1/messages"
    return await _do_request(url, headers, payload, _parse_anthropic_response)


async def _call_openai(
    system: str, prompt: str, config: dict, max_tokens: int
) -> tuple[str, int]:
    """OpenAI 风格 API: /chat/completions"""
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

    base_url = config['base_url'].rstrip('/')
    model = config.get('model', '').lower()

    # ✅ 修正路径拼接：DeepSeek 官方 OpenAI 路径 (https://api.deepseek.com/chat/completions) 不需要 /v1
    # 这一修改修正了向 DeepSeek 发送请求时因多出 /v1 导致的 404 错误。
    if "deepseek" in model:
        # DeepSeek 路径：https://api.deepseek.com/chat/completions
        url = f"{base_url}/chat/completions"
    else:
        # 兼容 base_url 本身带 /v1 的情况 (如 LM Studio: http://127.0.0.1:1234/v1)
        if base_url.endswith("/v1"):
            url = f"{base_url}/chat/completions"
        else:
            url = f"{base_url}/v1/chat/completions"

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
    cfg = _get_strong_config()
    return bool(cfg.get("api_key") and cfg.get("base_url"))


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
    """向后兼容的调用（自动检测 API 格式）"""
    global _local_calls
    _local_calls += 1
    config = {"api_key": api_key, "base_url": base_url, "model": model}
    return await _call_single(system, prompt, config, max_tokens)


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
    config = {"api_key": api_key, "base_url": base_url, "model": model}
    fmt = _detect_api_format(config)

    if fmt == "openai":
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": 10,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "Is this an image?"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="}}
            ]}],
        }
        url = f"{base_url.rstrip('/')}/v1/chat/completions"
    else:
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": 10,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "Is this an image?"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="}}
            ]}],
        }
        url = f"{base_url.rstrip('/')}/v1/messages"

    try:
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            resp = await client.post(url, headers=headers, json=payload)
            return resp.status_code == 200
    except:
        return False
