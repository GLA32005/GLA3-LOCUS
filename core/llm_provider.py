"""
LLM Provider — 统一 LLM 访问适配层
针对 Anthropic 风格接口（如 Claude, Qwen-OMLX）的封装。
"""

import json
import logging
import re
import httpx
from core.protocols import KnowledgeQueryType

logger = logging.getLogger(__name__)

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
        # 有些模型不写 json 关键字
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
            # 针对 "key": "value" 结构中 value 包含未转义引号的情况
            # 我们匹配 "key": " ... " 且后面跟着 , 或 } 的情况
            tmp = re.sub(r'("[\w_]+"\s*:\s*")(.*?)("(?=\s*[,\}]))', 
                         lambda m: m.group(1) + m.group(2).replace('"', '\\"') + m.group(3), 
                         tmp, flags=re.DOTALL)

            try:
                return json.loads(tmp, strict=False)
            except:
                pass

            # C. 补齐未闭合引号和括号
            # 补齐未闭合引号
            if tmp.count('"') % 2 != 0:
                tmp += '"'
            
            # 补齐未闭合括号 (考虑字符串内部情况)
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

async def call_llm_anthropic_style(
    api_key: str, 
    base_url: str, 
    model: str, 
    system: str, 
    prompt: str, 
    max_tokens: int = 1500
) -> tuple[str, int]:
    """
    使用原生 httpx 直接请求本地 LLM 接口，包含指数退避重试机制。
    """
    import asyncio
    
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": prompt}]
    }
    
    url = f"{base_url.rstrip('/')}/v1/messages"
    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=180.0, trust_env=False) as client:
                resp = await client.post(url, headers=headers, json=payload)
                if resp.status_code == 429:
                    wait_time = 2 ** attempt
                    logger.warning(f"LLM 速率限制 (429)，等待 {wait_time}s 后重试...")
                    await asyncio.sleep(wait_time)
                    continue
                
                resp.raise_for_status()
                data = resp.json()
                
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
                
        except (httpx.HTTPError, KeyError) as e:
            if attempt == max_retries - 1:
                logger.error(f"LLM 调用在 {max_retries} 次重试后失败: {e}")
                return "", 0
            wait_time = 1.0 * (attempt + 1)
            logger.warning(f"LLM 调用失败: {e}，正在进行第 {attempt+1} 次重试...")
            await asyncio.sleep(wait_time)
            
    return "", 0

# ── Vision 能力检测 ──
# 移除了全局变量缓存，由调用方管理状态以避免污染

async def check_vision_support(
    api_key: str, base_url: str, model: str
) -> bool:
    """探测当前模型是否支持 Vision"""
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    # 发送一个最小的带图片消息测试
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
