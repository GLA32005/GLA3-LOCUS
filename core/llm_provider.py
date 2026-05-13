import logging
import httpx
import json

logger = logging.getLogger(__name__)

async def call_llm_anthropic_style(
    api_key: str, 
    base_url: str, 
    model: str, 
    system: str, 
    prompt: str, 
    max_tokens: int = 1500
) -> tuple[str, int]:
    """
    使用原生 httpx 直接请求本地 LLM 接口（绕过 SDK 可能存在的认证或 Header 冲突）。
    """
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
    
    try:
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.post(
                url, 
                json=payload, 
                headers=headers, 
                timeout=180.0
            )
        
        if response.status_code != 200:
            logger.error(f"LLM Provider: 请求失败 {response.status_code} - {response.text}")
            return "", 0
            
        data = response.json()
        
        # 提取文本和思维链
        text = ""
        thinking = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")
            if block.get("type") == "thinking":
                thinking += block.get("thinking", "")
        
        # 如果 text 为空但有思维链，尝试从思维链里捞
        if not text.strip() and thinking:
            text = thinking
            
        tokens = data.get("usage", {}).get("total_tokens", 0)
        return text, tokens

    except Exception as e:
        logger.error(f"LLM Provider: 发生异常: {e}")
        return "", 0


# ── Vision 能力检测 ────────────────────────────────────────

_vision_supported: bool | None = None  # 缓存，只检测一次


async def check_vision_support(
    api_key: str, base_url: str, model: str
) -> bool:
    """
    探测当前模型是否支持 Vision（多模态图片输入）。
    发送一个最小的带图片消息，根据响应判断。
    结果缓存，只检测一次。
    """
    global _vision_supported
    if _vision_supported is not None:
        return _vision_supported

    # 1x1 白色 PNG（最小有效图片）
    tiny_png_b64 = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4"
        "nGP4z8BQDwAEgAF/pooBPQAAAABJRU5ErkJggg=="
    )

    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 50,
        "messages": [{
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": tiny_png_b64,
                    },
                },
                {"type": "text", "text": "Describe this image in one word."},
            ],
        }],
    }

    url = f"{base_url.rstrip('/')}/v1/messages"
    try:
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.post(
                url, json=payload, headers=headers, timeout=30.0
            )
        if response.status_code == 200:
            _vision_supported = True
            logger.info("LLM Provider: Vision 支持 ✅")
        else:
            _vision_supported = False
            logger.info(
                f"LLM Provider: Vision 不支持 ❌ (status={response.status_code})"
            )
    except Exception as e:
        _vision_supported = False
        logger.info(f"LLM Provider: Vision 检测失败，默认关闭: {e}")

    return _vision_supported


async def call_llm_with_vision(
    api_key: str,
    base_url: str,
    model: str,
    system: str,
    prompt: str,
    image_b64: str,
    image_media_type: str = "image/png",
    max_tokens: int = 1500,
) -> tuple[str, int]:
    """
    带图片的 LLM 调用。仅在 check_vision_support() 返回 True 时使用。
    """
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": image_media_type,
                        "data": image_b64,
                    },
                },
                {"type": "text", "text": prompt},
            ],
        }],
    }

    url = f"{base_url.rstrip('/')}/v1/messages"
    try:
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.post(
                url, json=payload, headers=headers, timeout=180.0
            )

        if response.status_code != 200:
            logger.error(
                f"LLM Vision: 请求失败 {response.status_code}"
            )
            return "", 0

        data = response.json()
        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")
        tokens = data.get("usage", {}).get("total_tokens", 0)
        return text, tokens

    except Exception as e:
        logger.error(f"LLM Vision: 异常: {e}")
        return "", 0

