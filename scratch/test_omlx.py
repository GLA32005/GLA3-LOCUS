import asyncio
import httpx
import json

async def test_omlx():
    url = "http://127.0.0.1:8866/v1/messages"
    
    # 尝试几种不同的组合
    payload = {
        "model": "Qwen3.5-9B-MLX-8bit",
        "max_tokens": 10,
        "messages": [{"role": "user", "content": "hi"}]
    }
    
    headers_list = [
        # 1. 模拟 Anthropic SDK (带你截图里的 Key)
        {
            "x-api-key": os.getenv("API_KEY", "missing_key"),
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        },
        # 2. 完全不带 Key
        {
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        },
        # 3. 模拟 OpenAI 风格但发往 Claude 端口 (有些中转是这样的)
        {
            "Authorization": "Bearer Ww131421",
            "content-type": "application/json"
        }
    ]

    async with httpx.AsyncClient() as client:
        for i, h in enumerate(headers_list):
            print(f"\n--- 测试组合 {i+1} ---")
            print(f"Headers: {h}")
            try:
                resp = await client.post(url, json=payload, headers=h, timeout=5.0)
                print(f"Status: {resp.status_code}")
                print(f"Response: {resp.text}")
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_omlx())
