"""
Screenshot Tool — Web 页面截图
基于 Playwright 对 HTTP 服务进行截图，供 LLM Vision 分析。
如果 Playwright 未安装，运行时优雅降级。
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import time
import tempfile

from . import BaseTool, ToolResult

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30  # 秒


class ScreenshotTool(BaseTool):
    """
    Playwright 截图工具。
    params 字段：
      protocol: "http" / "https"（默认自动检测）
      wait_ms:  页面加载等待时间（默认 3000ms）
    返回：
      raw.screenshot_b64: base64 编码的截图
      raw.title: 页面标题
      raw.status: HTTP 状态码
    """

    async def run(self, target: str, params: dict) -> ToolResult:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return ToolResult(
                success=False, raw={},
                error="playwright not found — pip install playwright && playwright install chromium"
            )

        url = self._normalize_url(target, params)
        wait_ms = int(params.get("wait_ms", 3000))
        timeout = int(params.get("timeout_s", _DEFAULT_TIMEOUT))

        logger.info(f"ScreenshotTool: capturing {url}")
        t0 = time.time()

        try:
            async with async_playwright() as p:
                browser = await asyncio.wait_for(
                    p.chromium.launch(headless=True),
                    timeout=10,
                )
                try:
                    page = await browser.new_page(
                        viewport={"width": 1280, "height": 900}
                    )
                    response = await asyncio.wait_for(
                        page.goto(url, wait_until="domcontentloaded"),
                        timeout=timeout,
                    )

                    # 等待额外的渲染时间
                    await asyncio.sleep(wait_ms / 1000)

                    title = await page.title()
                    status = response.status if response else 0

                    # 截图为 bytes
                    screenshot_bytes = await page.screenshot(
                        type="png", full_page=False
                    )
                    screenshot_b64 = base64.b64encode(screenshot_bytes).decode()

                    duration_ms = int((time.time() - t0) * 1000)

                    logger.info(
                        f"ScreenshotTool: {url} title='{title}' "
                        f"status={status} size={len(screenshot_bytes)}B"
                    )

                    return ToolResult(
                        success=True,
                        raw={
                            "screenshot_b64": screenshot_b64,
                            "title": title,
                            "status": status,
                            "url": url,
                        },
                        info_gain=0.5,
                        duration_ms=duration_ms,
                    )
                finally:
                    await browser.close()

        except asyncio.TimeoutError:
            duration_ms = int((time.time() - t0) * 1000)
            return ToolResult(
                success=False, raw={},
                error=f"timeout after {timeout}s",
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = int((time.time() - t0) * 1000)
            error_msg = str(e)
            if "Executable doesn't exist" in error_msg:
                error_msg = "playwright chromium not installed — run: playwright install chromium"
            logger.warning(f"ScreenshotTool error: {error_msg}")
            return ToolResult(
                success=False, raw={},
                error=error_msg,
                duration_ms=duration_ms,
            )

    @staticmethod
    def _normalize_url(target: str, params: dict) -> str:
        if target.startswith("http"):
            return target
        proto = params.get("protocol", "")
        if not proto:
            port = ""
            if ":" in target:
                _, port = target.split(":", 1)
            proto = "https" if port in ("443", "8443") else "http"
        return f"{proto}://{target}"
