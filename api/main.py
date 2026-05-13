"""
FastAPI 入口 — Human 审批接口

职责：
  1. 提供 Payload REQUIRES_APPROVAL 人工审批端点（Loop A 硬性节点）
  2. 提供 Cleanup 人工审批端点（Loop C 硬性节点，约束⑦）
  3. 提供任务状态查询端点（运营可视化）
  4. 写回 State（通过 StateAPI），不绕过约束

安全说明：
  - 所有写操作需要 Bearer token（X-API-Key header）
  - token 从环境变量 API_KEY 读取
  - 不暴露 payload 明文内容（仅 ID + 摘要）
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ── 鉴权 ──────────────────────────────────────────────────────

_API_KEY         = os.environ.get("API_KEY", "changeme")
_api_key_header  = APIKeyHeader(name="X-API-Key", auto_error=True)


async def _require_key(api_key: str = Security(_api_key_header)) -> str:
    if api_key != _API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )
    return api_key


# ── StateAPI 依赖注入 ─────────────────────────────────────────

_state_api_instance = None


def register_state_api(state_api) -> None:
    """由启动脚本注入 StateAPI 单例，必须在 uvicorn 启动前调用。"""
    global _state_api_instance
    _state_api_instance = state_api


# ── Lifespan（FastAPI 推荐的启动/关闭钩子）────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    启动时：验证 StateAPI 连接可用。
    关闭时：可在此处做连接清理（当前无需额外操作）。
    """
    if _state_api_instance is None:
        logger.warning(
            "API: StateAPI not registered — endpoints will return 503. "
            "Call register_state_api() before starting uvicorn."
        )
    else:
        try:
            # 轻量连通性探测：ping Redis
            await _state_api_instance.redis.ping()
            logger.info("API: StateAPI connection verified (Redis OK)")
        except Exception as e:
            logger.error(f"API: StateAPI connection check failed: {e}")
    yield
    # shutdown hook — nothing to teardown at the API layer


# ── App ───────────────────────────────────────────────────────

app = FastAPI(
    title="Pentest Agent Human Approval API",
    description="Human-in-the-loop approval endpoints for the agentic pentest framework.",
    version="0.1.0",
    lifespan=lifespan,
)


async def _get_state_api():
    """返回全局 StateAPI 单例（由 main entrypoint 初始化后注入）"""
    if _state_api_instance is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="StateAPI not initialized",
        )
    return _state_api_instance


# ── Request / Response 模型 ───────────────────────────────────

class ApprovalDecision(BaseModel):
    approved:   bool
    note:       str = ""      # 审批意见（记录用）


class CleanupApproval(BaseModel):
    approved_task_ids:   list[str]   # 批准执行的任务 ID 列表
    rejected_task_ids:   list[str] = []
    note:                str = ""


# ── Payload 审批（REQUIRES_APPROVAL）────────────────────────

@app.get("/payloads/pending-approval",
         summary="列出待人工审批的 payload",
         dependencies=[Depends(_require_key)])
async def list_pending_approval_payloads(
    state_api=Depends(_get_state_api),
):
    """返回 status=REQUIRES_APPROVAL 的 pending_payloads 列表（不含 content 明文）"""
    items = await state_api._get_items_by_index("idx:payload_ids", "payload:")
    result = []
    for p in items:
        if p.get("status") == "REQUIRES_APPROVAL":
            result.append({
                "id":            p["id"],
                "target":        p.get("target"),
                "technique":     p.get("technique"),
                "vector_type":   p.get("vector_type"),
                "noise_cost":    p.get("noise_cost"),
                "retry_count":   p.get("retry_count", 0),
                "created_at":    p.get("created_at"),
                "critic_scores": p.get("critic_scores"),
            })
    return {"payloads": result, "count": len(result)}


@app.post("/payloads/{payload_id}/approve",
          summary="批准或拒绝单个 payload",
          dependencies=[Depends(_require_key)])
async def decide_payload(
    payload_id: str,
    decision:   ApprovalDecision,
    state_api=Depends(_get_state_api),
):
    key = f"payload:{payload_id}"
    raw = await state_api.redis.get(key)
    if not raw:
        raise HTTPException(status_code=404, detail=f"Payload {payload_id} not found")

    p = json.loads(raw)
    if p.get("status") != "REQUIRES_APPROVAL":
        raise HTTPException(
            status_code=409,
            detail=f"Payload status is {p.get('status')}, expected REQUIRES_APPROVAL",
        )

    now = datetime.now(timezone.utc).isoformat()
    if decision.approved:
        p["status"]      = "APPROVED"
        p["approved_at"] = now
        p["approval_note"] = decision.note
    else:
        p["status"]        = "BLOCKED"
        p["reject_reason"] = "HUMAN_REJECTED"
        p["approval_note"] = decision.note

    await state_api.redis.set(key, json.dumps(p))
    logger.info(
        f"Human {'approved' if decision.approved else 'rejected'} payload {payload_id}"
    )
    return {"payload_id": payload_id, "new_status": p["status"]}


# ── Cleanup 审批（约束⑦）────────────────────────────────────

@app.get("/cleanup/tasks",
         summary="列出待人工审批的清理任务",
         dependencies=[Depends(_require_key)])
async def list_cleanup_tasks(
    state_api=Depends(_get_state_api),
):
    """返回 status=PENDING_HUMAN 的 cleanup 任务（含完整操作信息，供人工确认）"""
    tasks = await state_api.get_pending_cleanup_tasks()
    return {"tasks": tasks, "count": len(tasks)}


@app.post("/cleanup/approve",
          summary="批量审批或拒绝清理任务",
          dependencies=[Depends(_require_key)])
async def approve_cleanup(
    approval: CleanupApproval,
    state_api=Depends(_get_state_api),
):
    """
    批准部分或全部清理任务。
    批准的任务进入 APPROVED（Executor 将执行）。
    拒绝的任务进入 HUMAN_REJECTED（不执行，记录原因）。
    """
    now = datetime.now(timezone.utc).isoformat()
    updated = []

    for tid in approval.approved_task_ids:
        key = f"cleanup_task:{tid}"
        raw = await state_api.redis.get(key)
        if raw:
            t = json.loads(raw)
            t["status"]      = "APPROVED"
            t["approved_at"] = now
            t["approval_note"] = approval.note
            await state_api.redis.set(key, json.dumps(t))
            updated.append({"id": tid, "status": "APPROVED"})

    for tid in approval.rejected_task_ids:
        key = f"cleanup_task:{tid}"
        raw = await state_api.redis.get(key)
        if raw:
            t = json.loads(raw)
            t["status"]        = "HUMAN_REJECTED"
            t["approval_note"] = approval.note
            await state_api.redis.set(key, json.dumps(t))
            updated.append({"id": tid, "status": "HUMAN_REJECTED"})

    logger.info(
        f"Cleanup approval: {len(approval.approved_task_ids)} approved, "
        f"{len(approval.rejected_task_ids)} rejected"
    )
    return {
        "updated": updated,
        "approved_count":  len(approval.approved_task_ids),
        "rejected_count":  len(approval.rejected_task_ids),
    }


# ── 进度查询（只读）────────────────────────────────────────

@app.get("/progress",
         summary="实时进度摘要（每 5 秒刷新）",
         dependencies=[Depends(_require_key)])
async def get_progress(state_api=Depends(_get_state_api)):
    """
    返回机器可读的进度快照，驱动 TUI 或轮询监控。
    包含：主机发现进度、凭据获取、payload 执行统计。
    """
    import time
    try:
        total_hosts = await state_api.count_hosts()
        owned_hosts = await state_api.count_owned_hosts()
        pending_payloads = await state_api.count_pending_payloads()
        running_recon = await state_api.count_running_recon()
        focus = await state_api.get_focus()
        vectors = await state_api.get_vectors_summary()
        done_tasks = await state_api.get_done_tasks()

        # 计算进度百分比（基于 mission scope 预估）
        mission = await state_api.get_mission()
        scope_ips = sum(
            sum(1 for _ in range(
                max(256, 2 ** (32 - int(cidr.split("/")[-1])))
                if "/" in cidr else 1
            ))
            for cidr in mission.get("scope", [])
        )

        return {
            "timestamp": int(time.time()),
            "hosts": {
                "discovered": total_hosts,
                "owned":      owned_hosts,
                "scope_hint": min(total_hosts, scope_ips) if scope_ips else None,
                "owned_pct":  round(owned_hosts / max(total_hosts, 1) * 100, 1),
            },
            "active_target": focus.get("active_target"),
            "current_goal":  focus.get("current_goal"),
            "confidence":    focus.get("confidence", 0.0),
            "stall_count":   focus.get("stall_count", 0),
            "recon": {
                "running": running_recon,
            },
            "payloads": {
                "pending": pending_payloads,
                "vectors_total":   vectors.get("total", 0),
                "vectors_success": vectors.get("success_count", 0),
            },
            "pending_tasks": len(done_tasks),
        }
    except Exception as e:
        logger.error(f"Progress endpoint error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/footprints",
         summary="查询所有 footprints（攻击轨迹）",
         dependencies=[Depends(_require_key)])
async def get_footprints(
    cleaned: bool | None = None,
    state_api=Depends(_get_state_api),
):
    """
    返回全量 footprints。
    cleaned=true  → 只返回已清理的
    cleaned=false → 只返回未清理的
    cleaned=None  → 全量
    """
    footprints = await state_api.get_all_footprints()
    if cleaned is not None:
        footprints = [f for f in footprints if f.get("cleaned", False) == cleaned]
    return {"footprints": footprints, "count": len(footprints)}


# ── 报告端点 ─────────────────────────────────────────────────

_report_generator = None


def register_report_generator(report_gen) -> None:
    """由启动脚本注入 ReportGenerator 单例。"""
    global _report_generator
    _report_generator = report_gen


@app.get("/report",
         summary="获取最新渗透测试报告",
         dependencies=[Depends(_require_key)])
async def get_latest_report(
    state_api=Depends(_get_state_api),
):
    """返回最新报告的 JSON。若尚未生成过报告，返回 404。"""
    import glob
    output_dir = os.environ.get("REPORT_OUTPUT_DIR", "reports")
    json_files = sorted(glob.glob(os.path.join(output_dir, "report_*.json")))
    if not json_files:
        raise HTTPException(status_code=404, detail="No report generated yet")

    with open(json_files[-1]) as f:
        report = json.load(f)
    return report


@app.post("/report/generate",
          summary="手动触发报告生成",
          dependencies=[Depends(_require_key)])
async def generate_report(
    state_api=Depends(_get_state_api),
):
    """按需生成新的渗透测试报告。"""
    if _report_generator is None:
        raise HTTPException(
            status_code=503,
            detail="ReportGenerator not initialized",
        )
    mission = await state_api.get_mission()
    report = await _report_generator.generate(state_api, mission)
    return {
        "status": "generated",
        "report_file": report.get("report_file"),
        "executive_summary": report.get("executive_summary"),
    }


# ── 启动入口（直接运行 uvicorn）──────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("API_PORT", 8080)),
        reload=False,
    )
