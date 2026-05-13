-- ══════════════════════════════════════════════════════
-- Agentic Pentest Framework — ClickHouse 表结构
-- 审计日志组：追加写入，永不修改
-- ══════════════════════════════════════════════════════

-- tried_vectors 表
-- 记录所有攻击尝试，是 Planner 决策的经验来源
CREATE TABLE IF NOT EXISTS tried_vectors
(
    id            UUID,
    target        String,                    -- "ip:port/path"
    type          Enum8(
                    'SQLI'          = 1,
                    'XSS'           = 2,
                    'SSRF'          = 3,
                    'AUTH_BYPASS'   = 4,
                    'BRUTE_FORCE'   = 5,
                    'CRED_REUSE'    = 6,
                    'PRIVESC'       = 7,
                    'LATERAL_MOVE'  = 8,
                    'LOTL'          = 9,
                    'RECON'         = 10
                  ),
    payload       String,
    result        Enum8(
                    'SUCCESS'        = 1,
                    'FAIL'           = 2,
                    'CRITIC_BLOCKED' = 3,
                    'SANDBOX_FAIL'   = 4,
                    'ABANDONED'      = 5,
                    'UNKNOWN'        = 6,
                    'TIMEOUT'        = 7
                  ),
    fail_reason   Enum8(
                    'PATCHED'           = 1,
                    'WAF_BLOCKED'       = 2,
                    'VERSION_MISMATCH'  = 3,
                    'HALLUCINATION'     = 4,
                    'CRITIC_BLOCKED'    = 5,
                    'MAX_RETRY'         = 6,
                    'OUT_OF_SCOPE'      = 7,
                    'DOS_RISK'          = 8,
                    'SYNTAX_ERROR'      = 9,
                    'HIGH_NOISE'        = 10,
                    'UNKNOWN'           = 11
                  ),
    info_gain     Float32 DEFAULT 0.0,      -- 0.0~1.0，情报价值
    novelty       Float32 DEFAULT 1.0,      -- 新颖度，已试过的会衰减
    retry_count   UInt8   DEFAULT 0,
    tokens_used   UInt32  DEFAULT 0,
    duration_ms   UInt32  DEFAULT 0,
    agent_id      String,
    ts            DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (target, type, ts)
TTL ts + INTERVAL 90 DAY;            -- 90天后自动归档


-- footprints 表
-- 记录 Agent 在目标系统上留下的所有痕迹
-- Cleanup Agent 读取此表生成逆向操作
CREATE TABLE IF NOT EXISTS footprints
(
    id          UUID,
    type        Enum8(
                  'FILE_WRITE'        = 1,
                  'ACCOUNT_CREATE'    = 2,
                  'REG_MODIFY'        = 3,
                  'SCHEDULED_TASK'    = 4,
                  'SERVICE_INSTALL'   = 5,
                  'WEBSHELL'          = 6,
                  'PERSISTENCE'       = 7,
                  'TOOLMAKING_TIMEOUT'= 8,
                  'CONSTRAINT_VIOLATION' = 9,
                  'UNKNOWN'           = 10
                ),
    target      String,               -- 目标主机 IP
    detail      String,               -- JSON 格式的详细信息
    cleaned     Bool DEFAULT false,   -- Cleanup 后标记为 true
    ts          DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (target, type, ts);


-- ══════════════════════════════════════════════════════
-- Neo4j 初始化 Cypher
-- assets 图谱的约束和索引
-- ══════════════════════════════════════════════════════

-- 主机节点唯一约束
-- NOTE: 以下 Cypher 语句需通过 cypher-shell 执行，不能在 ClickHouse 的 init.sql 中执行。
-- 使用方式：docker exec -i <neo4j_container> cypher-shell -u neo4j -p password < neo4j_init.cypher
--
-- CREATE CONSTRAINT host_ip_unique IF NOT EXISTS
-- FOR (h:Host) REQUIRE h.ip IS UNIQUE;
--
-- CREATE INDEX service_port IF NOT EXISTS
-- FOR (s:Service) ON (s.port);
--
-- CREATE INDEX cred_username IF NOT EXISTS
-- FOR (c:Credential) ON (c.username);


-- ══════════════════════════════════════════════════════
-- Redis Key 规范
-- ══════════════════════════════════════════════════════
-- mission              → 只读，启动时加载
-- focus                → 全量 JSON，Planner 每轮覆写
-- context_retrievals   → 临时，每轮 Think 后清空
-- payload:{id}         → pending_payloads 条目
-- recon_task:{id}      → pending_recon_tasks 条目
-- async_task:{id}      → async_tasks 条目
-- cleanup_task:{id}    → pending_cleanup_tasks 条目
