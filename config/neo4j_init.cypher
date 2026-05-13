// ══════════════════════════════════════════════════════
// Agentic Pentest Framework — Neo4j 初始化
// 通过 cypher-shell 执行：
//   cypher-shell -u neo4j -p password < config/neo4j_init.cypher
// ══════════════════════════════════════════════════════

// 主机节点唯一约束
CREATE CONSTRAINT host_ip_unique IF NOT EXISTS
FOR (h:Host) REQUIRE h.ip IS UNIQUE;

// Service 节点索引
CREATE INDEX service_port IF NOT EXISTS
FOR (s:Service) ON (s.port);

// Credential 节点索引
CREATE INDEX cred_username IF NOT EXISTS
FOR (c:Credential) ON (c.username);
