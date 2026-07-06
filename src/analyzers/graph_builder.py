"""
Neo4j 漏洞知识图谱模块（新增）
将扫描结果构建为图数据库，支持多维关联查询

【主流技术使用标注】
★ 图数据库: 使用 Neo4j 存储漏洞知识图谱
★ 知识图谱: 项目→文件→漏洞→CVE→攻击路径 多级关联
★ 图查询: 支持 Cypher 查询分析漏洞关联关系
★ 可视化: 生成图谱可视化数据供前端展示
"""

import json
import os
from typing import Optional


class VulnerabilityGraph:
    """
    漏洞知识图谱构建器
    将扫描结果转化为图结构，支持图查询和可视化
    """

    def __init__(self):
        self.neo4j_available = False
        self.driver = None
        self._init_neo4j()

    def _init_neo4j(self):
        """初始化 Neo4j 连接"""
        try:
            from neo4j import GraphDatabase
            from config.settings import NEO4J_CONFIG

            config = NEO4J_CONFIG
            if not config.get("enabled"):
                return

            self.driver = GraphDatabase.driver(
                config["uri"],
                auth=(config["user"], config["password"])
            )
            self.driver.verify_connectivity()
            self.neo4j_available = True
            print("  🟢 Neo4j 已连接")
        except ImportError:
            pass
        except Exception as e:
            print(f"  ⚠️ Neo4j 连接失败: {e}")

    def build_graph(self, findings: list, project_info: dict):
        """
        构建漏洞知识图谱

        Args:
            findings: 扫描发现列表
            project_info: 项目信息
        """
        if not self.neo4j_available or not self.driver:
            print("  ⚠️ Neo4j 未启用，跳过知识图谱构建")
            return

        with self.driver.session() as session:
            # 创建项目节点
            project_name = project_info.get("name", "unknown")
            session.run("""
                MERGE (p:Project {name: $name, path: $path, source: $source})
            """, name=project_name,
                 path=project_info.get("path", ""),
                 source=project_info.get("source", ""))

            for finding in findings:
                file_path = finding.get("file", "unknown")
                vuln_type = finding.get("vuln_name", "未知")
                severity = finding.get("severity", "信息")
                cwe = finding.get("cwe", "")
                category = finding.get("category", "")

                # 创建文件节点
                session.run("""
                    MERGE (f:File {path: $path})
                    MERGE (p:Project {name: $project_name})
                    MERGE (p)-[:CONTAINS]->(f)
                """, path=file_path, project_name=project_name)

                # 创建漏洞节点
                session.run("""
                    MATCH (f:File {path: $path})
                    MERGE (v:Vulnerability {
                        id: $vid,
                        type: $vtype,
                        severity: $severity,
                        cwe: $cwe,
                        category: $category
                    })
                    MERGE (f)-[:HAS_VULNERABILITY {line: $line}]->(v)
                """, path=file_path,
                     vid=finding.get("id", ""),
                     vtype=vuln_type,
                     severity=severity,
                     cwe=cwe,
                     category=category,
                     line=finding.get("line", 0))

                # 创建 CVE 关联（如果有 RAG 数据）
                related_cves = finding.get("related_cves", [])
                for cve in related_cves:
                    cve_id = cve.get("id", "")
                    if cve_id:
                        session.run("""
                            MATCH (v:Vulnerability {id: $vid})
                            MERGE (c:CVE {id: $cve_id, score: $score, severity: $cve_severity})
                            MERGE (v)-[:RELATED_TO_CVE]->(c)
                        """, vid=finding.get("id", ""),
                             cve_id=cve_id,
                             score=cve.get("cvss_score", 0),
                             cve_severity=cve.get("cvss_severity", ""))

        print(f"  🕸️ 知识图谱构建完成: {len(findings)} 个漏洞节点")

    def query_by_severity(self, severity: str = "高危") -> list:
        """按严重程度查询漏洞"""
        if not self.neo4j_available or not self.driver:
            return []

        with self.driver.session() as session:
            result = session.run("""
                MATCH (f:File)-[:HAS_VULNERABILITY]->(v:Vulnerability {severity: $sev})
                OPTIONAL MATCH (v)-[:RELATED_TO_CVE]->(c:CVE)
                RETURN f.path AS file, v.type AS vuln, v.id AS vid,
                       v.line AS line, collect(DISTINCT c.id) AS cves
            """, sev=severity)
            return [dict(r) for r in result]

    def query_attack_path(self, vuln_id: str) -> dict:
        """查询漏洞的攻击路径"""
        if not self.neo4j_available or not self.driver:
            return {}

        with self.driver.session() as session:
            result = session.run("""
                MATCH path = (f:File)-[:HAS_VULNERABILITY]->(v:Vulnerability {id: $vid})
                OPTIONAL MATCH (v)-[:RELATED_TO_CVE]->(c:CVE)
                RETURN f.path AS file, v.type AS vuln,
                       v.severity AS severity, v.cwe AS cwe,
                       collect(DISTINCT c.id) AS cves,
                       collect(DISTINCT {
                           id: c.id, score: c.score, severity: c.severity
                       }) AS cve_details
            """, vid=vuln_id)
            record = result.single()
            return dict(record) if record else {}

    def export_graph_json(self) -> dict:
        """导出图谱为 JSON（供可视化）"""
        if not self.neo4j_available or not self.driver:
            return {"nodes": [], "edges": []}

        with self.driver.session() as session:
            # 查询所有节点和关系
            result = session.run("""
                MATCH (n)-[r]->(m)
                RETURN n, r, m
                LIMIT 200
            """)

            nodes = {}
            edges = []
            for record in result:
                n = record["n"]
                m = record["m"]
                r = record["r"]

                # 源节点
                n_id = n.element_id
                if n_id not in nodes:
                    labels = list(n.labels)
                    nodes[n_id] = {
                        "id": n_id,
                        "label": labels[0] if labels else "Node",
                        "name": n.get("name") or n.get("path") or n.get("id") or "",
                        "properties": dict(n.items()),
                    }

                # 目标节点
                m_id = m.element_id
                if m_id not in nodes:
                    labels = list(m.labels)
                    nodes[m_id] = {
                        "id": m_id,
                        "label": labels[0] if labels else "Node",
                        "name": m.get("name") or m.get("path") or m.get("id") or "",
                        "properties": dict(m.items()),
                    }

                # 关系
                edges.append({
                    "source": n_id,
                    "target": m_id,
                    "label": r.type,
                    "properties": dict(r.items()),
                })

            return {"nodes": list(nodes.values()), "edges": edges}

    def close(self):
        """关闭连接"""
        if self.driver:
            self.driver.close()


def get_graph():
    """获取全局图谱实例"""
    return VulnerabilityGraph()
