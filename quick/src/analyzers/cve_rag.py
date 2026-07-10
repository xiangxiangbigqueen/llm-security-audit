"""
RAG-CVE 实时查询模块（新增）
从 NVD 数据库实时检索已知漏洞情报，增强 LLM 分析上下文

【主流技术使用标注】
★ RAG (检索增强生成): 从外部知识库检索 CVE 信息注入 LLM 上下文
★ 实时 API 查询: 调用 NVD (National Vulnerability Database) 官方 API
★ 缓存机制: LRU 缓存 + TTL 过期，避免重复查询
★ 结构化检索: 按 CVE ID / 关键词 / CVSS 分数多维度查询
"""

import json
import time
import hashlib
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional
from collections import OrderedDict


class LRUCache:
    """LRU 缓存（带 TTL 过期）"""

    def __init__(self, capacity: int = 100, ttl: int = 3600):
        self.cache = OrderedDict()
        self.timestamps = {}
        self.capacity = capacity
        self.ttl = ttl

    def get(self, key: str):
        if key not in self.cache:
            return None
        if time.time() - self.timestamps[key] > self.ttl:
            del self.cache[key]
            del self.timestamps[key]
            return None
        self.cache.move_to_end(key)
        return self.cache[key]

    def put(self, key: str, value):
        self.cache[key] = value
        self.timestamps[key] = time.time()
        self.cache.move_to_end(key)
        if len(self.cache) > self.capacity:
            oldest = next(iter(self.cache))
            del self.cache[oldest]
            del self.timestamps[oldest]


class CVERAG:
    """
    CVE RAG (检索增强生成) 引擎
    从 NVD 实时检索漏洞情报，用于增强 SAST 检测结果
    """

    def __init__(self):
        from config.quick_settings import CVE_CONFIG
        self.config = CVE_CONFIG
        self.cache = LRUCache(
            capacity=CVE_CONFIG.get("cache_size", 100),
            ttl=CVE_CONFIG.get("cache_ttl", 3600),
        )

    def search_by_keyword(self, keyword: str, max_results: int = 5) -> list:
        """
        按关键词搜索 CVE（RAG 检索）

        Args:
            keyword: 搜索关键词（如 "flask", "sql injection", "log4j"）
            max_results: 最大返回数

        Returns:
            CVE 列表
        """
        cache_key = f"keyword:{keyword}:{max_results}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 20),
        }

        results = self._query_nvd(params)
        self.cache.put(cache_key, results)
        return results

    def search_by_cve_id(self, cve_id: str) -> Optional[dict]:
        """
        按 CVE 编号精确查询

        Args:
            cve_id: 如 "CVE-2021-44228"

        Returns:
            单个 CVE 详情
        """
        cache_key = f"cve_id:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached[0] if cached else None

        params = {"cveId": cve_id}
        results = self._query_nvd(params)
        self.cache.put(cache_key, results)
        return results[0] if results else None

    def search_by_package(self, package_name: str, version: str = "") -> list:
        """
        按软件包名搜索已知漏洞（RAG 核心功能）

        Args:
            package_name: 包名，如 "django", "openssl"
            version: 版本号，如 "3.2.1"

        Returns:
            匹配的 CVE 列表
        """
        keyword = package_name
        if version:
            # 尝试多种版本格式匹配
            keyword = f'"{package_name}" "{version}"'

        return self.search_by_keyword(keyword, max_results=10)

    def analyze_dependencies(self, project_path: str) -> dict:
        """
        分析项目的依赖文件，查询所有依赖的已知 CVE

        Args:
            project_path: 项目路径

        Returns:
            {依赖名: [CVE列表]} 字典
        """
        dependencies = self._extract_dependencies(project_path)
        results = {}

        for dep_name, dep_version in dependencies:
            cves = self.search_by_package(dep_name, dep_version)
            if cves:
                results[f"{dep_name}=={dep_version}"] = cves

        return results

    def _extract_dependencies(self, project_path: str) -> list:
        """从项目中提取依赖列表"""
        import os
        import re

        dependencies = []

        # requirements.txt
        req_path = os.path.join(project_path, "requirements.txt")
        if os.path.exists(req_path):
            with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith(('#', '-', 'git+')):
                        match = re.match(r'([a-zA-Z0-9_.-]+)\s*[=><~!]+\s*([a-zA-Z0-9_.*-]+)', line)
                        if match:
                            dependencies.append((match.group(1), match.group(2)))
                        elif not line.startswith(('http', 'git')):
                            dependencies.append((line.split('=')[0].strip(), ""))

        # package.json
        pkg_path = os.path.join(project_path, "package.json")
        if os.path.exists(pkg_path):
            try:
                with open(pkg_path, 'r', encoding='utf-8', errors='ignore') as f:
                    pkg = json.load(f)
                for key in ['dependencies', 'devDependencies']:
                    deps = pkg.get(key, {})
                    for name, ver in deps.items():
                        dependencies.append((name, ver.lstrip('^~>=<')))
            except json.JSONDecodeError:
                pass

        return dependencies

    def _query_nvd(self, params: dict) -> list:
        """
        查询 NVD API
        """
        from config.quick_settings import CVE_CONFIG

        base_url = CVE_CONFIG["nvd_api_url"]
        headers = {
            'User-Agent': 'LLM-Security-Audit-System/1.0',
        }

        api_key = CVE_CONFIG.get("nvd_api_key", "")
        if api_key:
            headers['apiKey'] = api_key

        try:
            url = f"{base_url}?{urllib.parse.urlencode(params)}"
            req = urllib.request.Request(url, headers=headers)
            timeout = CVE_CONFIG.get("timeout", 10)

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            return self._parse_nvd_response(data)
        except (urllib.error.URLError, urllib.error.HTTPError,
                json.JSONDecodeError, TimeoutError) as e:
            print(f"    ⚠️ NVD 查询失败: {type(e).__name__}")
            return []

    def _parse_nvd_response(self, data: dict) -> list:
        """解析 NVD API 返回数据"""
        cves = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            metrics = cve_data.get("metrics", {})

            # 提取 CVSS 分数
            cvss_score = None
            cvss_severity = "未知"
            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version_key in metrics:
                    cvss_data = metrics[version_key][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity", "未知")
                    break

            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # 提取受影响的产品
            configurations = cve_data.get("configurations", [])
            affected_products = []
            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    matches = node.get("cpeMatch", [])
                    for m in matches:
                        criteria = m.get("criteria", "")
                        if criteria:
                            parts = criteria.split(":")
                            if len(parts) > 4:
                                vendor = parts[3]
                                product = parts[4]
                                version_start = m.get("versionStartIncluding", "")
                                version_end = m.get("versionEndIncluding", "")
                                affected_products.append({
                                    "vendor": vendor,
                                    "product": product,
                                    "version_start": version_start,
                                    "version_end": version_end,
                                })

            cves.append({
                "id": cve_data.get("id", ""),
                "sourceIdentifier": cve_data.get("sourceIdentifier", ""),
                "published": cve_data.get("published", ""),
                "lastModified": cve_data.get("lastModified", ""),
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "description": description[:500] if description else "",
                "affected_products": affected_products[:5],
                "references": [
                    ref.get("url", "")
                    for ref in cve_data.get("references", [])[:3]
                ],
            })

        return cves

    def enrich_findings(self, findings: list, project_path: str) -> list:
        """
        用 CVE 情报丰富扫描发现（RAG 注入）

        Args:
            findings: 原始扫描结果
            project_path: 项目路径

        Returns:
            注入了 CVE 上下文的扫描结果
        """
        print(f"\n  📡 RAG-CVE: 正在检索已知漏洞情报...")

        # 根据发现类型检索相关 CVE
        cve_map = {
            "sql_injection": "sql injection",
            "command_injection": "command injection",
            "path_traversal": "path traversal",
            "hardcoded_secret": "hardcoded credential",
            "xss": "cross site scripting",
            "insecure_deserialization": "insecure deserialization",
            "ssrf": "server side request forgery",
        }

        for finding in findings:
            cat = finding.get("category", "")
            keyword = cve_map.get(cat)
            if keyword:
                related_cves = self.search_by_keyword(keyword, max_results=3)
                finding["related_cves"] = related_cves
                if related_cves:
                    finding["rag_cve_context"] = f"发现 {len(related_cves)} 个相关已知 CVE"
                    print(f"    └─ {finding['id']}: 关联 {len(related_cves)} 个 CVE")

        # 分析依赖
        dep_cves = self.analyze_dependencies(project_path)
        dep_findings = []
        for dep_name, cves in dep_cves.items():
            if cves:
                dep_findings.append({
                    "id": f"cve-dependency-{len(dep_findings)+1}",
                    "category": "dependency_vulnerability",
                    "vuln_name": f"依赖组件已知漏洞: {dep_name}",
                    "severity": "高危" if any(
                        c.get("cvss_severity") == "CRITICAL" or (c.get("cvss_score", 0) or 0) >= 9.0
                        for c in cves
                    ) else "中危",
                    "cwe": "CWE-1104",
                    "file": "requirements.txt / package.json",
                    "line": 1,
                    "match": f"{dep_name} 存在 {len(cves)} 个已知漏洞",
                    "related_cves": cves,
                    "source": "rag_cve_query",
                    "verified": True,
                    "is_real": True,
                    "risk_description": f"依赖 {dep_name} 包含 {len(cves)} 个已知 CVE 漏洞",
                    "fix_suggestion": f"升级 {dep_name} 到最新版本",
                })
                print(f"    └─ 依赖 {dep_name}: {len(cves)} 个已知漏洞")

        findings.extend(dep_findings)
        return findings

    def print_stats(self):
        """打印 CVE 查询统计"""
        print(f"  📡 RAG-CVE 引擎: 缓存命中 {self.cache.cache.__len__() if hasattr(self.cache, 'cache') else 0} 条")
