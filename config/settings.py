"""
LLM Security Audit System - SAST 安全审计配置
实验一：大模型驱动的开源项目安全审计系统

【主流技术使用标注】
★ LLM 配置: 使用 Claude Sonnet 4.6，配置 Agent 模式和 temperature（行 11-16）
★ SAST 规则库: 8 类漏洞的检测规则（行 48-147）
★ CWE 标准: 每类漏洞关联 CWE 编号（CWE-89/78/22/798/79/502/918）
★ OWASP 分类: 覆盖 OWASP Top 10 中 SQL注入/XSS/SSRF 等核心类别
★ 多语言支持: 9 种编程语言的 SAST 支持（行 35-45）
"""

# ============================================================
# 系统配置
# ============================================================

# LLM 配置（使用 Claude Code CLI 作为后端）
LLM_CONFIG = {
    "model": "claude-sonnet-4-6",       # 使用的模型
    "max_tokens": 8192,                  # 最大生成token
    "temperature": 0.1,                  # 分析任务使用低温度保证确定性
    "agent_mode": True,                  # 启用 Agent 模式进行多步骤分析
}

# 扫描配置
SCAN_CONFIG = {
    "max_file_size": 1024 * 1024,       # 最大分析文件大小 (1MB)
    "max_files": 500,                    # 最大分析文件数
    "timeout_per_file": 30,              # 单文件分析超时（秒）
    "parallel_agents": 3,                # 并行 Agent 数
    "exclude_patterns": [                # 排除文件模式
        "*.min.js", "*.min.css",
        "vendor/*", "node_modules/*",
        "dist/*", "build/*", ".git/*",
        "__pycache__/*", "*.pyc",
        "*.jpg", "*.png", "*.gif", "*.svg",
        "*.woff", "*.woff2", "*.ttf", "*.eot",
        "*.pdf", "*.doc", "*.docx",
        "package-lock.json", "yarn.lock",
        "*.o", "*.class", "*.jar",
    ],
    "languages": {                       # 支持的语言
        "python": [".py"],
        "javascript": [".js", ".jsx", ".ts", ".tsx"],
        "java": [".java"],
        "php": [".php"],
        "go": [".go"],
        "ruby": [".rb"],
        "csharp": [".cs"],
        "cpp": [".cpp", ".cc", ".c", ".h", ".hpp"],
        "rust": [".rs"],
    }
}

# 漏洞规则配置
VULN_CATEGORIES = {
    "sql_injection": {
        "name": "SQL注入",
        "severity": "高危",
        "cwe": "CWE-89",
        "patterns": [
            r"""execute\s*\(\s*["'](?:.*?SELECT.*?|.*?INSERT.*?|.*?UPDATE.*?|.*?DELETE.*?)[^"']*["']\s*[+%]""",
            r"""cursor\.execute\s*\(\s*f["']""",
            r"""\.query\s*\(\s*f["']""",
            r"""mysqli_query\s*\(\s*\$conn\s*,\s*\$""",
            r"""\.raw\s*\(\s*\$""",
            r"""db\.execute\s*\(\s*["'][^"']*\${""",
        ],
        "risk_description": "攻击者可通过构造恶意SQL语句操纵数据库，导致数据泄露、篡改或删除"
    },
    "command_injection": {
        "name": "命令注入",
        "severity": "高危",
        "cwe": "CWE-78",
        "patterns": [
            r"""os\.system\s*\(\s*["'][^"']*\${""",
            r"""subprocess\.(call|check_output|Popen|run)\s*\(\s*["'][^"']*\${""",
            r"""exec\s*\(\s*["'][^"']*\${""",
            r"""eval\s*\(\s*["'][^"']*\${""",
            r"""shell_exec\s*\(\s*\$""",
            r"""system\s*\(\s*\$""",
            r"""popen\s*\(\s*\$""",
            r"""Runtime\.getRuntime\(\)\.exec\s*\(\s*["'][^"']*\+""",
        ],
        "risk_description": "攻击者可通过注入恶意系统命令在服务器上执行任意操作"
    },
    "path_traversal": {
        "name": "路径遍历",
        "severity": "中危",
        "cwe": "CWE-22",
        "patterns": [
            r"""open\s*\(\s*["'][^"']*\.\./""",
            r"""\.\./.*\.\./""",
            r"""path\.join\s*\(\s*["'][^"']*\.\./""",
            r"""file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)""",
            r"""readFile\s*\(\s*req\.params""",
        ],
        "risk_description": "攻击者可读取服务器上的任意文件，包括配置文件、密码文件等敏感信息"
    },
    "hardcoded_secret": {
        "name": "硬编码密钥/凭证",
        "severity": "高危",
        "cwe": "CWE-798",
        "patterns": [
            r"""(?i)(api_key|apikey|secret|password|passwd|token|auth_token|access_key|private_key)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']""",
            r"""-----BEGIN (RSA |EC )?PRIVATE KEY-----""",
            r"""AKIA[0-9A-Z]{16}""",  # AWS Access Key
            r"""sk-[A-Za-z0-9]{32,}""",  # OpenAI API Key
        ],
        "risk_description": "硬编码的密钥和凭证可能被攻击者获取，导致云资源被盗用或系统被入侵"
    },
    "xss": {
        "name": "跨站脚本 (XSS)",
        "severity": "中危",
        "cwe": "CWE-79",
        "patterns": [
            r"""innerHTML\s*=\s*["'][^"']*\${""",
            r"""\.html\s*\(\s*["'][^"']*\${""",
            r"""dangerouslySetInnerHTML""",
            r"""v-html\s*=""",
            r"""document\.write\s*\(\s*["'][^"']*\${""",
            r"""response\.write\s*\(\s*\$_(GET|POST|REQUEST)""",
            r"""echo\s+\$_(GET|POST|REQUEST)""",
        ],
        "risk_description": "攻击者可在Web页面中注入恶意脚本，窃取用户Cookie、会话令牌或重定向到恶意网站"
    },
    "insecure_deserialization": {
        "name": "不安全反序列化",
        "severity": "高危",
        "cwe": "CWE-502",
        "patterns": [
            r"""pickle\.loads?\s*\(""",
            r"""yaml\.load\s*\(""",
            r"""JSON\.parse\s*\(\s*req""",
            r"""unserialize\s*\(\s*\$_(GET|POST|REQUEST)""",
            r"""read_object\s*\(\s*""",
        ],
        "risk_description": "攻击者可利用不安全反序列化漏洞执行远程代码"
    },
    "ssrf": {
        "name": "服务端请求伪造 (SSRF)",
        "severity": "中危",
        "cwe": "CWE-918",
        "patterns": [
            r"""requests\.(get|post|put|delete)\s*\(\s*["'][^"']*\${""",
            r"""urllib\.(request|urlopen)\s*\(\s*["'][^"']*\${""",
            r"""urlopen\s*\(\s*req\.params""",
            r"""axios\.(get|post)\s*\(\s*`[^`]*\${""",
            r"""HttpClient\.(Get|Post)\s*\(\s*["'][^"']*\+""",
            r"""file_get_contents\s*\(\s*\$url""",
        ],
        "risk_description": "攻击者可利用SSRF攻击内网服务，访问云原数据接口等敏感资源"
    }
}

# ============================================================
# RAG-CVE 实时查询配置（新增）
# ============================================================
CVE_CONFIG = {
    "enabled": True,                          # 是否启用 RAG-CVE 查询
    "nvd_api_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "nvd_api_key": "",                        # NVD API Key（可选，提高速率限制）
    "timeout": 10,                            # 查询超时
    "cache_size": 100,                        # 本地缓存大小
    "cache_ttl": 3600,                        # 缓存 TTL（秒）
}

# ============================================================
# AST 语义分析配置（新增）
# ============================================================
AST_CONFIG = {
    "enabled": True,                          # 是否启用 AST 分析
    "deep_analysis": True,                    # 是否进行深层数据流分析
    "max_function_complexity": 20,            # 函数复杂度阈值
}

# ============================================================
# 异步并行配置（新增）
# ============================================================
PARALLEL_CONFIG = {
    "enabled": True,                          # 是否启用异步并行
    "max_workers": 8,                         # 最大并行 Worker 数
    "chunk_size": 10,                         # 每批处理文件数
    "agent_timeout": 120,                     # Agent 超时（秒）
}

# ============================================================
# Neo4j 知识图谱配置（新增）
# ============================================================
NEO4J_CONFIG = {
    "enabled": False,                         # 是否启用（默认关闭，需安装 Neo4j）
    "uri": "bolt://localhost:7687",
    "user": "neo4j",
    "password": "password",
    "database": "neo4j",
}

# ============================================================
# Web UI 配置（新增）
# ============================================================
WEB_CONFIG = {
    "enabled": False,                         # 启动时是否自动打开 Web
    "host": "127.0.0.1",
    "port": 5000,
    "debug": False,
}

# 报告配置
REPORT_CONFIG = {
    "output_dir": "reports",
    "formats": ["markdown", "json", "html"],
    "severity_order": ["高危", "中危", "低危", "信息"],
    "neo4j_graph": False,                     # 是否在报告中嵌入图谱
}
