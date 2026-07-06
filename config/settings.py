"""
LLM Security Audit System - SAST 安全审计配置
实验一：大模型驱动的开源项目安全审计系统

【主流技术使用标注】
★ LLM 配置: 支持 DeepSeek/Qwen/GLM 等国内大模型 API（行 17-30）
★ SAST 规则库: 8 类漏洞的检测规则（行 48-147）
★ CWE 标准: 每类漏洞关联 CWE 编号（CWE-89/78/22/798/79/502/918）
★ OWASP 分类: 覆盖 OWASP Top 10 中 SQL注入/XSS/SSRF 等核心类别
★ 多语言支持: 9 种编程语言的 SAST 支持（行 35-45）
"""

# ============================================================
# 系统配置
# ============================================================

# LLM 配置（支持国内大模型 API，默认 DeepSeek）
LLM_CONFIG = {
    "enabled": True,                     # 是否启用 LLM 分析
    "model": "deepseek-chat",            # 使用的模型（DeepSeek / Qwen / GLM 等）
    "api_key": "",                       # API Key（设置环境变量 LLM_API_KEY 更安全）
    "api_base": "https://api.deepseek.com",  # API 地址
    # 其他国内 API 地址：
    # Qwen:  https://dashscope.aliyuncs.com/compatible-mode/v1
    # GLM:   https://open.bigmodel.cn/api/paas/v4
    # 月之暗面: https://api.moonshot.cn/v1
    "max_tokens": 8192,                  # 最大生成token
    "temperature": 0.1,                  # 分析任务使用低温度保证确定性
    "timeout": 120,                      # API 调用超时（秒）
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
    },
    # ============================================================
    # 10 种新增漏洞类型（扩展覆盖面）
    # ============================================================
    "xxe": {
        "name": "XML外部实体注入 (XXE)",
        "severity": "高危",
        "cwe": "CWE-611",
        "patterns": [
            r"""SAXParser\.parse\s*\(""",
            r"""DocumentBuilderFactory""",
            r"""SimpleXML\s*\(\s*file_get_contents""",
            r"""loadXML\s*\(""",
            r"""XMLReader""",
            r"""libxml_disable_entity_loader\s*\(\s*false""",
            r"""DOMDocument::load""",
        ],
        "risk_description": "攻击者可通过恶意XML实体引用读取服务器文件、执行SSRF攻击或导致拒绝服务"
    },
    "csrf": {
        "name": "跨站请求伪造 (CSRF)",
        "severity": "中危",
        "cwe": "CWE-352",
        "patterns": [
            r"""@csrf_exempt""",
            r"""csrf_exempt""",
            r"""csrf\.exempt""",
            r"""without_csrf""",
            r"""#csrf""",
            r"""skip_csrf""",
        ],
        "risk_description": "攻击者可伪造用户请求执行非授权操作，如修改密码、转账等敏感操作"
    },
    "open_redirect": {
        "name": "开放重定向",
        "severity": "中危",
        "cwe": "CWE-601",
        "patterns": [
            r"""redirect\s*\(\s*request\.args""",
            r"""redirect\s*\(\s*\$_GET""",
            r"""redirect\s*\(\s*req\.param""",
            r"""redirect\s*\(\s*\.\./\.""",
            r"""Location:\s*['""][^'""]*\${""",
            r"""header\s*\(\s*['""]Location:['""]\s*\.\s*\$""",
        ],
        "risk_description": "攻击者可利用未经验证的重定向将用户引导至钓鱼网站"
    },
    "ldap_injection": {
        "name": "LDAP注入",
        "severity": "高危",
        "cwe": "CWE-90",
        "patterns": [
            r"""ldap_search\s*\(""",
            r"""ldap_list\s*\(""",
            r"""ldap_read\s*\(""",
            r"""DirContext\.search""",
            r"""LdapTemplate""",
            r"""initialLdapContext""",
        ],
        "risk_description": "攻击者可篡改LDAP查询语句，绕过认证或获取未授权数据"
    },
    "nosql_injection": {
        "name": "NoSQL注入",
        "severity": "高危",
        "cwe": "CWE-943",
        "patterns": [
            r"""db\.\w+\.find\s*\(\s*\{[^}]*\$\w+""",
            r"""mongo_client.*find\s*\(\s*["']""",
            r"""\$where.*\$\w+""",
            r"""db\.\w+\.aggregate\s*\(\s*\{[^}]*\$""",
            r"""collection\.find\s*\(\s*["']""",
        ],
        "risk_description": "攻击者可通过注入NoSQL操作符绕过认证或获取非授权数据"
    },
    "ssti": {
        "name": "服务端模板注入 (SSTI)",
        "severity": "高危",
        "cwe": "CWE-1336",
        "patterns": [
            r"""render_template_string\s*\(""",
            r"""render_to_string""",
            r"""\.render\s*\(\s*request\.args""",
            r"""Template\s*\(\s*["'][^"']*\${""",
            r"""template\.replace""",
            r"""eval\(.*template""",
            r"""compile\(.*template""",
        ],
        "risk_description": "攻击者可通过注入模板表达式执行任意代码或读取敏感数据"
    },
    "insecure_upload": {
        "name": "不安全文件上传",
        "severity": "高危",
        "cwe": "CWE-434",
        "patterns": [
            r"""request\.files""",
            r"""$_FILES""",
            r"""upload\(""",
            r"""\.save\s*\(\s*["'][^"']*\.[^"']*["']\s*\)""",
            r"""move_uploaded_file""",
            r"""file_put_contents.*$_FILES""",
            r"""open\(.*filename.*['""][^'""]*\.\w+['""]""",
        ],
        "risk_description": "攻击者可上传恶意文件（WebShell、恶意脚本）导致服务器被控制"
    },
    "jwt_vuln": {
        "name": "JWT安全漏洞",
        "severity": "高危",
        "cwe": "CWE-347",
        "patterns": [
            r"""jwt\.decode.*verify=False""",
            r"""jwt\.decode.*None""",
            r"""algorithm=['""]none['""]""",
            r"""algorithms.*None""",
            r"""JWT_ALGORITHM.*['""]none['""]""",
            r"""jwt\.encode.*secret.*None""",
        ],
        "risk_description": "攻击者可利用JWT算法混淆、空签名或密钥泄露伪造身份令牌"
    },
    "log_forging": {
        "name": "日志伪造",
        "severity": "中危",
        "cwe": "CWE-117",
        "patterns": [
            r"""logging\.(info|warning|error|debug)\s*\(\s*[^"']*%s.*request""",
            r"""log\.(info|warn|error).*request\.args""",
            r"""\$_SERVER\['REQUEST_URI'\]""",
            r"""print\(.*request""",
            r"""console\.log.*req\.body""",
        ],
        "risk_description": "攻击者可通过注入换行符伪造日志条目，掩盖攻击痕迹或误导安全分析"
    },
    "crlf_injection": {
        "name": "CRLF注入/HTTP响应拆分",
        "severity": "高危",
        "cwe": "CWE-93",
        "patterns": [
            r"""header\s*\(\s*["'][^"']*%0[dDaA]""",
            r"""response\.headers\.add\s*\(\s*["'][^"']*\\r\\n""",
            r"""%0[dDaA].*%0[aA]""",
            r"""\\\\r\\\\n.*header""",
            r"""add_header.*%0""",
        ],
        "risk_description": "攻击者可通过注入CRLF序列实现HTTP响应拆分、缓存投毒或XSS攻击"
    },
    # ============================================================
    # 第三批新增：12 种漏洞（总数达30类）
    # ============================================================
    "idor": {
        "name": "不安全的直接对象引用 (IDOR)",
        "severity": "中危",
        "cwe": "CWE-639",
        "patterns": [
            r"""\.objects\.get\s*\(\s*["']\w+["']\s*=\s*request""",
            r"""\.query\.filter_by\s*\(\s*\w+\s*=\s*request""",
            r"""SELECT.*WHERE.*=\s*\$_(GET|POST)""",
            r"""findById\s*\(\s*req\.params""",
            r"""\.get\s*\(\s*request\.args""",
        ],
        "risk_description": "攻击者可修改资源ID参数访问其他用户的未授权数据"
    },
    "prototype_pollution": {
        "name": "原型链污染 (Prototype Pollution)",
        "severity": "高危",
        "cwe": "CWE-1321",
        "patterns": [
            r"""\.assign\s*\(\s*.*__proto__""",
            r"""\.merge\s*\(\s*.*constructor""",
            r"""\[\s*['""]__proto__['""]\s*\]""",
            r"""\.clone\s*\(\s*.*__proto__""",
            r"""deepMerge.*__proto__""",
            r"""extend\(true.*__proto__""",
        ],
        "risk_description": "攻击者可通过原型链污染实现属性注入，导致拒绝服务或远程代码执行"
    },
    "mass_assignment": {
        "name": "批量赋值漏洞 (Mass Assignment)",
        "severity": "中危",
        "cwe": "CWE-915",
        "patterns": [
            r"""update_attributes\s*\(\s*params""",
            r"""\.update\s*\(\s*request\.json""",
            r"""\.update_all\s*\(\s*params""",
            r"""fillable\s*=\s*\[""",
            r"""@user\.update\(.*params""",
            r"""User\.update\(.*request""",
        ],
        "risk_description": "攻击者可批量修改未授权的模型属性，提升权限或篡改关键数据"
    },
    "weak_crypto": {
        "name": "弱加密算法",
        "severity": "高危",
        "cwe": "CWE-327",
        "patterns": [
            r"""hashlib\.md5\s*\(""",
            r"""Cipher\.getInstance\(['""]DES['""]""",
            r"""Cipher\.getInstance\(['""]RC4['""]""",
            r"""sha1\s*\(""",
            r"""Crypt::DES""",
            r"""des\s*-\s*cbc""",
            r"""md5\(.*password""",
            r"""mysql_native_password""",
        ],
        "risk_description": "使用已被破解的加密算法（MD5、DES、RC4、SHA-1），可被攻击者逆向破解"
    },
    "certificate_vuln": {
        "name": "不安全的证书验证",
        "severity": "高危",
        "cwe": "CWE-295",
        "patterns": [
            r"""verify=False""",
            r"""ssl\._create_default_https_context""",
            r"""check_hostname\s*=\s*False""",
            r"""CERT_NONE""",
            r"""\.context\.check_hostname\s*=\s*False""",
            r"""REQUIRED""",
            r"""ssl._create_unverified_context""",
        ],
        "risk_description": "禁用证书验证可能导致中间人攻击，通信数据被窃听或篡改"
    },
    "redos": {
        "name": "正则表达式拒绝服务 (ReDoS)",
        "severity": "中危",
        "cwe": "CWE-1333",
        "patterns": [
            r"""\((.*[+*]){2,}\)""",
            r"""\(\.\*\)\1""",
            r"""\(\.\+\)\1""",
            r"""[^.]*\(\.\*\.\*""",
            r"""\((\w|\d)*\)\?\)\*""",
        ],
        "risk_description": "存在灾难性回溯的正则表达式，攻击者可构造特制输入导致CPU耗尽"
    },
    "memory_leak": {
        "name": "内存泄漏/资源未释放",
        "severity": "中危",
        "cwe": "CWE-401",
        "patterns": [
            r"""open\(.*['""][^'""]*['""]\)\s*$""",
            r"""FileInputStream""",
            r"""BufferedReader.*open""",
            r"""new\s+Thread\(\)""",
            r"""\.connect\(\)""",
            r"""malloc\(""",
            r"""new\s+\w+\[""",
        ],
        "risk_description": "资源未正确释放可能导致内存耗尽，造成拒绝服务"
    },
    "race_condition": {
        "name": "条件竞争/TOCTOU",
        "severity": "高危",
        "cwe": "CWE-367",
        "patterns": [
            r"""os\.path\.exists.*os\.(remove|unlink)""",
            r"""if.*exists.*open""",
            r"""if.*exists.*delete""",
            r"""check.*write""",
            r"""with\s+open\(\).*while""",
        ],
        "risk_description": "检查时间和使用时间之间存在窗口期，攻击者可利用竞争条件绕过安全检查"
    },
    "cleartext_storage": {
        "name": "明文存储敏感信息",
        "severity": "高危",
        "cwe": "CWE-312",
        "patterns": [
            r'password\s*=\s*["\'][A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]+["\']',
            r'credit_card',
            r'ssn\s*=',
            r'phone\s*=\s*["\']\d{11}["\']',
            r'id_card',
            r'bank_account',
            r'passport_number',
        ],
        "risk_description": "敏感信息（密码、身份证、银行卡号等）以明文存储，泄露后可造成严重损失"
    },
    "sqli_second_order": {
        "name": "二阶SQL注入",
        "severity": "高危",
        "cwe": "CWE-89",
        "patterns": [
            r"""SELECT.*FROM.*WHERE.*\|""",
            r"""SELECT.*FROM.*WHERE.*\+""",
            r"""SELECT.*FROM.*WHERE.*%""",
            r"""insert.*into.*values.*SELECT""",
            r"""INSERT.*SELECT""",
            r"""UPDATE.*SET.*=.*SELECT""",
        ],
        "risk_description": "攻击者可在首次请求中注入恶意数据，存储后触发二次查询时被利用"
    },
    "integer_overflow": {
        "name": "整数溢出/环绕",
        "severity": "中危",
        "cwe": "CWE-190",
        "patterns": [
            r"""int\(.*input""",
            r"""struct\.pack\s*\(\s*['""][iI]['""]""",
            r"""\.bit_length\s*\(\s*\)""",
            r"""ctypes\.c_int""",
            r"""atoi\s*\(\s*\$""",
            r"""intval\s*\(\s*\$""",
        ],
        "risk_description": "整数溢出可导致缓冲区溢出、逻辑错误或拒绝服务攻击"
    },
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
    "enabled": True,                          # 是否启用（需要本地 Neo4j 服务）
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
