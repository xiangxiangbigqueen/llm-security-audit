# 🔒 安全审计报告

**工具**: LLM Security Audit System v1.0.0
**扫描时间**: 
**报告生成**: 2026-07-10 14:39:27

## 📂 项目信息

- **项目名称**: xiangxiangbigqueen_llm-security-audit
- **项目路径**: `D:\llm-security-audit\workspace\xiangxiangbigqueen_llm-security-audit`
- **项目来源**: https://github.com/xiangxiangbigqueen/llm-security-audit.git
- **编程语言**: python(16)

## 📊 扫描摘要

| 指标 | 数值 |
|------|------|
| 总发现数 | 52 |
| 确认漏洞 | 52 |
| 高危 | 38 |
| 中危 | 14 |
| 低危 | 0 |
| 信息 | 0 |
| 扫描文件数 | 25 |
| 匹配规则数 | 52 |

## 🐛 漏洞详情

### 🔴 高危 (38 个)

#### SQL注入 — `tests\vulnerable_app.py:41`

- **漏洞ID**: sql_injection-1
- **CWE**: CWE-89
- **风险描述**: 攻击者可通过构造恶意SQL语句操纵数据库，导致数据泄露、篡改或删除
- **匹配内容**: `cursor.execute(f"`

- **攻击场景**: 攻击者可以通过发送类似 /search?q=test' OR '1'='1 的请求来获取所有用户数据。
- **修复建议**: 使用参数化查询（prepared statement）代替字符串拼接。例如：cursor.execute("SELECT * FROM users WHERE name LIKE ?", ('%' + keyword + '%',))

```
     39:     cursor = conn.cursor()
     40:     # 漏洞: 拼接用户输入
 >>> 41:     cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{keyword}%'")  # SQL 注入!
     42:     return str(cursor.fetchall())
     43: 
```

#### 🔗 证据链

**① 文件位置**
- 文件: `tests\vulnerable_app.py`
- 行号: 41

**② 调用路径（输入源 → 危险函数）**
```
  [8] 行 30: cursor.execute(query)  # SQL 注入!
  [9] 行 31: return str(cursor.fetchall())
  [10] 行 34: @app.route("/search")
  [11] 行 35: def search_users():
  [12] 行 37: keyword = request.args.get("q", "")
  [13] 行 38: conn = sqlite3.connect("users.db")
  [14] 行 39: cursor = conn.cursor()
  [15] 行 41: cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{keyword}%'")  # SQL 注入!
```
- **输入源**: Flask 请求
- **危险函数**: SQL注入

**③ 验证结果**
- **真实性**: ✅ 确认漏洞
- **严重程度**: 高危
- **可利用性**: 需要验证

**④ 证据完整性**: 5/5

**💥 PoC 利用代码**
```python
#!/usr/bin/env python3
"""
PoC: SQL Injection
Target: tests\vulnerable_app.py:41
CWE: CWE-89
"""

import requests

def test_sql_injection(target_url, param="id"):
    """检测 SQL 注入漏洞"""
    payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' AND 1=1--",
        "' AND 1=2--",
        "'; DROP TABLE users--",
        "' OR '1'='1' --",
    ]

    print(f"[*] 测试目标: {target_url}")
    print(f"[*] 参数: {param}")

    for payload in payloads:
        try:
            params 
```

---

#### 硬编码密钥/凭证 — `tests\vulnerable_app.py:84`

- **漏洞ID**: hardcoded_secret-2
- **CWE**: CWE-798
- **风险描述**: 硬编码的密钥和凭证可能被攻击者获取，导致云资源被盗用或系统被入侵
- **匹配内容**: `ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"`

- **攻击场景**: 攻击者可以通过查看源代码或反编译应用来获取这些硬编码的凭证，进而访问相关服务。
- **修复建议**: 使用环境变量或安全的密钥管理服务（如AWS Secrets Manager、HashiCorp Vault）来存储和管理敏感凭证。

```
     82: 
     83: # 直接硬编码的 AWS 密钥
 >>> 84: AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
     85: AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
     86: 
```

#### 🔗 证据链

**① 文件位置**
- 文件: `tests\vulnerable_app.py`
- 行号: 84

**② 调用路径（输入源 → 危险函数）**
```
  [5] 行 63: return output.decode()
  [6] 行 69: @app.route("/read")
  [7] 行 70: def read_file():
  [8] 行 72: filename = request.args.get("file", "README.md")
  [9] 行 74: filepath = os.path.join("data", filename)
  [10] 行 75: with open(filepath, "r") as f:  # 路径遍历!
  [11] 行 76: return f.read()
  [12] 行 84: AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
```
- **输入源**: Flask 请求
- **危险函数**: 硬编码密钥/凭证

**③ 验证结果**
- **真实性**: ✅ 确认漏洞
- **严重程度**: 高危
- **可利用性**: 需要验证

**④ 证据完整性**: 5/5

**💥 PoC 利用代码**
```python
#!/usr/bin/env python3
"""
PoC: Hardcoded Secret Leakage
Target: tests\vulnerable_app.py:84
CWE: CWE-798
"""

import re

def analyze_secret_leak(file_path):
    """分析泄露的密钥类型和风险"""
    with open(file_path, 'r') as f:
        content = f.read()

    # 检测各类密钥
    patterns = {
        "AWS Key": r"AKIA[0-9A-Z]{16}",
        "OpenAI Key": r"sk-[A-Za-z0-9]{32,}",
        "Private Key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "Generic Secret": r"(?i)(?:password|secret|token|api._key)\s*[:=]\
```

---

#### 硬编码密钥/凭证 — `tests\vulnerable_app.py:88`

- **漏洞ID**: hardcoded_secret-3
- **CWE**: CWE-798
- **风险描述**: 硬编码的密钥和凭证可能被攻击者获取，导致云资源被盗用或系统被入侵
- **匹配内容**: `SECRET = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"`


```
     86: 
     87: # 硬编码的 API 密钥
 >>> 88: API_SECRET = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"
     89: DB_PASSWORD = "SuperSecretPassword123!@#"
     90: JWT_SECRET = "my-secret-key-change-in-production-12345"
```

---

#### 硬编码密钥/凭证 — `tests\vulnerable_app.py:90`

- **漏洞ID**: hardcoded_secret-4
- **CWE**: CWE-798
- **风险描述**: 硬编码的密钥和凭证可能被攻击者获取，导致云资源被盗用或系统被入侵
- **匹配内容**: `SECRET = "my-secret-key-change-in-production-12345"`


```
     88: API_SECRET = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"
     89: DB_PASSWORD = "SuperSecretPassword123!@#"
 >>> 90: JWT_SECRET = "my-secret-key-change-in-production-12345"
     91: 
     92: # ============================================================
```

---

#### 不安全反序列化 — `tests\vulnerable_app.py:101`

- **漏洞ID**: insecure_deserialization-7
- **CWE**: CWE-502
- **风险描述**: 攻击者可利用不安全反序列化漏洞执行远程代码
- **匹配内容**: `pickle.loads(`

- **攻击场景**: 攻击者可以构造恶意的pickle序列化数据，通过发送类似 /deserialize?data=... 的请求来触发远程代码执行。
- **修复建议**: 避免对不可信数据进行pickle反序列化。如果必须反序列化，使用更安全的序列化格式（如JSON），并对数据进行严格的校验。

```
     99:     if data:
     100:         # 漏洞: 对不可信数据进行 pickle 反序列化
 >>> 101:         obj = pickle.loads(bytes.fromhex(data))  # 不安全反序列化!
     102:         return str(obj)
     103:     return "No data"
```

#### 🔗 证据链

**① 文件位置**
- 文件: `tests\vulnerable_app.py`
- 行号: 101

**② 调用路径（输入源 → 危险函数）**
```
  [6] 行 85: AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  [7] 行 88: API_SECRET = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"
  [8] 行 89: DB_PASSWORD = "SuperSecretPassword123!@#"
  [9] 行 90: JWT_SECRET = "my-secret-key-change-in-production-12345"
  [10] 行 95: @app.route("/deserialize")
  [11] 行 96: def unsafe_deserialize():
  [12] 行 98: data = request.args.get("data", "")
  [13] 行 101: obj = pickle.loads(bytes.fromhex(data))  # 不安全反序列化!
```
- **输入源**: Flask 请求
- **危险函数**: 不安全反序列化

**③ 验证结果**
- **真实性**: ✅ 确认漏洞
- **严重程度**: 高危
- **可利用性**: 需要验证

**④ 证据完整性**: 5/5

**💥 PoC 利用代码**
```python
#!/usr/bin/env python3
"""
PoC: 不安全反序列化
Target: tests\vulnerable_app.py:101
CWE: CWE-502
Risk: 高危

Description:
攻击者可利用不安全反序列化漏洞执行远程代码
"""

def verify_vulnerability():
    """验证此漏洞的通用步骤"""
    print("[*] 建议手工验证步骤:")
    print(f"  1. 查看文件: tests\vulnerable_app.py")
    print(f"  2. 定位到行: 101")
    print(f"  3. 分析输入是否可控")
    print(f"  4. 跟踪数据流向")
    print(f"  5. 构造利用请求")

if __name__ == "__main__":
    verify_vulnerability()

```

---

#### 服务端模板注入 (SSTI) — `tests\vulnerable_app.py:115`

- **漏洞ID**: ssti-8
- **CWE**: CWE-1336
- **风险描述**: 攻击者可通过注入模板表达式执行任意代码或读取敏感数据
- **匹配内容**: `render_template_string(`

- **攻击场景**: 攻击者可以通过发送类似 /hello?name=<script>alert('XSS')</script> 的请求来执行任意JavaScript代码。
- **修复建议**: 使用Flask的模板引擎自动转义功能，或手动对用户输入进行HTML转义。避免直接拼接用户输入到模板字符串中。

```
     113:     # 漏洞: 未转义直接渲染用户输入
     114:     html = f"<h1>Hello, {name}!</h1>"  # XSS!
 >>> 115:     return render_template_string(html)
     116: 
     117: 
```

#### 🔗 证据链

**① 文件位置**
- 文件: `tests\vulnerable_app.py`
- 行号: 115

**② 调用路径（输入源 → 危险函数）**
```
  [7] 行 98: data = request.args.get("data", "")
  [8] 行 101: obj = pickle.loads(bytes.fromhex(data))  # 不安全反序列化!
  [9] 行 102: return str(obj)
  [10] 行 109: @app.route("/hello")
  [11] 行 110: def hello():
  [12] 行 112: name = request.args.get("name", "World")
  [13] 行 114: html = f"<h1>Hello, {name}!</h1>"  # XSS!
  [14] 行 115: return render_template_string(html)
```
- **输入源**: Flask 请求
- **危险函数**: 服务端模板注入 (SSTI)

**③ 验证结果**
- **真实性**: ✅ 确认漏洞
- **严重程度**: 高危
- **可利用性**: 需要验证

**④ 证据完整性**: 5/5

**💥 PoC 利用代码**
```python
#!/usr/bin/env python3
"""
PoC: 服务端模板注入 (SSTI)
Target: tests\vulnerable_app.py:115
CWE: CWE-1336
Risk: 高危

Description:
攻击者可通过注入模板表达式执行任意代码或读取敏感数据
"""

def verify_vulnerability():
    """验证此漏洞的通用步骤"""
    print("[*] 建议手工验证步骤:")
    print(f"  1. 查看文件: tests\vulnerable_app.py")
    print(f"  2. 定位到行: 115")
    print(f"  3. 分析输入是否可控")
    print(f"  4. 跟踪数据流向")
    print(f"  5. 构造利用请求")

if __name__ == "__main__":
    verify_vulnerability()

```

---

#### 二阶SQL注入 — `tests\vulnerable_app.py:41`

- **漏洞ID**: sqli_second_order-9
- **CWE**: CWE-89
- **风险描述**: 攻击者可在首次请求中注入恶意数据，存储后触发二次查询时被利用
- **匹配内容**: `SELECT * FROM users WHERE name LIKE '%{keyword}%`


```
     39:     cursor = conn.cursor()
     40:     # 漏洞: 拼接用户输入
 >>> 41:     cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{keyword}%'")  # SQL 注入!
     42:     return str(cursor.fetchall())
     43: 
```

---

#### SQL注入 — `src\analyzers\ast_analyzer.py:143`

- **漏洞ID**: sql_injection-11
- **CWE**: CWE-89
- **风险描述**: 攻击者可通过构造恶意SQL语句操纵数据库，导致数据泄露、篡改或删除
- **匹配内容**: `cursor.execute(f"`

- **攻击场景**: 攻击者通过提供包含SQL注入payload的输入（如' OR '1'='1），若代码中未使用参数化查询，则可能被AST分析器误判为安全。
- **修复建议**: 1. 增强AST分析逻辑，追踪变量来源，识别用户可控输入。2. 结合数据流分析，标记从用户输入到SQL执行函数的路径。3. 推荐使用参数化查询或ORM框架，从根本上防止SQL注入。

```
     141:             node_text = content[node.start_byte:node.end_byte]
     142: 
 >>> 143:             # Python: cursor.execute(f"...") 或 execute("..." % var)
     144:             sql_patterns = [
     145:                 r'cursor\.execute\s*\(',
```

#### 🔗 证据链

**① 文件位置**
- 文件: `src\analyzers\ast_analyzer.py`
- 行号: 143

**② 调用路径（输入源 → 危险函数）**
```
  [5] 行 123: def detect_xss_ast(self, tree, content: str) -> list:
  [6] 行 128: findings = []
  [7] 行 132: lines = content.split('\n')
  [8] 行 133: root = tree.root_node
  [9] 行 135: self._walk_and_find_xss(root, content, lines, findings)
  [10] 行 138: def _walk_and_find_sql_injection(self, node, content: str, lines: list, findings: list):
  [11] 行 140: if node.type in ("call", "call_expression", "method_invocation"):
  [12] 行 141: node_text = content[node.start_byte:node.end_byte]
```
- **输入源**: 未识别到明确输入源
- **危险函数**: SQL注入

**③ 验证结果**
- **真实性**: ✅ 确认漏洞
- **严重程度**: 高危
- **可利用性**: 需要验证

**④ 证据完整性**: 5/5

**💥 PoC 利用代码**
```python
#!/usr/bin/env python3
"""
PoC: SQL Injection
Target: src\analyzers\ast_analyzer.py:143
CWE: CWE-89
"""

import requests

def test_sql_injection(target_url, param="id"):
    """检测 SQL 注入漏洞"""
    payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' AND 1=1--",
        "' AND 1=2--",
        "'; DROP TABLE users--",
        "' OR '1'='1' --",
    ]

    print(f"[*] 测试目标: {target_url}")
    print(f"[*] 参数: {param}")

    for payload in payloads:
        try:
            
```

---

#### XML外部实体注入 (XXE) — `config\settings.py:170`

- **漏洞ID**: xxe-18
- **CWE**: CWE-611
- **风险描述**: 攻击者可通过恶意XML实体引用读取服务器文件、执行SSRF攻击或导致拒绝服务
- **匹配内容**: `DocumentBuilderFactory`


```
     168:         "patterns": [
     169:             r"""SAXParser\.parse\s*\(""",
 >>> 170:             r"""DocumentBuilderFactory""",
     171:             r"""SimpleXML\s*\(\s*file_get_contents""",
     172:             r"""loadXML\s*\(""",
```

---

#### XML外部实体注入 (XXE) — `config\settings.py:173`

- **漏洞ID**: xxe-19
- **CWE**: CWE-611
- **风险描述**: 攻击者可通过恶意XML实体引用读取服务器文件、执行SSRF攻击或导致拒绝服务
- **匹配内容**: `XMLReader`


```
     171:             r"""SimpleXML\s*\(\s*file_get_contents""",
     172:             r"""loadXML\s*\(""",
 >>> 173:             r"""XMLReader""",
     174:             r"""libxml_disable_entity_loader\s*\(\s*false""",
     175:             r"""DOMDocument::load""",
```

---

#### XML外部实体注入 (XXE) — `config\settings.py:175`

- **漏洞ID**: xxe-20
- **CWE**: CWE-611
- **风险描述**: 攻击者可通过恶意XML实体引用读取服务器文件、执行SSRF攻击或导致拒绝服务
- **匹配内容**: `DOMDocument::load`


```
     173:             r"""XMLReader""",
     174:             r"""libxml_disable_entity_loader\s*\(\s*false""",
 >>> 175:             r"""DOMDocument::load""",
     176:         ],
     177:         "risk_description": "攻击者可通过恶意XML实体引用读取服务器文件、执行SSRF攻击或导致拒绝服务"
```

---

#### LDAP注入 — `config\settings.py:216`

- **漏洞ID**: ldap_injection-27
- **CWE**: CWE-90
- **风险描述**: 攻击者可篡改LDAP查询语句，绕过认证或获取未授权数据
- **匹配内容**: `LdapTemplate`


```
     214:             r"""ldap_read\s*\(""",
     215:             r"""DirContext\.search""",
 >>> 216:             r"""LdapTemplate""",
     217:             r"""initialLdapContext""",
     218:         ],
```

---

#### LDAP注入 — `config\settings.py:217`

- **漏洞ID**: ldap_injection-28
- **CWE**: CWE-90
- **风险描述**: 攻击者可篡改LDAP查询语句，绕过认证或获取未授权数据
- **匹配内容**: `initialLdapContext`


```
     215:             r"""DirContext\.search""",
     216:             r"""LdapTemplate""",
 >>> 217:             r"""initialLdapContext""",
     218:         ],
     219:         "risk_description": "攻击者可篡改LDAP查询语句，绕过认证或获取未授权数据"
```

---

#### 服务端模板注入 (SSTI) — `config\settings.py:240`

- **漏洞ID**: ssti-29
- **CWE**: CWE-1336
- **风险描述**: 攻击者可通过注入模板表达式执行任意代码或读取敏感数据
- **匹配内容**: `render_to_string`


```
     238:         "patterns": [
     239:             r"""render_template_string\s*\(""",
 >>> 240:             r"""render_to_string""",
     241:             r"""\.render\s*\(\s*request\.args""",
     242:             r"""Template\s*\(\s*["'][^"']*\${""",
```

---

#### 不安全文件上传 — `config\settings.py:258`

- **漏洞ID**: insecure_upload-30
- **CWE**: CWE-434
- **风险描述**: 攻击者可上传恶意文件（WebShell、恶意脚本）导致服务器被控制
- **匹配内容**: `move_uploaded_file`


```
     256:             r"""upload\(""",
     257:             r"""\.save\s*\(\s*["'][^"']*\.[^"']*["']\s*\)""",
 >>> 258:             r"""move_uploaded_file""",
     259:             r"""file_put_contents.*$_FILES""",
     260:             r"""open\(.*filename.*['""][^'""]*\.\w+['""]""",
```

---

#### JWT安全漏洞 — `config\settings.py:272`

- **漏洞ID**: jwt_vuln-31
- **CWE**: CWE-347
- **风险描述**: 攻击者可利用JWT算法混淆、空签名或密钥泄露伪造身份令牌
- **匹配内容**: `algorithms.*None`


```
     270:             r"""jwt\.decode.*None""",
     271:             r"""algorithm=['""]none['""]""",
 >>> 272:             r"""algorithms.*None""",
     273:             r"""JWT_ALGORITHM.*['""]none['""]""",
     274:             r"""jwt\.encode.*secret.*None""",
```

---

#### CRLF注入/HTTP响应拆分 — `config\settings.py:300`

- **漏洞ID**: crlf_injection-32
- **CWE**: CWE-93
- **风险描述**: 攻击者可通过注入CRLF序列实现HTTP响应拆分、缓存投毒或XSS攻击
- **匹配内容**: `add_header.*%0`


```
     298:             r"""%0[dDaA].*%0[aA]""",
     299:             r"""\\\\r\\\\n.*header""",
 >>> 300:             r"""add_header.*%0""",
     301:         ],
     302:         "risk_description": "攻击者可通过注入CRLF序列实现HTTP响应拆分、缓存投毒或XSS攻击"
```

---

#### 原型链污染 (Prototype Pollution) — `config\settings.py:329`

- **漏洞ID**: prototype_pollution-33
- **CWE**: CWE-1321
- **风险描述**: 攻击者可通过原型链污染实现属性注入，导致拒绝服务或远程代码执行
- **匹配内容**: `deepMerge.*__proto__`


```
     327:             r"""\[\s*['""]__proto__['""]\s*\]""",
     328:             r"""\.clone\s*\(\s*.*__proto__""",
 >>> 329:             r"""deepMerge.*__proto__""",
     330:             r"""extend\(true.*__proto__""",
     331:         ],
```

---

#### 弱加密算法 — `config\settings.py:357`

- **漏洞ID**: weak_crypto-34
- **CWE**: CWE-327
- **风险描述**: 使用已被破解的加密算法（MD5、DES、RC4、SHA-1），可被攻击者逆向破解
- **匹配内容**: `Crypt::DES`


```
     355:             r"""Cipher\.getInstance\(['""]RC4['""]""",
     356:             r"""sha1\s*\(""",
 >>> 357:             r"""Crypt::DES""",
     358:             r"""des\s*-\s*cbc""",
     359:             r"""md5\(.*password""",
```

---

#### 弱加密算法 — `config\settings.py:360`

- **漏洞ID**: weak_crypto-35
- **CWE**: CWE-327
- **风险描述**: 使用已被破解的加密算法（MD5、DES、RC4、SHA-1），可被攻击者逆向破解
- **匹配内容**: `mysql_native_password`


```
     358:             r"""des\s*-\s*cbc""",
     359:             r"""md5\(.*password""",
 >>> 360:             r"""mysql_native_password""",
     361:         ],
     362:         "risk_description": "使用已被破解的加密算法（MD5、DES、RC4、SHA-1），可被攻击者逆向破解"
```

---

#### 不安全的证书验证 — `config\settings.py:269`

- **漏洞ID**: certificate_vuln-36
- **CWE**: CWE-295
- **风险描述**: 禁用证书验证可能导致中间人攻击，通信数据被窃听或篡改
- **匹配内容**: `verify=False`


```
     267:         "cwe": "CWE-347",
     268:         "patterns": [
 >>> 269:             r"""jwt\.decode.*verify=False""",
     270:             r"""jwt\.decode.*None""",
     271:             r"""algorithm=['""]none['""]""",
```

---

#### 不安全的证书验证 — `config\settings.py:369`

- **漏洞ID**: certificate_vuln-37
- **CWE**: CWE-295
- **风险描述**: 禁用证书验证可能导致中间人攻击，通信数据被窃听或篡改
- **匹配内容**: `verify=False`


```
     367:         "cwe": "CWE-295",
     368:         "patterns": [
 >>> 369:             r"""verify=False""",
     370:             r"""ssl\._create_default_https_context""",
     371:             r"""check_hostname\s*=\s*False""",
```

---

#### 不安全的证书验证 — `config\settings.py:372`

- **漏洞ID**: certificate_vuln-38
- **CWE**: CWE-295
- **风险描述**: 禁用证书验证可能导致中间人攻击，通信数据被窃听或篡改
- **匹配内容**: `CERT_NONE`


```
     370:             r"""ssl\._create_default_https_context""",
     371:             r"""check_hostname\s*=\s*False""",
 >>> 372:             r"""CERT_NONE""",
     373:             r"""\.context\.check_hostname\s*=\s*False""",
     374:             r"""REQUIRED""",
```

---

#### 不安全的证书验证 — `config\settings.py:374`

- **漏洞ID**: certificate_vuln-39
- **CWE**: CWE-295
- **风险描述**: 禁用证书验证可能导致中间人攻击，通信数据被窃听或篡改
- **匹配内容**: `REQUIRED`


```
     372:             r"""CERT_NONE""",
     373:             r"""\.context\.check_hostname\s*=\s*False""",
 >>> 374:             r"""REQUIRED""",
     375:             r"""ssl._create_unverified_context""",
     376:         ],
```

---

#### 不安全的证书验证 — `config\settings.py:375`

- **漏洞ID**: certificate_vuln-40
- **CWE**: CWE-295
- **风险描述**: 禁用证书验证可能导致中间人攻击，通信数据被窃听或篡改
- **匹配内容**: `ssl._create_unverified_context`


```
     373:             r"""\.context\.check_hostname\s*=\s*False""",
     374:             r"""REQUIRED""",
 >>> 375:             r"""ssl._create_unverified_context""",
     376:         ],
     377:         "risk_description": "禁用证书验证可能导致中间人攻击，通信数据被窃听或篡改"
```

---

#### 条件竞争/TOCTOU — `config\settings.py:413`

- **漏洞ID**: race_condition-43
- **CWE**: CWE-367
- **风险描述**: 检查时间和使用时间之间存在窗口期，攻击者可利用竞争条件绕过安全检查
- **匹配内容**: `if.*exists.*open`


```
     411:         "patterns": [
     412:             r"""os\.path\.exists.*os\.(remove|unlink)""",
 >>> 413:             r"""if.*exists.*open""",
     414:             r"""if.*exists.*delete""",
     415:             r"""check.*write""",
```

---

#### 条件竞争/TOCTOU — `config\settings.py:414`

- **漏洞ID**: race_condition-44
- **CWE**: CWE-367
- **风险描述**: 检查时间和使用时间之间存在窗口期，攻击者可利用竞争条件绕过安全检查
- **匹配内容**: `if.*exists.*delete`


```
     412:             r"""os\.path\.exists.*os\.(remove|unlink)""",
     413:             r"""if.*exists.*open""",
 >>> 414:             r"""if.*exists.*delete""",
     415:             r"""check.*write""",
     416:             r"""with\s+open\(\).*while""",
```

---

#### 条件竞争/TOCTOU — `config\settings.py:415`

- **漏洞ID**: race_condition-45
- **CWE**: CWE-367
- **风险描述**: 检查时间和使用时间之间存在窗口期，攻击者可利用竞争条件绕过安全检查
- **匹配内容**: `check.*write`


```
     413:             r"""if.*exists.*open""",
     414:             r"""if.*exists.*delete""",
 >>> 415:             r"""check.*write""",
     416:             r"""with\s+open\(\).*while""",
     417:         ],
```

---

#### 明文存储敏感信息 — `config\settings.py:426`

- **漏洞ID**: cleartext_storage-46
- **CWE**: CWE-312
- **风险描述**: 敏感信息（密码、身份证、银行卡号等）以明文存储，泄露后可造成严重损失
- **匹配内容**: `credit_card`


```
     424:         "patterns": [
     425:             r'password\s*=\s*["\'][A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]+["\']',
 >>> 426:             r'credit_card',
     427:             r'ssn\s*=',
     428:             r'phone\s*=\s*["\']\d{11}["\']',
```

---

#### 明文存储敏感信息 — `config\settings.py:429`

- **漏洞ID**: cleartext_storage-47
- **CWE**: CWE-312
- **风险描述**: 敏感信息（密码、身份证、银行卡号等）以明文存储，泄露后可造成严重损失
- **匹配内容**: `id_card`


```
     427:             r'ssn\s*=',
     428:             r'phone\s*=\s*["\']\d{11}["\']',
 >>> 429:             r'id_card',
     430:             r'bank_account',
     431:             r'passport_number',
```

---

#### 明文存储敏感信息 — `config\settings.py:430`

- **漏洞ID**: cleartext_storage-48
- **CWE**: CWE-312
- **风险描述**: 敏感信息（密码、身份证、银行卡号等）以明文存储，泄露后可造成严重损失
- **匹配内容**: `bank_account`


```
     428:             r'phone\s*=\s*["\']\d{11}["\']',
     429:             r'id_card',
 >>> 430:             r'bank_account',
     431:             r'passport_number',
     432:         ],
```

---

#### 明文存储敏感信息 — `config\settings.py:431`

- **漏洞ID**: cleartext_storage-49
- **CWE**: CWE-312
- **风险描述**: 敏感信息（密码、身份证、银行卡号等）以明文存储，泄露后可造成严重损失
- **匹配内容**: `passport_number`


```
     429:             r'id_card',
     430:             r'bank_account',
 >>> 431:             r'passport_number',
     432:         ],
     433:         "risk_description": "敏感信息（密码、身份证、银行卡号等）以明文存储，泄露后可造成严重损失"
```

---

#### 二阶SQL注入 — `config\settings.py:440`

- **漏洞ID**: sqli_second_order-50
- **CWE**: CWE-89
- **风险描述**: 攻击者可在首次请求中注入恶意数据，存储后触发二次查询时被利用
- **匹配内容**: `SELECT.*FROM.*WHERE.*\|`


```
     438:         "cwe": "CWE-89",
     439:         "patterns": [
 >>> 440:             r"""SELECT.*FROM.*WHERE.*\|""",
     441:             r"""SELECT.*FROM.*WHERE.*\+""",
     442:             r"""SELECT.*FROM.*WHERE.*%""",
```

---

#### 二阶SQL注入 — `config\settings.py:441`

- **漏洞ID**: sqli_second_order-51
- **CWE**: CWE-89
- **风险描述**: 攻击者可在首次请求中注入恶意数据，存储后触发二次查询时被利用
- **匹配内容**: `SELECT.*FROM.*WHERE.*\+`


```
     439:         "patterns": [
     440:             r"""SELECT.*FROM.*WHERE.*\|""",
 >>> 441:             r"""SELECT.*FROM.*WHERE.*\+""",
     442:             r"""SELECT.*FROM.*WHERE.*%""",
     443:             r"""insert.*into.*values.*SELECT""",
```

---

#### 二阶SQL注入 — `config\settings.py:442`

- **漏洞ID**: sqli_second_order-52
- **CWE**: CWE-89
- **风险描述**: 攻击者可在首次请求中注入恶意数据，存储后触发二次查询时被利用
- **匹配内容**: `SELECT.*FROM.*WHERE.*%`


```
     440:             r"""SELECT.*FROM.*WHERE.*\|""",
     441:             r"""SELECT.*FROM.*WHERE.*\+""",
 >>> 442:             r"""SELECT.*FROM.*WHERE.*%""",
     443:             r"""insert.*into.*values.*SELECT""",
     444:             r"""INSERT.*SELECT""",
```

---

#### 二阶SQL注入 — `config\settings.py:443`

- **漏洞ID**: sqli_second_order-53
- **CWE**: CWE-89
- **风险描述**: 攻击者可在首次请求中注入恶意数据，存储后触发二次查询时被利用
- **匹配内容**: `insert.*into.*values.*SELECT`


```
     441:             r"""SELECT.*FROM.*WHERE.*\+""",
     442:             r"""SELECT.*FROM.*WHERE.*%""",
 >>> 443:             r"""insert.*into.*values.*SELECT""",
     444:             r"""INSERT.*SELECT""",
     445:             r"""UPDATE.*SET.*=.*SELECT""",
```

---

#### 二阶SQL注入 — `config\settings.py:444`

- **漏洞ID**: sqli_second_order-54
- **CWE**: CWE-89
- **风险描述**: 攻击者可在首次请求中注入恶意数据，存储后触发二次查询时被利用
- **匹配内容**: `INSERT.*SELECT`


```
     442:             r"""SELECT.*FROM.*WHERE.*%""",
     443:             r"""insert.*into.*values.*SELECT""",
 >>> 444:             r"""INSERT.*SELECT""",
     445:             r"""UPDATE.*SET.*=.*SELECT""",
     446:         ],
```

---

#### 二阶SQL注入 — `config\settings.py:445`

- **漏洞ID**: sqli_second_order-55
- **CWE**: CWE-89
- **风险描述**: 攻击者可在首次请求中注入恶意数据，存储后触发二次查询时被利用
- **匹配内容**: `UPDATE.*SET.*=.*SELECT`


```
     443:             r"""insert.*into.*values.*SELECT""",
     444:             r"""INSERT.*SELECT""",
 >>> 445:             r"""UPDATE.*SET.*=.*SELECT""",
     446:         ],
     447:         "risk_description": "攻击者可在首次请求中注入恶意数据，存储后触发二次查询时被利用"
```

---

### 🟡 中危 (14 个)

#### 正则表达式拒绝服务 (ReDoS) — `src\analyzers\cve_rag.py:162`

- **漏洞ID**: redos-10
- **CWE**: CWE-1333
- **风险描述**: 存在灾难性回溯的正则表达式，攻击者可构造特制输入导致CPU耗尽
- **匹配内容**: `(r'([a-zA-Z0-9_.-]+)\s*[=><~!]+\s*([a-zA-Z0-9_.*-]+)`

- **攻击场景**: 攻击者通过构造包含大量星号或连字符的版本号字符串，可能导致正则表达式引擎进行额外的回溯尝试。
- **修复建议**: 1. 明确版本号的合法字符集，例如只允许数字、点和字母：`[a-zA-Z0-9.]+`。
2. 限制版本号长度，例如 `{1,50}`。
3. 使用更严格的版本号格式验证，例如语义化版本号模式。

```
     160:                     line = line.strip()
     161:                     if line and not line.startswith(('#', '-', 'git+')):
 >>> 162:                         match = re.match(r'([a-zA-Z0-9_.-]+)\s*[=><~!]+\s*([a-zA-Z0-9_.*-]+)', line)
     163:                         if match:
     164:                             dependencies.append((match.group(1), match.group(2)))
```

#### 🔗 证据链

**① 文件位置**
- 文件: `src\analyzers\cve_rag.py`
- 行号: 162

**② 调用路径（输入源 → 危险函数）**
```
  [5] 行 148: def _extract_dependencies(self, project_path: str) -> list:
  [6] 行 153: dependencies = []
  [7] 行 156: req_path = os.path.join(project_path, "requirements.txt")
  [8] 行 157: if os.path.exists(req_path):
  [9] 行 158: with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
  [10] 行 160: line = line.strip()
  [11] 行 161: if line and not line.startswith(('#', '-', 'git+')):
  [12] 行 162: match = re.match(r'([a-zA-Z0-9_.-]+)\s*[=><~!]+\s*([a-zA-Z0-9_.*-]+)', line)
```
- **输入源**: 未识别到明确输入源
- **危险函数**: 正则表达式拒绝服务 (ReDoS)

**③ 验证结果**
- **真实性**: ✅ 确认漏洞
- **严重程度**: 中危
- **可利用性**: 需要验证

**④ 证据完整性**: 5/5

**💥 PoC 利用代码**
```python
#!/usr/bin/env python3
"""
PoC: 正则表达式拒绝服务 (ReDoS)
Target: src\analyzers\cve_rag.py:162
CWE: CWE-1333
Risk: 中危

Description:
存在灾难性回溯的正则表达式，攻击者可构造特制输入导致CPU耗尽
"""

def verify_vulnerability():
    """验证此漏洞的通用步骤"""
    print("[*] 建议手工验证步骤:")
    print(f"  1. 查看文件: src\analyzers\cve_rag.py")
    print(f"  2. 定位到行: 162")
    print(f"  3. 分析输入是否可控")
    print(f"  4. 跟踪数据流向")
    print(f"  5. 构造利用请求")

if __name__ == "__main__":
    verify_vulnerability()

```

---

#### 跨站脚本 (XSS) — `src\analyzers\ast_analyzer.py:205`

- **漏洞ID**: xss-12
- **CWE**: CWE-79
- **风险描述**: 攻击者可在Web页面中注入恶意脚本，窃取用户Cookie、会话令牌或重定向到恶意网站
- **匹配内容**: `dangerouslySetInnerHTML`

- **攻击场景**: 攻击者通过输入包含<script>标签的恶意内容，若代码直接赋值给innerHTML，则可能导致XSS攻击。
- **修复建议**: 1. 增强AST分析，追踪变量是否经过HTML转义（如escapeHtml函数）。2. 推荐使用安全的DOM操作（如textContent）或模板引擎的自动转义功能。3. 实施内容安全策略（CSP）作为纵深防御。

```
     203:                 r'innerHTML\s*=',
     204:                 r'\.html\s*\(',
 >>> 205:                 r'dangerouslySetInnerHTML',
     206:                 r'v-html\s*=',
     207:                 r'document\.write\s*\(',
```

#### 🔗 证据链

**① 文件位置**
- 文件: `src\analyzers\ast_analyzer.py`
- 行号: 205

**② 调用路径（输入源 → 危险函数）**
```
  [8] 行 190: if re.search(r'(open|readFile|file_get_contents)\s*\(', node_text):
  [9] 行 191: self._check_dynamic_arg(node, content, lines, findings,
  [10] 行 195: self._walk_and_find_path_traversal(child, content, lines, findings)
  [11] 行 197: def _walk_and_find_xss(self, node, content: str, lines: list, findings: list):
  [12] 行 199: if node.type in ("assignment", "expression_statement"):
  [13] 行 200: node_text = content[node.start_byte:node.end_byte]
  [14] 行 202: xss_patterns = [
  [15] 行 203: r'innerHTML\s*=',
```
- **输入源**: 未识别到明确输入源
- **危险函数**: 跨站脚本 (XSS)

**③ 验证结果**
- **真实性**: ✅ 确认漏洞
- **严重程度**: 中危
- **可利用性**: 需要验证

**④ 证据完整性**: 5/5

**💥 PoC 利用代码**
```python
#!/usr/bin/env python3
"""
PoC: Cross-Site Scripting (XSS)
Target: src\analyzers\ast_analyzer.py:205
CWE: CWE-79
"""

import requests

def test_xss(target_url, param="q"):
    """检测反射型 XSS 漏洞"""
    payload = "<script>alert('XSS')</script>"

    try:
        params = {param: payload}
        r = requests.get(target_url, params=params, timeout=10)
        if payload in r.text:
            print(f"[!] 发现 XSS 漏洞! Payload 在响应中未转义输出")
            print(f"[!] URL: {r.url}")
            return True
   
```

---

#### 路径遍历 — `src\exploit\poc_generator.py:217`

- **漏洞ID**: path_traversal-13
- **CWE**: CWE-22
- **风险描述**: 攻击者可读取服务器上的任意文件，包括配置文件、密码文件等敏感信息
- **匹配内容**: `../../../`

- **攻击场景**: 攻击者通过控制漏洞扫描结果中的 finding['file'] 字段，传入包含路径遍历序列（如 '../'）的文件名，导致 PoC 生成器在构建 file_path 时指向项目目录外的敏感文件。如果后续代码使用该路径进行文件操作（如读取、写入、执行），则可能导致敏感信息泄露或任意文件写入。
- **修复建议**: 1. 对 finding['file'] 进行严格的路径规范化处理，例如使用 os.path.normpath 和 os.path.realpath 解析路径，并确保解析后的路径仍在项目目录内。2. 使用白名单机制，只允许预定义的文件名或路径模式。3. 避免直接使用用户输入的文件路径进行文件操作，如果必须使用，应进行严格的验证和过滤。

```
     215:     """检测路径遍历漏洞"""
     216:     payloads = [
 >>> 217:         "../../../etc/passwd",
     218:         "....//....//....//etc/passwd",
     219:         "../../../../windows/win.ini",
```

#### 🔗 证据链

**① 文件位置**
- 文件: `src\exploit\poc_generator.py`
- 行号: 217

**② 调用路径（输入源 → 危险函数）**
```
  [5] 行 194: print(f"[-] 请求失败: {{e}}")
  [6] 行 196: print("[-] 未发现命令注入漏洞")
  [7] 行 199: if __name__ == "__main__":
  [8] 行 200: test_command_injection("http://target.com/page")
  [9] 行 203: def _poc_path_traversal(self, finding: dict) -> str:
  [10] 行 209: CWE: {finding.get("cwe", "CWE-22")}
  [11] 行 214: def test_path_traversal(target_url, param="file"):
  [12] 行 216: payloads = [
```
- **输入源**: 未识别到明确输入源
- **危险函数**: 路径遍历

**③ 验证结果**
- **真实性**: ✅ 确认漏洞
- **严重程度**: 中危
- **可利用性**: 需要验证

**④ 证据完整性**: 5/5

**💥 PoC 利用代码**
```python
#!/usr/bin/env python3
"""
PoC: Path Traversal
Target: src\exploit\poc_generator.py:217
CWE: CWE-22
"""

import requests

def test_path_traversal(target_url, param="file"):
    """检测路径遍历漏洞"""
    payloads = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "../../../../windows/win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\win.ini",
    ]

    indicators = ["root:", "admin:", "[fonts]", "[extensions]", "boot loader"]

   
```

---

#### 路径遍历 — `src\exploit\poc_generator.py:218`

- **漏洞ID**: path_traversal-14
- **CWE**: CWE-22
- **风险描述**: 攻击者可读取服务器上的任意文件，包括配置文件、密码文件等敏感信息
- **匹配内容**: `..//....//..../`


```
     216:     payloads = [
     217:         "../../../etc/passwd",
 >>> 218:         "....//....//....//etc/passwd",
     219:         "../../../../windows/win.ini",
     220:         "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
```

---

#### 路径遍历 — `src\exploit\poc_generator.py:219`

- **漏洞ID**: path_traversal-15
- **CWE**: CWE-22
- **风险描述**: 攻击者可读取服务器上的任意文件，包括配置文件、密码文件等敏感信息
- **匹配内容**: `../../../../`


```
     217:         "../../../etc/passwd",
     218:         "....//....//....//etc/passwd",
 >>> 219:         "../../../../windows/win.ini",
     220:         "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
     221:         "..\\\\..\\\\..\\\\windows\\\\win.ini",
```

---

#### 整数溢出/环绕 — `src\exploit\poc_generator.py:531`

- **漏洞ID**: integer_overflow-16
- **CWE**: CWE-190
- **风险描述**: 整数溢出可导致缓冲区溢出、逻辑错误或拒绝服务攻击
- **匹配内容**: `int(f"  🔎 输入源: {ev.get('input`

- **攻击场景**: 攻击者通过向系统注入大量虚假的漏洞发现结果，使 real_findings 列表变得非常大。虽然 Python 不会发生整数溢出，但循环处理大量数据可能导致 CPU 和内存资源耗尽，造成拒绝服务。
- **修复建议**: 1. 对 real_findings 列表的大小进行限制，例如设置最大处理数量。2. 在循环中添加超时机制或进度报告，避免长时间无响应。3. 考虑使用生成器或流式处理，避免一次性加载大量数据到内存。

```
     529:                     for step in ev['call_path'][-5:]:  # 最后 5 步
     530:                         print(f"     [{step['step']}] 行 {step['line']}: {step['code']}")
 >>> 531:                 print(f"  🔎 输入源: {ev.get('input_source', '未知')}")
     532:                 print(f"  🎯 危险函数: {ev.get('sink_function', '未知')}")
     533:                 print(f"  ✅ 验证: {'已确认' if ev['verification']['is_real'] else '未确认'}")
```

#### 🔗 证据链

**① 文件位置**
- 文件: `src\exploit\poc_generator.py`
- 行号: 531

**② 调用路径（输入源 → 危险函数）**
```
  [9] 行 523: print(f"\n  {'='*50}")
  [10] 行 524: print(f"  🔗 证据链: {ev['vulnerability_id']} - {ev['vuln_name']}")
  [11] 行 525: print(f"  {'='*50}")
  [12] 行 526: print(f"  📍 位置: {ev['file_location']['file']}:{ev['file_location']['line']}")
  [13] 行 527: if ev.get('call_path'):
  [14] 行 528: print(f"  🔀 调用路径:")
  [15] 行 530: print(f"     [{step['step']}] 行 {step['line']}: {step['code']}")
  [16] 行 531: print(f"  🔎 输入源: {ev.get('input_source', '未知')}")
```
- **输入源**: 未识别到明确输入源
- **危险函数**: 整数溢出/环绕

**③ 验证结果**
- **真实性**: ✅ 确认漏洞
- **严重程度**: 中危
- **可利用性**: 需要验证

**④ 证据完整性**: 5/5

**💥 PoC 利用代码**
```python
#!/usr/bin/env python3
"""
PoC: 整数溢出/环绕
Target: src\exploit\poc_generator.py:531
CWE: CWE-190
Risk: 中危

Description:
整数溢出可导致缓冲区溢出、逻辑错误或拒绝服务攻击
"""

def verify_vulnerability():
    """验证此漏洞的通用步骤"""
    print("[*] 建议手工验证步骤:")
    print(f"  1. 查看文件: src\exploit\poc_generator.py")
    print(f"  2. 定位到行: 531")
    print(f"  3. 分析输入是否可控")
    print(f"  4. 跟踪数据流向")
    print(f"  5. 构造利用请求")

if __name__ == "__main__":
    verify_vulnerability()

```

---

#### 跨站脚本 (XSS) — `config\settings.py:126`

- **漏洞ID**: xss-17
- **CWE**: CWE-79
- **风险描述**: 攻击者可在Web页面中注入恶意脚本，窃取用户Cookie、会话令牌或重定向到恶意网站
- **匹配内容**: `dangerouslySetInnerHTML`


```
     124:             r"""innerHTML\s*=\s*["'][^"']*\${""",
     125:             r"""\.html\s*\(\s*["'][^"']*\${""",
 >>> 126:             r"""dangerouslySetInnerHTML""",
     127:             r"""v-html\s*=""",
     128:             r"""document\.write\s*\(\s*["'][^"']*\${""",
```

---

#### 跨站请求伪造 (CSRF) — `config\settings.py:184`

- **漏洞ID**: csrf-21
- **CWE**: CWE-352
- **风险描述**: 攻击者可伪造用户请求执行非授权操作，如修改密码、转账等敏感操作
- **匹配内容**: `@csrf_exempt`


```
     182:         "cwe": "CWE-352",
     183:         "patterns": [
 >>> 184:             r"""@csrf_exempt""",
     185:             r"""csrf_exempt""",
     186:             r"""csrf\.exempt""",
```

---

#### 跨站请求伪造 (CSRF) — `config\settings.py:185`

- **漏洞ID**: csrf-23
- **CWE**: CWE-352
- **风险描述**: 攻击者可伪造用户请求执行非授权操作，如修改密码、转账等敏感操作
- **匹配内容**: `csrf_exempt`


```
     183:         "patterns": [
     184:             r"""@csrf_exempt""",
 >>> 185:             r"""csrf_exempt""",
     186:             r"""csrf\.exempt""",
     187:             r"""without_csrf""",
```

---

#### 跨站请求伪造 (CSRF) — `config\settings.py:187`

- **漏洞ID**: csrf-24
- **CWE**: CWE-352
- **风险描述**: 攻击者可伪造用户请求执行非授权操作，如修改密码、转账等敏感操作
- **匹配内容**: `without_csrf`


```
     185:             r"""csrf_exempt""",
     186:             r"""csrf\.exempt""",
 >>> 187:             r"""without_csrf""",
     188:             r"""#csrf""",
     189:             r"""skip_csrf""",
```

---

#### 跨站请求伪造 (CSRF) — `config\settings.py:188`

- **漏洞ID**: csrf-25
- **CWE**: CWE-352
- **风险描述**: 攻击者可伪造用户请求执行非授权操作，如修改密码、转账等敏感操作
- **匹配内容**: `#csrf`


```
     186:             r"""csrf\.exempt""",
     187:             r"""without_csrf""",
 >>> 188:             r"""#csrf""",
     189:             r"""skip_csrf""",
     190:         ],
```

---

#### 跨站请求伪造 (CSRF) — `config\settings.py:189`

- **漏洞ID**: csrf-26
- **CWE**: CWE-352
- **风险描述**: 攻击者可伪造用户请求执行非授权操作，如修改密码、转账等敏感操作
- **匹配内容**: `skip_csrf`


```
     187:             r"""without_csrf""",
     188:             r"""#csrf""",
 >>> 189:             r"""skip_csrf""",
     190:         ],
     191:         "risk_description": "攻击者可伪造用户请求执行非授权操作，如修改密码、转账等敏感操作"
```

---

#### 内存泄漏/资源未释放 — `config\settings.py:398`

- **漏洞ID**: memory_leak-41
- **CWE**: CWE-401
- **风险描述**: 资源未正确释放可能导致内存耗尽，造成拒绝服务
- **匹配内容**: `FileInputStream`


```
     396:         "patterns": [
     397:             r"""open\(.*['""][^'""]*['""]\)\s*$""",
 >>> 398:             r"""FileInputStream""",
     399:             r"""BufferedReader.*open""",
     400:             r"""new\s+Thread\(\)""",
```

---

#### 内存泄漏/资源未释放 — `config\settings.py:399`

- **漏洞ID**: memory_leak-42
- **CWE**: CWE-401
- **风险描述**: 资源未正确释放可能导致内存耗尽，造成拒绝服务
- **匹配内容**: `BufferedReader.*open`


```
     397:             r"""open\(.*['""][^'""]*['""]\)\s*$""",
     398:             r"""FileInputStream""",
 >>> 399:             r"""BufferedReader.*open""",
     400:             r"""new\s+Thread\(\)""",
     401:             r"""\.connect\(\)""",
```

---

## 📈 漏洞类型分布

| 漏洞类型 | 数量 |
|----------|------|
| 二阶SQL注入 | 7 |
| 跨站请求伪造 (CSRF) | 5 |
| 不安全的证书验证 | 5 |
| 明文存储敏感信息 | 4 |
| 硬编码密钥/凭证 | 3 |
| 路径遍历 | 3 |
| XML外部实体注入 (XXE) | 3 |
| 条件竞争/TOCTOU | 3 |
| SQL注入 | 2 |
| 服务端模板注入 (SSTI) | 2 |
| 跨站脚本 (XSS) | 2 |
| LDAP注入 | 2 |
| 弱加密算法 | 2 |
| 内存泄漏/资源未释放 | 2 |
| 不安全反序列化 | 1 |
| 正则表达式拒绝服务 (ReDoS) | 1 |
| 整数溢出/环绕 | 1 |
| 不安全文件上传 | 1 |
| JWT安全漏洞 | 1 |
| CRLF注入/HTTP响应拆分 | 1 |
| 原型链污染 (Prototype Pollution) | 1 |

## 💡 通用修复建议

### SQL 注入
- 使用参数化查询或 PreparedStatement
- 对用户输入进行严格的类型检查和过滤
- 最小化数据库账户权限

### 命令注入
- 避免使用 shell=True 或系统命令拼接
- 使用白名单机制验证用户输入
- 以最小权限运行应用程序

### XSS
- 对输出进行 HTML 实体编码
- 使用 Content-Security-Policy 头
- 避免使用 innerHTML、v-html 等危险方法

### 硬编码密钥
- 使用环境变量或密钥管理服务 (Vault, AWS Secrets Manager)
- 使用 .gitignore 排除配置文件
- 定期轮换密钥

---

*报告由 LLM Security Audit System 自动生成*