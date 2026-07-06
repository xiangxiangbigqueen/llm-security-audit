# 🔒 LLM Security Audit System

<p align="center">
  <strong>大模型驱动的开源项目安全审计系统</strong><br>
  《网络空间安全综合实验》实验一<br>
  <em>LLM + Agent + MCP + SAST + AST + RAG + Neo4j + Web</em>
</p>

<p align="center">
  <a href="#-快速开始">快速开始</a> •
  <a href="#%EF%B8%8F-30-类漏洞检测">30 类漏洞</a> •
  <a href="#-完整功能清单">完整功能</a> •
  <a href="#-主流技术">主流技术</a> •
  <a href="CLAUDE.md">详细文档</a>
</p>

---

## 🚀 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 扫描测试靶标（验证系统）
python main.py --target tests --quick

# 3. 打开 reports/ 目录下最新的 .html 文件查看报告
```

### 四种使用方式

| 方式 | 命令 |
|------|------|
| 交互菜单 | 双击 `demo.bat` |
| 命令行扫描 | `python main.py --target /path/to/project` |
| Web 界面 | `python main.py --web` → 浏览器打开 `http://127.0.0.1:5000` |
| Claude Code | `claude "使用 security-audit skill 扫描当前项目"` |

### 扫描 GitHub 仓库

```bash
python main.py --target https://github.com/用户名/仓库名.git --quick
```

### 输出

| 格式 | 文件 | 用途 |
|------|------|------|
| 📄 HTML | `*.html` | 浏览器打开，交互式可视化报告 |
| 📄 Markdown | `*.md` | 直接查看，适合提交作业 |
| 📄 JSON | `*.json` | 结构化数据 |

---

## 🛡️ 30 类漏洞检测

| 漏洞类型 | CWE | 严重程度 |
|----------|-----|----------|
| SQL 注入 | CWE-89 | 高危 |
| 二阶 SQL 注入 | CWE-89 | 高危 |
| 命令注入 | CWE-78 | 高危 |
| 硬编码密钥/凭证 | CWE-798 | 高危 |
| 不安全反序列化 | CWE-502 | 高危 |
| 服务端模板注入 SSTI | CWE-1336 | 高危 |
| XXE (XML外部实体) | CWE-611 | 高危 |
| 不安全文件上传 | CWE-434 | 高危 |
| JWT 安全漏洞 | CWE-347 | 高危 |
| CRLF 注入/HTTP响应拆分 | CWE-93 | 高危 |
| LDAP 注入 | CWE-90 | 高危 |
| NoSQL 注入 | CWE-943 | 高危 |
| 原型链污染 | CWE-1321 | 高危 |
| 弱加密算法 | CWE-327 | 高危 |
| 证书验证缺陷 | CWE-295 | 高危 |
| 条件竞争/TOCTOU | CWE-367 | 高危 |
| 明文存储敏感信息 | CWE-312 | 高危 |
| 跨站脚本 XSS | CWE-79 | 中危 |
| 路径遍历 | CWE-22 | 中危 |
| 服务端请求伪造 SSRF | CWE-918 | 中危 |
| CSRF | CWE-352 | 中危 |
| 开放重定向 | CWE-601 | 中危 |
| IDOR | CWE-639 | 中危 |
| 批量赋值 Mass Assignment | CWE-915 | 中危 |
| ReDoS 正则拒绝服务 | CWE-1333 | 中危 |
| 整数溢出 | CWE-190 | 中危 |
| 内存泄漏 | CWE-401 | 中危 |
| 日志伪造 | CWE-117 | 中危 |

---

## 📋 完整功能清单

### 一、安全扫描引擎

| 功能 | 说明 |
|------|------|
| **30 类漏洞检测** | 覆盖 OWASP Top 10 + 扩展，全部关联 CWE 编号（见上方清单） |
| **8 种编程语言** | Python / JavaScript / TypeScript / Java / PHP / Go / Ruby / C# / C++ / Rust |
| **SAST 规则匹配** | 正则引擎第一层快速扫描 |
| **AST 语义分析** | Tree-sitter 解析代码语法树，结构级精确检测 |
| **LLM 深度分析** | 接入 DeepSeek API 进行语义级漏洞验证（支持通义千问、智谱 GLM） |
| **RAG-CVE 情报** | 实时从 NVD 数据库检索已知 CVE，增强检测上下文 |

### 二、架构能力

| 功能 | 说明 |
|------|------|
| **多 Agent 协同** | Scanner Agent → Verifier Agent → Reporter Agent 三阶段流水线 |
| **MCP Server（11 工具）** | 通过 JSON-RPC 暴露扫描、文件操作、证据链等工具供 LLM Agent 调用 |
| **Claude Code Skill** | SKILL.md 定义安全审计能力，可在 Claude Code 中直接调用 |
| **异步并行扫描** | 8 Worker 线程池，大项目加速 5-7 倍 |
| **端到端自动化** | 项目加载 → SAST 扫描 → AST 分析 → RAG-CVE → 验证 → 报告，6 阶段全自动 |

### 三、漏洞验证与证据

| 功能 | 说明 |
|------|------|
| **三级验证** | 代码上下文分析 → SAST 交叉验证 → LLM 语义裁定 |
| **证据链追踪** | 每个漏洞包含：文件位置 + 代码上下文 + 调用路径 + 输入源→危险函数链路 |
| **PoC 自动生成** | 为确认漏洞生成可执行的 Python 验证代码，含复现步骤 |
| **数据流分析** | MCP 工具 `analyze_dataflow` 追踪数据从输入源到敏感操作的完整路径 |
| **可利用性评估** | 自动化判定漏洞是否可被实际利用 |

### 四、报告系统

| 功能 | 说明 |
|------|------|
| **3 格式报告** | Markdown（交作业）+ HTML（可视化）+ JSON（结构化数据） |
| **HTML 增强报告** | Chart.js 双图表（环形图+柱状图）+ 风险评分 + 证据链 + PoC 折叠 |
| **风险评分** | 基于严重程度自动计算 0-100 分，含可视化进度条 |
| **可搜索表格** | 全部漏洞汇总表，支持按等级筛选、关键词搜索、点击排序 |
| **文件级别分析** | 按文件统计漏洞分布数量 |
| **修复建议** | 每类漏洞附带可操作的修复方案 |

### 五、可视化与交互

| 功能 | 说明 |
|------|------|
| **Flask Web 仪表盘** | 浏览器可视化展示扫描结果，Chart.js 统计图 |
| **Neo4j 知识图谱** | 项目→文件→漏洞→CVE 多维关联图谱，Cypher 图查询 |
| **Web 实时扫描** | 浏览器界面提交扫描任务并查看实时进度 |

### 六、开发运维

| 功能 | 说明 |
|------|------|
| **GitHub Actions CI/CD** | push 自动触发安全审计，PR 自动生成摘要 |
| **一键 demo.bat** | Windows 交互式菜单，支持快速扫描/GitHub扫描/Web界面 |
| **国产 LLM API** | 默认 DeepSeek，可切换通义千问、智谱 GLM |
| **自动降级** | LLM API 不可用时自动回退到规则匹配模式 |

---

## ⭐ 主流技术

| # | 主流技术 | 实现位置 |
|---|----------|----------|
| 1 | **LLM 大模型** | [llm_api.py](src/analyzers/llm_api.py) — DeepSeek API 驱动 |
| 2 | **多 Agent 协同** | [main.py:100-212](main.py#L100) — 6 阶段流水线 |
| 3 | **MCP 协议** | [mcp_server.py](src/agents/mcp_server.py) — 11 个注册工具 |
| 4 | **Skills 机制** | [skills/SKILL.md](skills/SKILL.md) — 完整 Skill 定义 |
| 5 | **SAST 静态分析** | [settings.py:62-460](config/settings.py#L62) — 30 类漏洞规则 |
| 6 | **AST 语法树** | [ast_analyzer.py](src/analyzers/ast_analyzer.py) — Tree-sitter |
| 7 | **RAG 检索增强** | [cve_rag.py](src/analyzers/cve_rag.py) — NVD 实时查询 |
| 8 | **CWE/OWASP 标准** | [settings.py](config/settings.py) — 全部漏洞关联 CWE |
| 9 | **知识图谱** | [graph_builder.py](src/analyzers/graph_builder.py) — Neo4j |
| 10 | **Web 可视化** | [web/app.py](web/app.py) — Flask + Chart.js |
| 11 | **CI/CD 集成** | [.github/workflows/security-audit.yml](.github/workflows/security-audit.yml) |
| 12 | **并行编排** | [orchestrator.py](src/agents/orchestrator.py) — 8 Worker |
| 13 | **证据链** | [poc_generator.py](src/exploit/poc_generator.py) — source→sink |

---

## 🗂️ 项目结构

```
llm-security-audit/
├── main.py                     # 主入口 (CLI + Web 双模式)
├── config/settings.py          # 30 类漏洞规则 + CWE + LLM 配置
├── src/
│   ├── agents/                 # Agent 层
│   │   ├── scanner_agent.py    #   扫描器 Agent
│   │   ├── verifier_agent.py   #   验证器 Agent
│   │   ├── orchestrator.py     #   并行编排器
│   │   └── mcp_server.py       #   MCP 工具服务器 (11 工具)
│   ├── analyzers/              # 分析引擎
│   │   ├── ast_analyzer.py     #   Tree-sitter AST 分析
│   │   ├── cve_rag.py          #   RAG-CVE 情报检索
│   │   ├── graph_builder.py    #   Neo4j 知识图谱
│   │   └── llm_api.py          #   LLM API 客户端 (DeepSeek等)
│   ├── exploit/poc_generator.py# PoC 自动生成 + 证据链
│   ├── report/report_generator.py# 报告生成 (MD/JSON/HTML)
│   └── utils/repo_manager.py   # 仓库管理 (GitHub/GitLab/本地)
├── skills/SKILL.md             # Claude Code Skill
├── web/                        # Flask Web 仪表盘
├── .github/workflows/          # CI/CD 流水线
├── tests/                      # 测试靶标 (含 8 类漏洞)
├── docs/                       # 实验报告模板 + PPT大纲
├── CLAUDE.md                   # 完整文档 + 主流技术详细标注
└── README.md                   # 本文件
```

---

<p align="center">
  <strong>实验一 · 网络空间安全综合实验</strong><br>
  <a href="https://github.com/xiangxiangbigqueen/llm-security-audit">GitHub 仓库</a>
</p>
