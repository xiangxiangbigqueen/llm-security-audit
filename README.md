# 🔒 LLM Security Audit System
## 大模型驱动的开源项目安全审计系统

> 《网络空间安全综合实验》实验一  
> 基于 LLM + Agent + MCP + SAST 的多层安全审计系统  
> 技术栈: LLM / Agent / MCP / SAST / AST / RAG / Neo4j / Web / CI/CD

---

## 📋 目录

1. [快速开始](#-快速开始)
2. [使用方式](#-使用方式)
3. [30 类漏洞检测](#-30-类漏洞检测)
4. [完整功能清单](#-完整功能清单)
5. [主流技术使用标注](#-主流技术使用标注)
6. [增强功能模块](#-增强功能模块)
7. [项目结构](#-项目结构)
8. [实验要求对照表](#-实验要求逐项对照)
9. [技术栈总览](#-技术栈总览)

---

## 🚀 快速开始

### 环境要求

| 依赖 | 说明 |
|------|------|
| Python 3.10+ | 核心运行环境 |
| Git 2.0+ | 克隆远程仓库（扫描本地项目可省略） |
| DeepSeek API Key | 可选，启用 LLM 深度分析时设置 `LLM_API_KEY` |

### 安装

```bash
cd D:\Personal\Desktop\llm-security-audit
pip install -r requirements.txt
```

---

## 📋 使用方式

### 方式一：一键菜单（Windows 推荐）

```bash
# 双击 demo.bat，显示菜单：
# [1] Quick scan
# [2] Full scan
# [3] Scan GitHub repo
# [4] Scan local project
# [5] Start Web dashboard
# [6] View reports
# [7] Open reports folder
demo.bat
```

### 方式二：命令行扫描

```bash
# 快速扫描（仅规则匹配）
python main.py --target /path/to/project --quick

# 标准扫描（含验证 + PoC 生成）
python main.py --target /path/to/project

# 增强扫描（含 AST + RAG + 并行 + Neo4j）
python main.py --target /path/to/project --neo4j

# 扫描 GitHub 仓库
python main.py --target https://github.com/username/repo.git

# 启动 Web 界面
python main.py --web
```

### 方式三：LLM 增强分析

```bash
# 设置 DeepSeek API Key（也可用通义千问、智谱 GLM）
set LLM_API_KEY=sk-xxxxxxxx
set LLM_API_BASE=https://api.deepseek.com
set LLM_MODEL=deepseek-chat

# 然后运行，LLM 会自动验证漏洞
python main.py --target /path/to/project
```

### 输出

扫描完成后在 `reports/` 目录生成报告：

| 格式 | 文件 | 用途 |
|------|------|------|
| 📄 HTML | `*.html` | 浏览器打开，交互式可视化（含 Chart.js 图表、风险评分、证据链） |
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
| XXE (XML 外部实体) | CWE-611 | 高危 |
| 不安全文件上传 | CWE-434 | 高危 |
| JWT 安全漏洞 | CWE-347 | 高危 |
| CRLF 注入 / HTTP 响应拆分 | CWE-93 | 高危 |
| LDAP 注入 | CWE-90 | 高危 |
| NoSQL 注入 | CWE-943 | 高危 |
| 原型链污染 | CWE-1321 | 高危 |
| 弱加密算法 | CWE-327 | 高危 |
| 证书验证缺陷 | CWE-295 | 高危 |
| 条件竞争 / TOCTOU | CWE-367 | 高危 |
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

| 功能 | 详细说明 | 文件位置 |
|------|----------|----------|
| **30 类漏洞检测** | 覆盖 OWASP Top 10 + 扩展，全部关联 CWE 编号 | [settings.py:62-460](config/settings.py#L62) |
| **8 种编程语言** | Python / JS / TS / Java / PHP / Go / Ruby / C# / C++ / Rust | [settings.py:35-45](config/settings.py#L35) |
| **SAST 规则匹配** | 正则引擎第一层快速扫描，8 种漏洞模式匹配 | [scanner_agent.py:52-101](src/agents/scanner_agent.py#L52) |
| **AST 语义分析** | Tree-sitter 解析代码语法树，结构级精确检测 | [ast_analyzer.py](src/analyzers/ast_analyzer.py) |
| **LLM 深度分析** | 接入 DeepSeek API 进行语义级漏洞验证 | [llm_api.py](src/analyzers/llm_api.py) |
| **RAG-CVE 情报** | 实时从 NVD 数据库检索已知 CVE，增强检测上下文 | [cve_rag.py](src/analyzers/cve_rag.py) |

### 二、架构能力

| 功能 | 详细说明 | 文件位置 |
|------|----------|----------|
| **多 Agent 协同** | Scanner Agent → Verifier Agent → Reporter Agent 三阶段流水线 | [main.py:100-212](main.py#L100) |
| **MCP Server** | 11 个工具通过 JSON-RPC 暴露，供 LLM Agent 调用 | [mcp_server.py](src/agents/mcp_server.py) |
| **Claude Code Skill** | SKILL.md 定义安全审计能力，Claude Code 中直接调用 | [skills/SKILL.md](skills/SKILL.md) |
| **异步并行扫描** | 8 Worker 线程池，大项目加速 5-7 倍 | [orchestrator.py](src/agents/orchestrator.py) |
| **端到端自动化** | 加载 → SAST → AST → RAG → 验证 → PoC → 图谱 → 报告，8 阶段全自动 | [main.py](main.py) |

### 三、漏洞验证与证据

| 功能 | 详细说明 | 文件位置 |
|------|----------|----------|
| **三级验证** | 代码上下文分析 → SAST 交叉验证 → LLM 语义裁定 | [verifier_agent.py:37-58](src/agents/verifier_agent.py#L37) |
| **证据链追踪** | 文件位置 + 调用路径 + 输入源→危险函数 完整链路 | [poc_generator.py:245-397](src/exploit/poc_generator.py#L245) |
| **PoC 自动生成** | 为确认漏洞生成可执行的 Python 验证代码 | [poc_generator.py](src/exploit/poc_generator.py) |
| **数据流分析** | MCP 工具追踪 source→sink 完整路径 | [mcp_server.py:172-220](src/agents/mcp_server.py#L172) |

### 四、报告系统

| 功能 | 详细说明 |
|------|----------|
| **3 格式报告** | Markdown（交作业）+ HTML（可视化）+ JSON（结构化数据） |
| **HTML 增强报告** | Chart.js 双图表 + 风险评分 0-100 + 可搜索排序表格 + 证据链 + PoC |
| **修复建议** | 每类漏洞附带可操作的修复方案 |
| **文件级别分析** | 按文件统计漏洞分布数量 |

### 五、可视化与交互

| 功能 | 详细说明 | 文件位置 |
|------|----------|----------|
| **Flask Web 仪表盘** | 浏览器可视化，Chart.js 统计图 | [web/app.py](web/app.py) |
| **Neo4j 知识图谱** | 项目→文件→漏洞→CVE 多维关联 | [graph_builder.py](src/analyzers/graph_builder.py) |

### 六、开发运维

| 功能 | 详细说明 | 文件位置 |
|------|----------|----------|
| **GitHub Actions** | push 自动审计 + PR 摘要 + 高危报警 | [.github/workflows/security-audit.yml](.github/workflows/security-audit.yml) |
| **自动降级** | API 不可用时自动回退到规则匹配 | [llm_api.py:43-55](src/analyzers/llm_api.py#L43) |
| **国产 LLM** | 默认 DeepSeek，可切换通义千问、智谱 GLM | [settings.py:17-30](config/settings.py#L17) |

---

## ⭐ 主流技术使用标注

### 【主流技术 1】LLM 大模型驱动 — [llm_api.py](src/analyzers/llm_api.py)

| 位置 | 技术说明 |
|------|----------|
| [settings.py:17-30](config/settings.py#L17) | 配置 DeepSeek / Qwen / GLM 等国产大模型 |
| [llm_api.py:80-110](src/analyzers/llm_api.py#L80) | `analyze_security()` — LLM 代码安全分析 |
| [llm_api.py:113-131](src/analyzers/llm_api.py#L113) | `verify_finding()` — LLM 漏洞验证 |
| [llm_api.py:140-190](src/analyzers/llm_api.py#L140) | OpenAI 兼容接口，支持多厂商切换 |
| [scanner_agent.py:176-226](src/agents/scanner_agent.py#L176) | 扫描器集成 LLM 深度分析 |

### 【主流技术 2】多 Agent 协同 — [main.py](main.py)

| 位置 | 技术说明 |
|------|----------|
| [main.py:100-212](main.py#L100) | 6 阶段流水线：加载→SAST→AST→RAG→验证→报告 |
| [scanner_agent.py:15-18](src/agents/scanner_agent.py#L15) | Scanner Agent — 扫描器 Agent |
| [verifier_agent.py:13-18](src/agents/verifier_agent.py#L13) | Verifier Agent — 验证器 Agent |
| [report_generator.py:13-16](src/report/report_generator.py#L13) | Reporter — 报告生成 |

### 【主流技术 3】MCP 协议 — [mcp_server.py](src/agents/mcp_server.py)

| 位置 | 技术说明 |
|------|----------|
| [mcp_server.py:34-48](src/agents/mcp_server.py#L34) | 注册 11 个 MCP 工具 |
| [mcp_server.py:51-62](src/agents/mcp_server.py#L51) | `call_tool()` — JSON-RPC 工具调用 |
| [mcp_server.py:98-113](src/agents/mcp_server.py#L98) | `_tool_bandit_scan` — SAST 工具集成 |
| [mcp_server.py:172-220](src/agents/mcp_server.py#L172) | `_tool_dataflow_analysis` — 数据流追踪 |

### 【主流技术 4】Skills 机制 — [skills/SKILL.md](skills/SKILL.md)

| 位置 | 技术说明 |
|------|----------|
| [skills/SKILL.md:1-5](skills/SKILL.md#L1) | Skill 元数据声明 |
| [skills/SKILL.md:63-69](skills/SKILL.md#L63) | 描述多 Agent 工作流程 |

### 【主流技术 5】SAST 静态分析 — [settings.py](config/settings.py)

| 位置 | 技术说明 |
|------|----------|
| [settings.py:62-460](config/settings.py#L62) | 30 类漏洞规则库（CWE 标准） |
| [scanner_agent.py:52-101](src/agents/scanner_agent.py#L52) | 正则匹配引擎 |

### 【主流技术 6】AST 语义分析 — [ast_analyzer.py](src/analyzers/ast_analyzer.py)

| 位置 | 技术说明 |
|------|----------|
| [ast_analyzer.py:48-55](src/analyzers/ast_analyzer.py#L48) | `detect_sql_injection_ast()` — AST 级 SQL 注入检测 |
| [main.py:189-215](main.py#L189) | 集成到主流水线 |

### 【主流技术 7】RAG-CVE 情报 — [cve_rag.py](src/analyzers/cve_rag.py)

| 位置 | 技术说明 |
|------|----------|
| [cve_rag.py:46-68](src/analyzers/cve_rag.py#L46) | `search_by_keyword()` — 关键词搜索 CVE |
| [cve_rag.py:98-110](src/analyzers/cve_rag.py#L98) | `analyze_dependencies()` — 依赖 CVE 分析 |
| [cve_rag.py:218-254](src/analyzers/cve_rag.py#L218) | `enrich_findings()` — 注入 CVE 情报到扫描结果 |

### 【主流技术 8】CWE / OWASP 标准

| 位置 | 说明 |
|------|------|
| [settings.py:62-460](config/settings.py#L62) | 全部 30 类漏洞关联 CWE 编号（CWE-89/78/22/798/79/502/918 等） |

### 【主流技术 9】GitHub/GitLab 集成 — [repo_manager.py](src/utils/repo_manager.py)

| 位置 | 技术说明 |
|------|----------|
| [repo_manager.py:58-86](src/utils/repo_manager.py#L58) | git clone 远程仓库 |
| [repo_manager.py:88-96](src/utils/repo_manager.py#L88) | URL 类型自动识别 |

---

## 🆕 增强功能模块

### 1️⃣ MCP Server — [mcp_server.py](src/agents/mcp_server.py)

LLM Agent 可以调用的 11 个工具：

| 工具 | 功能 |
|------|------|
| `scan_python_security` | 调用 Bandit 扫描 Python 安全漏洞 |
| `scan_secrets` | 扫描硬编码密钥 |
| `scan_pattern` | 自定义正则规则扫描 |
| `scan_dependencies` | 检查依赖 CVE |
| `analyze_dataflow` | 追踪 source→sink 数据流 |
| `read_file` / `search_code` / `get_file_tree` | 文件操作 |
| `generate_evidence` / `verify_exploit` | 证据链与可利用性验证 |

### 2️⃣ 证据链 — [poc_generator.py](src/exploit/poc_generator.py)

每个漏洞包含 4 层证据：
- **① 文件位置**: 文件路径 + 行号 + 绝对路径
- **② 调用路径**: 输入源 → 中间步骤 → 危险函数
- **③ 验证结果**: 真实性 + 严重程度 + 可利用性
- **④ 证据完整性**: 自动检查 5 项证据是否齐全

### 3️⃣ 异步并行 — [orchestrator.py](src/agents/orchestrator.py)

| 文件数 | 串行 | 8 Worker 并行 | 加速比 |
|--------|------|---------------|--------|
| 100 | 100s | 15s | ~7x |

### 4️⃣ Neo4j 知识图谱 — [graph_builder.py](src/analyzers/graph_builder.py)

构建节点: `Project → File → Vulnerability → CVE`，支持 Cypher 查询

### 5️⃣ HTML 增强报告 — [report_generator.py:324-730](src/report/report_generator.py#L324)

| 特性 | 说明 |
|------|------|
| Chart.js 环形图 | 漏洞严重程度可视化 |
| Chart.js 柱状图 | 漏洞类型分布 |
| 风险评分 | 0-100 分 + 进度条 |
| 可搜索排序表格 | 按等级/文件/关键词筛选 |
| 折叠详情 | 点击展开证据链 + PoC + 代码上下文 |

---

## 🗂️ 项目结构

```
llm-security-audit/
├── main.py                     # ★ 主入口 — 端到端流水线编排
├── config/
│   └── settings.py             # ★ 核心配置 — LLM + 30类漏洞规则 + CWE标准
├── src/
│   ├── agents/
│   │   ├── scanner_agent.py    # ★ 扫描器 Agent
│   │   ├── verifier_agent.py   # ★ 验证器 Agent
│   │   ├── orchestrator.py     # 🆕 并行编排器
│   │   └── mcp_server.py       # 🆕 MCP 工具服务器
│   ├── analyzers/
│   │   ├── ast_analyzer.py     # 🆕 Tree-sitter AST 分析
│   │   ├── cve_rag.py          # 🆕 RAG-CVE 情报
│   │   ├── graph_builder.py    # 🆕 Neo4j 知识图谱
│   │   └── llm_api.py          # 🆕 LLM API 客户端
│   ├── exploit/
│   │   └── poc_generator.py    # ★ PoC 生成 + 证据链
│   ├── report/
│   │   └── report_generator.py # ★ 报告生成 (MD/JSON/HTML)
│   └── utils/
│       └── repo_manager.py     # ★ 仓库管理 (GitHub/GitLab)
├── skills/
│   └── SKILL.md                # ★ Claude Code Skill 定义
├── web/
│   ├── app.py                  # 🆕 Flask Web 应用
│   └── templates/index.html    # 🆕 Web 仪表盘
├── .github/workflows/
│   └── security-audit.yml      # 🆕 CI/CD 流水线
├── tests/
│   └── vulnerable_app.py       # 测试靶标
├── docs/
│   ├── 实验报告模板.md          # 实验报告模板
│   └── PPT大纲.md               # 汇报 PPT 大纲
├── CLAUDE.md                   # 完整使用说明（备份）
└── README.md                   # ★ 本文件
```

---

## ⚡ 实验要求逐项对照

| # | 实验要求 | 实现状态 | 核心代码位置 |
|---|----------|----------|-------------|
| 1 | 支持 GitHub/GitLab URL | ✅ | [repo_manager.py:42-47](src/utils/repo_manager.py#L42) |
| 2 | 自动识别编程语言 | ✅ | [repo_manager.py:108-136](src/utils/repo_manager.py#L108) |
| 3 | 获取项目文件结构 | ✅ | [repo_manager.py:138-179](src/utils/repo_manager.py#L138) |
| 4 | 多 Agent 协同 | ✅ | [main.py:100-212](main.py#L100) |
| 5 | LLM 驱动代码分析 | ✅ | [llm_api.py](src/analyzers/llm_api.py) |
| 6 | SAST 静态分析 | ✅ 30 类漏洞 | [settings.py:62-460](config/settings.py#L62) |
| 7 | MCP + Skills | ✅ | [mcp_server.py](src/agents/mcp_server.py) + [SKILL.md](skills/SKILL.md) |
| 8 | 漏洞自动验证 | ✅ | [verifier_agent.py:25-62](src/agents/verifier_agent.py#L25) |
| 9 | 漏洞自动利用（PoC） | ✅ + 证据链 | [poc_generator.py](src/exploit/poc_generator.py) |
| 10 | 结构化报告 | ✅ 3 格式 | [report_generator.py](src/report/report_generator.py) |
| 11 | 关联 CWE 编号 | ✅ 全部关联 | [settings.py](config/settings.py) |
| | **新增**: AST 语义分析 | ✅ | [ast_analyzer.py](src/analyzers/ast_analyzer.py) |
| | **新增**: RAG-CVE 情报 | ✅ | [cve_rag.py](src/analyzers/cve_rag.py) |
| | **新增**: 并行编排 | ✅ | [orchestrator.py](src/agents/orchestrator.py) |
| | **新增**: Web 界面 | ✅ | [web/app.py](web/app.py) |
| | **新增**: CI/CD | ✅ | [.github/workflows/security-audit.yml](.github/workflows/security-audit.yml) |
| | **新增**: Neo4j 图谱 | ✅ | [graph_builder.py](src/analyzers/graph_builder.py) |
| | **新增**: MCP Server | ✅ | [mcp_server.py](src/agents/mcp_server.py) |

---

## 📊 技术栈总览

| 技术类别 | 具体技术 | 用途 |
|----------|----------|------|
| **LLM** | DeepSeek / Qwen / GLM | 代码语义分析、漏洞验证 |
| **Agent** | Scanner / Verifier / Reporter | 多角色协同分析 |
| **MCP** | JSON-RPC 协议 | 工具链集成 |
| **Skills** | SKILL.md | 能力封装与复用 |
| **SAST** | 正则规则 + 语义分析 | 代码静态安全测试 |
| **AST** | Tree-sitter | 语法树级代码分析 |
| **RAG** | NVD API + LRU Cache | 实时 CVE 情报 |
| **CWE** | CWE-89/78/22/798/79/502/918... | 行业标准漏洞分类 |
| **图数据库** | Neo4j + Cypher | 漏洞知识图谱 |
| **Web** | Flask + Chart.js | 交互式仪表盘 |
| **CI/CD** | GitHub Actions | 自动化审计流水线 |
| **并行** | ThreadPoolExecutor | 多 Agent 并行扫描 |

---

<p align="center">
  <strong>实验一 · 网络空间安全综合实验</strong><br>
  <a href="https://github.com/xiangxiangbigqueen/llm-security-audit">GitHub 仓库</a>
</p>
