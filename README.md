# 🔒 LLM Security Audit System

<p align="center">
  <strong>大模型驱动的开源项目安全审计系统</strong><br>
  《网络空间安全综合实验》实验一<br>
  <em>LLM + Agent + SAST + AST + RAG + Neo4j + Web</em>
</p>

<p align="center">
  <a href="#-快速开始">快速开始</a> •
  <a href="#-使用方式">使用方式</a> •
  <a href="#-功能特性">功能特性</a> •
  <a href="#-主流技术">主流技术</a> •
  <a href="CLAUDE.md">完整文档</a>
</p>

---

## 🚀 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 扫描项目（以测试靶标为例）
python main.py --target tests --quick

# 3. 查看报告
# 打开 reports/ 目录下的 .html 文件
```

---

## 📋 使用方式

### 方式一：一键菜单（Windows）

```bash
# 双击 demo.bat，选 1 快速扫描
demo.bat
```

### 方式二：命令行扫描

```bash
# 快速扫描（仅规则匹配）
python main.py --target /path/to/project --quick

# 标准扫描（含验证 + PoC 生成）
python main.py --target /path/to/project

# 增强扫描（含 AST + RAG + 并行 + Neo4j 图谱）
python main.py --target /path/to/project --neo4j

# 扫描 GitHub 仓库
python main.py --target https://github.com/username/repo.git
```

### 方式三：Web 界面

```bash
python main.py --web
# 浏览器打开 http://127.0.0.1:5000
```

### 方式四：Claude Code Skill

```bash
claude "使用 security-audit skill 扫描当前项目"
```

### 实战步骤

```bash
cd D:\Personal\Desktop\llm-security-audit
pip install -r requirements.txt
python main.py --target tests --quick   # 验证系统
python main.py --target /path/to/你的项目   # 扫真实项目
```

### 输出

扫描完成后在 `reports/` 生成三种格式报告：

| 格式 | 文件 | 用途 |
|------|------|------|
| Markdown | `*.md` | 直接查看，提交作业 |
| HTML | `*.html` | 浏览器打开，交互展示 |
| JSON | `*.json` | 结构化数据 |

---

## ✨ 功能特性

### 基础能力（实验要求）
| 功能 | 说明 |
|------|------|
| ✅ GitHub/GitLab 接入 | URL 或本地目录自动识别 |
| ✅ 多语言 SAST | Python/JS/Java/PHP/Go/Ruby/C#/C++/Rust |
| ✅ **30 类漏洞检测** | 覆盖 OWASP Top 10 + 扩展 |
| ✅ 多 Agent 协同 | Scanner → Verifier → Reporter 流水线 |
| ✅ PoC 自动生成 | 为确认漏洞生成可执行验证代码 |
| ✅ **增强 HTML 报告** | 图表可视化 + 证据链 + PoC + 修复建议 |
| ✅ CWE 标准 | 全部漏洞关联 CWE 编号 |

### 30 类漏洞检测清单

| 类别 | 严重程度 | CWE |
|------|----------|-----|
| SQL 注入 | 高危 | CWE-89 |
| 二阶 SQL 注入 | 高危 | CWE-89 |
| 命令注入 | 高危 | CWE-78 |
| 路径遍历 | 中危 | CWE-22 |
| 硬编码密钥/凭证 | 高危 | CWE-798 |
| 跨站脚本 (XSS) | 中危 | CWE-79 |
| 不安全反序列化 | 高危 | CWE-502 |
| SSRF | 中危 | CWE-918 |
| XXE (XML外部实体) | 高危 | CWE-611 |
| CSRF | 中危 | CWE-352 |
| 开放重定向 | 中危 | CWE-601 |
| LDAP 注入 | 高危 | CWE-90 |
| NoSQL 注入 | 高危 | CWE-943 |
| SSTI (模板注入) | 高危 | CWE-1336 |
| 不安全文件上传 | 高危 | CWE-434 |
| JWT 安全漏洞 | 高危 | CWE-347 |
| 日志伪造 | 中危 | CWE-117 |
| CRLF 注入 | 高危 | CWE-93 |
| IDOR | 中危 | CWE-639 |
| 原型链污染 | 高危 | CWE-1321 |
| 批量赋值 | 中危 | CWE-915 |
| 弱加密算法 | 高危 | CWE-327 |
| 证书验证缺陷 | 高危 | CWE-295 |
| ReDoS | 中危 | CWE-1333 |
| 条件竞争/TOCTOU | 高危 | CWE-367 |
| 明文存储敏感信息 | 高危 | CWE-312 |
| 整数溢出 | 中危 | CWE-190 |
| 内存泄漏 | 中危 | CWE-401 |

### 增强能力（新增）
| 功能 | 说明 |
|------|------|
| 🌲 **AST 语义分析** | Tree-sitter 语法树级代码检测 |
| 📡 **RAG-CVE 情报** | 从 NVD 实时检索已知漏洞 |
| ⚡ **并行扫描** | 8 Worker 线程池，加速 5-7 倍 |
| 🌐 **Web 仪表盘** | Flask + Chart.js 可视化 |
| 🤖 **CI/CD 集成** | GitHub Actions 自动审计 |
| 🕸️ **Neo4j 图谱** | 项目→文件→漏洞→CVE 知识图谱 |

---

## ⭐ 主流技术

| # | 主流技术 | 实现位置 |
|---|----------|----------|
| 1 | **LLM 大模型驱动** | [scanner_agent.py:108](src/agents/scanner_agent.py#L108) / [verifier_agent.py:151](src/agents/verifier_agent.py#L151) |
| 2 | **多 Agent 协同** | [main.py:100-212](main.py#L100) — 6 阶段流水线 |
| 3 | **Skills 机制** | [skills/SKILL.md](skills/SKILL.md) — 完整 Skill 定义 |
| 4 | **MCP 协议** | [verifier_agent.py:16-18](src/agents/verifier_agent.py#L16) |
| 5 | **SAST 静态分析** | [settings.py:48-147](config/settings.py#L48) — 8 类漏洞规则 |
| 6 | **CWE/OWASP** | [settings.py](config/settings.py) — CWE-89/78/22/798/79/502/918 |
| 7 | **GitHub/GitLab** | [repo_manager.py:42-86](src/utils/repo_manager.py#L42) |
| 8 | **📡 RAG 检索增强** | [cve_rag.py](src/analyzers/cve_rag.py) — NVD 实时查询 |
| 9 | **🌲 AST 语法树** | [ast_analyzer.py](src/analyzers/ast_analyzer.py) |
| 10 | **⚡ 并行编排** | [orchestrator.py](src/agents/orchestrator.py) |
| 11 | **🌐 Web 可视化** | [web/app.py](web/app.py) |
| 12 | **🤖 CI/CD** | [.github/workflows/security-audit.yml](.github/workflows/security-audit.yml) |
| 13 | **🕸️ 知识图谱** | [graph_builder.py](src/analyzers/graph_builder.py) |

---

## 🗂️ 项目结构

```
llm-security-audit/
├── main.py                     # 主入口 (CLI + Web 双模式)
├── config/settings.py          # 系统配置 + 漏洞规则库 + CWE
├── src/
│   ├── agents/                 # 3 大 Agent
│   │   ├── scanner_agent.py    #   扫描器 Agent
│   │   ├── verifier_agent.py   #   验证器 Agent
│   │   └── orchestrator.py     #   并行编排器 🆕
│   ├── analyzers/              # 分析引擎
│   │   ├── ast_analyzer.py     #   AST 语义分析 🆕
│   │   ├── cve_rag.py          #   RAG-CVE 情报 🆕
│   │   └── graph_builder.py    #   Neo4j 图谱 🆕
│   ├── exploit/poc_generator.py# PoC 自动生成
│   ├── report/report_generator.py# 报告生成
│   └── utils/repo_manager.py   # 仓库管理
├── skills/SKILL.md             # Claude Code Skill
├── web/                        # Flask Web 仪表盘 🆕
├── .github/workflows/          # CI/CD 流水线 🆕
├── tests/                      # 测试靶标
├── docs/                       # 实验报告 + PPT大纲
├── CLAUDE.md                   # 完整文档（含 10 项主流技术标注）
└── README.md                   # 本文件
```

---

## 🧪 测试验证

```bash
# 测试系统是否正常
python main.py --target tests --quick

# 测试靶标包含的漏洞：
# - SQL 注入 (CWE-89)       ✅ 已检出
# - 命令注入 (CWE-78)       ✅ 已检出
# - 路径遍历 (CWE-22)       ✅ 已检出
# - 硬编码密钥 (CWE-798)    ✅ 已检出
# - XSS (CWE-79)            ✅ 已检出
# - 不安全反序列化 (CWE-502) ✅ 已检出
# - SSRF (CWE-918)          ✅ 已检出
```

---

## 📚 更多

完整文档（含主流技术详细标注、增强功能介绍、实验要求对照表）请查看 **[CLAUDE.md](CLAUDE.md)**。

---

<p align="center">
  <a href="https://github.com/xiangxiangbigqueen/llm-security-audit">GitHub 仓库</a> •
  实验一 · 网络空间安全综合实验
</p>
