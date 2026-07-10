# 🔒 LLM Security Audit System

> 大模型驱动的开源项目安全审计系统  
> 技术栈: LLM / Agent / MCP / SAST / AST / RAG / Neo4j / Web / GUI

---

## 🚀 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 快速扫描 (30组正则, 秒级, 零外部依赖)
python main.py --target /path/to/project

# 完整分析 (SAST工具 + LLM多Agent, 分钟级, 需要API Key)
export DEEPSEEK_API_KEY=sk-xxxxx
python main.py --target /path/to/project --full

# 启动桌面GUI
python main.py --gui

# 启动Web界面
python main.py --web
```

---

## ⚡ 两种模式对比

| | ⚡ 快速模式 (Quick) | 🔬 完整模式 (Full) |
|---|---|---|
| **检测引擎** | 30组正则表达式 | cppcheck + bandit + flawfinder + LLM |
| **速度** | 秒级 | 分钟级 |
| **语言支持** | Python / JS / TS / Java / PHP / Go / Ruby / C# / C++ / Rust | C / C++ / PHP / Python |
| **LLM** | 无需 (可选) | 需要 DeepSeek API Key |
| **外部工具** | 无 | cppcheck, bandit, flawfinder, phpstan |
| **Agent** | Scanner → Reporter | Scanner → Validator ⇄ 反馈环 → Exploiter → Reporter |
| **报告** | MD + JSON + HTML (Chart.js) | MD + HTML |
| **适用场景** | 快速排查、CI/CD | 深度审计、漏洞确认 |

---

## 📋 使用示例

```bash
# === 快速模式 ===
python main.py --target ./my-project                    # 扫描本地项目
python main.py --target https://github.com/user/repo    # 扫描GitHub仓库
python main.py --target ./my-project --parallel 8       # 8线程并行
python main.py --target ./my-project --llm              # 快速 + LLM验证

# === 完整模式 ===
python main.py --target ./my-project --full             # 完整SAST+LLM分析

# === GUI ===
python main.py --gui                                    # PyQt5桌面应用

# === Web ===
python main.py --web                                    # Flask Web仪表盘
```

---

## 🛡️ 漏洞检测覆盖

### 快速模式: 30 类漏洞

| 类型 | CWE | 类型 | CWE |
|------|-----|------|-----|
| SQL注入 | CWE-89 | 二阶SQL注入 | CWE-89 |
| 命令注入 | CWE-78 | 路径遍历 | CWE-22 |
| XSS | CWE-79 | SSRF | CWE-918 |
| XXE | CWE-611 | CSRF | CWE-352 |
| SSTI | CWE-1336 | NoSQL注入 | CWE-943 |
| LDAP注入 | CWE-90 | CRLF注入 | CWE-93 |
| 反序列化 | CWE-502 | JWT漏洞 | CWE-347 |
| 文件上传 | CWE-434 | 开放重定向 | CWE-601 |
| 硬编码密钥 | CWE-798 | 弱加密 | CWE-327 |
| 证书验证 | CWE-295 | 日志伪造 | CWE-117 |
| IDOR | CWE-639 | 批量赋值 | CWE-915 |
| 原型链污染 | CWE-1321 | 条件竞争 | CWE-367 |
| 整数溢出 | CWE-190 | 内存泄漏 | CWE-401 |
| 明文存储 | CWE-312 | ReDoS | CWE-1333 |

### 完整模式: 外部工具覆盖

| 语言 | 工具 | 检测重点 |
|------|------|---------|
| C/C++ | cppcheck + flawfinder | Buffer overflow, format string, memory |
| Python | bandit | SQLi, XSS, hardcoded secrets |
| PHP | phpstan + progpilot | XSS, SQLi, file inclusion |

---

## 🗂️ 项目结构

```
llm-security-audit/
├── main.py                    # ★ 统一CLI入口
├── config/
│   ├── quick_settings.py      # 快速模式配置 (30类漏洞规则)
│   ├── full_settings.py       # 完整模式配置 (LLM/工具/并发)
│   └── prompts/               # LLM Agent Prompt模板
├── quick/                     # 快速模式模块
│   └── src/
│       ├── agents/            # Scanner, Verifier, Orchestrator
│       ├── analyzers/         # AST, CVE-RAG, Neo4j图谱
│       ├── exploit/           # PoC生成 + 证据链
│       └── report/            # MD/JSON/HTML 报告
├── full/                      # 完整模式模块
│   ├── core/
│   │   ├── orchestrator.py   # 异步Agent流水线
│   │   ├── agents/           # 4个Agent (Scanner/Validator/Exploiter/Reporter)
│   │   ├── llm/              # DeepSeek异步客户端
│   │   └── models/           # 数据模型 (Vulnerability/Project/Evidence)
│   ├── mcp_server/           # MCP工具服务器 (5个SAST工具)
│   ├── parser/               # 仓库解析 + 语言检测
│   └── report/               # 报告生成 (MD/HTML)
├── gui/                       # 统一GUI (欢迎页 + 快速页 + 完整页)
├── web/                       # Flask Web 仪表盘
├── tests/                     # 测试靶标
├── skills/                    # Claude Code Skill
└── docs/                      # 实验文档
```

---

## 🔧 环境配置

### 完整模式需要的外部工具:

```bash
# macOS
brew install cppcheck
pip install bandit flawfinder

# Linux
sudo apt install cppcheck
pip install bandit flawfinder
```

### DeepSeek API Key:

```bash
# 设置环境变量
export DEEPSEEK_API_KEY=sk-your-key-here
# 或在项目根目录创建 .env 文件
echo "DEEPSEEK_API_KEY=sk-your-key-here" > .env
```

---

<p align="center">
  <strong>网络空间安全综合实验</strong><br>
  快速模式 · 30类正则 · 秒级扫描 | 完整模式 · SAST+LLM · 深度分析
</p>
