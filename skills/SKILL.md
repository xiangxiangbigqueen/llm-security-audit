---
name: security-audit
description: 对开源项目进行自动化安全审计，支持 SAST 扫描、LLM 深度分析和 PoC 生成
model: deepseek-chat
---

# 🛡️ Security Audit Skill

对目标开源项目进行**全方位自动化安全审计**。

## 使用方法

### 在 Claude Code 中调用本 Skill

```bash
claude "使用 security-audit skill 扫描当前项目"
claude "使用 security-audit skill 扫描 https://github.com/example/project.git"
claude "使用 security-audit skill 快速扫描 /path/to/project"
```

### 命令行直接调用

```bash
python main.py --target /path/to/project
python main.py --target /path/to/project --quick
python main.py --target /path/to/project --web
```

## MCP 工具（Tool Calling）

本 Skill 通过 MCP (Model Context Protocol) 暴露以下工具供 Agent 调用：

### 🔬 SAST 工具链
| 工具名 | 功能 | 说明 |
|--------|------|------|
| `scan_python_security` | Bandit Python 扫描 | 调用 Bandit 检测 Python 安全问题 |
| `scan_secrets` | 密钥扫描 | 检测硬编码密钥和凭证 |
| `scan_pattern` | 正则扫描 | 自定义规则模式匹配 |
| `scan_dependencies` | 依赖检查 | 检查依赖包的已知 CVE |
| `analyze_dataflow` | 数据流分析 | 追踪 source→sink 调用路径 |

### 📁 文件操作工具
| 工具名 | 功能 | 说明 |
|--------|------|------|
| `read_file` | 读取文件 | 读取任意文件内容 |
| `search_code` | 代码搜索 | 搜索代码中的特定模式 |
| `get_file_tree` | 文件树 | 获取项目文件结构 |

### 🔗 证据链工具
| 工具名 | 功能 | 说明 |
|--------|------|------|
| `generate_evidence` | 生成证据链 | 构建漏洞的完整证据链 |
| `verify_exploit` | 可利用性验证 | 验证漏洞是否可被利用 |

## 功能特性

| 模块 | 功能 | 技术 |
|------|------|------|
| MCP Server | 11 个工具供 Agent 调用 | MCP + JSON-RPC |
| 仓库接入 | 支持 GitHub/GitLab URL 或本地目录 | Git CLI |
| 静态扫描 | 8 类漏洞模式匹配 | 正则 + 语义分析 |
| AST 语义分析 | Tree-sitter 语法树级检测 | Tree-sitter |
| RAG-CVE 情报 | 实时 CVE 检索 | NVD API |
| LLM 深度分析 | 语义级漏洞验证 | DeepSeek API |
| 证据链 | 文件位置+调用路径+验证结果 | 数据流追踪 |
| PoC 生成 | 自动生成利用验证代码 | 模板 + LLM |
| Neo4j 图谱 | 知识图谱构建 | Neo4j + Cypher |
| Web 界面 | 可视化仪表盘 | Flask + Chart.js |
| CI/CD | 自动化审计流水线 | GitHub Actions |

## 工作流程

```
┌──────────────────────────────────────────────────────────┐
│  LLM Agent 通过 MCP 协议调用工具                           │
│                                                          │
│  Agent ──call──▶ MCP Server ──▶ SAST Tools (Bandit etc.) │
│                    │                                      │
│                    ├──▶ scan_pattern (正则匹配)             │
│                    ├──▶ analyze_dataflow (数据流追踪)       │
│                    ├──▶ generate_evidence (证据链)         │
│                    └──▶ verify_exploit (可利用性验证)      │
└──────────────────────────────────────────────────────────┘
```

## 本 Skill 涉及的主流技术

| # | 主流技术 | 说明 |
|---|----------|------|
| 1 | LLM 驱动 | DeepSeek API 分析代码安全 |
| 2 | 多 Agent 协同 | Scanner/Verifier/Reporter 三 Agent |
| 3 | MCP 协议 | 11 个工具注册，LLM Agent 可调用 |
| 4 | Skills 机制 | 本 SKILL.md 定义能力边界 |
| 5 | SAST 分析 | 8 类漏洞规则 + 外部工具集成 |
| 6 | CWE 标准 | 漏洞关联 CWE 编号 |
| 7 | 数据流追踪 | source→sink 调用路径分析 |
| 8 | 证据链 | 位置+路径+验证结果完整输出 |
