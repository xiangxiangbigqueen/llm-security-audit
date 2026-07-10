# CodeSentinel

基于 LLM 多智能体协作的开源项目安全审计系统。通过静态分析工具 + DeepSeek 大模型深度推理，自动发现代码中的安全漏洞并生成 PoC 验证。

## 系统架构

```
┌─────────────────────────────────────────────────┐
│                   GUI (PyQt5)                    │
├─────────────────────────────────────────────────┤
│              Orchestrator 编排引擎               │
│         (流水线调度 + 反馈环控制)                 │
├──────────┬──────────┬───────────┬───────────────┤
│ Scanner  │Validator │ Exploiter │   Reporter    │
│ 扫描智能体│验证智能体 │利用智能体  │  报告智能体   │
├──────────┴──────────┴───────────┴───────────────┤
│            MCP Tool Server (本地)                │
│   cppcheck │ flawfinder │ bandit │ phpstan      │
└─────────────────────────────────────────────────┘
```

## 功能特性

- **多语言支持**: C/C++、PHP、Python
- **多智能体协作**: Scanner → Validator → Exploiter → Reporter 四阶段流水线
- **反馈环机制**: Validator 可打回 Scanner 补充分析，最多迭代 3 轮
- **并发加速**: 文件扫描和漏洞验证均支持并发执行（默认 4 并发）
- **静态工具集成**: 通过本地 MCP Server 统一管理 cppcheck/flawfinder/bandit/phpstan
- **LLM 深度分析**: DeepSeek 模型进行数据流追踪、上下文推理
- **GUI 界面**: PyQt5 暗色主题桌面应用
- **报告生成**: Markdown/HTML 格式安全审计报告

## 快速开始

### 环境要求

- Python 3.9+
- macOS / Linux
- DeepSeek API Key

### 安装

```bash
cd CodeSentinel

# 方式1: 使用安装脚本 (推荐)
chmod +x setup.sh
./setup.sh

# 方式2: 手动安装
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 配置

编辑 `.env` 文件：

```env
# DeepSeek API (必填)
DEEPSEEK_API_KEY=sk-your-api-key-here
DEEPSEEK_BASE_URL=https://api.deepseek.com

# 静态工具路径 (通常自动检测)
CPPCHECK_PATH=cppcheck
FLAWFINDER_PATH=flawfinder
BANDIT_PATH=bandit
PHPSTAN_PATH=phpstan

# 性能配置
MAX_CONCURRENT_SCANS=4
FEEDBACK_MAX_ITERATIONS=3
```

### 运行

```bash
source .venv/bin/activate
python main.py
```

## 审计流程

1. **输入**: 输入 GitHub 仓库 URL 或本地代码路径
2. **解析**: 自动克隆仓库、识别语言、提取文件结构
3. **扫描**: 静态工具 + LLM 并发分析所有源文件
4. **验证**: 独立 Validator 智能体复核，过滤误报
5. **反馈环**: 对不确定的漏洞，打回 Scanner 补充上下文再分析
6. **PoC 生成**: 为确认的漏洞生成概念验证代码
7. **报告**: 输出结构化审计报告

## 项目结构

```
CodeSentinel/
├── main.py                 # 应用入口
├── config/
│   ├── settings.py         # 全局配置
│   └── prompts/            # 各智能体 Prompt 模板
├── core/
│   ├── orchestrator.py     # 编排引擎
│   ├── llm/
│   │   └── deepseek_client.py  # DeepSeek API 客户端
│   ├── agents/
│   │   ├── scanner_agent.py    # 扫描智能体
│   │   ├── validator_agent.py  # 验证智能体
│   │   ├── exploiter_agent.py  # 利用智能体
│   │   └── reporter_agent.py   # 报告智能体
│   └── models/
│       ├── project.py          # 项目元信息模型
│       └── vulnerability.py    # 漏洞数据模型
├── parser/
│   ├── repo_parser.py      # 仓库解析器
│   └── language_detector.py # 语言识别
├── mcp_server/
│   ├── server.py           # MCP 工具管理器
│   └── tools/              # 各静态分析具封装
│       ├── bandit_tool.py      # Python (Bandit)
│       ├── cppcheck_tool.py    # C/C++ (Cppcheck)
│       ├── flawfinder_tool.py  # C/C++ (Flawfinder)
│       ├── phpstan_tool.py     # PHP (PHPStan)
│       └── progpilot_tool.py   # PHP (Progpilot)
├── gui/
│   └── main_window.py     # PyQt5 主窗口
├── report/                 # 报告模板
├── output/
│   ├── repos/              # 克隆的仓库缓存
│   └── reports/            # 生成的审计报告
├── .env                    # 环境变量配置
├── requirements.txt        # Python 依赖
└── setup.sh                # 环境安装脚本
```

## 支持的漏洞类型

| 类型 | 适用语言 |
|------|---------|
| SQL Injection | Python, PHP |
| Command Injection | Python, C/C++, PHP |
| Path Traversal | Python, PHP, C |
| Buffer Overflow | C/C++ |
| Format String | C/C++ |
| XSS | PHP, Python |
| SSRF | Python, PHP |
| SSTI | Python |
| Insecure Deserialization | Python, PHP |
| Code Injection (eval/exec) | Python, PHP |
| Hardcoded Secrets | All |
| Integer Overflow | C/C++ |

## 静态分析工具安装

```bash
# C/C++ 工具
brew install cppcheck          # macOS
# flawfinder 通过 pip 自动安装

# Python 工具
pip install bandit

# PHP 工具 (可选)
brew install phpstan
# progpilot 需要 PHP 环境
```

## 注意事项

- DeepSeek API 需要有效余额，否则返回 402 错误
- 大型仓库扫描耗时较长，可通过调大 `MAX_CONCURRENT_SCANS` 加速
- 审计结果仅供参考，建议人工复核高危漏洞
- PoC 代码仅供安全研究，请勿用于非法用途