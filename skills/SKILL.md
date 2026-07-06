---
name: security-audit
description: 对开源项目进行自动化安全审计，支持 SAST 扫描、LLM 深度分析和 PoC 生成
model: claude-sonnet-4-6
---

# 🛡️ Security Audit Skill

对目标开源项目进行**全方位自动化安全审计**。

## 使用方法

### 在 Claude Code 中调用本 Skill

```bash
# 方式 1: 直接在当前项目运行
claude "使用 security-audit skill 扫描当前项目"

# 方式 2: 扫描远程仓库
claude "使用 security-audit skill 扫描 https://github.com/example/project.git"

# 方式 3: 快速扫描
claude "使用 security-audit skill 快速扫描 /path/to/project"
```

### 命令行直接调用

```bash
python main.py --target https://github.com/example/project.git
python main.py --target /path/to/local/project --quick
python main.py --target /path/to/local/project --output ./my-reports
```

## 功能特性

| 模块 | 功能 | 技术 |
|------|------|------|
| 仓库接入 | 支持 GitHub/GitLab URL 或本地目录 | Git CLI |
| 静态扫描 | 8 类漏洞模式匹配 | 正则 + 语义分析 |
| LLM 深度分析 | 代码语义级漏洞验证 | Claude Code Agent |
| 漏洞验证 | 多维度验证 | 上下文分析 + LLM |
| PoC 生成 | 自动生成利用验证代码 | 模板 + LLM 优化 |
| 报告生成 | 多格式结构化报告 | MD / JSON / HTML |

## 扫描的漏洞类型

- **SQL 注入** (CWE-89)
- **命令注入** (CWE-78)
- **路径遍历** (CWE-22)
- **硬编码密钥** (CWE-798)
- **跨站脚本 XSS** (CWE-79)
- **不安全反序列化** (CWE-502)
- **SSRF** (CWE-918)

## 工作流程

```
目标项目 → 仓库克隆 → 多 Agent 并行扫描 → 规则匹配 → LLM 验证 → PoC 生成 → 报告输出
                                                          ↓
                                                    SAST 工具交叉验证
```

## 自动 Agent 流程

本 Skill 支持 Claude Code 的多 Agent 编排能力：

1. **Scanner Agent**: 负责对代码文件进行静态规则扫描
2. **Verifier Agent**: 对 Scanner 的发现进行深入验证
3. **Reporter Agent**: 汇总结果生成结构化报告
