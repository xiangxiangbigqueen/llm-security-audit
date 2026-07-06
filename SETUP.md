# 🚀 项目部署指南

## 一、上传到 GitHub

### 方式 1：使用 GitHub CLI（推荐）

```bash
# 1. 安装 GitHub CLI
# Windows: winget install GitHub.cli
# macOS: brew install gh
# Linux: sudo apt install gh

# 2. 登录
gh auth login

# 3. 创建仓库并推送
gh repo create llm-security-audit --public --push --source=.
```

### 方式 2：手动创建

```bash
# 1. 在浏览器中打开 https://github.com/new
#    仓库名: llm-security-audit
#    选择 Public
#    不要勾选 "Initialize this repository with a README"

# 2. 在本地执行：
git remote add origin https://github.com/你的用户名/llm-security-audit.git
git branch -M main
git push -u origin main
```

## 二、安装 Neo4j 知识图谱

### 方式 1：Docker（最简单）

```bash
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:5-community
```

### 方式 2：Windows 直接安装

1. 下载 Neo4j Community Edition: https://neo4j.com/download-center/
2. 解压到本地目录
3. 命令行启动:
```bash
cd neo4j-community-5.x.x/bin
neo4j.bat console
```
4. 打开 http://localhost:7474 确认启动
5. 默认用户名/密码: neo4j / neo4j (首次登录需修改)

### 验证 Neo4j 是否可用

```bash
cd D:\Personal\Desktop\llm-security-audit
python -c "
from src.analyzers.graph_builder import VulnerabilityGraph
g = VulnerabilityGraph()
print('Neo4j 可用:', g.neo4j_available)
"
```

## 三、验证所有功能

```bash
# 1. 基础扫描
python main.py --target tests --quick

# 2. 增强扫描（AST + RAG + 并行）
python main.py --target tests

# 3. 带 Neo4j 图谱的增强扫描
python main.py --target tests --neo4j

# 4. 启动 Web 界面
python main.py --web

# 5. 测试 RAG-CVE 联网查询
python -c "
from src.analyzers.cve_rag import CVERAG
rag = CVERAG()
cves = rag.search_by_keyword('log4j')
for c in cves[:3]:
    print(f'{c[\"id\"]}: CVSS={c[\"cvss_score\"]}')
"
```

## 四、提交作业

1. 将实验报告模板 `docs/实验报告模板.md` 导出为 Word
2. 运行一次完整扫描生成最新报告
3. 将 PPT 大纲 `docs/PPT大纲.md` 制作成 PPT
4. 录制系统演示视频
5. 打包提交：`demo.bat` 中的全部功能 + 报告 + PPT + 演示视频
