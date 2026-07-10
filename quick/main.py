#!/usr/bin/env python3
"""
LLM Security Audit System - 主入口（增强版）
实验一：大模型驱动的开源项目安全审计系统

【主流技术使用标注】
★ LLM 驱动: 通过 Agent 调用 Claude Code 进行语义分析
★ 多 Agent 协同: Scanner/Verifier/Reporter 三 Agent 流水线
★ AST 语义分析: Tree-sitter 语法树级代码安全检测
★ 异步并行编排: asyncio + ThreadPoolExecutor 多 Agent 并行
★ RAG-CVE: 从 NVD 实时检索漏洞情报增强检测上下文
★ Neo4j 知识图谱: 构建项目→文件→漏洞→CVE 关联图谱
★ Web UI: Flask 交互式仪表盘
★ CI/CD: GitHub Actions 自动化审计流水线
★ 端到端自动化: 加载→扫描→AST→RAG→验证→PoC→图谱→报告
★ MCP 工具链: 通过 claude CLI 集成外部工具

用法:
    python main.py --target <repo-url|本地路径>
    python main.py --target /path/to/project --quick
    python main.py --target /path/to/project --no-ast --no-rag
    python main.py --web                          # 启动 Web 界面
    python main.py --target /path --neo4j         # 启用 Neo4j 图谱
"""

import os
import sys
import argparse
import json
import time

# 解决 Windows 终端 GBK 编码的 Unicode 显示问题
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# 确保项目根目录在 Python 路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.utils.repo_manager import RepoManager
from src.agents.scanner_agent import ScannerAgent
from src.agents.verifier_agent import VerifierAgent
from src.agents.orchestrator import get_orchestrator
from src.exploit.poc_generator import PoCGenerator
from src.report.report_generator import ReportGenerator


def print_banner():
    """打印启动横幅"""
    banner = """
╔══════════════════════════════════════════════════════════╗
║     🔒  LLM Security Audit System  v2.0.0 (增强版)     ║
║     大模型驱动的开源项目安全审计系统                     ║
║     实验一 · 网络空间安全综合实验                       ║
║                                                        ║
║  技术栈: LLM + Agent + SAST + AST + RAG + Neo4j + Web  ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="LLM Security Audit System - 大模型驱动的开源项目安全审计 (增强版)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    # 基础扫描
    python main.py --target https://github.com/example/project.git
    python main.py --target /path/to/local/project

    # 增强功能
    python main.py --target /path/to/project --no-ast       # 禁用 AST 分析
    python main.py --target /path/to/project --no-rag       # 禁用 CVE 查询
    python main.py --target /path/to/project --neo4j         # 启用 Neo4j 图谱
    python main.py --target /path/to/project --parallel 16   # 16 线程并行

    # 启动 Web 界面
    python main.py --web

    # 快速模式
    python main.py --target /path/to/project --quick
        """
    )

    # 基础参数
    parser.add_argument("--target", "-t",
                        help="目标项目: GitHub/GitLab URL 或本地目录路径")
    parser.add_argument("--output", "-o", default="reports",
                        help="报告输出目录 (默认: reports)")
    parser.add_argument("--work-dir", default="workspace",
                        help="工作目录 (默认: workspace)")

    # 模式选择
    parser.add_argument("--web", action="store_true",
                        help="启动 Web 交互界面")
    parser.add_argument("--quick", "-q", action="store_true",
                        help="快速模式: 仅规则匹配，跳过 LLM/AST/RAG 等增强分析")

    # 功能开关
    parser.add_argument("--llm", action="store_true", default=True,
                        help="启用 LLM 深度分析 (默认启用)")
    parser.add_argument("--poc", action="store_true", default=True,
                        help="自动生成 PoC 验证代码 (默认启用)")
    parser.add_argument("--no-ast", action="store_true",
                        help="禁用 Tree-sitter AST 语义分析")
    parser.add_argument("--no-rag", action="store_true",
                        help="禁用 RAG-CVE 实时查询")
    parser.add_argument("--neo4j", action="store_true",
                        help="启用 Neo4j 知识图谱 (需安装 Neo4j)")
    parser.add_argument("--parallel", type=int, default=8,
                        help="并行 Worker 数 (默认: 8)")

    return parser.parse_args()


def main():
    """主流程"""
    args = parse_args()

    # ============================================================
    # 模式 0: Web 界面
    # ============================================================
    if args.web:
        print("  🌐 启动 Web 交互界面...")
        from web.app import app as web_app
        from config.quick_settings import WEB_CONFIG
        web_app.run(
            host=WEB_CONFIG.get("host", "127.0.0.1"),
            port=WEB_CONFIG.get("port", 5000),
            debug=WEB_CONFIG.get("debug", False),
        )
        return {"mode": "web"}

    # ============================================================
    # 模式 1: CLI 扫描模式
    # ============================================================
    if not args.target:
        print("❌ 请指定目标项目 (--target) 或使用 --web 启动 Web 界面")
        print("   示例: python main.py --target /path/to/project")
        sys.exit(1)

    print_banner()
    total_start = time.time()

    # ---------------------------------------------------------------
    # 阶段 1: 项目加载
    # ---------------------------------------------------------------
    print(f"\n📂 阶段 1/6: 项目加载")
    print(f"  {'='*50}")
    print(f"  目标: {args.target}")

    repo = RepoManager(args.target, work_dir=args.work_dir)
    project_path = repo.resolve()
    project_info = repo.get_project_info()
    files = repo.get_file_list()

    print(f"  项目名称: {project_info['name']}")
    print(f"  代码文件数: {len(files)}")
    print(f"  语言分布: {project_info.get('languages', {})}")

    # 初始化 MCP Server（新增）
    mcp_server = None
    if not args.quick:
        print(f"\n🛠️  初始化 MCP 工具服务器...")
        from src.agents.mcp_server import create_mcp_server
        mcp_server = create_mcp_server(project_path)
        mcp_server.print_tools()

    # ---------------------------------------------------------------
    # 阶段 2: 并行 SAST 扫描（使用 Orchestrator 并优化）
    # ---------------------------------------------------------------
    print(f"\n🔍 阶段 2/6: SAST 并行扫描")
    print(f"  {'='*50}")

    scanner = ScannerAgent(llm_enabled=args.llm and not args.quick)
    orchestrator = get_orchestrator(max_workers=args.parallel)

    # 扫描单个文件的函数
    def scan_single_file(file_info):
        return scanner.scan_single(file_info, project_path)

    if args.quick or len(files) < 5:
        # 小项目或快速模式: 串行
        findings = scanner.scan(project_path, files)
    else:
        # 大项目: 并行扫描
        print(f"  ⚡ 启用 {args.parallel} 线程并行扫描...")
        findings = orchestrator.parallel_scan_files(files, scan_single_file)

    scan_stats = scanner.print_summary()

    # ---------------------------------------------------------------
    # 阶段 2.5: AST 语义分析（新增）
    # ---------------------------------------------------------------
    ast_findings = []
    if not args.quick and not args.no_ast:
        print(f"\n🌲 阶段 2.5/6: Tree-sitter AST 语义分析")
        print(f"  {'='*50}")
        try:
            from src.analyzers.ast_analyzer import get_ast_analyzer
            ast = get_ast_analyzer()

            def analyze_ast(file_info):
                filepath = file_info["path"]
                relpath = file_info["relpath"]
                ext = os.path.splitext(filepath)[1].lower()
                if not ast.can_parse(ext):
                    return []
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    return ast.analyze(relpath, content)
                except:
                    return []

            if args.quick or len(files) < 10:
                for f in files:
                    ast_findings.extend(analyze_ast(f))
            else:
                ast_findings = orchestrator.parallel_scan_files(files, analyze_ast)

            # AST 发现的漏洞也合并到主列表
            if ast_findings:
                print(f"  🌲 AST 分析发现: {len(ast_findings)} 个潜在问题")
                findings.extend(ast_findings)
        except ImportError as e:
            print(f"  ⚠️ AST 分析不可用: {e} (pip install tree-sitter tree-sitter-python)")
        except Exception as e:
            print(f"  ⚠️ AST 分析异常: {type(e).__name__}")

    # ---------------------------------------------------------------
    # 阶段 3: RAG-CVE 实时情报增强（新增）
    # ---------------------------------------------------------------
    if not args.quick and not args.no_rag and findings:
        print(f"\n📡 阶段 3/6: RAG-CVE 实时漏洞情报检索")
        print(f"  {'='*50}")
        try:
            from src.analyzers.cve_rag import CVERAG
            cve_rag = CVERAG()
            findings = cve_rag.enrich_findings(findings, project_path)
        except Exception as e:
            print(f"  ⚠️ RAG-CVE 查询异常: {type(e).__name__}")

    # ---------------------------------------------------------------
    # 阶段 4: 漏洞验证与 PoC 生成
    # ---------------------------------------------------------------
    if findings:
        print(f"\n🔎 阶段 4/6: 漏洞验证 & PoC 生成")
        print(f"  {'='*50}")

        if not args.quick:
            verifier = VerifierAgent(project_path, llm_enabled=args.llm)
            findings = verifier.verify_findings(findings)
            verifier.print_summary()
        else:
            print(f"  ⚡ 快速模式: 跳过漏洞验证")
            for f in findings:
                f["is_real"] = True

        if args.poc and not args.quick:
            poc_gen = PoCGenerator(project_path, llm_enabled=args.llm)
            findings = poc_gen.generate(findings)
            poc_gen.print_summary()
    else:
        print(f"\n  ✅ 未发现安全问题！")

    # ---------------------------------------------------------------
    # 阶段 5: Neo4j 知识图谱（新增）
    # ---------------------------------------------------------------
    if args.neo4j and findings:
        print(f"\n🕸️ 阶段 5/6: Neo4j 漏洞知识图谱")
        print(f"  {'='*50}")
        try:
            from src.analyzers.graph_builder import VulnerabilityGraph
            graph = VulnerabilityGraph()
            if graph.neo4j_available:
                graph.build_graph(findings, project_info)

                # 将图谱数据注入报告
                graph_json = graph.export_graph_json()
                project_info["knowledge_graph"] = graph_json
            graph.close()
        except Exception as e:
            print(f"  ⚠️ 知识图谱异常: {type(e).__name__}")

    # ---------------------------------------------------------------
    # 阶段 6: 报告生成
    # ---------------------------------------------------------------
    print(f"\n📄 阶段 6/6: 报告生成")
    print(f"  {'='*50}")

    report_gen = ReportGenerator(output_dir=args.output)
    report_paths = report_gen.generate(findings, project_info, scan_stats)

    # ============================================================
    # 总耗时 & 总结
    # ============================================================
    total_elapsed = time.time() - total_start

    print(f"\n{'='*60}")
    print(f"  ✅ 安全审计完成!")
    print(f"  {'='*60}")
    print(f"  项目: {project_info['name']}")
    print(f"  总耗时: {total_elapsed:.1f} 秒")
    print(f"  发现: {len(findings)} 个问题")
    print(f"  技术能力: ", end="")
    flags = []
    if not args.quick:
        flags.append("LLM/AST/RAG")
        if ast_findings:
            flags.append(f"AST({len(ast_findings)})")
    if args.neo4j:
        flags.append("Neo4j")
    if args.parallel > 1:
        flags.append(f"并行(x{args.parallel})")
    print(f"[{', '.join(flags)}]" if flags else "[规则匹配]")
    print(f"  报告: ")
    for fmt, path in report_paths.items():
        print(f"    - {fmt.upper()}: {path}")
    print(f"{'='*60}")

    orchestrator.shutdown()

    return {
        "project": project_info["name"],
        "files_scanned": scan_stats.get("files_scanned", 0),
        "findings_count": len(findings),
        "ast_findings": len(ast_findings),
        "elapsed": total_elapsed,
        "reports": report_paths,
        "mode": "enhanced" if not args.quick else "quick",
        "features": flags,
    }


if __name__ == "__main__":
    result = main()

    # 以 JSON 格式输出结果（供 Skill 调用时解析）
    if "--json" in sys.argv:
        print(json.dumps(result, ensure_ascii=False, indent=2))
