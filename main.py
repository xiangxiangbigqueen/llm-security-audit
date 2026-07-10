#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM Security Audit System — 统一入口
=====================================
两种模式:
  --quick    快速模式（正则匹配，零依赖，秒级扫描）
  --full     完整模式（SAST工具 + LLM多Agent深度分析）

用法:
  python main.py --target /path/to/project              # 默认快速模式
  python main.py --target /path/to/project --full       # 完整模式
  python main.py --target https://github.com/xxx/yyy    # 扫描GitHub仓库
  python main.py --gui                                  # 启动桌面GUI
  python main.py --web                                  # 启动Web界面
"""

import sys
import os
import argparse
from pathlib import Path

# Windows GBK 编码兼容 (仅在真实终端下生效, IDLE 下自动跳过)
if sys.platform == 'win32':
    try:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except (AttributeError, ValueError):
        pass  # IDLE 等环境没有 buffer, 跳过

# 项目根目录
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))


def get_parser():
    """构建CLI参数解析器"""
    parser = argparse.ArgumentParser(
        description="LLM Security Audit System — 大模型驱动的安全审计系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py --target ./my-project                   快速扫描本地项目
  python main.py --target ./my-project --full            完整深度分析
  python main.py --target https://github.com/user/repo   扫描GitHub仓库
  python main.py --gui                                  启动桌面GUI
  python main.py --web                                  启动Web仪表盘
        """
    )
    parser.add_argument("--target", type=str, help="目标路径 (本地目录 或 GitHub/GitLab URL)")
    parser.add_argument("--quick", action="store_true", default=False,
                        help="快速模式: 30组正则规则匹配 (默认)")
    parser.add_argument("--full", action="store_true",
                        help="完整模式: SAST工具 + LLM多Agent深度分析")
    parser.add_argument("--gui", action="store_true",
                        help="启动PyQt5桌面GUI应用")
    parser.add_argument("--web", action="store_true",
                        help="启动Flask Web仪表盘")
    parser.add_argument("--output", type=str, default="reports",
                        help="报告输出目录 (默认: reports)")
    parser.add_argument("--parallel", type=int, default=None,
                        help="并行Worker数 (仅快速模式)")
    parser.add_argument("--llm", action="store_true", default=None,
                        help="快速模式下启用LLM验证 (可选)")
    parser.add_argument("--neo4j", action="store_true",
                        help="启用Neo4j知识图谱 (仅快速模式)")
    return parser


def _ensure_dirs():
    """确保必要的目录存在"""
    dirs = ["reports", "output/reports", "output/repos"]
    for d in dirs:
        os.makedirs(BASE_DIR / d, exist_ok=True)


def run_quick_mode(target: str, output: str, parallel: int = None,
                   llm: bool = None, neo4j: bool = False):
    """快速模式 —— 30组正则 + 可选LLM验证"""
    print("\n" + "=" * 60)
    print("  [Quick Mode]")
    print("  Engine: 30 regex patterns")
    print("=" * 60 + "\n")

    # 添加quick模块路径
    quick_path = str(BASE_DIR / "quick")
    if quick_path not in sys.path:
        sys.path.append(quick_path)

    from src.agents.scanner_agent import ScannerAgent
    from src.agents.verifier_agent import VerifierAgent
    from src.exploit.poc_generator import PoCGenerator
    from src.report.report_generator import ReportGenerator
    from src.utils.repo_manager import RepoManager

    # 阶段1: 加载项目
    print("[Phase 1] Loading project...")
    repo = RepoManager(target)
    repo_path = repo.resolve()
    project_info = repo.get_project_info()
    files = repo.get_file_list()
    print(f"  Project: {project_info.get('name', target)}")
    print(f"  Files: {len(files)}")

    # 阶段2: 扫描 (使用 RegexScanner)
    print("\n[Phase 2] Regex scanning...")
    scanner = ScannerAgent()
    findings = scanner.scan(repo_path, files)
    print(f"  Found {len(findings)} potential issues")

    # 阶段3: 可选LLM验证
    if llm:
        print("\n[Phase 3] LLM verification...")
        verifier = VerifierAgent(repo_path, llm_enabled=True)
        confirmed = verifier.verify_findings(findings)
        print(f"  Confirmed {len(confirmed)} vulnerabilities")
    else:
        confirmed = findings

    # 阶段4: PoC生成
    print("\n[Phase 4] PoC generation...")
    poc_gen = PoCGenerator(repo_path)
    confirmed = poc_gen.generate(confirmed)

    # 阶段5: Neo4j (可选)
    if neo4j:
        print("\n[Phase 5] Neo4j graph...")
        try:
            from src.analyzers.graph_builder import VulnerabilityGraph
            graph = VulnerabilityGraph()
            graph.build_graph(confirmed, project_info)
            graph.close()
        except Exception as e:
            print(f"  Neo4j unavailable, skipped: {e}")

    # 阶段6: 报告
    print("\n[Phase 6] Generating report...")
    scan_stats = {
        "files_scanned": len(files),
        "patterns_matched": len(findings),
        "mode": "quick",
        "elapsed": 0,
    }
    report_gen = ReportGenerator(output_dir=output)
    paths = report_gen.generate(confirmed, project_info, scan_stats)

    print(f"\n{'=' * 60}")
    print(f"  Done! {len(confirmed)} findings")
    for fmt, p in paths.items():
        print(f"  {fmt}: {p}")
    print(f"{'=' * 60}\n")
    return paths


def run_full_mode(target: str, output: str):
    """完整模式 —— SAST工具 + LLM多Agent深度分析"""
    import asyncio

    print("\n" + "=" * 60)
    print("  🔬 完整模式 (Full Mode)")
    print("  检测引擎: SAST工具 + LLM多Agent协作")
    print("=" * 60 + "\n")

    # 添加full模块路径
    full_path = str(BASE_DIR / "full")
    if full_path not in sys.path:
        sys.path.append(full_path)

    from core.orchestrator import Orchestrator
    from core.llm.deepseek_client import DeepSeekClient
    from parser.repo_parser import RepoParser
    from report.generator import ReportGenerator as FullReportGenerator

    # 阶段1: 加载项目
    print("[阶段1] 加载项目...")
    parser = RepoParser()
    if target.startswith("http"):
        repo_path = parser.clone_repo(target)
    else:
        repo_path = parser.parse_local(target)
    project = parser.get_metadata(repo_path, source_url=target if target.startswith("http") else None)
    print(f"  项目: {project.name}")
    print(f"  语言: {project.languages}")
    print(f"  文件数: {project.file_count}")

    # 阶段2-5: 异步Agent流水线
    print("\n[阶段2-5] Agent流水线...")
    llm_client = DeepSeekClient()
    orchestrator = Orchestrator(llm_client)

    async def _run():
        result = await orchestrator.run_audit(project)
        await llm_client.close()
        return result

    result = asyncio.run(_run())

    # 阶段6: 报告
    print("\n[阶段6] 生成报告...")
    report_gen = FullReportGenerator()
    report_data = result.report_data

    md_path = report_gen.generate_markdown(report_data,
                                           str(BASE_DIR / output / f"report_{project.name}.md"))
    html_path = report_gen.generate_html(report_data,
                                         str(BASE_DIR / output / f"report_{project.name}.html"))

    print(f"\n{'=' * 60}")
    print(f"  ✅ 完整审计完成！耗时 {result.duration:.1f}秒")
    print(f"  确认漏洞: {len(result.vulnerabilities)} 个")
    print(f"  反馈环迭代: {result.iterations} 次")
    print(f"  📄 Markdown: {md_path}")
    print(f"  📄 HTML: {html_path}")
    print(f"{'=' * 60}\n")
    return {"markdown": md_path, "html": html_path}


def run_gui():
    """启动PyQt5桌面GUI"""
    print("\n启动 CodeSentinel 桌面GUI...\n")
    sys.path.append(str(BASE_DIR / "full"))
    sys.path.insert(0, str(BASE_DIR))

    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtCore import Qt

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("CodeSentinel")
    app.setOrganizationName("LLM-Security-Audit")

    from gui.main_window import MainWindow
    window = MainWindow()
    window.show()

    print("GUI已启动。关闭窗口退出。\n")
    sys.exit(app.exec_())


def run_web():
    """启动Flask Web界面"""
    print("\n启动 Web 仪表盘...\n")
    sys.path.append(str(BASE_DIR / "quick"))

    from web.app import app as flask_app
    flask_app.run(host="127.0.0.1", port=5000, debug=False)


def main():
    parser = get_parser()
    args = parser.parse_args()
    _ensure_dirs()

    # GUI 模式
    if args.gui:
        run_gui()
        return

    # Web 模式
    if args.web:
        run_web()
        return

    # 扫描模式 (需要 --target)
    if not args.target:
        parser.print_help()
        print("\n❌ 请指定 --target, 或使用 --gui / --web")
        print("   示例: python main.py --target ./my-project")
        print("   示例: python main.py --target ./my-project --full")
        print("   示例: python main.py --gui")
        sys.exit(1)

    # 默认: 如果既没指定 --quick 也没指定 --full, 默认 quick
    if not args.quick and not args.full:
        args.quick = True

    if args.full:
        run_full_mode(args.target, args.output)
    else:
        run_quick_mode(
            target=args.target,
            output=args.output,
            parallel=args.parallel,
            llm=args.llm,
            neo4j=args.neo4j,
        )


if __name__ == "__main__":
    main()
