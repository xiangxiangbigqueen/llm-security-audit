"""
Web 交互界面（新增）
Flask Web 应用，可视化展示安全审计结果

【主流技术使用标注】
★ Web 可视化: 基于 Flask 的交互式仪表盘
★ 实时扫描: 浏览器端提交扫描任务并实时查看进度
★ 图表统计: 使用 Chart.js 展示漏洞分类统计
★ 代码高亮: 漏洞代码上下文语法高亮显示
"""

import os
import sys
import json
import threading

# 确保项目根目录在路径中
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, render_template, request, jsonify, send_file

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()

# 内存存储最近的扫描结果
scan_results = {}
scan_history = []


def run_scan_task(target: str, output_dir: str) -> dict:
    """在后台线程中运行扫描"""
    from main import main as run_scan
    import argparse
    import io
    from contextlib import redirect_stdout

    # 捕获输出
    f = io.StringIO()
    result = {}
    try:
        with redirect_stdout(f):
            # 模拟参数
            sys.argv = ["main.py", "--target", target,
                        "--output", output_dir, "--quick"]
            # 临时替换 main 的参数解析
            result = run_scan_internal(target, output_dir)
    except Exception as e:
        result = {"error": str(e)}

    output = f.getvalue()
    return {"result": result, "output": output}


def run_scan_internal(target: str, output_dir: str) -> dict:
    """内部扫描函数"""
    from src.utils.repo_manager import RepoManager
    from src.agents.scanner_agent import ScannerAgent
    from src.agents.verifier_agent import VerifierAgent
    from src.exploit.poc_generator import PoCGenerator
    from src.report.report_generator import ReportGenerator

    repo = RepoManager(target)
    project_path = repo.resolve()
    project_info = repo.get_project_info()
    files = repo.get_file_list()

    scanner = ScannerAgent(llm_enabled=False)
    findings = scanner.scan(project_path, files)
    scan_stats = scanner.print_summary()

    if findings:
        verifier = VerifierAgent(project_path, llm_enabled=False)
        findings = verifier.verify_findings(findings)
        poc_gen = PoCGenerator(project_path, llm_enabled=False)
        findings = poc_gen.generate(findings)

    report_gen = ReportGenerator(output_dir=output_dir)
    report_paths = report_gen.generate(findings, project_info, scan_stats)

    return {
        "project": project_info.get("name", "unknown"),
        "files_scanned": scan_stats.get("files_scanned", 0),
        "findings_count": len(findings),
        "reports": list(report_paths.values()),
        "findings": findings,
        "project_info": project_info,
    }


@app.route("/")
def index():
    """首页"""
    return render_template("index.html", history=scan_history[-10:])


@app.route("/scan", methods=["POST"])
def start_scan():
    """启动扫描"""
    target = request.json.get("target", "")
    if not target:
        return jsonify({"error": "请提供目标路径或 URL"}), 400

    output_dir = request.json.get("output", "reports")

    # 在后台运行
    def scan_thread():
        result = run_scan_internal(target, output_dir)
        scan_results["latest"] = result
        scan_history.append({
            "target": target,
            "time": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "findings": len(result.get("findings", [])),
        })

    thread = threading.Thread(target=scan_thread, daemon=True)
    thread.start()

    return jsonify({"status": "started", "target": target})


@app.route("/status")
def scan_status():
    """获取扫描状态"""
    result = scan_results.get("latest")
    if result:
        return jsonify({"status": "done", "data": result})
    return jsonify({"status": "waiting"})


@app.route("/report/<path:report_path>")
def view_report(report_path):
    """查看报告"""
    full_path = os.path.join(os.path.dirname(__file__), "..", "reports", report_path)
    if os.path.exists(full_path):
        return send_file(full_path)
    return "报告未找到", 404


@app.route("/api/history")
def get_history():
    """获取扫描历史"""
    return jsonify(scan_history[-20:])


if __name__ == "__main__":
    from config.settings import WEB_CONFIG
    print(f"  🌐 启动 Web 界面: http://{WEB_CONFIG['host']}:{WEB_CONFIG['port']}")
    app.run(
        host=WEB_CONFIG.get("host", "127.0.0.1"),
        port=WEB_CONFIG.get("port", 5000),
        debug=WEB_CONFIG.get("debug", False),
    )
