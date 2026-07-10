"""
快速模式扫描页面 —— 正则匹配 + 可选LLM验证
"""
import os
import sys
import webbrowser
from pathlib import Path

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTableWidget, QTableWidgetItem,
    QTextEdit, QProgressBar, QFileDialog, QMessageBox,
    QHeaderView, QGroupBox, QFrame, QSplitter,
    QTreeWidget, QTreeWidgetItem, QTabWidget,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor

# 确保路径
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.append(str(BASE_DIR / "quick"))


def _build_file_tree(files: list) -> dict:
    """从文件列表构建嵌套目录树 {name: subtree|None}"""
    tree = {}
    for f in files:
        relpath = f.get("relpath", "") if isinstance(f, dict) else str(f)
        parts = relpath.replace("\\", "/").split("/")
        node = tree
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                node[part] = None  # 文件
            else:
                if part not in node:
                    node[part] = {}
                elif node[part] is None:
                    node[part] = {}  # 同名文件→目录转换（极少见）
                node = node[part]
    return tree


class QuickScanWorker(QThread):
    """快速扫描工作线程"""
    progress_signal = pyqtSignal(str, float, str)       # phase, percent, message
    log_signal = pyqtSignal(str, str)                    # source, message
    file_tree_signal = pyqtSignal(dict)                  # project_info for tree
    finished_signal = pyqtSignal(object, object, object) # findings, project_info, scan_stats
    error_signal = pyqtSignal(str)

    def __init__(self, target: str, output_dir: str, concurrency: int = 4):
        super().__init__()
        self.target = target
        self.output_dir = output_dir
        self.concurrency = concurrency

    def run(self):
        try:
            from src.agents.scanner_agent import ScannerAgent
            from src.utils.repo_manager import RepoManager
            from src.report.report_generator import ReportGenerator
            from src.exploit.poc_generator import PoCGenerator

            # 阶段1: 加载
            self.progress_signal.emit("load", 0.05, "加载项目...")
            repo = RepoManager(self.target)
            repo_path = repo.resolve()
            project_info = repo.get_project_info()
            files = repo.get_file_list()
            # 从文件列表构建目录树传给 GUI
            file_tree = _build_file_tree(files)
            project_info["_file_tree"] = file_tree
            self.file_tree_signal.emit(project_info)
            self.log_signal.emit("系统",
                f"项目: {project_info.get('name', self.target)} | "
                f"语言: {project_info.get('languages', {})} | "
                f"文件: {len(files)}")

            # 阶段2: 正则扫描 (带进度回调)
            scanner = ScannerAgent(concurrency=self.concurrency)
            scanner.set_progress_callback(
                lambda phase, cur, total, msg: self._on_scanner_progress(phase, cur, total, msg, len(files))
            )
            self.progress_signal.emit("regex", 0.10, f"正则扫描 ({len(files)} 个文件)...")
            findings = scanner.scan(repo_path, files)
            self.log_signal.emit("Scanner", f"正则扫描完成: 发现 {len(findings)} 个潜在漏洞")

            # 阶段3: PoC
            self.progress_signal.emit("poc", 0.75, "生成 PoC...")
            poc_gen = PoCGenerator(repo_path)
            findings = poc_gen.generate(findings)
            poc_count = sum(1 for f in findings if f.get("has_poc"))
            self.log_signal.emit("PoC", f"PoC 生成完成: {poc_count} 个")
            self.progress_signal.emit("poc", 0.85, f"PoC 完成 ({poc_count} 个)")

            # 阶段4: 报告
            self.progress_signal.emit("report", 0.90, "生成报告...")
            from gui.report_utils import get_report_folder, get_report_path

            report_folder = get_report_folder(self.target, "quick")
            html_path = get_report_path(self.target, "quick", "html")
            md_path = get_report_path(self.target, "quick", "md")
            json_path = get_report_path(self.target, "quick", "json")

            scan_stats = {
                "files_scanned": len(files),
                "patterns_matched": len(findings),
                "mode": "quick",
                "elapsed": 0,
                "report_html": html_path,
                "report_md": md_path,
            }
            report_gen = ReportGenerator(output_dir=report_folder)
            report_data = report_gen._prepare_report_data(findings, project_info, scan_stats, "")
            report_gen._generate_markdown(report_data, md_path)
            report_gen._generate_json(report_data, json_path)
            report_gen._generate_html(report_data, html_path)
            self.log_signal.emit("系统", f"报告已保存到 {report_folder}")

            self.progress_signal.emit("done", 1.0, f"完成 — {len(findings)} 个漏洞")
            self.finished_signal.emit(findings, project_info, scan_stats)

        except Exception as e:
            self.log_signal.emit("错误", str(e))
            self.progress_signal.emit("error", 0, f"错误: {e}")
            self.error_signal.emit(str(e))

    def _on_scanner_progress(self, phase, cur, total, msg, total_files):
        """将 ScannerAgent 的回调转为 GUI 信号"""
        if phase == "regex":
            pct = 0.10 + (cur / max(total, 1)) * 0.60
            self.progress_signal.emit("regex", pct, f"分析 ({cur}/{total}) {msg.split(chr(10))[0]}")
            if cur % 5 == 0 or cur == total:
                self.log_signal.emit("Scanner", msg)
        elif phase == "llm":
            pct = 0.70 + (cur / max(total, 1)) * 0.05
            self.progress_signal.emit("llm", pct, f"LLM 验证 ({cur}/{total})")
            self.log_signal.emit("LLM", msg)


class QuickScanPage(QWidget):
    """快速模式页面"""

    def __init__(self, on_back=None, concurrency=None):
        super().__init__()
        self.on_back = on_back
        self.worker = None
        self.current_findings = []
        self._last_html_path = None
        self._concurrency = concurrency if concurrency is not None else {"value": 4}
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(10, 10, 10, 10)

        # 顶部导航
        nav = QHBoxLayout()
        back_btn = QPushButton("← 返回")
        back_btn.setFixedWidth(80)
        back_btn.clicked.connect(self.on_back)
        nav.addWidget(back_btn)
        title = QLabel("⚡ 快速扫描模式 — 正则匹配引擎")
        title.setFont(QFont("", 14, QFont.Bold))
        nav.addWidget(title)
        nav.addStretch()
        layout.addLayout(nav)

        # 输入区
        input_frame = QFrame()
        input_layout = QHBoxLayout(input_frame)
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.addWidget(QLabel("目标:"))
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("输入GitHub仓库URL 或 本地代码路径...")
        input_layout.addWidget(self.input_field)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self._browse)
        input_layout.addWidget(browse_btn)
        self.start_btn = QPushButton("开始扫描")
        self.start_btn.clicked.connect(self._start_scan)
        self.start_btn.setStyleSheet("QPushButton { background: #1a3a2e; color: #28a745; border-color: #28a745; }")
        input_layout.addWidget(self.start_btn)
        layout.addWidget(input_frame)

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("就绪")
        layout.addWidget(self.progress_bar)

        # 主内容: 文件树(左) + 结果区(右)
        main_splitter = QSplitter(Qt.Horizontal)

        # 左侧文件树
        tree_group = QGroupBox("项目结构")
        tree_layout = QVBoxLayout(tree_group)
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabel("文件")
        tree_layout.addWidget(self.file_tree)
        main_splitter.addWidget(tree_group)

        # 右侧: Tab页 (漏洞列表 + 漏洞详情)
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        self.tabs = QTabWidget()
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(5)
        self.vuln_table.setHorizontalHeaderLabels(["ID", "漏洞类型", "严重等级", "文件", "行号"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.vuln_table.cellClicked.connect(self._show_detail)
        self.tabs.addTab(self.vuln_table, "漏洞列表")
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.tabs.addTab(self.detail_view, "漏洞详情")
        right_layout.addWidget(self.tabs)
        main_splitter.addWidget(right_panel)

        main_splitter.setSizes([250, 850])
        layout.addWidget(main_splitter)

        # 底部: 日志
        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout(log_group)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(130)
        log_layout.addWidget(self.log_view)
        layout.addWidget(log_group)

        # 底部按钮行: 设置(左) + 导出(右)
        bottom_layout = QHBoxLayout()
        self.settings_btn = QPushButton("⚙ 设置")
        self.settings_btn.setFixedWidth(70)
        self.settings_btn.setStyleSheet("QPushButton { background: transparent; border: 1px solid #3a3a5a; border-radius: 4px; color: #777; padding: 4px 8px; } QPushButton:hover { border-color: #00d4ff; color: #00d4ff; }")
        self.settings_btn.clicked.connect(self._show_settings)
        bottom_layout.addWidget(self.settings_btn)
        bottom_layout.addStretch()
        self.export_btn = QPushButton("导出 HTML 报告")
        self.export_btn.setStyleSheet("QPushButton { background: #1a3a5e; color: #00d4ff; border-color: #00d4ff; }")
        self.export_btn.clicked.connect(self._export_report)
        self.export_btn.setEnabled(False)
        bottom_layout.addWidget(self.export_btn)
        layout.addLayout(bottom_layout)

    def _browse(self):
        folder = QFileDialog.getExistingDirectory(self, "选择代码目录")
        if folder:
            self.input_field.setText(folder)

    def _start_scan(self):
        target = self.input_field.text().strip()
        if not target:
            QMessageBox.warning(self, "提示", "请输入仓库URL或本地路径")
            return

        self.start_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.vuln_table.setRowCount(0)
        self.detail_view.clear()
        self.log_view.clear()
        self.file_tree.clear()

        self.worker = QuickScanWorker(target, str(BASE_DIR / "reports"), self._concurrency["value"])
        self.worker.progress_signal.connect(self._on_progress)
        self.worker.log_signal.connect(self._on_log)
        self.worker.file_tree_signal.connect(self._on_file_tree)
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.error_signal.connect(self._on_error)
        self.worker.start()

    def _on_progress(self, phase, percent, message):
        self.progress_bar.setValue(int(percent * 100))
        self.progress_bar.setFormat(message)

    def _on_log(self, source, message):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_view.append(f"[{ts}] [{source}] {message}")

    def _on_file_tree(self, project_info):
        """更新文件结构树"""
        self.file_tree.clear()
        name = project_info.get("name", "project")
        root = QTreeWidgetItem(self.file_tree, [name])

        file_tree = project_info.get("_file_tree", {})
        if file_tree:
            def _add_items(parent, subtree):
                # 先目录后文件排序
                items = sorted(subtree.items(), key=lambda x: (x[1] is not None, x[0]))
                for item_name, sub in items:
                    display = item_name + "/" if sub is not None else item_name
                    node = QTreeWidgetItem(parent, [display])
                    if sub is not None:
                        _add_items(node, sub)
            _add_items(root, file_tree)
        root.setExpanded(True)

    def _on_finished(self, findings, project_info, scan_stats):
        self.start_btn.setEnabled(True)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat(f"完成 — {len(findings)} 个漏洞")

        self.current_findings = findings
        self._update_table(findings)
        self.export_btn.setEnabled(True)
        self._last_html_path = scan_stats.get("report_html", "")

        QMessageBox.information(self, "扫描完成",
                                f"扫描完成！\n发现 {len(findings)} 个潜在漏洞\n报告已保存到 reports/quick/ 目录")

    def _on_error(self, error_msg):
        self.start_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("扫描失败")
        self.export_btn.setEnabled(False)
        QMessageBox.critical(self, "扫描失败", f"扫描过程中出错:\n\n{error_msg}")

    def _show_settings(self):
        from gui.settings_dialog import SettingsDialog
        dlg = SettingsDialog(current_concurrency=self._concurrency["value"], parent=self)
        if dlg.exec_():
            self._concurrency["value"] = dlg.concurrency

    def _export_report(self):
        if self._last_html_path:
            folder = os.path.dirname(self._last_html_path)
            if os.path.exists(folder):
                os.startfile(folder)
                return
        QMessageBox.warning(self, "提示", "报告文件夹不存在，请先完成扫描")

    def _update_table(self, findings):
        self.vuln_table.setRowCount(len(findings))
        colors = {"高危": QColor("#dc3545"), "中危": QColor("#fd7e14"),
                  "低危": QColor("#28a745"), "信息": QColor("#0d6efd")}
        for row, f in enumerate(findings):
            self.vuln_table.setItem(row, 0, QTableWidgetItem(f.get("id", "")))
            self.vuln_table.setItem(row, 1, QTableWidgetItem(f.get("vuln_name", "")))
            sev = f.get("severity", "信息")
            sev_item = QTableWidgetItem(sev)
            sev_item.setForeground(colors.get(sev, QColor("#fff")))
            self.vuln_table.setItem(row, 2, sev_item)
            self.vuln_table.setItem(row, 3, QTableWidgetItem(f.get("file", "")))
            self.vuln_table.setItem(row, 4, QTableWidgetItem(str(f.get("line", ""))))

    def _show_detail(self, row, col):
        if row < len(self.current_findings):
            f = self.current_findings[row]
            detail = f"""漏洞ID: {f.get('id', 'N/A')}
类型: {f.get('vuln_name', 'N/A')}
严重等级: {f.get('severity', 'N/A')}
CWE: {f.get('cwe', 'N/A')}
文件: {f.get('file', 'N/A')}:{f.get('line', 'N/A')}

风险描述:
{f.get('risk_description', 'N/A')}

代码上下文:
{f.get('context', 'N/A')}

{chr(10) + '修复建议:' + chr(10) + f.get('fix_suggestion', 'N/A') if f.get('fix_suggestion') else ''}
{chr(10) + '攻击场景:' + chr(10) + f.get('exploit_scenario', 'N/A') if f.get('exploit_scenario') else ''}"""
            poc = f.get('poc', {})
            if isinstance(poc, dict) and poc.get('poc_code'):
                detail += f"\n\nPoC代码:\n{poc['poc_code'][:500]}"
            self.detail_view.setPlainText(detail)
