"""主窗口"""
import asyncio
import os
import sys
import webbrowser
from pathlib import Path
from typing import Optional

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTabWidget,
    QTextEdit, QTableWidget, QTableWidgetItem,
    QTreeWidget, QTreeWidgetItem, QSplitter,
    QProgressBar, QFileDialog, QMessageBox,
    QHeaderView, QFrame, QGroupBox,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QIcon

from config.full_settings import BASE_DIR, DEEPSEEK_API_KEY
from core.orchestrator import Orchestrator, AuditResult
from core.llm.deepseek_client import DeepSeekClient
from core.models.project import ProjectMetadata
from parser.repo_parser import RepoParser
from report.generator import ReportGenerator
from gui.report_utils import get_report_path


class AuditWorker(QThread):
    """审计工作线程"""
    progress_signal = pyqtSignal(str, float, str)  # agent_name, progress, message
    log_signal = pyqtSignal(str, str)  # agent_name, message
    finished_signal = pyqtSignal(object)  # AuditResult
    error_signal = pyqtSignal(str)

    def __init__(self, orchestrator: Orchestrator, project: ProjectMetadata):
        super().__init__()
        self.orchestrator = orchestrator
        self.project = project
        self._loop = None

    def run(self):
        """在新线程中运行异步审计"""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        self.orchestrator.set_progress_callback(
            lambda name, prog, msg: self.progress_signal.emit(name, prog, msg)
        )
        self.orchestrator.set_log_callback(
            lambda name, msg: self.log_signal.emit(name, msg)
        )

        try:
            result = self._loop.run_until_complete(
                self.orchestrator.run_audit(self.project)
            )
            self.finished_signal.emit(result)
        except Exception as e:
            self.error_signal.emit(str(e))
        finally:
            self._loop.close()

    def cancel(self):
        self.orchestrator.cancel()


class MainWindow(QMainWindow):
    """CodeSentinel 主窗口"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CodeSentinel - 开源项目安全审计系统")
        self.setMinimumSize(1200, 800)

        self.repo_parser = RepoParser()
        self.report_generator = ReportGenerator()
        self.audit_worker: Optional[AuditWorker] = None
        self.current_result: Optional[AuditResult] = None

        self._init_ui()
        self._load_stylesheet()

    def _load_stylesheet(self):
        """加载样式表"""
        qss_path = Path(__file__).parent / "styles" / "dark_theme.qss"
        if qss_path.exists():
            with open(qss_path, 'r') as f:
                self.setStyleSheet(f.read())

    def _init_ui(self):
        """初始化界面"""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(10)

        # 顶部: 输入区域
        self._create_input_area(main_layout)

        # 中间: 主工作区 (左右分栏)
        splitter = QSplitter(Qt.Horizontal)

        # 左侧: 文件树
        self._create_file_tree(splitter)

        # 右侧: Tab区域
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # 智能体状态面板
        self._create_agent_panel(right_layout)

        # Tab: 漏洞列表 / 报告预览
        self._create_tabs(right_layout)

        splitter.addWidget(right_widget)
        splitter.setSizes([250, 950])
        main_layout.addWidget(splitter)

        # 底部: 日志面板
        self._create_log_panel(main_layout)

    def _create_input_area(self, parent_layout):
        """创建输入区域"""
        input_frame = QFrame()
        input_layout = QHBoxLayout(input_frame)

        input_layout.addWidget(QLabel("仓库/路径:"))

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("输入GitHub仓库URL 或 本地代码路径...")
        input_layout.addWidget(self.input_field)

        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self._browse_folder)
        input_layout.addWidget(browse_btn)

        self.start_btn = QPushButton("开始审计")
        self.start_btn.clicked.connect(self._start_audit)
        input_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("stopButton")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_audit)
        input_layout.addWidget(self.stop_btn)

        parent_layout.addWidget(input_frame)

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p% - 就绪")
        parent_layout.addWidget(self.progress_bar)

    def _create_file_tree(self, splitter):
        """创建文件结构树"""
        tree_group = QGroupBox("项目结构")
        tree_layout = QVBoxLayout(tree_group)

        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabel("文件")
        tree_layout.addWidget(self.file_tree)

        splitter.addWidget(tree_group)

    def _create_agent_panel(self, parent_layout):
        """创建智能体状态面板"""
        agent_frame = QFrame()
        agent_layout = QHBoxLayout(agent_frame)
        agent_layout.setSpacing(20)

        self.agent_labels = {}
        agents = [
            ("Scanner", "扫描"),
            ("Validator", "验证"),
            ("Exploiter", "利用"),
            ("Reporter", "报告"),
        ]

        for agent_id, agent_name in agents:
            agent_widget = QFrame()
            agent_widget.setFrameShape(QFrame.Box)
            agent_widget_layout = QVBoxLayout(agent_widget)
            agent_widget_layout.setAlignment(Qt.AlignCenter)

            name_label = QLabel(agent_name)
            name_label.setAlignment(Qt.AlignCenter)
            name_label.setFont(QFont("", 11, QFont.Bold))
            agent_widget_layout.addWidget(name_label)

            status_label = QLabel("○ 等待")
            status_label.setAlignment(Qt.AlignCenter)
            agent_widget_layout.addWidget(status_label)

            self.agent_labels[agent_id] = status_label
            agent_layout.addWidget(agent_widget)

        parent_layout.addWidget(agent_frame)

    def _create_tabs(self, parent_layout):
        """创建Tab页"""
        self.tabs = QTabWidget()

        # Tab 1: 漏洞列表
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(6)
        self.vuln_table.setHorizontalHeaderLabels(["ID", "类型", "严重等级", "文件", "行号", "状态"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.vuln_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.vuln_table.cellClicked.connect(self._on_vuln_clicked)
        self.tabs.addTab(self.vuln_table, "漏洞列表")

        # Tab 2: 漏洞详情
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.tabs.addTab(self.detail_view, "漏洞详情")

        # Tab 3: 报告预览
        self.report_view = QTextEdit()
        self.report_view.setReadOnly(True)
        self.tabs.addTab(self.report_view, "报告预览")

        parent_layout.addWidget(self.tabs)

    def _create_log_panel(self, parent_layout):
        """创建日志面板"""
        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout(log_group)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(150)
        log_layout.addWidget(self.log_text)

        # 导出按钮
        export_layout = QHBoxLayout()
        # 设置按钮(左下角)
        self.settings_btn = QPushButton("⚙ 设置")
        self.settings_btn.setFixedWidth(70)
        self.settings_btn.setStyleSheet("QPushButton { background: transparent; border: 1px solid #3a3a5a; border-radius: 4px; color: #777; padding: 4px 8px; } QPushButton:hover { border-color: #00d4ff; color: #00d4ff; }")
        self.settings_btn.clicked.connect(self._show_settings_dialog)
        export_layout.addWidget(self.settings_btn)
        export_layout.addStretch()

        export_html_btn = QPushButton("导出HTML报告")
        export_html_btn.clicked.connect(self._export_html)
        export_layout.addWidget(export_html_btn)

        export_md_btn = QPushButton("导出Markdown报告")
        export_md_btn.clicked.connect(self._export_markdown)
        export_layout.addWidget(export_md_btn)

        log_layout.addLayout(export_layout)
        parent_layout.addWidget(log_group)

    def _browse_folder(self):
        """浏览文件夹"""
        folder = QFileDialog.getExistingDirectory(self, "选择代码目录")
        if folder:
            self.input_field.setText(folder)

    def _start_audit(self):
        """开始审计"""
        target = self.input_field.text().strip()
        if not target:
            QMessageBox.warning(self, "提示", "请输入仓库URL或本地路径")
            return

        if not DEEPSEEK_API_KEY:
            QMessageBox.warning(self, "配置错误", "请在.env文件中配置DEEPSEEK_API_KEY")
            return

        # 解析项目
        try:
            if target.startswith("http"):
                self._append_log("系统", f"正在克隆仓库: {target}")
                repo_path = self.repo_parser.clone_repo(target)
            else:
                repo_path = self.repo_parser.parse_local(target)

            project = self.repo_parser.get_metadata(repo_path, source_url=target if target.startswith("http") else None)
            self._update_file_tree(project)
            self._append_log("系统", f"项目解析完成: {project.name}, 语言: {project.languages}, 文件数: {project.file_count}")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"项目解析失败: {e}")
            return

        # 启动审计
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)

        llm_client = DeepSeekClient()
        orchestrator = Orchestrator(llm_client)

        self.audit_worker = AuditWorker(orchestrator, project)
        self.audit_worker.progress_signal.connect(self._on_progress)
        self.audit_worker.log_signal.connect(self._on_log)
        self.audit_worker.finished_signal.connect(self._on_audit_finished)
        self.audit_worker.error_signal.connect(self._on_audit_error)
        self.audit_worker.start()

    def _stop_audit(self):
        """停止审计"""
        if self.audit_worker:
            self.audit_worker.cancel()
            self._append_log("系统", "正在停止审计...")

    def _on_progress(self, agent_name: str, progress: float, message: str):
        """处理进度更新"""
        total_progress = int(progress * 100)
        self.progress_bar.setValue(total_progress)
        self.progress_bar.setFormat(f"%p% - {message}")

        # 更新智能体状态
        if agent_name in self.agent_labels:
            if progress >= 1.0:
                self.agent_labels[agent_name].setText("✓ 完成")
                self.agent_labels[agent_name].setStyleSheet("color: #28a745;")
            elif progress > 0:
                self.agent_labels[agent_name].setText(f"⟳ {int(progress*100)}%")
                self.agent_labels[agent_name].setStyleSheet("color: #ffc107;")

    def _on_log(self, agent_name: str, message: str):
        """处理日志"""
        self._append_log(agent_name, message)

    def _on_audit_finished(self, result: AuditResult):
        """审计完成"""
        self.current_result = result
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("100% - 审计完成")

        # 更�漏洞列表
        self._update_vuln_table(result.vulnerabilities)

        # 更新报告预览
        if result.report_data:
            report_md = self.report_generator._render_markdown(result.report_data)
            self.report_view.setPlainText(report_md)

            # 自动保存报告到 reports/full/
            try:
                target = self.input_field.text().strip()
                html_path = get_report_path(target, "full", "html")
                md_path = get_report_path(target, "full", "md")
                self.report_generator.generate_html(result.report_data, html_path)
                self.report_generator.generate_markdown(result.report_data, md_path)
                self._last_html_path = html_path
                self._append_log("系统", f"HTML报告已保存: {html_path}")
                self._append_log("系统", f"Markdown报告已保存: {md_path}")
            except Exception as e:
                self._append_log("系统", f"报告自动保存失败: {e}")

        self._append_log("系统",
                        f"审计完成! 耗时{result.duration:.1f}秒, "
                        f"发现{len(result.vulnerabilities)}个确认漏洞, "
                        f"反馈环迭代{result.iterations}次")

        # 检查外部工具是否已安装，未安装则逐一提示
        import shutil
        tool_cmds = {
            "cppcheck":   "winget install cppcheck  或  choco install cppcheck",
            "flawfinder": "pip install flawfinder",
            "bandit":     "pip install bandit",
            "phpstan":    "winget install phpstan  或  choco install phpstan",
        }
        for tool, cmd in tool_cmds.items():
            if not shutil.which(tool):
                self._append_log("提示", f"工具 [{tool}] 未安装 → {cmd}")

        QMessageBox.information(self, "审计完成",
                              f"发现 {len(result.vulnerabilities)} 个确认漏洞\n耗时: {result.duration:.1f}秒")

    def _on_audit_error(self, error_msg: str):
        """审计出错"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._append_log("错误", error_msg)
        QMessageBox.critical(self, "审计错误", f"审计过程中出错:\n{error_msg}")

    def _update_file_tree(self, project: ProjectMetadata):
        """更新文件树"""
        self.file_tree.clear()
        root = QTreeWidgetItem(self.file_tree, [project.name])

        def _add_items(parent_item, tree_dict):
            for name, subtree in sorted(tree_dict.items()):
                item = QTreeWidgetItem(parent_item, [name])
                if subtree is not None and isinstance(subtree, dict):
                    _add_items(item, subtree)

        _add_items(root, project.file_tree)
        root.setExpanded(True)

    def _update_vuln_table(self, vulnerabilities):
        """更新漏洞列表表格"""
        self.vuln_table.setRowCount(len(vulnerabilities))
        severity_colors = {
            "critical": QColor("#dc3545"),
            "high": QColor("#fd7e14"),
            "medium": QColor("#ffc107"),
            "low": QColor("#28a745"),
        }

        for row, vuln in enumerate(vulnerabilities):
            self.vuln_table.setItem(row, 0, QTableWidgetItem(vuln.vulnerability_id))
            self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln.vulnerability_type))

            severity_item = QTableWidgetItem(vuln.severity.upper())
            severity_item.setForeground(severity_colors.get(vuln.severity, QColor("#fff")))
            self.vuln_table.setItem(row, 2, severity_item)

            self.vuln_table.setItem(row, 3, QTableWidgetItem(vuln.file_path))
            self.vuln_table.setItem(row, 4, QTableWidgetItem(str(vuln.line_number)))
            self.vuln_table.setItem(row, 5, QTableWidgetItem(vuln.validation_status))

    def _on_vuln_clicked(self, row, col):
        """点击漏洞查看详情"""
        if self.current_result and row < len(self.current_result.vulnerabilities):
            vuln = self.current_result.vulnerabilities[row]
            detail = f"""漏洞ID: {vuln.vulnerability_id}
类型: {vuln.vulnerability_type}
严重等级: {vuln.severity.upper()}
文件: {vuln.file_path}:{vuln.line_number}

=== 代码片段 ===
{vuln.code_snippet}

=== 数据流 ===
{vuln.data_flow}

=== 判断理由 ===
{vuln.reasoning}

=== 验证结果 ===
状态: {vuln.validation_status}
置信度: {vuln.validation_confidence}
验证理由: {vuln.validation_reasoning}

=== PoC代码 ===
{vuln.poc_code or '无'}

=== 影响分析 ===
{vuln.impact_analysis or '无'}

=== 利用步骤 ===
{chr(10).join(vuln.exploit_steps) if vuln.exploit_steps else '无'}
"""
            self.detail_view.setPlainText(detail)
            self.tabs.setCurrentIndex(1)  # 切换到详情Tab

    def _show_settings_dialog(self):
        """打开设置弹窗"""
        from gui.settings_dialog import SettingsDialog
        import config.full_settings as fs
        dlg = SettingsDialog(current_concurrency=fs.MAX_CONCURRENT_SCANS, parent=self)
        if dlg.exec_():
            fs.MAX_CONCURRENT_SCANS = dlg.concurrency

    def _export_html(self):
        """导出HTML报告——一键保存到 reports/full/ 并打开目录"""
        if not self.current_result or not self.current_result.report_data:
            QMessageBox.warning(self, "提示", "没有可导出的报告数据")
            return

        target = self.input_field.text().strip()
        path = get_report_path(target, "full", "html")
        output = self.report_generator.generate_html(self.current_result.report_data, path)
        self._last_html_path = output
        self._append_log("系统", f"HTML报告已保存: {output}")
        os.startfile(os.path.dirname(output))
        QMessageBox.information(self, "导出成功", f"报告已保存到:\n{output}")

    def _export_markdown(self):
        """导出Markdown报告——一键保存到 reports/full/"""
        if not self.current_result or not self.current_result.report_data:
            QMessageBox.warning(self, "提示", "没有可导出的报告数据")
            return

        target = self.input_field.text().strip()
        path = get_report_path(target, "full", "md")
        output = self.report_generator.generate_markdown(self.current_result.report_data, path)
        self._append_log("系统", f"Markdown报告已保存: {output}")
        os.startfile(os.path.dirname(output))
        QMessageBox.information(self, "导出成功", f"报告已保存到:\n{output}")

    def _append_log(self, source: str, message: str):
        """添加日志"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] [{source}] {message}")