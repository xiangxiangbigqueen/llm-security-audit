"""
完整模式扫描页面 —— 嵌入 Branch C 的 CodeSentinel 主界面
"""
import sys
from pathlib import Path

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

# 确保路径
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.append(str(BASE_DIR / "full"))


class FullScanPage(QWidget):
    """完整模式页面 —— 嵌入 Branch C 原始 MainWindow"""

    def __init__(self, on_back=None, concurrency=None):
        super().__init__()
        self.on_back = on_back
        self._concurrency = concurrency if concurrency is not None else {"value": 4}
        self.embedded_window = None
        self._init_ui()

    def _show_settings(self):
        """打开设置弹窗"""
        from gui.settings_dialog import SettingsDialog
        dlg = SettingsDialog(current_concurrency=self._concurrency["value"], parent=self)
        if dlg.exec_():
            self._concurrency["value"] = dlg.concurrency
            import config.full_settings as fs
            fs.MAX_CONCURRENT_SCANS = self._concurrency["value"]

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        # 顶部导航
        nav = QHBoxLayout()
        back_btn = QPushButton("← 返回")
        back_btn.setFixedWidth(80)
        back_btn.clicked.connect(self.on_back)
        nav.addWidget(back_btn)

        title = QLabel("🔬 完整分析模式 — SAST工具 + LLM多Agent协作")
        title.setFont(QFont("", 14, QFont.Bold))
        nav.addWidget(title)
        nav.addStretch()

        # 模式说明
        info = QLabel("注意：深度分析需配置API Key；外部工具cppcheck/flawfinder/phpstan/progpilot需自行安装")
        info.setStyleSheet("color: #888; font-size: 12px;")
        nav.addWidget(info)
        layout.addLayout(nav)

        # 应用并发设置到 full_settings 模块
        import config.full_settings as fs
        fs.MAX_CONCURRENT_SCANS = self._concurrency["value"]

        # 嵌入 Branch C 的主窗口
        try:
            from full.gui.main_window import MainWindow as CodeSentinelMain
            self.embedded_window = CodeSentinelMain()
            # 把 CodeSentinel 的 centralWidget 嵌入到当前页面
            central = self.embedded_window.centralWidget()
            if central:
                central.setParent(self)
                layout.addWidget(central)
            else:
                # fallback: 直接嵌入整个窗口的内容
                layout.addWidget(self.embedded_window)
        except Exception as e:
            error_label = QLabel(f"无法加载完整模式界面:\n{e}\n\n请确保已安装完整模式依赖:\npip install PyQt5 aiohttp openai bandit flawfinder gitpython python-dotenv")
            error_label.setAlignment(Qt.AlignCenter)
            error_label.setStyleSheet("color: #dc3545; padding: 40px;")
            error_label.setWordWrap(True)
            layout.addWidget(error_label)

