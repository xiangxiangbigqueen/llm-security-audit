"""
统一GUI入口 — 欢迎界面 + 模式路由
"""
import sys
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame, QStackedWidget,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

# 确保项目根目录和子模块在 path 中
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))         # root first
sys.path.append(str(BASE_DIR / "quick"))  # then quick
sys.path.append(str(BASE_DIR / "full"))   # then full


class WelcomePage(QWidget):
    """欢迎界面 —— 选择扫描模式"""

    def __init__(self, on_quick, on_full, on_settings=None):
        super().__init__()
        self._on_quick = on_quick
        self._on_full = on_full
        self._on_settings = on_settings
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(30)

        # 标题
        title = QLabel("CodeSentinel")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("", 36, QFont.Bold))
        title.setStyleSheet("color: #00d4ff;")
        layout.addWidget(title)

        subtitle = QLabel("LLM Security Audit System\n大模型驱动的开源项目安全审计系统")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setFont(QFont("", 13))
        subtitle.setStyleSheet("color: #888;")
        layout.addWidget(subtitle)

        layout.addSpacing(20)

        # 两条分割线之间的按钮区域
        line1 = QFrame()
        line1.setFrameShape(QFrame.HLine)
        line1.setStyleSheet("background: #2a2a4a; max-height: 1px;")
        layout.addWidget(line1)

        layout.addSpacing(20)

        # 模式选择按钮
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(40)
        btn_layout.setAlignment(Qt.AlignCenter)

        # 快速模式按钮
        quick_btn = QPushButton("⚡ 快速模式\nQuick Scan")
        quick_btn.setFont(QFont("", 14, QFont.Bold))
        quick_btn.setMinimumSize(250, 150)
        quick_btn.setStyleSheet("""
            QPushButton {
                background: #1a3a2e;
                border: 2px solid #28a745;
                border-radius: 12px;
                color: #28a745;
                padding: 20px;
            }
            QPushButton:hover {
                background: #1f4a35;
                border-color: #3ddc6e;
            }
        """)
        quick_btn.clicked.connect(self._on_quick)
        btn_layout.addWidget(quick_btn)

        # 完整模式按钮
        full_btn = QPushButton("🔬 完整模式\nFull Analysis")
        full_btn.setFont(QFont("", 14, QFont.Bold))
        full_btn.setMinimumSize(250, 150)
        full_btn.setStyleSheet("""
            QPushButton {
                background: #1a1a3e;
                border: 2px solid #00d4ff;
                border-radius: 12px;
                color: #00d4ff;
                padding: 20px;
            }
            QPushButton:hover {
                background: #1f1f4e;
                border-color: #4de8ff;
            }
        """)
        full_btn.clicked.connect(self._on_full)
        btn_layout.addWidget(full_btn)

        layout.addLayout(btn_layout)

        layout.addSpacing(20)

        line2 = QFrame()
        line2.setFrameShape(QFrame.HLine)
        line2.setStyleSheet("background: #2a2a4a; max-height: 1px;")
        layout.addWidget(line2)

        layout.addSpacing(10)

        # 底部说明
        desc_layout = QVBoxLayout()
        desc_layout.setAlignment(Qt.AlignCenter)

        quick_desc = QLabel("快速模式：简单模式快速校验，但误报率略高")
        quick_desc.setAlignment(Qt.AlignCenter)
        quick_desc.setStyleSheet("color: #555; font-size: 12px;")
        desc_layout.addWidget(quick_desc)

        full_desc = QLabel("完整模式：使用SAST工具完整分析，耗时较长")
        full_desc.setAlignment(Qt.AlignCenter)
        full_desc.setStyleSheet("color: #555; font-size: 12px;")
        desc_layout.addWidget(full_desc)

        api_desc = QLabel("深度分析需在 .env 文件或设置中配置 API Key")
        api_desc.setAlignment(Qt.AlignCenter)
        api_desc.setStyleSheet("color: #555; font-size: 12px;")
        desc_layout.addWidget(api_desc)

        concurrency_desc = QLabel("可在设置中修改最大并发数以提高分析速度")
        concurrency_desc.setAlignment(Qt.AlignCenter)
        concurrency_desc.setStyleSheet("color: #555; font-size: 12px;")
        desc_layout.addWidget(concurrency_desc)

        layout.addLayout(desc_layout)

        # 把设置按钮推到底部
        layout.addStretch()

        # 左下角设置按钮
        settings_layout = QHBoxLayout()
        settings_btn = QPushButton("⚙ 设置")
        settings_btn.setFixedWidth(80)
        settings_btn.setStyleSheet("""
            QPushButton {
                background: transparent; border: 1px solid #3a3a5a;
                border-radius: 4px; color: #777; padding: 4px 10px;
            }
            QPushButton:hover { border-color: #00d4ff; color: #00d4ff; }
        """)
        settings_btn.clicked.connect(self._on_settings if self._on_settings else lambda: None)
        settings_layout.addWidget(settings_btn)
        settings_layout.addStretch()
        layout.addLayout(settings_layout)


class MainWindow(QMainWindow):
    """主窗口 —— 管理欢迎页 / 快速模式页 / 完整模式页"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CodeSentinel - LLM Security Audit System")
        self.setMinimumSize(1100, 750)

        # 并发设置 — 共享 dict，所有页面引用同一份，改一处全改
        self._concurrency = {"value": 4}

        # 加载样式表
        self._load_stylesheet()

        # 页面栈
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        # 欢迎页
        self.welcome_page = WelcomePage(
            on_quick=self._show_quick,
            on_full=self._show_full,
            on_settings=self._show_settings,
        )
        self.stack.addWidget(self.welcome_page)

        # 各模式页面 (延迟创建)
        self.quick_page = None
        self.full_page = None

        self.stack.setCurrentWidget(self.welcome_page)

    def _load_stylesheet(self):
        """加载暗色主题样式表"""
        qss_path = Path(__file__).parent / "styles" / "dark_theme.qss"
        if qss_path.exists():
            with open(qss_path, 'r', encoding='utf-8') as f:
                self.setStyleSheet(f.read())
        else:
            # 内置最小暗色主题
            self.setStyleSheet("""
                QMainWindow, QWidget {
                    background-color: #0f0f23;
                    color: #e0e0e0;
                    font-family: -apple-system, 'Microsoft YaHei', 'Segoe UI', sans-serif;
                }
                QPushButton {
                    background: #1a1a3e;
                    border: 1px solid #2a2a4a;
                    border-radius: 6px;
                    padding: 8px 16px;
                    color: #e0e0e0;
                }
                QPushButton:hover {
                    background: #2a2a4e;
                    border-color: #00d4ff;
                }
                QPushButton:pressed {
                    background: #0f0f2e;
                }
                QLineEdit {
                    background: #0a0a1a;
                    border: 1px solid #2a2a4a;
                    border-radius: 6px;
                    padding: 8px 12px;
                    color: #e0e0e0;
                }
                QLineEdit:focus {
                    border-color: #00d4ff;
                }
                QProgressBar {
                    background: #0a0a1a;
                    border: 1px solid #2a2a4a;
                    border-radius: 4px;
                    text-align: center;
                    color: #e0e0e0;
                }
                QProgressBar::chunk {
                    background: #00d4ff;
                    border-radius: 3px;
                }
                QTableWidget {
                    background: #0a0a1a;
                    gridline-color: #1a1a3e;
                    border: 1px solid #2a2a4a;
                }
                QTableWidget::item {
                    padding: 4px 8px;
                }
                QTableWidget::item:selected {
                    background: #1a2a4a;
                }
                QHeaderView::section {
                    background: #1a1a3e;
                    border: 1px solid #2a2a4a;
                    padding: 6px;
                }
                QTextEdit {
                    background: #0a0a1a;
                    border: 1px solid #2a2a4a;
                    color: #e0e0e0;
                }
                QTabWidget::pane {
                    border: 1px solid #2a2a4a;
                    background: #0f0f23;
                }
                QTabBar::tab {
                    background: #1a1a3e;
                    border: 1px solid #2a2a4a;
                    padding: 6px 16px;
                    color: #888;
                }
                QTabBar::tab:selected {
                    background: #0f0f23;
                    color: #00d4ff;
                    border-bottom-color: #0f0f23;
                }
                QGroupBox {
                    border: 1px solid #2a2a4a;
                    border-radius: 8px;
                    margin-top: 10px;
                    padding-top: 16px;
                    color: #aaa;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 12px;
                    padding: 0 4px;
                }
            """)

    def _show_quick(self):
        """切换到快速模式页面"""
        if self.quick_page is None:
            from gui.quick_page import QuickScanPage
            self.quick_page = QuickScanPage(on_back=self._show_welcome,
                                             concurrency=self._concurrency)
            self.stack.addWidget(self.quick_page)
        self.stack.setCurrentWidget(self.quick_page)
        self.setWindowTitle("CodeSentinel - 快速扫描模式")

    def _show_full(self):
        """切换到完整模式页面"""
        if self.full_page is None:
            from gui.full_page import FullScanPage
            self.full_page = FullScanPage(on_back=self._show_welcome,
                                           concurrency=self._concurrency)
            self.stack.addWidget(self.full_page)
        self.stack.setCurrentWidget(self.full_page)
        self.setWindowTitle("CodeSentinel - 完整分析模式")

    def _show_settings(self):
        """打开设置弹窗"""
        from gui.settings_dialog import SettingsDialog
        dlg = SettingsDialog(current_concurrency=self._concurrency["value"], parent=self)
        if dlg.exec_():
            self._concurrency["value"] = dlg.concurrency

    def _show_welcome(self):
        """返回欢迎页"""
        self.stack.setCurrentWidget(self.welcome_page)
        self.setWindowTitle("CodeSentinel - LLM Security Audit System")
