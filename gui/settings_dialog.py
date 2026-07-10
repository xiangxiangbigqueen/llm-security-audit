"""设置弹窗 —— 允许用户在扫描前调整并发数和 API Key"""
import os
from pathlib import Path

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QSpinBox, QPushButton, QGroupBox,
    QLineEdit,
)
from PyQt5.QtCore import Qt

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"


def _read_env_key() -> str:
    """从 .env 文件读取 DEEPSEEK_API_KEY"""
    if not ENV_FILE.exists():
        return ""
    with open(ENV_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith("DEEPSEEK_API_KEY="):
                return line.split("=", 1)[1].strip()
    return ""


def _write_env_key(key: str):
    """将 API Key 写入 .env 文件（同时更新 LLM_API_KEY）"""
    lines = []
    if ENV_FILE.exists():
        with open(ENV_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()

    found_deepseek = False
    found_llm = False
    for i, line in enumerate(lines):
        if line.startswith("DEEPSEEK_API_KEY="):
            lines[i] = f"DEEPSEEK_API_KEY={key}\n"
            found_deepseek = True
        elif line.startswith("LLM_API_KEY="):
            lines[i] = f"LLM_API_KEY={key}\n"
            found_llm = True

    if not found_deepseek:
        lines.append(f"DEEPSEEK_API_KEY={key}\n")
    if not found_llm:
        lines.append(f"LLM_API_KEY={key}\n")

    with open(ENV_FILE, 'w', encoding='utf-8') as f:
        f.writelines(lines)

    # 同步更新到环境变量
    os.environ["DEEPSEEK_API_KEY"] = key
    os.environ["LLM_API_KEY"] = key


class SettingsDialog(QDialog):
    """设置对话框"""

    def __init__(self, current_concurrency: int = 4, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置")
        self.setMinimumWidth(400)
        self._concurrency = current_concurrency
        self._api_key = _read_env_key()
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # API Key 设置
        api_group = QGroupBox("API Key")
        api_layout = QVBoxLayout(api_group)

        api_desc = QLabel("请配置 API Key 以进行 LLM 深度分析。\nDeepSeek API Key 获取地址: https://platform.deepseek.com")
        api_desc.setStyleSheet("color: #888; font-size: 12px;")
        api_desc.setWordWrap(True)
        api_layout.addWidget(api_desc)

        self.api_input = QLineEdit()
        self.api_input.setPlaceholderText("sk-xxxxxxxxxxxxxxxx")
        if self._api_key:
            self.api_input.setText(self._api_key)
        self.api_input.setEchoMode(QLineEdit.Password)
        self.api_input.setStyleSheet(
            "QLineEdit { background: #0a0a1a; border: 1px solid #2a2a4a; color: #e0e0e0; padding: 6px; border-radius: 4px; }"
            "QLineEdit:focus { border-color: #00d4ff; }"
        )
        api_layout.addWidget(self.api_input)

        # 显示/隐藏切换
        self.show_key_btn = QPushButton("显示")
        self.show_key_btn.setFixedWidth(60)
        self.show_key_btn.setStyleSheet("QPushButton { font-size: 11px; padding: 2px 6px; }")
        self.show_key_btn.clicked.connect(self._toggle_key_visibility)
        show_layout = QHBoxLayout()
        show_layout.addWidget(self.show_key_btn)
        show_layout.addStretch()
        api_layout.addLayout(show_layout)

        layout.addWidget(api_group)

        # 并发数设置
        group = QGroupBox("扫描并发数")
        group_layout = QVBoxLayout(group)

        desc = QLabel("同时分析的文件数。数值越大速度越快，但可能触发 API 速率限制。\n建议: 4-8 (免费API) / 8-16 (付费API)")
        desc.setStyleSheet("color: #888; font-size: 12px;")
        desc.setWordWrap(True)
        group_layout.addWidget(desc)

        spin_layout = QHBoxLayout()
        spin_layout.addWidget(QLabel("最大并发数:"))
        self.spin = QSpinBox()
        self.spin.setRange(1, 32)
        self.spin.setValue(self._concurrency)
        self.spin.setStyleSheet(
            "QSpinBox { background: #0a0a1a; border: 1px solid #2a2a4a; color: #e0e0e0; padding: 6px; border-radius: 4px; }"
        )
        spin_layout.addWidget(self.spin)
        spin_layout.addStretch()
        group_layout.addLayout(spin_layout)
        layout.addWidget(group)

        layout.addStretch()

        # 按钮
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self._on_save)
        save_btn.setStyleSheet("QPushButton { background: #1a3a5e; color: #00d4ff; border-color: #00d4ff; }")
        btn_layout.addWidget(save_btn)
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def _toggle_key_visibility(self):
        if self.api_input.echoMode() == QLineEdit.Password:
            self.api_input.setEchoMode(QLineEdit.Normal)
            self.show_key_btn.setText("隐藏")
        else:
            self.api_input.setEchoMode(QLineEdit.Password)
            self.show_key_btn.setText("显示")

    def _on_save(self):
        key = self.api_input.text().strip()
        if key:
            _write_env_key(key)
        self.accept()

    @property
    def concurrency(self) -> int:
        return self.spin.value()
