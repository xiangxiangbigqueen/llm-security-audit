"""智能体基类"""
import logging
import time
from typing import Any, Dict, Optional
from dataclasses import dataclass, field

from core.llm.deepseek_client import DeepSeekClient
from core.llm.message_builder import MessageBuilder


@dataclass
class AgentMessage:
    """智能体间通信消息"""
    sender: str
    receiver: str
    msg_type: str
    payload: Dict
    timestamp: float = field(default_factory=time.time)
    correlation_id: str = ""


class BaseAgent:
    """智能体基类"""

    def __init__(self, name: str, llm_client: DeepSeekClient):
        self.name = name
        self.llm_client = llm_client
        self.logger = logging.getLogger(f"agent.{name}")
        self.status = "idle"  # idle/running/completed/error
        self.progress = 0.0
        self._callbacks = []

    def on_progress(self, callback):
        """注册进度回调"""
        self._callbacks.append(callback)

    def _emit_progress(self, progress: float, message: str = ""):
        """触发进度更新"""
        self.progress = progress
        for cb in self._callbacks:
            try:
                cb(self.name, progress, message)
            except Exception:
                pass

    def _emit_log(self, level: str, message: str):
        """触发日志事件"""
        self.logger.info(f"[{self.name}] {message}")
        for cb in self._callbacks:
            try:
                cb(self.name, self.progress, f"[{level.upper()}] {message}")
            except Exception:
                pass

    async def read_file_content(self, file_path: str, max_lines: int = 400) -> str:
        """读取源代码文件内容"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[:max_lines]
                return ''.join(lines)
        except Exception as e:
            self.logger.warning(f"读取文件失败 {file_path}: {e}")
            return ""