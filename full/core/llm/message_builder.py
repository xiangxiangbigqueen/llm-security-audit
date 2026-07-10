"""LLM消息构建器"""
from typing import List, Dict


class MessageBuilder:
    """构建LLM对话消息列表"""

    def __init__(self, system_prompt: str):
        self.system_prompt = system_prompt
        self.messages: List[Dict[str, str]] = []

    def build(self) -> List[Dict[str, str]]:
        """构建完整消息列表"""
        result = [{"role": "system", "content": self.system_prompt}]
        result.extend(self.messages)
        return result

    def add_user_message(self, content: str) -> "MessageBuilder":
        """添加用户消息"""
        self.messages.append({"role": "user", "content": content})
        return self

    def add_assistant_message(self, content: str) -> "MessageBuilder":
        """添加助手消息"""
        self.messages.append({"role": "assistant", "content": content})
        return self

    def reset(self) -> "MessageBuilder":
        """重置对话"""
        self.messages = []
        return self

    @staticmethod
    def format_code_context(file_path: str, code: str, language: str = "") -> str:
        """格式化代码上下文"""
        return f"文件: {file_path}\n```{language}\n{code}\n```"

    @staticmethod
    def format_vulnerability_list(vulns: list) -> str:
        """格式化漏洞列表为文本"""
        import json
        return json.dumps([v.to_dict() if hasattr(v, 'to_dict') else v for v in vulns],
                         ensure_ascii=False, indent=2)