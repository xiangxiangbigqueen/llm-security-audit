"""验证智能体"""
import json
import os
from typing import List, Dict, Tuple

from .base_agent import BaseAgent
from core.llm.deepseek_client import DeepSeekClient
from core.llm.message_builder import MessageBuilder
from core.models.vulnerability import Vulnerability
from core.models.project import ProjectMetadata
from config.prompts.validator import VALIDATOR_SYSTEM_PROMPT, VALIDATOR_CONTEXT_PROMPT


class ValidatorAgent(BaseAgent):
    """验证智能体 - 独立复核扫描结果，过滤误报"""

    def __init__(self, llm_client: DeepSeekClient):
        super().__init__("Validator", llm_client)

    async def validate(
        self, vulnerabilities: List[Vulnerability], project: ProjectMetadata
    ) -> Dict[str, List[Vulnerability]]:
        """
        验证漏洞列表
        Returns:
            {"confirmed": [...], "rejected": [...], "need_more_context": [...]}
        """
        self.status = "running"
        self._emit_progress(0.0, f"开始验证 {len(vulnerabilities)} 个漏洞...")

        confirmed = []
        rejected = []
        need_more_context = []

        total = len(vulnerabilities)
        for i, vuln in enumerate(vulnerabilities):
            progress = (i + 1) / max(total, 1)
            self._emit_progress(progress, f"验证漏洞 #{i+1}/{total}: {vuln.vulnerability_type}")

            # 读取漏洞相关代码上下文
            context_code = await self._get_context_code(vuln, project)

            # LLM验证
            judgment = await self._validate_single(vuln, context_code, project)

            if judgment["judgment"] == "CONFIRMED":
                vuln.validation_status = "confirmed"
                vuln.validation_confidence = judgment.get("confidence", 0.8)
                vuln.validation_reasoning = judgment.get("reasoning", "")
                vuln.defense_measures = judgment.get("defense_measures_found", [])
                confirmed.append(vuln)
            elif judgment["judgment"] == "NEED_MORE_CONTEXT":
                vuln.validation_status = "need_more_context"
                vuln.validation_reasoning = judgment.get("requested_context", "")
                need_more_context.append(vuln)
            else:
                vuln.validation_status = "rejected"
                vuln.validation_reasoning = judgment.get("reasoning", "")
                rejected.append(vuln)

        self._emit_progress(1.0, f"验证完成: 确认{len(confirmed)} 误报{len(rejected)} 待补充{len(need_more_context)}")
        self.status = "completed"

        return {
            "confirmed": confirmed,
            "rejected": rejected,
            "need_more_context": need_more_context,
        }

    async def _validate_single(self, vuln: Vulnerability, context_code: str, project: ProjectMetadata) -> Dict:
        """验证单个漏洞"""
        builder = MessageBuilder(VALIDATOR_SYSTEM_PROMPT)

        vuln_info = json.dumps(vuln.to_dict(), ensure_ascii=False, indent=2)
        prompt = VALIDATOR_CONTEXT_PROMPT.format(
            vulnerability_info=vuln_info,
            source_code=context_code[:6000],
            project_structure=json.dumps(project.file_tree, ensure_ascii=False)[:2000],
        )
        builder.add_user_message(prompt)

        try:
            result = await self.llm_client.chat_json(builder.build())
            validations = result.get("validations", [])
            if validations:
                return validations[0]
            return {"judgment": "CONFIRMED", "confidence": 0.5, "reasoning": "默认通过"}
        except Exception as e:
            self._emit_log("warning", f"验证失败: {e}")
            return {"judgment": "CONFIRMED", "confidence": 0.3, "reasoning": f"验证异常，默认保留: {e}"}

    async def _get_context_code(self, vuln: Vulnerability, project: ProjectMetadata) -> str:
        """获取漏洞周围的代码上下文"""
        file_path = vuln.file_path
        if not os.path.isabs(file_path):
            file_path = os.path.join(project.path, file_path)

        if not os.path.exists(file_path):
            return f"[文件不存在: {vuln.file_path}]"

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # 获取漏洞行周围的上下文 (前后30行)
            start = max(0, vuln.line_number - 30)
            end = min(len(lines), vuln.line_number + 30)
            context_lines = lines[start:end]

            # 添加行号
            numbered = [f"{start + i + 1}: {line}" for i, line in enumerate(context_lines)]
            return f"文件: {vuln.file_path}\n" + ''.join(numbered)
        except Exception as e:
            return f"[读取文件失败: {e}]"