"""报告智能体"""
import json
from typing import List, Dict

from .base_agent import BaseAgent
from core.llm.deepseek_client import DeepSeekClient
from core.llm.message_builder import MessageBuilder
from core.models.vulnerability import Vulnerability
from core.models.project import ProjectMetadata
from config.prompts.reporter import REPORTER_SYSTEM_PROMPT, REPORTER_CONTEXT_PROMPT


class ReporterAgent(BaseAgent):
    """报告智能体 - 整合所有结果，生成结构化审计报告"""

    def __init__(self, llm_client: DeepSeekClient):
        super().__init__("Reporter", llm_client)

    async def generate(
        self, project: ProjectMetadata, vulnerabilities: List[Vulnerability]
    ) -> Dict:
        """生成审计报告内容"""
        self.status = "running"
        self._emit_progress(0.0, "生成审计报告...")

        # 构建报告数据
        report_data = await self._generate_report_content(project, vulnerabilities)

        self._emit_progress(1.0, "报告生成完成")
        self.status = "completed"
        return report_data

    async def _generate_report_content(self, project: ProjectMetadata, vulnerabilities: List[Vulnerability]) -> Dict:
        """使用LLM生成报告内容"""
        builder = MessageBuilder(REPORTER_SYSTEM_PROMPT)

        # 漏洞摘要
        vuln_summary = {
            "critical": sum(1 for v in vulnerabilities if v.severity == "critical"),
            "high": sum(1 for v in vulnerabilities if v.severity == "high"),
            "medium": sum(1 for v in vulnerabilities if v.severity == "medium"),
            "low": sum(1 for v in vulnerabilities if v.severity == "low"),
        }

        prompt = REPORTER_CONTEXT_PROMPT.format(
            project_info=json.dumps({
                "name": project.name,
                "languages": project.languages,
                "file_count": project.file_count,
                "total_lines": project.total_lines,
                "source_url": project.source_url or "本地项目",
            }, ensure_ascii=False),
            vulnerabilities=json.dumps([v.to_dict() for v in vulnerabilities], ensure_ascii=False, indent=2)[:8000],
            exploits=json.dumps([{"id": v.vulnerability_id, "poc": v.poc_code[:500], "impact": v.impact_analysis}
                                 for v in vulnerabilities if v.poc_code], ensure_ascii=False)[:4000],
        )
        builder.add_user_message(prompt)

        try:
            result= await self.llm_client.chat_json(builder.build())
            result["vulnerabilities_summary"] = vuln_summary
            result["project_info"] = {
                "name": project.name,
                "path": project.path,
                "languages": project.languages,
                "file_count": project.file_count,
            }
            result["vulnerabilities"] = [v.to_dict() for v in vulnerabilities]
            return result
        except Exception as e:
            self._emit_log("warning", f"报告生成LLM调用失败: {e}")
            # 返回基础报告
            return {
                "executive_summary": f"CodeSentinel 安全审计报告 - {project.name}",
                "risk_score": min(100, len(vulnerabilities) * 15),
                "vulnerabilities_summary": vuln_summary,
                "project_info": {"name": project.name, "languages": project.languages},
                "vulnerabilities": [v.to_dict() for v in vulnerabilities],
                "detailed_findings": [],
            }