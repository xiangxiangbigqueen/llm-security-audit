"""扫描智能体"""
import json
import os
from typing import List, Dict

from .base_agent import BaseAgent
from core.llm.deepseek_client import DeepSeekClient
from core.llm.message_builder import MessageBuilder
from core.models.vulnerability import Vulnerability
from core.models.project import ProjectMetadata
from config.prompts.scanner import SCANNER_SYSTEM_PROMPT, SCANNER_RESCAN_PROMPT, SCANNER_TOOL_RESULT_PROMPT
from mcp_server.server import MCPToolServer


class ScannerAgent(BaseAgent):
    """扫描智能体 - 对代码进行静态分析，识别潜在安全风险"""

    def __init__(self, llm_client: DeepSeekClient):
        super().__init__("Scanner", llm_client)
        self.mcp_server = MCPToolServer()

    async def scan(self, project: ProjectMetadata) -> List[Vulnerability]:
        """执行完整扫描流程"""
        self.status = "running"
        self._emit_progress(0.0, "开始扫描...")
        vulnerabilities = []

        try:
            # 1. 执行静态分析工具
            self._emit_progress(0.1, "执行静态分析工具...")
            tool_results = await self._run_static_tools(project)

            # 2. 获取目标文件
            from parser.language_detector import LanguageDetector
            detector = LanguageDetector()
            target_files = detector.get_target_files(project.path, project.supported_languages)

            # 3. 逐文件/批量进行LLM分析
            total_files = len(target_files)
            for i, file_path in enumerate(target_files):
                progress = 0.2 + (i / max(total_files, 1)) * 0.7
                rel_path = os.path.relpath(file_path, project.path)
                self._emit_progress(progress, f"分析文件: {rel_path}")

                # 读取文件内容
                content = await self.read_file_content(file_path)
                if not content.strip():
                    continue

                # 获取该文件的工具结果
                file_tool_findings = self._get_file_tool_findings(file_path, tool_results)

                # LLM分析
                vulns = await self._analyze_file(file_path, content, file_tool_findings, project)
                vulnerabilities.extend(vulns)

            self._emit_progress(1.0, f"扫描完成，发现 {len(vulnerabilities)} 个潜在漏洞")
            self.status = "completed"

        except Exception as e:
            self.status = "error"
            self._emit_log("error", f"扫描异常: {e}")
            raise

        return vulnerabilities

    async def rescan_with_context(self, vulns: List[Vulnerability], additional_context: str) -> List[Vulnerability]:
        """根据反馈重新扫描"""
        self._emit_progress(0.0, "根据反馈重新分析...")

        builder = MessageBuilder(SCANNER_SYSTEM_PROMPT)
        prompt = SCANNER_RESCAN_PROMPT.format(
            feedback=additional_context,
            additional_context=json.dumps([v.to_dict() for v in vulns], ensure_ascii=False)
        )
        builder.add_user_message(prompt)

        try:
            result = await self.llm_client.chat_json(builder.build())
            new_vulns = self._parse_vulnerabilities(result)
            self._emit_progress(1.0, f"重新分析完成，发现 {len(new_vulns)} 个漏洞")
            return new_vulns
        except Exception as e:
            self._emit_log("warning", f"重新分析失败: {e}")
            return vulns

    async def _run_static_tools(self, project: ProjectMetadata) -> List[Dict]:
        """运行静态分析工具"""
        languages = project.supported_languages
        if not languages:
            return []
        results = await self.mcp_server.run_all(project.path, languages)
        return results

    def _get_file_tool_findings(self, file_path: str, tool_results: List[Dict]) -> str:
        """获取特定文件的工具发现"""
        findings = []
        for result in tool_results:
            for finding in result.get("findings", []):
                if finding.get("file", "") in file_path or file_path.endswith(finding.get("file", "NOMATCH")):
                    findings.append(f"[{result['tool']}] Line {finding.get('line', '?')}: {finding.get('message', '')}")
        return "\n".join(findings) if findings else "无工具发现"

    async def _analyze_file(self, file_path: str, content: str, tool_findings: str, project: ProjectMetadata) -> List[Vulnerability]:
        """使用LLM分析单个文件"""
        builder = MessageBuilder(SCANNER_SYSTEM_PROMPT)

        # 构建用户消息
        user_msg = f"""请分析以下代码文件的安全漏洞:

文件路径: {os.path.relpath(file_path, project.path)}
编程语言: {project.primary_language}

静态工具发现:
{tool_findings}

源代码:
```
{content[:8000]}
```

请识别所有安全漏洞并以JSON格式输出。"""

        builder.add_user_message(user_msg)

        try:
            result = await self.llm_client.chat_json(builder.build())
            return self._parse_vulnerabilities(result, file_path)
        except Exception as e:
            self._emit_log("warning", f"文件分析失败 {file_path}: {e}")
            return []

    def _parse_vulnerabilities(self, data: dict, default_file: str = "") -> List[Vulnerability]:
        """解析LLM返回的漏洞数据"""
        vulnerabilities = []
        for item in data.get("vulnerabilities", []):
            try:
                vuln = Vulnerability(
                    vulnerability_type=item.get("vulnerability_type", "Unknown"),
                    severity=item.get("severity", "medium"),
                    file_path=item.get("file_path", default_file),
                    line_number=item.get("line_number", 0),
                    code_snippet=item.get("code_snippet", ""),
                    data_flow=item.get("data_flow", ""),
                    reasoning=item.get("reasoning", ""),
                )
                vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.warning(f"解析漏洞数据失败: {e}")
        return vulnerabilities