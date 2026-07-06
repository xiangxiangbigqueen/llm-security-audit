"""Progpilot PHP安全分析工具封装"""
import asyncio
import json
import logging
from typing import Dict, List

from config.settings import PROGPILOT_PATH

logger = logging.getLogger(__name__)


class ProgpilotTool:
    """Progpilot PHP安全分析工具"""

    def __init__(self):
        self.tool_path = PROGPILOT_PATH

    async def scan(self, target_path: str) -> Dict:
        """
        执行progpilot扫描
        Args:
            target_path: 待扫描的PHP文件或目录
        Returns:
            扫描结果字典
        """
        cmd = ["php", self.tool_path, target_path]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            output = stdout.decode('utf-8', errors='ignore')
            findings = self._parse_output(output)

            return {
                "tool": "progpilot",
                "target": target_path,
                "findings": findings,
                "raw_output": output[:5000],
            }
        except FileNotFoundError:
            logger.warning("progpilot或PHP未安装")
            return {"tool": "progpilot", "target": target_path, "findings": [], "error": "工具未安装"}
        except Exception as e:
            logger.error(f"progpilot扫描异常: {e}")
            return {"tool": "progpilot", "target": target_path, "findings": [], "error": str(e)}

    def _parse_output(self, output: str) -> List[Dict]:
        """解析progpilot输出"""
        findings = []
        try:
            data = json.loads(output)
            if isinstance(data, list):
                for item in data:
                    findings.append({
                        "file": item.get("source_file", ""),
                        "line": item.get("source_line", 0),
                        "message": item.get("vuln_name", ""),
                        "severity": "high",
                        "vuln_type": item.get("vuln_type", ""),
                    })
        except json.JSONDecodeError:
            logger.warning("无法解析progpilot输出")
        return findings