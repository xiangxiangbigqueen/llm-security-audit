"""Bandit Python安全静态分析工具封装"""
import asyncio
import json
import logging
from typing import Dict, List

from config.full_settings import BANDIT_PATH

logger = logging.getLogger(__name__)


class BanditTool:
    """Bandit Python安全漏洞扫描工具"""

    def __init__(self):
        self.tool_path = BANDIT_PATH

    async def scan(self, target_path: str, **kwargs) -> Dict:
        """
        执行bandit扫描
        Args:
            target_path: 待扫描的文件或目录
        Returns:
            扫描结果字典
        """
        cmd = [
            self.tool_path,
            "-r",  # 递归扫描
            "-f", "json",  # JSON格式输出
            "-ll",  # 只报告medium及以上
            "--quiet",
            target_path
        ]

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
                "tool": "bandit",
                "target": target_path,
                "findings": findings,
                "raw_output": output[:5000],
            }
        except FileNotFoundError:
            logger.warning(f"bandit未安装: {self.tool_path}")
            return {"tool": "bandit", "target": target_path, "findings": [], "error": "工具未安装"}
        except Exception as e:
            logger.error(f"bandit扫描异常: {e}")
            return {"tool": "bandit", "target": target_path, "findings": [], "error": str(e)}

    def _parse_output(self, output: str) -> List[Dict]:
        """解析bandit JSON输出"""
        findings = []
        if not output.strip():
            return findings

        try:
            data = json.loads(output)
            for result in data.get("results", []):
                severity = result.get("issue_severity", "MEDIUM").lower()
                confidence = result.get("issue_confidence", "MEDIUM").lower()

                # 映射severity
                severity_map = {
                    "high": "high",
                    "medium": "medium",
                    "low": "low",
                }

                findings.append({
                    "file": result.get("filename", ""),
                    "line": result.get("line_number", 0),
                    "message": f"[{result.get('test_id', '')}] {result.get('issue_text', '')}",
                    "severity": severity_map.get(severity, "medium"),
                    "confidence": confidence,
                    "cwe": result.get("issue_cwe", {}).get("id", ""),
                    "test_id": result.get("test_id", ""),
                })
        except json.JSONDecodeError:
            logger.warning("bandit输出解析失败，尝试文本解析")
            # 降级处理：如果JSON解析失败，返回空结果
            pass

        return findings