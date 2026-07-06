"""PHPStan静态分析工具封装"""
import asyncio
import json
import logging
from typing import Dict, List

from config.settings import PHPSTAN_PATH

logger = logging.getLogger(__name__)


class PHPStanTool:
    """PHPStan PHP静态类型分析工具"""

    def __init__(self):
        self.tool_path = PHPSTAN_PATH

    async def scan(self, target_path: str, level: int = 5) -> Dict:
        """
        执行PHPStan分析
        Args:
            target_path: 待分析的PHP文件或目录
            level: 分析等级(0-9)
        Returns:
            扫描结果字典
        """
        cmd = [
            self.tool_path,
            "analyse",
            "--level", str(level),
            "--error-format", "json",
            "--no-progress",
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
            findings = self._parse_json(output)

            return {
                "tool": "phpstan",
                "target": target_path,
                "findings": findings,
                "raw_output": output[:5000],
            }
        except FileNotFoundError:
            logger.warning(f"phpstan未安装: {self.tool_path}")
            return {"tool": "phpstan", "target": target_path, "findings": [], "error": "工具未安装"}
        except Exception as e:
            logger.error(f"phpstan分析异常: {e}")
            return {"tool": "phpstan", "target": target_path, "findings": [], "error": str(e)}

    def _parse_json(self, output: str) -> List[Dict]:
        """解析PHPStan JSON输出"""
        findings = []
        try:
            data = json.loads(output)
            if "files" in data:
                for file_path, file_data in data["files"].items():
                    for msg in file_data.get("messages", []):
                        findings.append({
                            "file": file_path,
                            "line": msg.get("line", 0),
                            "message": msg.get("message", ""),
                            "severity": "warning",
                        })
        except json.JSONDecodeError:
            logger.warning("无法解析phpstan JSON输出")
        return findings