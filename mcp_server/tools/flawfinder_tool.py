"""Flawfinder静态分析工具封装"""
import asyncio
import json
import logging
from typing import Dict, List

from config.settings import FLAWFINDER_PATH

logger = logging.getLogger(__name__)


class FlawfinderTool:
    """Flawfinder C/C++安全漏洞扫描工具"""

    def __init__(self):
        self.tool_path = FLAWFINDER_PATH

    async def scan(self, target_path: str, min_level: int = 1) -> Dict:
        """
        执行flawfinder扫描
        Args:
            target_path: 待扫描的文件或目录
            min_level: 最低风险等级(1-5)
        Returns:
            扫描结果字典
        """
        cmd = [
            self.tool_path,
            "--minlevel", str(min_level),
            "--columns",
            "--dataonly",
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
                "tool": "flawfinder",
                "target": target_path,
                "findings": findings,
                "raw_output": output[:5000],
            }
        except FileNotFoundError:
            logger.warning(f"flawfinder未安装: {self.tool_path}")
            return {"tool": "flawfinder", "target": target_path, "findings": [], "error": "工具未安装"}
        except Exception as e:
            logger.error(f"flawfinder扫描异常: {e}")
            return {"tool": "flawfinder", "target": target_path, "findings": [], "error": str(e)}

    def _parse_output(self, output: str) -> List[Dict]:
        """解析flawfinder文本输出"""
        findings = []
        for line in output.strip().split('\n'):
            if not line.strip() or line.startswith('Flawfinder'):
                continue
            # 格式: file:line:col:  [level] (category)  message
            try:
                if ':' in line and '[' in line:
                    parts = line.split(':')
                    if len(parts) >= 3:
                        file_path = parts[0]
                        line_num = int(parts[1]) if parts[1].isdigit() else 0
                        rest = ':'.join(parts[2:])
                        findings.append({
                            "file": file_path,
                            "line": line_num,
                            "message": rest.strip(),
                            "severity": "warning",
                        })
            except (ValueError, IndexError):
                continue
        return findings