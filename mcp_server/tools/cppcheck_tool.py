"""Cppcheck静态分析工具封装"""
import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List

from config.settings import CPPCHECK_PATH

logger = logging.getLogger(__name__)


class CppcheckTool:
    """Cppcheck C/C++静态分析工具"""

    def __init__(self):
        self.tool_path = CPPCHECK_PATH

    async def scan(self, target_path: str, enable_checks: List[str] = None) -> Dict:
        """
        执行cppcheck扫描
        Args:
            target_path: 待扫描的文件或目录
            enable_checks: 启用的检查类别
        Returns:
            扫描结果字典
        """
        if enable_checks is None:
            enable_checks = ["all"]

        cmd = [
            self.tool_path,
            "--enable=" + ",".join(enable_checks),
            "--xml",
            "--xml-version=2",
            "--force",
            target_path
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            # cppcheck输出XML到stderr
            xml_output = stderr.decode('utf-8', errors='ignore')
            findings = self._parse_xml(xml_output)

            return {
                "tool": "cppcheck",
                "target": target_path,
                "findings": findings,
                "raw_output": xml_output[:5000],  # 限制长度
            }
        except FileNotFoundError:
            logger.warning(f"cppcheck未安装或路径错误: {self.tool_path}")
            return {"tool": "cppcheck", "target": target_path, "findings": [], "error": "工具未安装"}
        except Exception as e:
            logger.error(f"cppcheck扫描异常: {e}")
            return {"tool": "cppcheck", "target": target_path, "findings": [], "error": str(e)}

    def _parse_xml(self, xml_str: str) -> List[Dict]:
        """解析cppcheck XML输出"""
        findings = []
        try:
            root = ET.fromstring(xml_str)
            for error in root.findall('.//error'):
                severity = error.get('severity', 'unknown')
                if severity in ('error', 'warning', 'style', 'performance', 'portability'):
                    location = error.find('location')
                    finding = {
                        "id": error.get('id', ''),
                        "severity": severity,
                        "message": error.get('msg', ''),
                        "verbose": error.get('verbose', ''),
                        "file": location.get('file', '') if location is not None else '',
                        "line": int(location.get('line', 0)) if location is not None else 0,
                    }
                    findings.append(finding)
        except ET.ParseError:
            logger.warning("无法解析cppcheck XML输出")
        return findings