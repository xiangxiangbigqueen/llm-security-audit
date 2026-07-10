"""MCP工具服务管理器 - 统一管理所有静态分析工具"""
import logging
from typing import Dict, List

from .tools.cppcheck_tool import CppcheckTool
from .tools.flawfinder_tool import FlawfinderTool
from .tools.phpstan_tool import PHPStanTool
from .tools.progpilot_tool import ProgpilotTool
from .tools.bandit_tool import BanditTool

logger = logging.getLogger(__name__)


class MCPToolServer:
    """MCP工具服务器 - 管理所有静态分析工具"""

    def __init__(self):
        self.tools = {
            "cppcheck": CppcheckTool(),
            "flawfinder": FlawfinderTool(),
            "phpstan": PHPStanTool(),
            "progpilot": ProgpilotTool(),
            "bandit": BanditTool(),
        }

    def get_tools_for_language(self, language: str) -> List[str]:
        """根据语言获取适用的工具列表"""
        lang_tools = {
            "C": ["cppcheck", "flawfinder"],
            "C++": ["cppcheck", "flawfinder"],
            "PHP": ["phpstan", "progpilot"],
            "Python": ["bandit"],
        }
        return lang_tools.get(language, [])

    async def run_tool(self, tool_name: str, target_path: str, **kwargs) -> Dict:
        """执行指定工具"""
        if tool_name not in self.tools:
            return {"error": f"未知工具: {tool_name}"}

        tool = self.tools[tool_name]
        logger.info(f"执行工具 [{tool_name}] -> {target_path}")
        result = await tool.scan(target_path, **kwargs)
        logger.info(f"工具 [{tool_name}] 完成, 发现 {len(result.get('findings', []))} 个问题")
        return result

    async def run_all_for_language(self, language: str, target_path: str) -> List[Dict]:
        """对指定语言执行所有适用工具"""
        tool_names = self.get_tools_for_language(language)
        results = []

        for tool_name in tool_names:
            result = await self.run_tool(tool_name, target_path)
            results.append(result)

        return results

    async def run_all(self, target_path: str, languages: List[str]) -> List[Dict]:
        """对所有语言执行适用工具"""
        all_results = []
        processed_tools = set()

        for lang in languages:
            tool_names = self.get_tools_for_language(lang)
            for tool_name in tool_names:
                if tool_name not in processed_tools:
                    result = await self.run_tool(tool_name, target_path)
                    all_results.append(result)
                    processed_tools.add(tool_name)

        return all_results

    def get_available_tools(self) -> List[str]:
        """获取所有可用工具名称"""
        return list(self.tools.keys())