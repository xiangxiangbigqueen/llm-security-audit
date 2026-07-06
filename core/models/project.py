"""项目元信息数据模型"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ProjectMetadata:
    """项目元信息"""
    name: str
    path: str
    languages: Dict[str, float] = field(default_factory=dict)  # {语言: 百分比}
    file_count: int = 0
    total_lines: int = 0
    file_tree: Dict = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    source_url: Optional[str] = None
    branch: str = "main"

    @property
    def primary_language(self) -> str:
        """获取主要编程语言"""
        if not self.languages:
            return "Unknown"
        return max(self.languages, key=self.languages.get)

    @property
    def supported_languages(self) -> List[str]:
        """获取支持审计的语言列表"""
        supported = {"C", "C++", "PHP", "Python"}
        return [lang for lang in self.languages if lang in supported]