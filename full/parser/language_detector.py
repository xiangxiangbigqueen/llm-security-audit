"""语言识别模块"""
import os
from pathlib import Path
from typing import Dict
from config.full_settings import LANGUAGE_EXTENSIONS


class LanguageDetector:
    """代码语言检测器"""

    def __init__(self):
        # 构建扩展名到语言的映射
        self.ext_to_lang: Dict[str, str] = {}
        for lang, exts in LANGUAGE_EXTENSIONS.items():
            for ext in exts:
                self.ext_to_lang[ext] = lang

    def detect(self, repo_path: str) -> Dict[str, float]:
        """
        识别项目语言分布
        返回 {语言: 百分比}
        """
        lang_counts: Dict[str, int] = {}
        total_files = 0

        for root, dirs, files in os.walk(repo_path):
            # 跳过隐藏目录和常见非代码目录
            dirs[:] = [d for d in dirs if not d.startswith('.')
                       and d not in ('node_modules', 'vendor', '.git', '__pycache__', 'build', 'dist')]

            for filename in files:
                ext = Path(filename).suffix.lower()
                if ext in self.ext_to_lang:
                    lang = self.ext_to_lang[ext]
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1
                    total_files += 1

        if total_files == 0:
            return {}

        # 计算百分比
        return {lang: round(count / total_files * 100, 1)
                for lang, count in sorted(lang_counts.items(),
                                          key=lambda x: x[1], reverse=True)}

    def get_target_files(self, repo_path: str, languages: list = None) -> list:
        """获取目标语言的所有源文件路径"""
        target_exts = set()
        if languages:
            for lang in languages:
                if lang in LANGUAGE_EXTENSIONS:
                    target_exts.update(LANGUAGE_EXTENSIONS[lang])
        else:
            for exts in LANGUAGE_EXTENSIONS.values():
                target_exts.update(exts)

        files = []
        for root, dirs, filenames in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')
                       and d not in ('node_modules', 'vendor', '.git', '__pycache__', 'build', 'dist')]
            for filename in filenames:
                if Path(filename).suffix.lower() in target_exts:
                    files.append(os.path.join(root, filename))
        return files