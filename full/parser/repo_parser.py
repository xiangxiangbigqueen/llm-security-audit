"""代码仓库解析器"""
import os
import logging
import tempfile
from pathlib import Path
from typing import Dict, Optional

import git

from config.full_settings import TEMP_REPO_DIR
from core.models.project import ProjectMetadata
from .language_detector import LanguageDetector

logger = logging.getLogger(__name__)


class RepoParser:
    """代码仓库解析器"""

    def __init__(self):
        self.lang_detector = LanguageDetector()

    def clone_repo(self, url: str, branch: str = "main") -> str:
        """克隆远程仓库到本地临时目录，返回本地路径"""
        repo_name = url.rstrip('/').split('/')[-1].replace('.git', '')
        target_dir = str(TEMP_REPO_DIR / repo_name)

        if os.path.exists(target_dir):
            logger.info(f"仓库已存在本地: {target_dir}")
            return target_dir

        logger.info(f"正在克隆仓库: {url} -> {target_dir}")
        try:
            git.Repo.clone_from(url, target_dir, branch=branch, depth=1)
            logger.info(f"仓库克隆完成: {target_dir}")
        except git.GitCommandError as e:
            # 尝试不指定分支
            try:
                git.Repo.clone_from(url, target_dir, depth=1)
                logger.info(f"仓库克隆完成(默认分支): {target_dir}")
            except git.GitCommandError as e2:
                raise RuntimeError(f"克隆仓库失败: {e2}")

        return target_dir

    def parse_local(self, path: str) -> str:
        """处理本地目录输入"""
        if not os.path.isdir(path):
            raise ValueError(f"路径不存在或不是目录: {path}")
        return os.path.abspath(path)

    def extract_structure(self, repo_path: str, max_depth: int = 3) -> Dict:
        """提取文件结构树"""
        tree = {}

        def _walk(current_path: str, current_dict: Dict, depth: int):
            if depth > max_depth:
                return
            try:
                entries = sorted(os.listdir(current_path))
            except PermissionError:
                return

            for entry in entries:
                if entry.startswith('.') or entry in ('node_modules', 'vendor', '__pycache__', 'build', 'dist'):
                    continue
                full_path = os.path.join(current_path, entry)
                if os.path.isdir(full_path):
                    current_dict[entry + '/'] = {}
                    _walk(full_path, current_dict[entry + '/'], depth + 1)
                else:
                    current_dict[entry] = None

        _walk(repo_path, tree, 0)
        return tree

    def count_lines(self, file_path: str) -> int:
        """统计文件行数"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except Exception:
            return 0

    def get_metadata(self, repo_path: str, source_url: str = None) -> ProjectMetadata:
        """汇总项目元信息"""
        repo_path = os.path.abspath(repo_path)
        name = os.path.basename(repo_path)

        # 语言识别
        languages = self.lang_detector.detect(repo_path)

        # 文件统计
        target_files = self.lang_detector.get_target_files(repo_path)
        file_count = len(target_files)
        total_lines = sum(self.count_lines(f) for f in target_files)

        # 文件结构
        file_tree = self.extract_structure(repo_path)

        # 依赖检测
        dependencies = self._detect_dependencies(repo_path)

        return ProjectMetadata(
            name=name,
            path=repo_path,
            languages=languages,
            file_count=file_count,
            total_lines=total_lines,
            file_tree=file_tree,
            dependencies=dependencies,
            source_url=source_url,
        )

    def _detect_dependencies(self, repo_path: str) -> list:
        """检测项目依赖文件"""
        dep_files = ['Makefile', 'CMakeLists.txt', 'composer.json', 'package.json', 'requirements.txt']
        found = []
        for dep_file in dep_files:
            if os.path.exists(os.path.join(repo_path, dep_file)):
                found.append(dep_file)
        return found