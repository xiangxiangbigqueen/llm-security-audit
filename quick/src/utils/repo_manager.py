"""
仓库接入模块
功能：支持 GitHub/GitLab URL 或本地项目目录的接入

【主流技术使用标注】
★ GitHub/GitLab 集成: 自动识别 URL 类型，支持远程仓库克隆（行 42-47, 58-86）
★ Git 主流实践: shallow clone（--depth=1）快速拉取（行 77-78）
★ URL 解析: 使用 urllib.parse 进行标准 URL 解析（行 98-106）
★ 多语言识别: 自动检测项目使用的编程语言（行 108-136）
★ 文件过滤: 智能排除非代码文件和二进制文件（行 138-179）
"""

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional
import subprocess
import json
import urllib.parse


class RepoManager:
    """仓库管理器：克隆/加载目标项目"""

    def __init__(self, target: str, work_dir: Optional[str] = None):
        """
        初始化仓库管理器

        Args:
            target: GitHub/GitLab URL 或本地目录路径
            work_dir: 工作目录（克隆到此目录下）
        """
        self.target = target
        self.work_dir = work_dir or os.path.join(os.getcwd(), "workspace")
        self.repo_name = None
        self.repo_path = None
        self.repo_type = None  # 'local', 'github', 'gitlab'
        self.language_stats = {}

    def resolve(self) -> str:
        """
        解析并获取目标项目代码

        Returns:
            项目本地路径
        """
        if os.path.isdir(self.target):
            return self._load_local()
        elif self._is_git_url(self.target):
            return self._clone_repo()
        else:
            raise ValueError(f"无法识别的目标: {self.target}。请提供本地目录或Git URL。")

    def _load_local(self) -> str:
        """加载本地目录"""
        self.repo_path = os.path.abspath(self.target)
        self.repo_name = os.path.basename(self.repo_path)
        self.repo_type = 'local'
        print(f"  ✓ 加载本地项目: {self.repo_path}")
        self._analyze_languages()
        return self.repo_path

    def _clone_repo(self) -> str:
        """克隆远程仓库"""
        self.repo_name = self._extract_repo_name(self.target)
        self.repo_path = os.path.join(self.work_dir, self.repo_name)

        # 检测 URL 类型
        if 'github.com' in self.target:
            self.repo_type = 'github'
        elif 'gitlab.com' in self.target:
            self.repo_type = 'gitlab'
        else:
            self.repo_type = 'git'

        # 如果已存在则跳过克隆
        if os.path.exists(self.repo_path):
            print(f"  ✓ 项目已存在: {self.repo_path}")
        else:
            os.makedirs(self.work_dir, exist_ok=True)
            print(f"  → 正在克隆仓库: {self.target}")
            result = subprocess.run(
                ["git", "clone", "--depth=1", self.target, self.repo_path],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode != 0:
                raise RuntimeError(f"克隆失败: {result.stderr}")
            print(f"  ✓ 克隆完成: {self.repo_path}")

        self._analyze_languages()
        return self.repo_path

    def _is_git_url(self, url: str) -> bool:
        """判断是否为 Git URL"""
        git_patterns = [
            r'^https?://(github|gitlab)\.com/',
            r'^git@',
            r'^ssh://',
            r'\.git$',
        ]
        return any(re.match(p, url) for p in git_patterns)

    def _extract_repo_name(self, url: str) -> str:
        """从 URL 提取仓库名"""
        # 处理 https://github.com/user/repo.git
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.strip('/')
        if path.endswith('.git'):
            path = path[:-4]
        # path = "user/repo"
        return path.replace('/', '_')

    def _analyze_languages(self):
        """分析项目使用的编程语言（简化版）"""
        from config.quick_settings import SCAN_CONFIG

        ext_map = {}
        for lang, exts in SCAN_CONFIG["languages"].items():
            for ext in exts:
                ext_map[ext] = lang

        counts = {}
        for root, dirs, files in os.walk(self.repo_path):
            # 排除不需要的目录
            dirs[:] = [d for d in dirs if not d.startswith('.')
                       and d not in ('node_modules', 'vendor', 'dist', 'build',
                                     '__pycache__', '.git')]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in ext_map:
                    lang = ext_map[ext]
                    counts[lang] = counts.get(lang, 0) + 1

        self.language_stats = dict(sorted(
            counts.items(), key=lambda x: x[1], reverse=True
        ))

        if self.language_stats:
            print(f"  📊 项目语言分布: {', '.join(f'{k}({v} files)' for k, v in self.language_stats.items())}")
        else:
            print(f"  ⚠️  未识别到支持的代码文件")

    def get_file_list(self) -> list:
        """获取项目文件列表（排除非代码文件）"""
        from config.quick_settings import SCAN_CONFIG
        import fnmatch

        files = []
        exclude = SCAN_CONFIG["exclude_patterns"]

        for root, dirs, filenames in os.walk(self.repo_path):
            # 跳过隐藏目录和常见非代码目录
            dirs[:] = [d for d in dirs if not d.startswith('.')
                       and d not in ('node_modules', 'vendor', 'dist', 'build',
                                     '__pycache__', '.git', 'venv', 'env')]
            for f in filenames:
                filepath = os.path.join(root, f)
                relpath = os.path.relpath(filepath, self.repo_path)

                # 检查排除模式
                excluded = False
                for pat in exclude:
                    if fnmatch.fnmatch(relpath, pat) or fnmatch.fnmatch(f, pat):
                        excluded = True
                        break

                if not excluded:
                    size = os.path.getsize(filepath)
                    if size <= SCAN_CONFIG["max_file_size"]:
                        files.append({
                            "path": filepath,
                            "relpath": relpath,
                            "size": size,
                            "ext": os.path.splitext(f)[1].lower(),
                        })

        # 按文件大小排序，小的优先分析
        files.sort(key=lambda x: x["size"])

        # 限制文件数量
        if len(files) > SCAN_CONFIG["max_files"]:
            print(f"  ⚠️  项目文件过多({len(files)})，限制分析前{SCAN_CONFIG['max_files']}个文件")
            files = files[:SCAN_CONFIG["max_files"]]

        return files

    def get_project_info(self) -> dict:
        """获取项目元信息"""
        info = {
            "name": self.repo_name,
            "path": self.repo_path,
            "type": self.repo_type,
            "source": self.target,
            "languages": self.language_stats,
        }

        # 尝试读取 README 以获取项目描述
        for readme_name in ['README.md', 'README.rst', 'README.txt', 'README']:
            readme_path = os.path.join(self.repo_path, readme_name)
            if os.path.exists(readme_path):
                try:
                    with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1000)
                    info["description"] = content[:500]
                except:
                    pass
                break

        return info

    def cleanup(self):
        """清理克隆的仓库（如果是临时克隆）"""
        if self.repo_type != 'local' and os.path.exists(self.repo_path):
            shutil.rmtree(self.repo_path, ignore_errors=True)
            print(f"  已清理临时仓库: {self.repo_path}")
