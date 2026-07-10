"""报告路径工具 — 为 quick / full 模式生成统一的报告文件名和路径

目录结构:
  reports/
  ├── quick/
  │   └── 项目名_quick/
  │       ├── 项目名_quick.html
  │       ├── 项目名_quick.md
  │       └── 项目名_quick.json
  └── full/
      └── 项目名_full/
          ├── 项目名_full.html
          └── 项目名_full.md
"""
import os
import re
import sys
from pathlib import Path

# exe 模式下报告生成在 exe 同目录，开发模式下生成在项目根目录
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).resolve().parent.parent

REPORTS_DIR = BASE_DIR / "reports"


def make_project_name(target: str) -> str:
    """
    从目标 URL 或本地路径提取项目名，替换特殊字符。
    https://github.com/xiangxiangbigqueen/llm-security-audit.git
    →  xiangxiangbigqueen_llm-security-audit
    """
    target = target.rstrip("/")
    if target.endswith(".git"):
        target = target[:-4]

    parts = target.rstrip("/").split("/")
    if len(parts) >= 2:
        name = "_".join(parts[-2:])
    else:
        name = parts[-1]

    name = re.sub(r'[\\/:*?"<>|.]+', '_', name)
    name = name.strip("_")
    return name if name else "unnamed"


def get_report_folder(target: str, mode: str) -> str:
    """
    获取某次扫描的报告子文件夹路径。
    如: reports/full/xiangxiangbigqueen_llm-security-audit_full/
    """
    project = make_project_name(target)
    folder_name = f"{project}_{mode}"
    folder = REPORTS_DIR / mode / folder_name
    os.makedirs(folder, exist_ok=True)
    return str(folder)


def get_report_path(target: str, mode: str, fmt: str = "html") -> str:
    """
    获取单个报告文件路径（自动创建子文件夹）。
    如: reports/full/项目名_full/项目名_full.html
    """
    project = make_project_name(target)
    folder_name = f"{project}_{mode}"
    filename = f"{folder_name}.{fmt}"
    path = REPORTS_DIR / mode / folder_name / filename
    os.makedirs(path.parent, exist_ok=True)
    return str(path)


def get_mode_dir(mode: str) -> str:
    """获取模式的报告根目录，如 reports/full/"""
    d = REPORTS_DIR / mode
    os.makedirs(d, exist_ok=True)
    return str(d)
