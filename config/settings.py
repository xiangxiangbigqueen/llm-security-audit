"""全局配置模块"""
import os
from pathlib import Path
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 项目根目录
BASE_DIR = Path(__file__).resolve().parent.parent

# DeepSeek API配置
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
DEEPSEEK_MODEL = "deepseek-chat"

# LLM参数
LLM_TEMPERATURE = 0.1  # 安全审计需要低随机性
LLM_MAX_TOKENS = 4096
LLM_RETRY_COUNT = 3
LLM_RETRY_DELAY = 2  # 秒

# 工具路径配置
CPPCHECK_PATH = os.getenv("CPPCHECK_PATH", "cppcheck")
FLAWFINDER_PATH = os.getenv("FLAWFINDER_PATH", "flawfinder")
PHPSTAN_PATH = os.getenv("PHPSTAN_PATH", "phpstan")
PROGPILOT_PATH = os.getenv("PROGPILOT_PATH", "tools/progpilot.phar")
BANDIT_PATH = os.getenv("BANDIT_PATH", "bandit")

# 系统配置
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "4"))
FEEDBACK_MAX_ITERATIONS = int(os.getenv("FEEDBACK_MAX_ITERATIONS", "3"))

# 输出目录
TEMP_REPO_DIR = BASE_DIR / os.getenv("TEMP_REPO_DIR", "output/repos")
REPORT_OUTPUT_DIR = BASE_DIR / os.getenv("REPORT_OUTPUT_DIR", "output/reports")

# 确保输出目录存在
TEMP_REPO_DIR.mkdir(parents=True, exist_ok=True)
REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 支持的语言映射
LANGUAGE_EXTENSIONS = {
    "C": [".c", ".h"],
    "C++": [".cpp", ".cc", ".cxx", ".hpp", ".hh"],
    "PHP": [".php"],
    "Python": [".py"],
}

# 漏洞严重等级
SEVERITY_LEVELS = ["critical", "high", "medium", "low"]

# 漏洞类型
VULNERABILITY_TYPES = [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Buffer Overflow",
    "Format String",
    "XSS",
    "File Inclusion",
    "Deserialization",
    "Hardcoded Secrets",
    "Integer Overflow",
    "SSRF",
    "Insecure Deserialization",
    "Code Injection",
    "SSTI",
    "Broken Authentication",
    "Sensitive Data Exposure",
]