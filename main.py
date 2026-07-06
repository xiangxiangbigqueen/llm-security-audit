"""CodeSentinel - 开源项目安全审计系统 主入口"""
import sys
import os
import logging
from pathlib import Path

# 添加项目根目录到Python路径
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from dotenv import load_dotenv
load_dotenv()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(name)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger("CodeSentinel")


def main():
    """应用主入口"""
    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtCore import Qt

    # 高DPI支持
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("CodeSentinel")
    app.setOrganizationName("CodeSentinel")

    from gui.main_window import MainWindow
    window = MainWindow()
    window.show()

    logger.info("CodeSentinel 启动成功")
    logger.info(f"项目根目录: {BASE_DIR}")

    api_key = os.getenv("DEEPSEEK_API_KEY", "")
    if not api_key:
        logger.warning("未配置DEEPSEEK_API_KEY，请在.env文件中设置")
    else:
        logger.info("DeepSeek API Key 已配置")

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()