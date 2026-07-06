#!/bin/bash
# CodeSentinel 环境配置脚本 (macOS)

set -e

echo "=== CodeSentinel 环境配置 ==="
echo ""

# 1. 检查Python版本
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "[✓] Python版本: $PYTHON_VERSION"

# 2. 创建虚拟环境
echo "[*] 创建虚拟环境..."
python3 -m venv .venv
source .venv/bin/activate
echo "[✓] 虚拟环境已激活"

# 3. 安装Python依赖
echo "[*] 安装Python依赖..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "[✓] Python依赖安装完成"

# 4. 安装静态分析工具
echo "[*] 安装静态分析工具..."

# cppcheck
if ! command -v cppcheck &> /dev/null; then
    echo "[*] 安装cppcheck..."
    brew install cppcheck 2>/dev/null || echo "[!] brew install cppcheck 失败，请手动安装"
fi
echo "[✓] cppcheck: $(cppcheck --version 2>/dev/null || echo '未安装')"

# flawfinder (通过pip安装)
echo "[✓] flawfinder: 已通过pip安装"

# PHP工具（需要PHP环境）
if command -v php &> /dev/null; then
    echo "[✓] PHP已安装: $(php --version | head -1)"
    if command -v phpstan &> /dev/null; then
        echo "[✓] phpstan已安装"
    else
        echo "[!] phpstan未安装，运行: brew install phpstan"
    fi
else
    echo "[!] 未检测到PHP，跳过PHP工具检查"
    echo "    如需PHP审计支持，请先安装: brew install php"
fi

# 5. 配置环境变量
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo ""
    echo "[!] 请编辑 .env 文件，填入你的 DeepSeek API Key"
    echo "    获取API Key: https://platform.deepseek.com/"
fi

# 6. 创建输出目录
mkdir -p output/reports output/repos

echo ""
echo "=== 配置完成 ==="
echo ""
echo "激活环境: source .venv/bin/activate"
echo "启动系统: python main.py"
echo ""