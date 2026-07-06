@echo off
title LLM Security Audit Demo
echo ================================================
echo   LLM Security Audit System
echo   实验一：大模型驱动的开源项目安全审计
echo ================================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 未找到 Python，请先安装
    pause
    exit /b 1
)

:menu
echo.
echo  ┌─ 请选择 ──────────────────────────────┐
echo  │  1. 快速扫描测试项目                    │
echo  │  2. 完整扫描测试项目                    │
echo  │  3. 启动 Web 仪表盘                    │
echo  │  4. 查看已生成报告                      │
echo  │  0. 退出                               │
echo  └────────────────────────────────────────┘
echo.
set /p choice="请输入 (0-4): "

if "%choice%"=="1" goto quick
if "%choice%"=="2" goto full
if "%choice%"=="3" goto web
if "%choice%"=="4" goto reports
if "%choice%"=="0" goto end
goto menu

:quick
echo.
echo [1] 快速扫描测试项目...
python main.py --target tests --quick --output reports
echo.
echo 完成！
pause
goto menu

:full
echo.
echo [2] 完整扫描测试项目...
python main.py --target tests --no-ast --no-rag --output reports
echo.
echo 完成！
pause
goto menu

:web
echo.
echo [3] 启动 Web 仪表盘...
start http://127.0.0.1:5000
python main.py --web
pause
goto menu

:reports
echo.
echo [4] 已生成的报告：
echo.
if exist reports\*.md (
    dir /b reports\*.md
) else (
    echo   （暂无报告，请先运行扫描）
)
echo.
pause
goto menu

:end
echo.
echo 感谢使用！
pause
