@echo off
chcp 65001 >nul 2>&1
title LLM Security Audit System - Demo

echo ================================================
echo   LLM Security Audit System - 增强版演示
echo   实验一：大模型驱动的开源项目安全审计
echo ================================================
echo.
echo  新增功能:
echo    - Tree-sitter AST 语义分析
echo    - RAG-CVE 实时漏洞情报
echo    - 异步并行扫描引擎
echo    - Web 交互式仪表盘
echo    - Neo4j 知识图谱
echo    - GitHub Actions CI/CD
echo.

:: 检查 Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 未找到 Python，请先安装 Python 3.10+
    echo.
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
) else (
    for /f "delims=" %%i in ('python --version 2^>^&1') do echo [OK] %%i
)

:menu
echo.
echo ================================================
echo  请选择演示模式:
echo ================================================
echo  [基础功能]
echo  1. 快速扫描测试项目
echo  2. 标准扫描测试项目 (规则匹配+验证+PoC)
echo.
echo  [增强功能]
echo  3. 增强扫描测试项目 (AST+RAG+并行)
echo  4. 增强扫描指定本地项目
echo  5. 增强扫描 GitHub 仓库
echo.
echo  [Web 界面]
echo  6. 启动 Web 仪表盘
echo.
echo  [工具]
echo  7. 查看已生成的报告
echo  8. 清理工作目录
echo  0. 退出
echo ================================================
set /p choice="请输入选择 (0-8): "

if "%choice%"=="1" goto quick_demo
if "%choice%"=="2" goto std_demo
if "%choice%"=="3" goto enhanced_demo
if "%choice%"=="4" goto enhanced_local
if "%choice%"=="5" goto enhanced_github
if "%choice%"=="6" goto web_ui
if "%choice%"=="7" goto view_reports
if "%choice%"=="8" goto cleanup
if "%choice%"=="0" goto end
echo 无效选择，请重新输入
timeout /t 1 >nul
goto menu

:quick_demo
echo.
echo [Demo] 快速扫描测试项目...
python main.py --target tests --quick --output reports
if %errorlevel% neq 0 (
    echo [ERROR] 扫描失败，请检查依赖是否安装
    echo 运行: pip install -r requirements.txt
)
echo.
echo [完成] 报告已生成到 reports/ 目录
pause
goto menu

:std_demo
echo.
echo [Demo] 标准扫描测试项目...
python main.py --target tests --no-ast --no-rag --output reports
echo.
echo [完成]
pause
goto menu

:enhanced_demo
echo.
echo [Demo] 增强扫描测试项目 (AST+RAG+并行)...
python main.py --target tests --output reports
echo.
echo [完成]
pause
goto menu

:enhanced_local
set /p local_path="请输入本地项目路径: "
if "%local_path%"=="" goto menu
echo.
echo [增强扫描] 目标: %local_path%
python main.py --target "%local_path%" --output reports
pause
goto menu

:enhanced_github
set /p repo_url="请输入 GitHub 仓库 URL: "
if "%repo_url%"=="" goto menu
echo.
echo [增强扫描] 目标: %repo_url%
python main.py --target "%repo_url%" --output reports
pause
goto menu

:web_ui
echo.
echo [Web] 启动 Web 仪表盘...
echo [注意] 启动后请在浏览器中打开 http://127.0.0.1:5000
echo.
start http://127.0.0.1:5000
python main.py --web
pause
goto menu

:view_reports
echo.
echo [报告列表]:
if exist reports\ (
    dir /b reports\*.md reports\*.html reports\*.json 2>nul
    if %errorlevel% neq 0 (
        echo   暂无报告，请先运行扫描
    )
) else (
    echo   暂无报告，请先运行扫描
)
echo.
pause
goto menu

:cleanup
echo.
echo [清理] 清理工作目录...
if exist workspace (
    rmdir /s /q workspace
    echo   已完成
) else (
    echo   workspace 目录不存在
)
pause
goto menu

:end
echo.
echo 感谢使用 LLM Security Audit System
echo.
pause
