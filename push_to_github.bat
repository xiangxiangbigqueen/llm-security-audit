@echo off
chcp 65001 >nul
title 一键推送 GitHub

echo ================================================
echo   一键推送 LLM Security Audit System 到 GitHub
echo ================================================
echo.

:: 检查 git
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未安装 Git，请先安装: https://git-scm.com/
    pause
    exit /b 1
)

cd /d "%~dp0"

:: 检查是否有网络
ping -n 1 github.com >nul 2>&1
if %errorlevel% neq 0 (
    echo [警告] 当前网络无法访问 GitHub，请切换网络后重试
    echo.
)

echo 步骤 1/3: 创建 GitHub 仓库...
gh repo create xiangxiangbigqueen/llm-security-audit --public --description "LLM Security Audit System - 大模型驱动的开源项目安全审计系统" --homepage "" 2>nul
if %errorlevel% neq 0 (
    echo [信息] 仓库可能已存在，继续推送...
)

echo 步骤 2/3: 设置远程仓库...
git remote remove origin 2>nul
git remote add origin https://github.com/xiangxiangbigqueen/llm-security-audit.git

echo 步骤 3/3: 推送代码...
git branch -M main
git push -u origin main

if %errorlevel% equ 0 (
    echo.
    echo ================================================
    echo ✅ 推送成功!
    echo    仓库地址: https://github.com/xiangxiangbigqueen/llm-security-audit
    echo ================================================
) else (
    echo.
    echo ❌ 推送失败，请检查:
    echo    1. 网络是否能访问 GitHub
    echo    2. 是否已安装 GitHub CLI: winget install GitHub.cli
    echo    3. 是否已登录: gh auth login
    echo.
    echo 或者手动执行:
    echo   git remote add origin https://github.com/xiangxiangbigqueen/llm-security-audit.git
    echo   git branch -M main
    echo   git push -u origin main
)

pause
