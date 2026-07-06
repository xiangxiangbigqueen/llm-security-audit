@echo off
title LLM Security Audit Demo
cls
echo ================================================
echo   LLM Security Audit System
echo ================================================
echo.
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found
    pause
    exit /b 1
)
:menu
cls
echo ================================================
echo  Select:
echo ================================================
echo.
echo  [1]  Quick scan  (test samples)
echo  [2]  Full scan    (test samples + PoC)
echo.
echo  [3]  Scan GitHub repo
echo  [4]  Scan local project
echo.
echo  [5]  Start Web dashboard
echo  [6]  View reports
echo  [7]  Open reports folder
echo.
echo  [0]  Exit
echo.
set /p choice=Enter (0-7): 
if "%choice%"=="1" goto quick_test
if "%choice%"=="2" goto full_test
if "%choice%"=="3" goto scan_github
if "%choice%"=="4" goto scan_local
if "%choice%"=="5" goto web_ui
if "%choice%"=="6" goto view_reports
if "%choice%"=="7" goto open_reports
if "%choice%"=="0" goto end
goto menu
:quick_test
cls
echo [1] Scanning test samples...
python main.py --target tests --quick --output reports
pause
goto menu
:full_test
cls
echo [2] Full scan with PoC...
python main.py --target tests --no-ast --no-rag --output reports
pause
goto menu
:scan_github
cls
echo [3] Scan GitHub repository
echo.
echo Enter URL, or type 0 to go back:
set /p repo_url=URL: 
if "%repo_url%"=="" goto menu
if "%repo_url%"=="0" goto menu
if "%repo_url%"=="exit" goto menu
echo.
echo Scanning: %repo_url%
python main.py --target "%repo_url%" --quick --output reports
echo.
echo Done! Select another option or 0 to exit.
pause
goto menu
:scan_local
cls
echo [4] Scan local project
echo.
echo Enter folder path, or type 0 to go back:
set /p local_path=Path: 
if "%local_path%"=="" goto menu
if "%local_path%"=="0" goto menu
if "%local_path%"=="exit" goto menu
if not exist "%local_path%" (
    echo.
    echo [ERROR] Path not found, please check and try again
    echo Tips: Path examples -
    echo   C:\Users8995\homomorphic_encryption
    echo   D:\Personal\Desktop\your-project
    echo.
    pause
    goto scan_local
)
echo.
echo Scanning: %local_path%
python main.py --target "%local_path%" --quick --output reports
echo.
echo Done!
pause
goto menu
:web_ui
cls
echo [5] Starting Web UI...
echo Open: http://127.0.0.1:5000
start http://127.0.0.1:5000
python main.py --web
pause
goto menu
:view_reports
cls
dir /b /o-d reports".md 2>nul
pause
goto menu
:open_reports
cls
start reports
echo Reports folder opened
pause
goto menu
:end
cls
echo Bye!
pause
