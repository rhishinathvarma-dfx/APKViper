@echo off
REM ============================================================
REM DarkAudit v2.0.0 — CLI Runner (Headless Mode)
REM Usage: darkaudit-cli.bat --scan app.apk [--format json|html|sarif|pdf|excel] [--output report.json]
REM        darkaudit-cli.bat --server [--port 8089]
REM        darkaudit-cli.bat --help
REM ============================================================
setlocal

set "SCRIPT_DIR=%~dp0"
set "JAR_NAME=DarkAudit-2.0.0.jar"
set "JAVA_OPTS=-Xmx2g"

if "%~1"=="" (
    echo DarkAudit v2.0.0 — CLI Runner
    echo.
    echo Usage:
    echo   darkaudit-cli --scan ^<apk_path^>                          Scan APK ^(JSON output^)
    echo   darkaudit-cli --scan ^<apk_path^> --format html            Scan with HTML report
    echo   darkaudit-cli --scan ^<apk_path^> --format sarif           Scan with SARIF ^(CI/CD^)
    echo   darkaudit-cli --scan ^<apk_path^> --format pdf             Scan with PDF report
    echo   darkaudit-cli --scan ^<apk_path^> --format excel           Scan with Excel report
    echo   darkaudit-cli --scan ^<apk_path^> --output report.json     Specify output path
    echo   darkaudit-cli --server --port 8089                        Start REST API server
    echo   darkaudit-cli --help                                      Show all options
    echo.
    echo Exit codes: 0=pass, 1=error, 2=critical/high findings
    exit /b 1
)

:: Find Java
set "JAVA_CMD="
for /d %%G in ("%USERPROFILE%\.jdks\openjdk-*") do (
    if exist "%%G\bin\java.exe" set "JAVA_CMD=%%G\bin\java.exe"
)
if not defined JAVA_CMD (
    if defined JAVA_HOME (
        if exist "%JAVA_HOME%\bin\java.exe" set "JAVA_CMD=%JAVA_HOME%\bin\java.exe"
    )
)
if not defined JAVA_CMD (
    where java >nul 2>&1
    if %ERRORLEVEL% EQU 0 set "JAVA_CMD=java"
)
if not defined JAVA_CMD (
    echo [ERROR] Java not found! Install JDK 11+ or set JAVA_HOME.
    exit /b 1
)

"%JAVA_CMD%" %JAVA_OPTS% -jar "%SCRIPT_DIR%%JAR_NAME%" %*
exit /b %ERRORLEVEL%

