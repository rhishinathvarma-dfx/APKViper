@echo off
title DarkAudit v2.0.0 - Android Security Assessment Platform
echo ============================================
echo   DarkAudit v2.0.0 - Android SAST Scanner
echo   Advanced Security Assessment Platform
echo   100%% Offline - No Internet Required
echo ============================================
echo.

set "SCRIPT_DIR=%~dp0"
set "JAR_NAME=DarkAudit-2.0.0.jar"
set "JAVA_OPTS=-Xmx2g -Dsun.java2d.opengl=true"

:: Collect any arguments passed to this script
set "ARGS=%*"

:: Try JDK paths in user home (newest first)
for /d %%G in ("%USERPROFILE%\.jdks\openjdk-*") do (
    if exist "%%G\bin\java.exe" (
        echo [+] Found JDK: %%G
        "%%G\bin\java.exe" %JAVA_OPTS% -jar "%SCRIPT_DIR%%JAR_NAME%" %ARGS%
        goto :end
    )
)

:: Try JAVA_HOME
if defined JAVA_HOME (
    if exist "%JAVA_HOME%\bin\java.exe" (
        echo [+] Using JAVA_HOME: %JAVA_HOME%
        "%JAVA_HOME%\bin\java.exe" %JAVA_OPTS% -jar "%SCRIPT_DIR%%JAR_NAME%" %ARGS%
        goto :end
    )
)

:: Try system java
where java >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [+] Using system Java
    java %JAVA_OPTS% -jar "%SCRIPT_DIR%%JAR_NAME%" %ARGS%
    goto :end
)

echo.
echo [ERROR] Java not found! Install JDK 11+ or set JAVA_HOME.
echo.
echo Download JDK: https://adoptium.net/
echo.
echo Usage examples:
echo   DarkAudit.bat                                   Launch GUI
echo   DarkAudit.bat --scan app.apk                    Headless scan (JSON output)
echo   DarkAudit.bat --scan app.apk --format html      Headless scan (HTML report)
echo   DarkAudit.bat --scan app.apk --format sarif     CI/CD integration (SARIF)
echo   DarkAudit.bat --scan app.apk --format pdf       PDF report
echo   DarkAudit.bat --scan app.apk --format excel     Excel report
echo   DarkAudit.bat --server --port 8089              REST API server
echo   DarkAudit.bat --help                            Show all options
echo.
pause

:end
