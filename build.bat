@echo off
echo =========================================
echo   Burp Link Extractor - Build Script
echo =========================================
echo.

REM Create output directory
echo [1/3] Creating output directory...
if not exist out mkdir out

REM Check if burp-extender-api.jar exists
if exist burp-extender-api.jar (
    echo [2/3] Compiling using burp-extender-api.jar...
    javac -cp burp-extender-api.jar -d out src\burp\*.java

    if errorlevel 1 (
        echo ERROR: Compilation failed!
        pause
        exit /b 1
    )
) else (
    echo WARNING: burp-extender-api.jar not found!
    echo.
    echo Please either:
    echo   1. Download burp-extender-api.jar from https://portswigger.net/burp/extender/api/
    echo   2. Or compile manually using your Burp JAR file:
    echo      javac -cp "C:\Path\To\burpsuite_community.jar" -d out src\burp\*.java
    echo.
    pause
    exit /b 1
)

REM Create JAR file
echo [3/3] Creating JAR file...
cd out
jar -cf LinkExtractor.jar burp\*.class
cd ..

if exist out\LinkExtractor.jar (
    echo.
    echo =========================================
    echo   Build Successful!
    echo =========================================
    echo.
    echo Extension JAR created at: out\LinkExtractor.jar
    echo.
    echo Next steps:
    echo   1. Open Burp Suite Community Edition
    echo   2. Go to Extensions -^> Installed
    echo   3. Click 'Add' and select 'out\LinkExtractor.jar'
    echo.
) else (
    echo.
    echo ERROR: Failed to create JAR file!
    pause
    exit /b 1
)

pause
