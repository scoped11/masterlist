@echo off
title R6 DMA Pipeline — Dump → GitHub → Run
cd /d "%~dp0"

echo ============================================
echo  R6 DMA Pipeline
echo  1. Dump offsets  2. Push GitHub  3. Run cheat
echo ============================================
echo.

:: Step 1: Run the offset dumper
echo [1/3] Running offset dumper...
dma_main.exe --offsets --game r6
if errorlevel 1 (
    echo [!] Dumper failed or no DMA device. Skipping to cheat launch.
    goto :PULL
)

:: Copy fresh offsets into the offsets folder
if exist "r6_offsets_dump.ini" (
    copy /y "r6_offsets_dump.ini" "offsets\r6_offsets.ini" >nul
    echo [+] Offsets updated in offsets\r6_offsets.ini
)

:: Step 2: Commit and push to GitHub
echo.
echo [2/3] Pushing offsets to GitHub...
git add offsets\r6_offsets.ini
git diff --cached --quiet offsets\r6_offsets.ini
if errorlevel 1 (
    git commit -m "Update R6 offsets — %date% %time%"
    git push origin master
    echo [+] Pushed to GitHub
) else (
    echo [=] No offset changes to push
)

:PULL
:: Pull latest (in case offsets were pushed from another machine)
echo.
echo [2b/3] Pulling latest from GitHub...
git pull origin master --no-edit 2>nul
echo [+] Repo up to date

:: Step 3: Launch the cheat
echo.
echo [3/3] Launching R6 DMA cheat...
echo     Config: offsets\r6_offsets.ini
echo     Web panel: http://localhost:8777
echo     Press END in-game to exit
echo.
start "" r6_dma.exe --offsets=offsets\r6_offsets.ini --noscan
echo [+] Cheat launched. Check console window for status.
echo.
pause
