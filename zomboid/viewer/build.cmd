@echo off
setlocal
cd /d "%~dp0"
where cl >nul 2>&1
if errorlevel 1 (
  echo Open "x64 Native Tools Command Prompt for VS 2022" and run this script again.
  exit /b 1
)
if not exist x64 mkdir x64
cl /nologo /EHsc /O2 /std:c++17 /D_CRT_SECURE_NO_WARNINGS /Fe:x64\pz_live_viewer.exe pz_live_viewer.cpp ws2_32.lib
if errorlevel 1 exit /b 1
echo Built: x64\pz_live_viewer.exe
endlocal