@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Vc\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
  call "C:\Program Files\Microsoft Visual Studio\18\Community\Vc\Auxiliary\Build\vcvars64.bat" >nul 2>&1
)
if errorlevel 1 (
  echo Could not find VS2022 vcvars64.bat
  exit /b 1
)
cd /d "%~dp0.."
if not exist build mkdir build
echo Building pz_viewer.exe...
cl /nologo /EHsc /O2 /std:c++17 /W3 /D_CRT_SECURE_NO_WARNINGS /I"external\pz" ^
  external\pz\pz_main.cpp external\pz\pz_game.cpp external\pz\pz_config.cpp ^
  external\pz\pz_menu.cpp external\pz\pz_telemetry_file.cpp ^
  /Fe"build\pz_viewer.exe" /link ws2_32.lib user32.lib gdi32.lib advapi32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)
echo Build OK: build\pz_viewer.exe
echo Usage: build\pz_viewer.exe --mock 1 --mode web_radar
endlocal