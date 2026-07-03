@echo off
setlocal

set VCVARS="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist %VCVARS% set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist %VCVARS% set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

call %VCVARS% >nul 2>&1

echo Building Unturned SWHE External...

cl /O2 /EHsc /std:c++20 /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN ^
   /I"." ^
   source\main.cpp ^
   source\mem.cpp ^
   source\unturned.cpp ^
   WaryasSWHE\exploit.cpp ^
   WaryasSWHE\utils.cpp ^
   WaryasSWHE\pe_mapper.cpp ^
   source\types\game.cpp ^
   source\types\unity.cpp ^
   gdi32.lib user32.lib psapi.lib ntdll.lib shell32.lib shlwapi.lib ^
   /Fe:unturned_swhe.exe ^
   /link /SUBSYSTEM:CONSOLE

if %errorlevel% neq 0 (
    echo BUILD FAILED
    pause
    exit /b 1
)

echo.
echo Build OK: unturned_swhe.exe
del *.obj 2>nul
pause
