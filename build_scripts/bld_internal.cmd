@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 > nul
cd /d "%~dp0.."
echo Building Unturned Internal DLL...
cl /nologo /EHsc /O2 /std:c++17 /W3 /MT /LD /DINTERNAL_MODE /D_WIN32_WINNT=0x0A00 ^
   /I"source\cheat\internal" ^
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" ^
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" ^
   /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt" ^
   "source\cheat\internal\unturned_internal.cpp" ^
   /Fe"build\unturned_internal.dll" ^
   /Fo"build\obj\unturned_internal.obj" ^
   /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" ^
         /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64" ^
         kernel32.lib user32.lib gdi32.lib gdiplus.lib msimg32.lib advapi32.lib ntdll.lib psapi.lib ^
         /SUBSYSTEM:WINDOWS /DLL
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
echo Build OK: build\unturned_internal.dll
del /q "build\unturned_internal.exp" 2>nul
del /q "build\obj\unturned_internal.obj" 2>nul
