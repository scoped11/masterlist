@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 > nul
cd /d "%~dp0.."
echo Building Delta Force DMA Radar...
cl /nologo /EHsc /O2 /std:c++17 /W3 /MT /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt" "C:\Users\K\Desktop\PenisFinger\source\cheat\deltaforce_dma.cpp" /Fe"C:\Users\K\Desktop\PenisFinger\build\df_dma.exe" /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64" kernel32.lib user32.lib gdi32.lib winmm.lib /SUBSYSTEM:WINDOWS
if errorlevel 1 (
    echo BUILD FAILED
    pause
    exit /b 1
)
echo Build OK: build\df_dma.exe
