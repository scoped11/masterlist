@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 > nul
cd /d "%~dp0.."
echo Building Universal DMA Radar...
cl /nologo /EHsc /O2 /std:c++17 /W3 /MT /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt" "C:\Users\K\Desktop\PenisFinger\source\cheat\dma_radar.cpp" /Fe"C:\Users\K\Desktop\PenisFinger\build\dma_radar.exe" /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64" kernel32.lib user32.lib gdi32.lib winmm.lib ws2_32.lib wininet.lib /SUBSYSTEM:WINDOWS
if errorlevel 1 (
    echo BUILD FAILED
    pause
    exit /b 1
)
echo Build OK: build\dma_radar.exe
echo.
echo Usage:
echo   dma_radar.exe --game r6
echo   dma_radar.exe --game rust
echo   dma_radar.exe --game apex
echo   dma_radar.exe --game bf2042
echo   dma_radar.exe --game tarkov
echo   dma_radar.exe --game pubg
echo   dma_radar.exe --game cs2
echo   dma_radar.exe --game hunt
echo   dma_radar.exe --game valorant
echo   dma_radar.exe custom_offsets.ini
