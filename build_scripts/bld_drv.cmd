@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 > nul
cl /nologo /c /kernel /GS- /W3 /D_AMD64_ /DAMD64 /DWIN64 /D_WIN64 /D_WIN32_WINNT=0x0A00 /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\km" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt" /Fo"C:\Users\K\Desktop\PenisFinger\build\obj\BetestDriver.obj" "C:\Users\K\Desktop\PenisFinger\betest_legacy\source\BetestDriver.c"
if errorlevel 1 exit /b %errorlevel%
link /nologo /DRIVER /SUBSYSTEM:NATIVE /MACHINE:X64 /ENTRY:DriverEntry /OUT:"C:\Users\K\Desktop\PenisFinger\build\Betest.sys" "C:\Users\K\Desktop\PenisFinger\build\obj\BetestDriver.obj" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\km\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64" ntoskrnl.lib hal.lib BufferOverflowFastFailK.lib
