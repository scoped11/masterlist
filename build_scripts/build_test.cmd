call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64

rem -- test_bedaisy.exe
cl /nologo /EHsc /std:c++17 /W4 /D_WIN32_WINNT=0x0A00 /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt" "C:\Users\K\Desktop\PenisFinger\test_bedaisy.cpp" /Fe"C:\Users\K\Desktop\PenisFinger\build\test_bedaisy.exe" /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64" kernel32.lib ntdll.lib
if errorlevel 1 exit /b %errorlevel%

rem -- test_target.sys
cl /nologo /c /kernel /GS- /W4 /D_AMD64_ /DAMD64 /DWIN64 /D_WIN64 /D_WIN32_WINNT=0x0A00 /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\km" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt" /Fo"C:\Users\K\Desktop\PenisFinger\build\obj\test_target.obj" "C:\Users\K\Desktop\PenisFinger\test_target.c"
if errorlevel 1 exit /b %errorlevel%
link /nologo /DRIVER /SUBSYSTEM:NATIVE /MACHINE:X64 /ENTRY:DriverEntry /OUT:"C:\Users\K\Desktop\PenisFinger\build\test_target.sys" "C:\Users\K\Desktop\PenisFinger\build\obj\test_target.obj" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\km\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64" ntoskrnl.lib BufferOverflowFastFailK.lib
if errorlevel 1 exit /b %errorlevel%

rem -- mapper.exe
cl /nologo /EHsc /std:c++17 /W4 /D_WIN32_WINNT=0x0A00 /I"C:\Users\K\Desktop\PenisFinger\mapper" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt" "C:\Users\K\Desktop\PenisFinger\mapper\mapper.cpp" "C:\Users\K\Desktop\PenisFinger\mapper\main.cpp" /Fe"C:\Users\K\Desktop\PenisFinger\build\mapper.exe" /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64" kernel32.lib ntdll.lib
if errorlevel 1 exit /b %errorlevel%

rem -- loader.exe
cl /nologo /EHsc /std:c++17 /W4 /D_WIN32_WINNT=0x0A00 /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt" "C:\Users\K\Desktop\PenisFinger\loader.cpp" /Fe"C:\Users\K\Desktop\PenisFinger\build\loader.exe" /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64" kernel32.lib advapi32.lib wevtapi.lib
if errorlevel 1 exit /b %errorlevel%
