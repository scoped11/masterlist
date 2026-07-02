call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64

rem -- mapper.exe (BEDaisy primitive)
cl /nologo /EHsc /std:c++17 /W4 /D_WIN32_WINNT=0x0A00 /I"C:\Users\K\Desktop\PenisFinger\mapper" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt" "C:\Users\K\Desktop\PenisFinger\mapper\mapper.cpp" "C:\Users\K\Desktop\PenisFinger\mapper\main.cpp" /Fe"C:\Users\K\Desktop\PenisFinger\build\mapper.exe" /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64" kernel32.lib ntdll.lib
if errorlevel 1 exit /b %errorlevel%

rem -- loader.exe
cl /nologo /EHsc /std:c++17 /W4 /D_WIN32_WINNT=0x0A00 /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt" "C:\Users\K\Desktop\PenisFinger\loader.cpp" /Fe"C:\Users\K\Desktop\PenisFinger\build\loader.exe" /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64" kernel32.lib advapi32.lib wevtapi.lib
if errorlevel 1 exit /b %errorlevel%
