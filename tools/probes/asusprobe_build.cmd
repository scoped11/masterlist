set PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
cl /nologo /EHsc /D_WIN32_WINNT=0x0A00 "C:\Users\K\Desktop\PenisFinger\build\obj\asusprobe.cpp" /Fe"C:\Users\K\Desktop\PenisFinger\build\obj\asusprobe.exe" /link kernel32.lib ntdll.lib
