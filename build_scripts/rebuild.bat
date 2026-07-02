@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cl.exe /EHa /std:c++17 /O2 /MT /Fe:C:\Users\K\Desktop\PenisFinger\run\mapper_nal.exe C:\Users\K\Desktop\PenisFinger\source\mapper\main_nal.cpp C:\Users\K\Desktop\PenisFinger\source\mapper\mapper.cpp /link /SUBSYSTEM:CONSOLE
echo Build exit: %errorlevel%
