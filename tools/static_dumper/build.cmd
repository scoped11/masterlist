@echo off
cd /d "%~dp0"
cl /nologo /O2 /EHsc /Fe:..\..\build\static_dumper.exe static_dumper.cpp shlwapi.lib /link /SUBSYSTEM:CONSOLE
if %errorlevel% equ 0 (
    echo [+] Build OK: build\static_dumper.exe
) else (
    echo [!] Build failed
)
