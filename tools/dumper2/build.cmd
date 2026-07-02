@echo off
cd /d "%~dp0"
cl /nologo /O2 /EHsc /Fe:..\..\build\dumper2.exe dumper2.cpp advapi32.lib psapi.lib shlwapi.lib /link /SUBSYSTEM:CONSOLE
if %errorlevel% equ 0 (
    echo [+] Build OK: build\dumper2.exe
) else (
    echo [!] Build failed
)
