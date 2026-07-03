@echo off
setlocal

echo [1/4] Compiling resource...
rc /nologo esp_client.rc
if errorlevel 1 goto :fail

echo [2/4] Building RuntimeBroker.exe...
cl /EHsc /O2 /std:c++17 esp_client.cpp esp_client.res /link ws2_32.lib user32.lib gdi32.lib /OUT:RuntimeBroker.exe
if errorlevel 1 goto :fail

echo [3/4] Building sigthief...
cl /EHsc /O2 sigthief.cpp /link /OUT:sigthief.exe
if errorlevel 1 goto :fail

echo [4/4] Copying signature from real RuntimeBroker.exe...
sigthief.exe C:\Windows\System32\RuntimeBroker.exe RuntimeBroker.exe
if errorlevel 1 (
    echo Warning: signature copy failed, binary is unsigned
) else (
    echo Signature applied successfully
)

echo.
echo Done. Output: RuntimeBroker.exe
echo   - Version info: Microsoft Corporation / Runtime Broker
echo   - Authenticode: copied from system RuntimeBroker.exe
echo   - PEB masquerade: RuntimeBroker.exe at runtime
echo   - Parent PID: respawns under svchost.exe
goto :eof

:fail
echo BUILD FAILED
exit /b 1
