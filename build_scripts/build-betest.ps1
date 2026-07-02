param(
    [string]$Configuration = "Release",
    [string]$CertSubject = "CN=BetestTestCert"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutDir = Join-Path $Root "build"
$ObjDir = Join-Path $OutDir "obj"
New-Item -ItemType Directory -Force -Path $OutDir, $ObjDir | Out-Null

# Auto-detect VS installation (2022=17, future=18, etc.)
$VsDevCmd = Get-ChildItem "C:\Program Files\Microsoft Visual Studio" -Recurse -Filter "VsDevCmd.bat" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $VsDevCmd) { $VsDevCmd = "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" }
$KitVersion = "10.0.26100.0"
$KitRoot = "C:\Program Files (x86)\Windows Kits\10"
$KitInclude = Join-Path $KitRoot "Include\$KitVersion"
$KitLib = Join-Path $KitRoot "Lib\$KitVersion"
$SignTool = Join-Path $KitRoot "bin\$KitVersion\x64\signtool.exe"

if (!(Test-Path $VsDevCmd)) {
    throw "VsDevCmd.bat not found at $VsDevCmd"
}

if (!(Test-Path $SignTool)) {
    throw "signtool.exe not found at $SignTool"
}

$DriverSrc  = Join-Path $Root "BetestDriver.c"
$ClientSrc  = Join-Path $Root "BetestClient.cpp"
$LoaderSrc  = Join-Path $Root "loader.cpp"
$MapperDir  = Join-Path $Root "mapper"
$MapperSrc1  = Join-Path $MapperDir "mapper.cpp"
$MapperSrc2  = Join-Path $MapperDir "main.cpp"
$MapperSrc2V  = Join-Path $MapperDir "main_vm.cpp"
$MapperSrc2VB = Join-Path $MapperDir "main_vbox.cpp"
$MapperSrc2VI = Join-Path $MapperDir "main_vboxinject.cpp"
$VboxInjectDllSrc = Join-Path $MapperDir "vboxinject_dll.cpp"
$DriverObj    = Join-Path $ObjDir "BetestDriver.obj"
$DriverSys    = Join-Path $OutDir "Betest.sys"
$ClientExe    = Join-Path $OutDir "BetestClient.exe"
$MapperExe    = Join-Path $OutDir "mapper.exe"
$MapperVmExe  = Join-Path $OutDir "mapper_vm.exe"
$MapperVboxExe= Join-Path $OutDir "mapper_vbox.exe"
$MapperVboxInjectExe = Join-Path $OutDir "mapper_vboxinject.exe"
$VboxInjectDll = Join-Path $OutDir "mapper_vboxinject.dll"
$LoaderExe    = Join-Path $OutDir "loader.exe"

$DriverIncludes = @(
    "/I`"$KitInclude\km`"",
    "/I`"$KitInclude\shared`"",
    "/I`"$KitInclude\ucrt`""
) -join " "

$DriverLibs = @(
    "/LIBPATH:`"$KitLib\km\x64`"",
    "/LIBPATH:`"$KitLib\ucrt\x64`"",
    "ntoskrnl.lib",
    "hal.lib",
    "BufferOverflowFastFailK.lib"
) -join " "

$ClientIncludes = @(
    "/I`"$KitInclude\um`"",
    "/I`"$KitInclude\shared`"",
    "/I`"$KitInclude\ucrt`""
) -join " "

$ClientLibs = @(
    "/LIBPATH:`"$KitLib\um\x64`"",
    "/LIBPATH:`"$KitLib\ucrt\x64`"",
    "kernel32.lib",
    "user32.lib"
) -join " "

$MapperIncludes = @(
    "/I`"$MapperDir`"",
    "/I`"$KitInclude\um`"",
    "/I`"$KitInclude\shared`"",
    "/I`"$KitInclude\ucrt`""
) -join " "

$MapperLibs = @(
    "/LIBPATH:`"$KitLib\um\x64`"",
    "/LIBPATH:`"$KitLib\ucrt\x64`"",
    "kernel32.lib",
    "ntdll.lib"
) -join " "

$Cmd = @"
@echo on
set PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%
call "$VsDevCmd" -arch=x64 -host_arch=x64
cl /nologo /c /kernel /GS- /W4 /D_AMD64_ /DAMD64 /DWIN64 /D_WIN64 /D_WIN32_WINNT=0x0A00 $DriverIncludes /Fo"$DriverObj" "$DriverSrc"
if errorlevel 1 exit /b %errorlevel%
link /nologo /DRIVER /SUBSYSTEM:NATIVE /MACHINE:X64 /ENTRY:DriverEntry /OUT:"$DriverSys" "$DriverObj" $DriverLibs
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /W4 /D_WIN32_WINNT=0x0A00 $ClientIncludes "$ClientSrc" /Fe"$ClientExe" /link $ClientLibs
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /std:c++17 /W4 /D_WIN32_WINNT=0x0A00 $MapperIncludes "$MapperSrc1" "$MapperSrc2" /Fe"$MapperExe" /link $MapperLibs
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /std:c++17 /W4 /D_WIN32_WINNT=0x0A00 $MapperIncludes "$MapperSrc1" "$MapperSrc2V" /Fe"$MapperVmExe" /link $MapperLibs
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /std:c++17 /W4 /D_WIN32_WINNT=0x0A00 $MapperIncludes "$MapperSrc1" "$MapperSrc2VB" /Fe"$MapperVboxExe" /link $MapperLibs
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /std:c++17 /LD /W4 /D_WIN32_WINNT=0x0A00 $MapperIncludes "$VboxInjectDllSrc" /Fe"$VboxInjectDll" /link $MapperLibs
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /std:c++17 /W4 /D_WIN32_WINNT=0x0A00 $MapperIncludes "$MapperSrc1" "$MapperSrc2VI" /Fe"$MapperVboxInjectExe" /link $MapperLibs advapi32.lib
if errorlevel 1 exit /b %errorlevel%
cl /nologo /EHsc /std:c++17 /W4 /D_WIN32_WINNT=0x0A00 $ClientIncludes "$LoaderSrc" /Fe"$LoaderExe" /link $ClientLibs wevtapi.lib
if errorlevel 1 exit /b %errorlevel%
"@

$CmdPath = Join-Path $ObjDir "build.cmd"
Set-Content -LiteralPath $CmdPath -Value $Cmd -Encoding ASCII
cmd.exe /d /c "`"$CmdPath`""
if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE"
}

$cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $CertSubject } |
    Sort-Object NotBefore -Descending |
    Select-Object -First 1

if ($cert) {
    & $SignTool sign /v /fd SHA256 /s My /sm /n ($CertSubject -replace '^CN=', '') $DriverSys
    & $SignTool verify /v /kp $DriverSys
} else {
    Write-Warning "No LocalMachine code-signing cert found for $CertSubject. Build completed unsigned."
}

Write-Host "Driver:      $DriverSys"
Write-Host "Client:      $ClientExe"
Write-Host "Mapper:      $MapperExe"
Write-Host "MapperVM:    $MapperVmExe"
Write-Host "MapperVBox:  $MapperVboxExe"
Write-Host "Loader:      $LoaderExe"

