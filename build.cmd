@echo off
REM ==========================================================================
REM build.cmd - HookProxy ???????????????REM
REM ???(build\):
REM   HpxDrv64.sys          x64 ??????(???????????+ ?????
REM   user\HookProxy.dll    x64 ???(??? 9 ?????? + ??????)
REM   user\HpxGui.exe       x64 ?????? GUI(??????/???????????/???????
REM   user\HpxProbe.exe     x64 ????????TCP/UDP ???,MARKER ???)
REM
REM ???: build.cmd [all|drv|user]
REM ????? MSVC 14.50 + WDK 10.0.26100(????????????,??vcvars)
REM ==========================================================================
setlocal enabledelayedexpansion

set "VCT=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.50.35717"
set "KIT=C:\Program Files (x86)\Windows Kits\10"
set "KITVER=10.0.26100.0"
set "SDK=%KIT%\Include\%KITVER%"
set "KMLIB64=%KIT%\Lib\%KITVER%\km\x64"
set "UMLIB64=%KIT%\Lib\%KITVER%\um\x86"
set "CL64=%VCT%\bin\Hostx64\x64\cl.exe"
set "LINK64=%VCT%\bin\Hostx64\x64\link.exe"
set "SRC=%~dp0"
set "OUT=%SRC%build"

set "KM_INC=/I"%SDK%\km" /I"%SDK%\km\crt" /I"%SDK%\shared" /I"%VCT%\include" /I"%SDK%\ucrt" /I"%SDK%\um" /I"%SRC%src\common""
set "KM_FLAGS=/utf-8 /kernel /Zc:wchar_t /GR- /GS- /Zl /O2 /W3 /D_KERNEL_MODE=1 /D_NT_TARGET_VERSION=0x0A00 /DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A00000B /DNDIS_WDM=1 /DNDIS_SUPPORT_NDIS6=1 /D_AMD64_=1 /DAMD64 /D_WIN64=1"
set "UM_INC=/I"%SRC%src\common" /I"%SRC%src\engine" /I"%VCT%\include" /I"%SDK%\ucrt" /I"%SDK%\um" /I"%SDK%\shared""
set "UM_FLAGS=/utf-8 /Zc:wchar_t /O2 /W3 /DWIN32 /D_WINDOWS /D_WIN64 /D_WIN32_WINNT=0x0601 /DWINVER=0x0601 /DNTDDI_VERSION=0x06010000"

if not exist "%CL64%" ( echo [ERR] MSVC not found & exit /b 1 )
if not exist "%KMLIB64%\ntoskrnl.lib" ( echo [ERR] WDK km libs not found & exit /b 1 )
if not exist "%SDK%\km\fwpsk.h" ( echo [ERR] WDK headers not found & exit /b 1 )
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%OUT%\user" mkdir "%OUT%\user"

set TARGET=%1
if "%TARGET%"=="" set TARGET=all

if /i "%TARGET%"=="drv"  call :drv  || ( echo [ERR] drv build failed & exit /b 1 )
if /i "%TARGET%"=="user" call :user || ( echo [ERR] user build failed & exit /b 1 )
if /i "%TARGET%"=="nul"  call :nul  || ( echo [ERR] nul build failed & exit /b 1 )
if /i "%TARGET%"=="all" (
  call :drv  || ( echo [ERR] drv build failed & exit /b 1 )
  call :user || ( echo [ERR] user build failed & exit /b 1 )
)
echo.
echo ==== BUILD OK ====
dir /b "%OUT%\*.sys" 2>nul
dir /b "%OUT%\user\*.dll" "%OUT%\user\*.exe" 2>nul
endlocal
exit /b 0

REM ------------------------------- ??? -------------------------------------
:drv
echo.
echo ===== [drv] HpxDrv64.sys (x64) =====
pushd "%SRC%"
"%CL64%" /nologo /c %KM_INC% %KM_FLAGS% /Fo"%OUT%\hpxdrv.obj" src\drv\hpxdrv.c || ( popd & exit /b 1 )
popd
pushd "%OUT%"
"%LINK64%" /nologo /DRIVER /MACHINE:X64 /SUBSYSTEM:NATIVE,6.02 /ENTRY:DriverEntry ^
  /NODEFAULTLIB /INCREMENTAL:NO /OPT:REF /OPT:ICF /OUT:HpxDrv64.sys hpxdrv.obj ^
  "%KMLIB64%\ntoskrnl.lib" "%KMLIB64%\fwpkclnt.lib" "%KMLIB64%\hal.lib" "%KMLIB64%\ndis.lib" || ( popd & exit /b 1 )
REM 签名固化进构建:未签名驱动装载报 gle=577(ERROR_INVALID_IMAGE_HASH),曾致"安装驱动失败"
"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" sign /fd SHA256 /s MY /sha1 863FEA96D6CE29A881A0DFCE65FCB23292DD3564 HpxDrv64.sys || ( popd & exit /b 1 )
popd
echo [OK] HpxDrv64.sys (signed)
exit /b 0

REM ------------------------------- ?????-----------------------------------
:user
echo.
echo ===== [user] HookProxy.dll / HpxGui.exe / HpxProbe.exe (x64) =====
pushd "%SRC%"
"%CL64%" /nologo /c %UM_INC% %UM_FLAGS% /Fo"%OUT%\user\engine.obj" src\engine\engine.c || ( popd & exit /b 1 )
"%CL64%" /nologo /c %UM_INC% %UM_FLAGS% /Fo"%OUT%\user\socks5.obj" src\engine\socks5.c || ( popd & exit /b 1 )
"%CL64%" /nologo /c %UM_INC% %UM_FLAGS% /Fo"%OUT%\user\gui.obj" src\gui\gui.c || ( popd & exit /b 1 )
"%CL64%" /nologo /c %UM_INC% %UM_FLAGS% /Fo"%OUT%\user\probe.obj" src\probe\probe.c || ( popd & exit /b 1 )
popd
copy /y "%SRC%src\engine\hookproxy.def" "%OUT%\user\hookproxy.def" >nul
pushd "%OUT%\user"
"%LINK64%" /nologo /MACHINE:X64 /DLL ^
  /libpath:"%VCT%\lib\x64" /libpath:"%KIT%\Lib\%KITVER%\um\x64" /libpath:"%KIT%\Lib\%KITVER%\ucrt\x64" ^
  /DEF:hookproxy.def /OUT:HookProxy.dll engine.obj socks5.obj ws2_32.lib advapi32.lib || ( popd & exit /b 1 )
"%LINK64%" /nologo /MACHINE:X64 /SUBSYSTEM:WINDOWS ^
  /libpath:"%VCT%\lib\x64" /libpath:"%KIT%\Lib\%KITVER%\um\x64" /libpath:"%KIT%\Lib\%KITVER%\ucrt\x64" ^
  /OUT:HpxGui.exe gui.obj user32.lib gdi32.lib comctl32.lib advapi32.lib shell32.lib || ( popd & exit /b 1 )
"%LINK64%" /nologo /MACHINE:X64 /SUBSYSTEM:CONSOLE ^
  /libpath:"%VCT%\lib\x64" /libpath:"%KIT%\Lib\%KITVER%\um\x64" /libpath:"%KIT%\Lib\%KITVER%\ucrt\x64" ^
  /OUT:HpxProbe.exe probe.obj ws2_32.lib advapi32.lib || ( popd & exit /b 1 )
popd
echo [OK] HookProxy.dll HpxGui.exe HpxProbe.exe
exit /b 0

REM ------------------------------- ?????? ---------------------------------
:nul
echo.
echo ===== [nul] HpxNul.sys (x64 load probe) =====
pushd "%SRC%"
"%CL64%" /nologo /c %KM_INC% %KM_FLAGS% /Fo"%OUT%\nuldrv.obj" src\test\nuldrv.c || ( popd & exit /b 1 )
popd
pushd "%OUT%"
"%LINK64%" /nologo /DRIVER /MACHINE:X64 /SUBSYSTEM:NATIVE,6.02 /ENTRY:DriverEntry ^
  /NODEFAULTLIB /INCREMENTAL:NO /OUT:HpxNul.sys nuldrv.obj ^
  "%KMLIB64%\ntoskrnl.lib" "%KMLIB64%\hal.lib" "%KMLIB64%\fwpkclnt.lib" "%KMLIB64%\ndis.lib" || ( popd & exit /b 1 )
"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" sign /fd SHA256 /s MY /sha1 863FEA96D6CE29A881A0DFCE65FCB23292DD3564 HpxNul.sys || ( popd & exit /b 1 )
popd
echo [OK] HpxNul.sys
exit /b 0
