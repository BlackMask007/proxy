@echo off
REM build_nul.cmd - ???+????????????????set "VCT=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.50.35717"
set "KIT=C:\Program Files (x86)\Windows Kits\10"
set "KITVER=10.0.26100.0"
set "SDK=%KIT%\Include\%KITVER%"
set "KMLIB64=%KIT%\Lib\%KITVER%\km\x64"
set "CL64=%VCT%\bin\Hostx64\x64\cl.exe"
set "LINK64=%VCT%\bin\Hostx64\x64\link.exe"
set "ST=%KIT%\bin\%KITVER%\x64\signtool.exe"
set "SRC=%~dp0"
"%CL64%" /nologo /c /I"%SDK%\km" /I"%SDK%\km\crt" /I"%SDK%\shared" /I"%VCT%\include" /I"%SDK%\ucrt" /I"%SDK%\um" ^
  /utf-8 /kernel /Zc:wchar_t /GR- /GS- /Zl /O2 /W3 /D_KERNEL_MODE=1 /D_NT_TARGET_VERSION=0x0A00 /DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A00000B ^
  /D_AMD64_=1 /DAMD64 /D_WIN64=1 /Fo"%SRC%build\nuldrv.obj" src\test\nuldrv.c || exit /b 1
pushd "%SRC%build"
"%LINK64%" /nologo /DRIVER /MACHINE:X64 /SUBSYSTEM:NATIVE,6.02 /ENTRY:DriverEntry /NODEFAULTLIB /INCREMENTAL:NO /OUT:HpxNul.sys nuldrv.obj ^
  "%KMLIB64%\ntoskrnl.lib" "%KMLIB64%\hal.lib" || ( popd & exit /b 1 )
"%ST%" sign /fd SHA256 /s MY /sha1 863FEA96D6CE29A881A0DFCE65FCB23292DD3564 HpxNul.sys >nul || ( popd & exit /b 1 )
popd
echo [OK] HpxNul.sys
