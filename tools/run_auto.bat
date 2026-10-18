@echo off
cd /d C:\hpx
taskkill /F /IM HpxProbe.exe >nul 2>&1
taskkill /F /IM HpxGui.exe >nul 2>&1
taskkill /F /IM HpxTgt.exe >nul 2>&1
ping -n 3 127.0.0.1 >nul
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe
copy /y C:\hpx\drop\HpxGui.exe C:\hpx\HpxGui.exe
C:\hpx\HpxProbe.exe auto > C:\hpx\auto_out.txt 2>&1
echo AUTO-EXIT=%errorlevel% >> C:\hpx\auto_out.txt
echo AUTO-DONE
