@echo off
cd /d C:\hpx
taskkill /F /IM HpxProbe.exe >nul 2>&1
taskkill /F /IM HpxTgt.exe >nul 2>&1
taskkill /F /IM HpxGui.exe >nul 2>&1
sc stop HpxDrv64 >nul 2>&1
ping -n 4 127.0.0.1 >nul
copy /y C:\hpx\drop\HpxDrv64.sys C:\hpx\HpxDrv64.sys
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe
copy /y C:\hpx\drop\HpxGui.exe C:\hpx\HpxGui.exe
del C:\hpx\HpxTgt.exe >nul 2>&1
echo === AUTO TEST === > C:\hpx\auto_out.txt
C:\hpx\HpxProbe.exe auto >> C:\hpx\auto_out.txt 2>&1
echo AUTO-RC=%errorlevel% >> C:\hpx\auto_out.txt
echo === E2E REGRESSION === > C:\hpx\e2e_out.txt
C:\hpx\run_e2e.bat
echo ALL-DONE
