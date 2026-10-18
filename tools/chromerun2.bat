@echo off
cd /d C:\hpx
taskkill /F /IM HpxProbe.exe >nul 2>&1
taskkill /F /IM chrome.exe >nul 2>&1
sc stop HpxDrv64 >nul 2>&1
ping -n 3 127.0.0.1 >nul
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe >nul
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll >nul
copy /y C:\hpx\drop\HpxDrv64.sys C:\hpx\HpxDrv64.sys >nul
del hold_live.txt >nul 2>&1
start /b cmd /c "C:\hpx\HpxProbe.exe hold 150 --node 10.10.10.254:1081 --img chrome.exe > C:\hpx\hold_out.txt 2>&1"
ping -n 6 127.0.0.1 >nul
echo ENGINE-READY
