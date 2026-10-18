@echo off
cd /d C:\hpx
taskkill /F /IM HpxProbe.exe >nul 2>&1
taskkill /F /IM curl.exe >nul 2>&1
taskkill /F /IM HpxGui.exe >nul 2>&1
sc stop HpxDrv64 >nul 2>&1
ping -n 3 127.0.0.1 >nul
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe >nul
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll >nul
copy /y C:\hpx\drop\HpxDrv64.sys C:\hpx\HpxDrv64.sys >nul
del relay.log relay.1.log >nul 2>&1
echo === longevity: engine IDLE (no proxying), 24 samples x 20s === > long.txt
start /b cmd /c "C:\hpx\HpxProbe.exe hold 520 --node 10.10.10.254:1081 > C:\hpx\hold_out.txt 2>&1"
ping -n 8 127.0.0.1 >nul
for /L %%i in (1,1,24) do (
  echo --- sample %%i --- >> long.txt
  C:\Windows\System32\ping.exe -n 2 -w 1000 10.10.10.254 >> long.txt
  wmic OS get FreePhysicalMemory /value >> long.txt
  ping -n 18 127.0.0.1 >nul
)
ping -n 30 127.0.0.1 >nul
echo === diag === >> long.txt
type C:\hpx\hold_out.txt >> long.txt
dir C:\hpx\relay*.log >> long.txt 2>&1
echo LONG-DONE
