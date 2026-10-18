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
del relay.log >nul 2>&1
start /b cmd /c "C:\hpx\HpxProbe.exe hold 200 --node 10.10.10.254:1081 --img curl.exe > C:\hpx\hold_out.txt 2>&1"
ping -n 6 127.0.0.1 >nul
echo === stability: 10 sequential fetches via chain === > stab.txt
for /L %%i in (1,1,10) do (
  C:\Windows\System32\curl.exe -s -m 20 -A "Mozilla/5.0" -H "Referer: https://ip111.cn/" -w "[%%i] code=%%{http_code} time=%%{time_total} size=%%{size_download}" https://us.ip111.cn/ip.php >> stab.txt 2>&1
  echo. >> stab.txt
  ping -n 3 127.0.0.1 >nul
)
echo STAB-DONE
