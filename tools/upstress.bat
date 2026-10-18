@echo off
cd /d C:\hpx
taskkill /F /IM HpxProbe.exe >nul 2>&1
taskkill /F /IM curl.exe >nul 2>&1
taskkill /F /IM HpxGui.exe >nul 2>&1
taskkill /F /IM NodeDirect.exe >nul 2>&1
sc stop HpxDrv64 >nul 2>&1
ping -n 3 127.0.0.1 >nul
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe >nul
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll >nul
copy /y C:\hpx\drop\HpxDrv64.sys C:\hpx\HpxDrv64.sys >nul
copy /y C:\Windows\System32\curl.exe C:\hpx\NodeDirect.exe >nul
start /b cmd /c "C:\hpx\HpxProbe.exe hold 220 --node 10.10.10.254:1081 --img curl.exe > C:\hpx\hold_out.txt 2>&1"
ping -n 6 127.0.0.1 >nul
echo === upload stress: 6x5MB alternating chain / node-direct === > upstress.txt
for /L %%i in (1,1,6) do (
  C:\Windows\System32\curl.exe -s -m 40 -X POST --data-binary @C:\hpx\up5.bin -o nul -w "[chain %%i] up=%%{speed_upload} code=%%{http_code}" "https://speedtest.j3j.net/backend/empty.php" >> upstress.txt 2>&1
  echo. >> upstress.txt
  C:\hpx\NodeDirect.exe --socks5-hostname 10.10.10.254:1081 -s -m 40 -X POST --data-binary @C:\hpx\up5.bin -o nul -w "[node  %%i] up=%%{speed_upload} code=%%{http_code}" "https://speedtest.j3j.net/backend/empty.php" >> upstress.txt 2>&1
  echo. >> upstress.txt
)
echo UPSTRESS-DONE
