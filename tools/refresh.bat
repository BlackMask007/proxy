@echo off
cd /d C:\hpx
taskkill /F /IM HpxProbe.exe >nul 2>&1
taskkill /F /IM curl.exe >nul 2>&1
sc stop HpxDrv64 >nul 2>&1
ping -n 3 127.0.0.1 >nul
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe >nul
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll >nul
copy /y C:\hpx\drop\HpxDrv64.sys C:\hpx\HpxDrv64.sys >nul
del relay.log >nul 2>&1
start /b cmd /c "C:\hpx\HpxProbe.exe hold 200 --node 10.10.10.254:1081 --img curl.exe > C:\hpx\hold_out.txt 2>&1"
ping -n 6 127.0.0.1 >nul
echo === refresh stress: 10x full ip111.cn main document === > refresh.txt
for /L %%i in (1,1,10) do (
  C:\Windows\System32\curl.exe -s -L -m 20 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" -H "Referer: https://ip111.cn/" -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: none" -H "Cache-Control: no-cache" -o m%%i.html http://ip111.cn/
  findstr /c:"74.82.195.54" m%%i.html >nul && (echo [%%i] NODE-IP OK >> refresh.txt) || (echo [%%i] LEAK-NODE-IP-MISSING >> refresh.txt)
  findstr /r /c:"[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*" m%%i.html | findstr /v "74.82.195.54" >> refresh.txt
  ping -n 3 127.0.0.1 >nul
)
echo REFRESH-DONE
