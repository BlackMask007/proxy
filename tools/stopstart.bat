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
echo === cycle: start #1 -> fetch -> stop -> start #2 -> 4x immediate spawns === > cycle.txt
start /b cmd /c "C:\hpx\HpxProbe.exe hold 20 --node 10.10.10.254:1081 --img curl.exe > C:\hpx\h1.txt 2>&1"
ping -n 6 127.0.0.1 >nul
C:\Windows\System32\curl.exe -s -m 20 -A "Mozilla/5.0" -H "Referer: https://ip111.cn/" -H "Sec-Fetch-Dest: iframe" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: cross-site" -o c1.txt https://us.ip111.cn/ip.php
echo --- fetch1 --- >> cycle.txt
type c1.txt >> cycle.txt
echo. >> cycle.txt
ping -n 25 127.0.0.1 >nul
echo === engine stopped (EmptyData) ; restart #2 === >> cycle.txt
start /b cmd /c "C:\hpx\HpxProbe.exe hold 25 --node 10.10.10.254:1081 --img curl.exe > C:\hpx\h2.txt 2>&1"
ping -n 6 127.0.0.1 >nul
start /b C:\Windows\System32\curl.exe -s -m 20 -A "Mozilla/5.0" -H "Referer: https://ip111.cn/" -H "Sec-Fetch-Dest: iframe" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: cross-site" -o d1.txt https://us.ip111.cn/ip.php
start /b C:\Windows\System32\curl.exe -s -m 20 -A "Mozilla/5.0" -H "Referer: https://ip111.cn/" -H "Sec-Fetch-Dest: iframe" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: cross-site" -o d2.txt https://us.ip111.cn/ip.php
start /b C:\Windows\System32\curl.exe -s -m 20 -A "Mozilla/5.0" -H "Referer: https://ip111.cn/" -H "Sec-Fetch-Dest: iframe" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: cross-site" -o d3.txt https://sspanel.net/ip.php
start /b C:\Windows\System32\curl.exe -s -m 20 -A "Mozilla/5.0" -H "Referer: https://ip111.cn/" -H "Sec-Fetch-Dest: iframe" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: cross-site" -o d4.txt https://sspanel.net/ip.php
ping -n 30 127.0.0.1 >nul
for %%F in (d1 d2 d3 d4) do (
  echo --- %%F --- >> cycle.txt
  type %%F.txt >> cycle.txt 2>&1
  echo. >> cycle.txt
)
echo CYCLE-DONE
