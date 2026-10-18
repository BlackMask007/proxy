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
start /b cmd /c "C:\hpx\HpxProbe.exe hold 90 --node 10.10.10.254:1081 --img curl.exe > C:\hpx\hold_out.txt 2>&1"
ping -n 6 127.0.0.1 >nul
echo === race: 8 processes connect immediately at spawn === > race.txt
start /b C:\Windows\System32\curl.exe -s -m 25 -A "Mozilla/5.0" -o r1.txt https://us.ip111.cn/ip.php
start /b C:\Windows\System32\curl.exe -s -m 25 -A "Mozilla/5.0" -o r2.txt https://us.ip111.cn/ip.php
start /b C:\Windows\System32\curl.exe -s -m 25 -A "Mozilla/5.0" -o r3.txt https://us.ip111.cn/ip.php
start /b C:\Windows\System32\curl.exe -s -m 25 -A "Mozilla/5.0" -o r4.txt https://us.ip111.cn/ip.php
start /b C:\Windows\System32\curl.exe -s -m 25 -A "Mozilla/5.0" -o r5.txt https://sspanel.net/ip.php
start /b C:\Windows\System32\curl.exe -s -m 25 -A "Mozilla/5.0" -o r6.txt https://sspanel.net/ip.php
start /b C:\Windows\System32\curl.exe -s -m 25 -A "Mozilla/5.0" -o r7.txt https://sspanel.net/ip.php
start /b C:\Windows\System32\curl.exe -s -m 25 -A "Mozilla/5.0" -o r8.txt https://sspanel.net/ip.php
ping -n 30 127.0.0.1 >nul
for %%F in (r1 r2 r3 r4 r5 r6 r7 r8) do (
  echo --- %%F --- >> race.txt
  type %%F.txt >> race.txt 2>&1
  echo. >> race.txt
)
echo RACE-DONE
