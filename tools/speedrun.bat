@echo off
cd /d C:\hpx
taskkill /F /IM HpxProbe.exe >nul 2>&1
taskkill /F /IM curl.exe >nul 2>&1
sc stop HpxDrv64 >nul 2>&1
ping -n 3 127.0.0.1 >nul
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe >nul
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll >nul
copy /y C:\hpx\drop\HpxDrv64.sys C:\hpx\HpxDrv64.sys >nul
start /b cmd /c "C:\hpx\HpxProbe.exe hold 150 --node 10.10.10.254:1081 --img curl.exe > C:\hpx\hold_out.txt 2>&1"
ping -n 6 127.0.0.1 >nul
del spd.bin >nul 2>&1
C:\Windows\System32\curl.exe -s -m 90 -A "Mozilla/5.0" -o spd.bin -w "speed=%%{speed_download} time=%%{time_total} size=%%{size_download}" "https://speedtest.j3j.net/backend/garbage.php?ckSize=25" > spd.txt 2>&1
echo SPEED-DONE
