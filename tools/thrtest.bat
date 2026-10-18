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
del nd.bin ch.bin >nul 2>&1
start /b cmd /c "C:\hpx\HpxProbe.exe hold 240 --node 10.10.10.254:1081 --img curl.exe > C:\hpx\hold_out.txt 2>&1"
ping -n 6 127.0.0.1 >nul
echo === A: system-proxy regime (direct SOCKS to node, unregistered exe) === > thr.txt
C:\hpx\NodeDirect.exe --socks5-hostname 10.10.10.254:1081 -s -m 60 -o nd.bin -w "speed=%%{speed_download} time=%%{time_total} size=%%{size_download}" "https://speedtest.j3j.net/backend/garbage.php?ckSize=50" >> thr.txt 2>&1
echo. >> thr.txt
ping -n 4 127.0.0.1 >nul
echo === B: our transparent chain (registered curl.exe) === >> thr.txt
C:\Windows\System32\curl.exe -s -m 60 -o ch.bin -w "speed=%%{speed_download} time=%%{time_total} size=%%{size_download}" "https://speedtest.j3j.net/backend/garbage.php?ckSize=50" >> thr.txt 2>&1
echo. >> thr.txt
echo THR-DONE
