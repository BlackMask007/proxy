@echo off
cd /d C:\hpx
taskkill /F /IM HpxProbe.exe >nul 2>&1
taskkill /F /IM curl.exe >nul 2>&1
sc stop HpxDrv64 >nul 2>&1
ping -n 3 127.0.0.1 >nul
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe >nul
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll >nul
copy /y C:\hpx\drop\HpxDrv64.sys C:\hpx\HpxDrv64.sys >nul
del warm.bin >nul 2>&1
echo === warm: start unbound transfer === > warm.txt
start /b cmd /c "C:\Windows\System32\curl.exe --socks5-hostname 10.10.10.254:1081 -s -m 45 -o C:\hpx\warm.bin https://speedtest.j3j.net/backend/garbage.php?ckSize=50 2> C:\hpx\warm_err.txt"
ping -n 10 127.0.0.1 >nul
echo === bind while transfer in flight === >> warm.txt
start /b cmd /c "C:\hpx\HpxProbe.exe hold 45 --node 10.10.10.254:1081 --img curl.exe > C:\hpx\hold_out.txt 2>&1"
ping -n 40 127.0.0.1 >nul
dir warm.bin >> warm.txt 2>&1
echo WARM-DONE
