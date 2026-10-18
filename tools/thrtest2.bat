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
del nd.bin ch.bin up5.bin >nul 2>&1
C:\Windows\System32\fsutil file createnew C:\hpx\up5.bin 5242880 >nul 2>&1
if not exist C:\hpx\up5.bin C:\Windows\System32\curl.exe -s -m 30 -o up5.bin "https://speedtest.j3j.net/backend/garbage.php?ckSize=5"
start /b cmd /c "C:\hpx\HpxProbe.exe hold 240 --node 10.10.10.254:1081 --img curl.exe > C:\hpx\hold_out.txt 2>&1"
ping -n 6 127.0.0.1 >nul
echo === D1: A-down (system-proxy regime) === > thr2.txt
C:\hpx\NodeDirect.exe --socks5-hostname 10.10.10.254:1081 -s -m 60 -o nd.bin -w "down=%%{speed_download} time=%%{time_total}" "https://speedtest.j3j.net/backend/garbage.php?ckSize=50" >> thr2.txt 2>&1
echo. >> thr2.txt
echo === D2: B-down (our chain) === >> thr2.txt
C:\Windows\System32\curl.exe -s -m 60 -o ch.bin -w "down=%%{speed_download} time=%%{time_total}" "https://speedtest.j3j.net/backend/garbage.php?ckSize=50" >> thr2.txt 2>&1
echo. >> thr2.txt
echo === U1: A-up (system-proxy regime) === >> thr2.txt
C:\hpx\NodeDirect.exe --socks5-hostname 10.10.10.254:1081 -s -m 60 -X POST --data-binary @C:\hpx\up5.bin -o nul -w "up=%%{speed_upload} code=%%{http_code} time=%%{time_total}" "https://speedtest.j3j.net/backend/empty.php" >> thr2.txt 2>&1
echo. >> thr2.txt
echo === U2: B-up (our chain) === >> thr2.txt
C:\Windows\System32\curl.exe -s -m 60 -X POST --data-binary @C:\hpx\up5.bin -o nul -w "up=%%{speed_upload} code=%%{http_code} time=%%{time_total}" "https://speedtest.j3j.net/backend/empty.php" >> thr2.txt 2>&1
echo. >> thr2.txt
echo THR2-DONE
