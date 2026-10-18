@echo off
cd /d C:\hpx
taskkill /F /IM HpxGui.exe >nul 2>&1
taskkill /F /IM HpxProbe.exe >nul 2>&1
taskkill /F /IM curl.exe >nul 2>&1
taskkill /F /IM chrome.exe >nul 2>&1
sc stop HpxDrv64 >nul 2>&1
ping -n 8 127.0.0.1 >nul
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe >nul
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll >nul
copy /y C:\hpx\drop\HpxGui.exe C:\hpx\HpxGui.exe >nul
copy /y C:\hpx\drop\HpxDrv64.sys C:\hpx\HpxDrv64.sys >nul
if errorlevel 1 (
  ping -n 8 127.0.0.1 >nul
  copy /y C:\hpx\drop\HpxDrv64.sys C:\hpx\HpxDrv64.sys >nul
)
certutil -hashfile C:\hpx\HpxDrv64.sys MD5 > C:\hpx\dep_hash.txt 2>&1
del hold_live.txt >nul 2>&1
start /b cmd /c "C:\hpx\HpxProbe.exe hold 150 --node 10.10.10.254:1081 --global > C:\hpx\hold_out.txt 2>&1"
ping -n 6 127.0.0.1 >nul
call C:\hpx\webprobe.bat
del C:\hpx\page3.png >nul 2>&1
"C:\Program Files\Google\Chrome\Application\chrome.exe" --headless=new --disable-gpu --hide-crash-restore-bubble --virtual-time-budget=20000 --window-size=1280,1500 --screenshot=C:\hpx\page3.png https://ip111.cn/ >nul 2>&1
echo GLOBAL-DONE
