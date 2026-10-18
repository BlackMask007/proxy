@echo off
cd /d C:\hpx
taskkill /F /IM HpxProbe.exe >nul 2>&1
ping -n 3 127.0.0.1 >nul
echo === COPY === > drvtest.txt
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe >> drvtest.txt 2>&1
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll >> drvtest.txt 2>&1
echo === HASH === >> drvtest.txt
certutil -hashfile C:\hpx\HpxProbe.exe MD5 >> drvtest.txt 2>&1
echo === BANNER === >> drvtest.txt
C:\hpx\HpxProbe.exe wfp >> drvtest.txt 2>&1
echo === UNINSTALL === >> drvtest.txt
C:\hpx\HpxProbe.exe drv uninstall >> drvtest.txt 2>&1
sc query HpxDrv64 >> drvtest.txt 2>&1
echo === INSTALL === >> drvtest.txt
C:\hpx\HpxProbe.exe drv install >> drvtest.txt 2>&1
sc query HpxDrv64 >> drvtest.txt 2>&1
echo DRVTEST-DONE >> drvtest.txt
