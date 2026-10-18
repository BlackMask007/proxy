@echo off
cd /d C:\hpx
echo BAT-STARTED > direct_out.txt
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll >> direct_out.txt 2>&1
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe >> direct_out.txt 2>&1
echo BEFORE-RUN >> direct_out.txt
C:\hpx\HpxProbe.exe auto >> direct_out.txt 2>&1
echo AFTER-RUN RC=%errorlevel% >> direct_out.txt
echo BAT-DONE
