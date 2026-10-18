@echo off
cd /d C:\hpx
echo === DIR === > dbg.txt
dir C:\hpx\drop /b >> dbg.txt 2>&1
dir C:\hpx\Hpx*.exe /b >> dbg.txt 2>&1
echo === RUN === >> dbg.txt
C:\hpx\HpxProbe.exe auto >> dbg.txt 2>&1
echo AUTO-RC=%errorlevel% >> dbg.txt
echo DBG-DONE
