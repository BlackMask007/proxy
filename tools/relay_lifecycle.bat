@echo off
C:\hpx\HpxProbe.exe drv cycle || exit /b 1
C:\hpx\HpxProbe.exe lifecycle2 || exit /b 1
C:\hpx\HpxProbe.exe lifecycle
