@echo off
cd /d C:\hpx
echo === conns to node === > connchk.txt
netstat -ano | findstr "10.10.10.254" >> connchk.txt 2>&1
echo === counts === >> connchk.txt
netstat -ano | find "10.10.10.254" | find /c ":" >> connchk.txt
echo === timewait total === >> connchk.txt
netstat -ano | find "TIME_WAIT" | find /c "TIME_WAIT" >> connchk.txt
echo === est total === >> connchk.txt
netstat -ano | find "ESTABLISHED" | find /c "ESTABLISHED" >> connchk.txt
echo CONNCHK-DONE
