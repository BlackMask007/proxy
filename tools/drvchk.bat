@echo off
cd /d C:\hpx
echo === A: with driver loaded === > drvchk.txt
C:\hpx\NodeDirect.exe --socks5-hostname 10.10.10.254:1081 -s -m 12 -o nodechk.html -w "code=%%{http_code} time=%%{time_total}" https://us.ip111.cn/ip.php >> drvchk.txt 2>&1
echo. >> drvchk.txt
echo EXIT=%errorlevel% >> drvchk.txt
echo === B: driver stopped === >> drvchk.txt
sc stop HpxDrv64 >> drvchk.txt 2>&1
ping -n 5 127.0.0.1 >nul
C:\hpx\NodeDirect.exe --socks5-hostname 10.10.10.254:1081 -s -m 12 -o nodechk.html -w "code=%%{http_code} time=%%{time_total}" https://us.ip111.cn/ip.php >> drvchk.txt 2>&1
echo. >> drvchk.txt
echo EXIT=%errorlevel% >> drvchk.txt
echo DRVCHK-DONE
