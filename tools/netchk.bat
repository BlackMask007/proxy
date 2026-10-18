@echo off
cd /d C:\hpx
echo === ping node === > netchk.txt
ping -n 3 10.10.10.254 >> netchk.txt
echo === curl socks retry === >> netchk.txt
C:\hpx\NodeDirect.exe --socks5-hostname 10.10.10.254:1081 -s -m 15 -o nodechk.html -w "code=%%{http_code} time=%%{time_total}" https://us.ip111.cn/ip.php >> netchk.txt 2>&1
echo. >> netchk.txt
echo CURL-EXIT=%errorlevel% >> netchk.txt
echo === second retry === >> netchk.txt
C:\hpx\NodeDirect.exe --socks5-hostname 10.10.10.254:1081 -s -m 15 -o nodechk.html -w "code=%%{http_code} time=%%{time_total}" https://us.ip111.cn/ip.php >> netchk.txt 2>&1
echo. >> netchk.txt
echo CURL-EXIT=%errorlevel% >> netchk.txt
echo NETCHK-DONE
