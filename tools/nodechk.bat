@echo off
cd /d C:\hpx
C:\hpx\NodeDirect.exe --socks5-hostname 10.10.10.254:1081 -s -m 15 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" -H "Referer: https://ip111.cn/" -H "Sec-Fetch-Dest: iframe" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: cross-site" -o nodechk.html https://us.ip111.cn/ip.php
echo CURL-EXIT=%errorlevel% > nodechk.txt
type nodechk.html >> nodechk.txt
echo NODECHK-DONE
