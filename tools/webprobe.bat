@echo off
setlocal enabledelayedexpansion
cd /d C:\hpx
set UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
echo === WEBPROBE %date% %time% === > web_out.txt
echo. >> web_out.txt
echo [A] transparent chain (VM DNS, our proxy to node) >> web_out.txt
for %%U in (https://us.ip111.cn/ip.php https://sspanel.net/ip.php) do (
  echo --- A %%U --- >> web_out.txt
  C:\Windows\System32\curl.exe -s -m 20 -A "%UA%" -H "Referer: https://ip111.cn/" -H "Sec-Fetch-Dest: iframe" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: cross-site" -w "[code=%%{http_code} time=%%{time_total}]" %%U >> web_out.txt 2>&1
  echo. >> web_out.txt
  ping -n 4 127.0.0.1 >nul
)
echo. >> web_out.txt
echo [B] socks5-hostname (node DNS, node path) >> web_out.txt
for %%U in (https://us.ip111.cn/ip.php https://sspanel.net/ip.php) do (
  echo --- B %%U --- >> web_out.txt
  C:\Windows\System32\curl.exe -s -m 20 --socks5-hostname 10.10.10.254:1081 -A "%UA%" -H "Referer: https://ip111.cn/" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: zh-CN,zh;q=0.9" -H "Sec-Fetch-Dest: iframe" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: cross-site" -w "[code=%%{http_code} time=%%{time_total}]" %%U >> web_out.txt 2>&1
  echo. >> web_out.txt
  ping -n 4 127.0.0.1 >nul
)
echo. >> web_out.txt
echo [C] socks5 IP mode (VM DNS resolved by curl, node path) >> web_out.txt
for %%U in (https://us.ip111.cn/ip.php https://sspanel.net/ip.php) do (
  echo --- C %%U --- >> web_out.txt
  C:\Windows\System32\curl.exe -s -m 20 --socks5 10.10.10.254:1081 -A "%UA%" -H "Referer: https://ip111.cn/" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: zh-CN,zh;q=0.9" -H "Sec-Fetch-Dest: iframe" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: cross-site" -w "[code=%%{http_code} time=%%{time_total}]" %%U >> web_out.txt 2>&1
  echo. >> web_out.txt
  ping -n 4 127.0.0.1 >nul
)
echo. >> web_out.txt
echo [DNS] VM resolver answers (x2 for poison randomization check) >> web_out.txt
nslookup sspanel.net >> web_out.txt 2>&1
nslookup sspanel.net >> web_out.txt 2>&1
nslookup us.ip111.cn >> web_out.txt 2>&1
echo. >> web_out.txt
echo WEBPROBE-DONE >> web_out.txt
echo WEBPROBE-DONE
