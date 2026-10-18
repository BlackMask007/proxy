@echo off
cd /d C:\hpx
echo === ipconfig === > netchk2.txt
ipconfig /all >> netchk2.txt 2>&1
echo === ping gateway === >> netchk2.txt
ping -n 2 10.10.10.1 >> netchk2.txt 2>&1
echo === ping node === >> netchk2.txt
ping -n 2 10.10.10.254 >> netchk2.txt 2>&1
echo === ping 223.5.5.5 === >> netchk2.txt
ping -n 2 223.5.5.5 >> netchk2.txt 2>&1
echo === driver === >> netchk2.txt
sc query HpxDrv64 >> netchk2.txt 2>&1
echo === tcp 1081 === >> netchk2.txt
C:\hpx\NodeDirect.exe --socks5-hostname 10.10.10.254:1081 -s -m 10 -o nul -w "code=%%{http_code}" https://us.ip111.cn/ip.php >> netchk2.txt 2>&1
echo. >> netchk2.txt
echo EXIT=%errorlevel% >> netchk2.txt
echo NETCHK2-DONE
