@echo off
cd /d C:\hpx
sc stop HpxDrv64 >nul 2>&1
ping -n 4 127.0.0.1 >nul
copy /y C:\hpx\drop\HpxDrv64.sys C:\hpx\HpxDrv64.sys >nul
copy /y C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll >nul
copy /y C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe >nul
netsh advfirewall firewall delete rule name=HPXEcho >nul 2>&1
netsh advfirewall firewall add rule name=HPXEcho dir=in action=allow protocol=TCP localport=80 >nul
echo === PREFLIGHT === > e2e_out.txt
sc query HpxDrv64 >> e2e_out.txt 2>&1
echo === E2E RUN === >> e2e_out.txt
HpxProbe.exe e2e --node 10.10.10.254:1081 --tcp 223.5.5.5:80 --udp 223.5.5.5:53 --back 3 >> e2e_out.txt 2>&1
echo E2E-EXIT=%errorlevel% >> e2e_out.txt
echo === POSTFLIGHT === >> e2e_out.txt
sc query HpxDrv64 >> e2e_out.txt 2>&1
dir C:\Windows\Minidump /b /a >> e2e_out.txt 2>&1
echo RUN-DONE >> e2e_out.txt
