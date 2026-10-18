$out = @()
$out += "=== stop service ==="
sc.exe stop HpxDrv64 2>&1 | Out-Null
for ($i = 0; $i -lt 60; $i++) {
  $s = Get-Service HpxDrv64 -ErrorAction SilentlyContinue
  if ($s -and $s.Status -eq "Stopped") { break }
  Start-Sleep -Milliseconds 250
}
$out += ("service state: " + (Get-Service HpxDrv64).Status)
$out += "=== replace files ==="
Copy-Item C:\hpx\drop\HpxDrv64.sys C:\hpx\HpxDrv64.sys -Force
Copy-Item C:\hpx\drop\HookProxy.dll C:\hpx\HookProxy.dll -Force
Copy-Item C:\hpx\drop\HpxProbe.exe C:\hpx\HpxProbe.exe -Force
Copy-Item C:\hpx\drop\HpxGui.exe C:\hpx\HpxGui.exe -Force
foreach ($f in @("HpxDrv64.sys","HookProxy.dll","HpxProbe.exe","HpxGui.exe")) {
  $out += ($f + " " + (Get-FileHash ("C:\hpx\" + $f) -Algorithm MD5).Hash)
}
Set-Content -Path C:\hpx\deploy.txt -Value ($out -join "`r`n") -Encoding UTF8
