# blakSOC network isolation for Windows Wazuh agents (Windows Defender Firewall).
# Blocks all inbound/outbound traffic except to the Wazuh manager(s) listed in
# C:\Program Files (x86)\ossec-agent\blaksoc-allow.txt. "release" restores the previous policy.
param([ValidateSet("isolate", "release")] [string]$Mode = "isolate")
$ErrorActionPreference = "Stop"
$root = "${env:ProgramFiles(x86)}\ossec-agent"
$log = "$root\active-response\active-responses.log"
$allow = "$root\blaksoc-allow.txt"
$group = "blakSOC isolation"
function Log($m) { Add-Content -Path $log -Value "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') blaksoc-isolate-win: $m" }

$null = [Console]::In.ReadLine()  # consume Wazuh JSON message

if ($Mode -eq "isolate") {
  if (Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue) { Log "already isolated"; exit 0 }
  $managers = if (Test-Path $allow) { Get-Content $allow | Where-Object { $_ -match '\S' } } else { @() }
  foreach ($ip in $managers) {
    New-NetFirewallRule -DisplayName "blakSOC allow $ip out" -Group $group -Direction Outbound -RemoteAddress $ip -Action Allow | Out-Null
    New-NetFirewallRule -DisplayName "blakSOC allow $ip in" -Group $group -Direction Inbound -RemoteAddress $ip -Action Allow | Out-Null
  }
  Get-NetFirewallProfile | ForEach-Object { $_ | Select-Object Name, DefaultInboundAction, DefaultOutboundAction } | Export-Clixml "$root\blaksoc-fw-backup.xml"
  Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
  Log "isolated (allow: $($managers -join ', '))"
} else {
  Remove-NetFirewallRule -Group $group -ErrorAction SilentlyContinue
  if (Test-Path "$root\blaksoc-fw-backup.xml") {
    Import-Clixml "$root\blaksoc-fw-backup.xml" | ForEach-Object { Set-NetFirewallProfile -Name $_.Name -DefaultInboundAction $_.DefaultInboundAction -DefaultOutboundAction $_.DefaultOutboundAction }
    Remove-Item "$root\blaksoc-fw-backup.xml"
  } else {
    Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow
  }
  Log "released"
}
