# Run ONLY inside an isolated disposable VM. Requires elevation.
# Blocks outbound traffic for ALL processes (including children), restoring policies in finally.
param([Parameter(ValueFromRemainingArguments=$true)][string[]]$ScanArgs)
$ErrorActionPreference = 'Stop'
$machine = Get-CimInstance Win32_ComputerSystem
$identity = "$($machine.Manufacturer) $($machine.Model)"
if ($identity -notmatch '(?i)virtual|vmware|hyper-v|kvm|qemu|virtualbox|parallels|xen') { throw 'Refusing to change host firewall: no VM identified. Use an isolated VM.' }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Requires elevation inside a dedicated VM' }
# Refuse a VM with any operational physical/virtual network interface.
# A disconnected guest NIC is a stronger boundary than a guest firewall alone.
$upAdapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch '(?i)loopback' })
if ($upAdapters.Count -gt 0) { throw 'VM network adaptor is connected. Disconnect ALL VM network adaptors in the hypervisor before running.' }
if ($ScanArgs -contains '--update' -or $ScanArgs -contains '--collect-android' -or $ScanArgs -contains '--allow-external-collector') { throw 'External operations are forbidden' }
$profiles = @('Domain','Private','Public')
$original = @(Get-NetFirewallProfile | Select-Object Name,DefaultOutboundAction,Enabled)
try {
  foreach ($name in $profiles) { Set-NetFirewallProfile -Name $name -Enabled True -DefaultOutboundAction Block }
  $effective = @(Get-NetFirewallProfile)
  if (@($effective | Where-Object { $_.Enabled -ne $true -or $_.DefaultOutboundAction -ne 'Block' }).Count -ne 0) { throw 'Firewall policy not enforced' }
  # Firewall block-default does not override existing outbound ALLOW rules.
  # Therefore refuse unless the VM has zero enabled outbound allow rules.
  $allows = @(Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction Stop)
  if ($allows.Count -gt 0) { throw "Found $($allows.Count) outbound allow rules; refusing to scan" }
  & python -X utf8 tools/containment_probe.py --mode strict
  if ($LASTEXITCODE -ne 0) { throw 'Containment probe failed' }
  & python -X utf8 scan/zero-breach-toolkit.py --no-feeds @ScanArgs
  $scanExit = $LASTEXITCODE
} finally {
  foreach ($item in $original) { Set-NetFirewallProfile -Name $item.Name -Enabled $item.Enabled -DefaultOutboundAction $item.DefaultOutboundAction }
}

if ($scanExit -is [int]) { exit $scanExit }
