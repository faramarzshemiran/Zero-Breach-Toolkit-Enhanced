# Requires Administrator; opt-in outbound rule for explicit Python executable only.
# This rule does NOT guarantee child-process isolation. Run in disconnected VM for sensitive evidence.
param([Parameter(Mandatory=$true)][string]$PythonPath,[switch]$Remove)
$ErrorActionPreference='Stop'
$rule='ZeroBreach-Offline-Python-Egress'
if($Remove) { Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue; exit 0 }
if(-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) { throw 'Python executable not found' }
if(Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue) { throw 'Rule exists; remove first' }
New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Block -Program (Resolve-Path -LiteralPath $PythonPath).Path -Profile Any | Out-Null
Write-Output 'Rule installed for Python only; use disconnected VM for child-process containment.'
