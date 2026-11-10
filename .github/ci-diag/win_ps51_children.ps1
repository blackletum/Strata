# DIAGNOSTIC ONLY (ci/checks-green; dropped before anything goes to main). Run from pwsh (PowerShell 7), as GitHub's Windows steps are.
# For each cmdlet family Strata's product code asks a Windows PowerShell 5.1 child for (powershell.exe -NoProfile -Command ...), the exit code
# and the first error line, (a) with the PSModulePath PowerShell 7 hands down and (b) with PowerShell 7's entries dropped (what the
# test runners do). Also where 5.1 finds each core module, and why Microsoft.PowerShell.Security fails to load.
$ErrorActionPreference = 'Continue'
$exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$raw = $env:PSModulePath
$kept = ($raw -split ';' | Where-Object { $_ -and -not ($_.ToLower().Replace('/', '\') -like '*\powershell\*' -and $_.ToLower() -notlike '*\windowspowershell\*') }) -join ';'
"PSModulePath (raw):  $raw"
"PSModulePath (kept): $kept"
$probes = [ordered]@{
  'CimCmdlets Get-CimInstance + Select/ConvertTo-Json (hardware, setup, mcp)' = 'Get-CimInstance Win32_Processor | Select-Object -First 1 Name | ConvertTo-Json -Compress'
  'CimCmdlets Win32_Process filter (cloudflared, harness, tune)'              = '@(Get-CimInstance Win32_Process -Filter "Name=''powershell.exe''").Count'
  'Management Get-ChildItem/Get-ItemProperty HKLM (DX adapters)'             = '@(Get-ChildItem HKLM:\SOFTWARE\Microsoft\DirectX | ForEach-Object { Get-ItemProperty $_.PSPath }).Count'
  'Utility Start-Sleep/Measure-Object (telemetry loops)'                      = 'Start-Sleep -Milliseconds 10; (1,2,3 | Measure-Object -Maximum).Maximum'
  'Utility Add-Type assembly + New-Object (fonts)'                            = 'Add-Type -AssemblyName System.Drawing; (New-Object System.Drawing.Text.InstalledFontCollection).Families.Count'
  'Utility Add-Type C# (disk temperature)'                                    = 'Add-Type -TypeDefinition "public static class CigX { public static int A() { return 7; } }"; [CigX]::A()'
  'Utility Add-Type Windows.Forms (folder dialog, snapshot save dialog)'      = 'Add-Type -AssemblyName System.Windows.Forms; "forms ok"'
  'Storage Get-PhysicalDisk (temperature)'                                    = '@(Get-PhysicalDisk).Count'
  'Storage Get-Partition|Get-Disk|Get-PhysicalDisk (bench_facts)'             = 'Get-Partition -DriveLetter C | Get-Disk | Get-PhysicalDisk | Select-Object MediaType | ConvertTo-Json -Compress'
  '.NET GetFolderPath (model-directory-default)'                              = '[Environment]::GetFolderPath("MyDocuments")'
  'Utility Get-FileHash (install.ps1)'                                        = '(Get-FileHash -LiteralPath $env:ComSpec).Hash.Length'
  'Archive Expand-Archive autoload (install.ps1)'                             = 'Import-Module Microsoft.PowerShell.Archive -ErrorAction Stop; (Get-Command Expand-Archive).Source'
  'Utility Invoke-WebRequest resolve (install.ps1)'                           = '(Get-Command Invoke-WebRequest -ErrorAction Stop).Source'
  'Security Get-Acl (host test helper only)'                                  = '(Get-Acl -LiteralPath $env:ComSpec).Sddl.Length'
  '.NET File.GetAccessControl (helper fix candidate)'                         = '[System.IO.File]::GetAccessControl($env:ComSpec).GetSecurityDescriptorSddlForm("Access").Length'
}
foreach ($mode in 'raw', 'kept') {
  $env:PSModulePath = if ($mode -eq 'raw') { $raw } else { $kept }
  "=== PSModulePath $mode"
  foreach ($k in $probes.Keys) {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probes[$k]))
    $err = Join-Path $env:RUNNER_TEMP 'cig-err.txt'
    $out = & $exe -NoProfile -NonInteractive -EncodedCommand $enc 2> $err
    $rc = $LASTEXITCODE
    $first = (Get-Content -LiteralPath $err -ErrorAction SilentlyContinue | Where-Object { $_ -match '\S' } | Select-Object -First 1)
    "{0,-4} rc={1} out={2} err={3}" -f $mode, $rc, (($out | Out-String).Trim() -replace '\s+', ' '), $first
    "     $k"
  }
  $where = 'Get-Module -ListAvailable Microsoft.PowerShell.Security,Microsoft.PowerShell.Utility,Microsoft.PowerShell.Management,CimCmdlets,Microsoft.PowerShell.Archive | ForEach-Object { $_.Name + " " + $_.Version + " " + $_.Path }; try { Import-Module Microsoft.PowerShell.Security -ErrorAction Stop; "Security import ok" } catch { "Security import failed: " + $_.Exception.Message }; "5.1 sees PSModulePath: " + $env:PSModulePath'
  & $exe -NoProfile -NonInteractive -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($where))) 2>&1 | ForEach-Object { "     $_" }
}
$env:PSModulePath = $raw
