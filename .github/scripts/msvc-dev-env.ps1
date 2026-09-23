# Puts the x64 MSVC developer environment (cl, link, dumpbin, the Windows SDK) into $GITHUB_ENV for the
# following steps of a GitHub Actions job. It replaces ilammy/msvc-dev-cmd, whose latest release still
# runs on Node 20: vswhere finds the newest Visual Studio with the x64 C++ tools, vcvars64.bat is run in
# cmd, and every variable it adds or changes is exported.
$ErrorActionPreference = 'Stop'

$VsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $VsWhere)) {
  throw "vswhere.exe not found at $VsWhere"
}
$Install = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $Install) {
  throw 'no Visual Studio installation with the x64 C++ tools'
}
$VcVars = Join-Path $Install 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $VcVars)) {
  throw "vcvars64.bat not found at $VcVars"
}
Write-Host "Visual Studio: $Install"

$Before = @{}
foreach ($Item in Get-ChildItem env:) {
  $Before[$Item.Name] = $Item.Value
}
$Lines = & cmd.exe /d /c "`"$VcVars`" >nul 2>&1 && set"
if ($LASTEXITCODE -ne 0) {
  throw "vcvars64.bat failed with exit code $LASTEXITCODE"
}
$Exported = 0
foreach ($Line in $Lines) {
  if ($Line -match '^([^=]+)=(.*)$') {
    $Name = $Matches[1]
    $Value = $Matches[2]
    if (-not $Before.ContainsKey($Name) -or $Before[$Name] -ne $Value) {
      Add-Content -Path $env:GITHUB_ENV -Value "$Name=$Value" -Encoding utf8
      $Exported++
    }
  }
}
if ($Exported -eq 0) {
  throw 'vcvars64.bat changed no environment variables'
}
Write-Host "exported $Exported variables"
