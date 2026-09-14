[CmdletBinding()]
param([string]$OutputDir = (Join-Path $env:LOCALAPPDATA 'AmneziaRouteSync\app-guard-build'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Для сборки нужны Visual Studio Build Tools с C++ и Windows SDK.' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'Не найдены инструменты сборки C++.' }
$vc = Get-ChildItem (Join-Path $installation 'VC\Tools\MSVC') -Directory | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
$sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$sdk = Get-ChildItem (Join-Path $sdkRoot 'Include') -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'um\fwpmu.h') } | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $vc -or -not $sdk) { throw 'Не найдены заголовки MSVC/Windows SDK.' }
[IO.Directory]::CreateDirectory($OutputDir) | Out-Null
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$env:INCLUDE = "$($vc.FullName)\include;$($sdk.FullName)\ucrt;$($sdk.FullName)\shared;$($sdk.FullName)\um"
$env:LIB = "$($vc.FullName)\lib\x64;$sdkRoot\Lib\$($sdk.Name)\ucrt\x64;$sdkRoot\Lib\$($sdk.Name)\um\x64"
$source = Join-Path $PSScriptRoot 'app-vpn-guard.cpp'
& (Join-Path $vc.FullName 'bin\Hostx64\x64\cl.exe') /nologo /std:c++17 /W4 /WX /O2 /EHsc /MT /utf-8 $source "/Fo:$OutputDir\app-vpn-guard.obj" "/Fe:$OutputDir\app-vpn-guard.exe" /link Fwpuclnt.lib Iphlpapi.lib ws2_32.lib rpcrt4.lib ole32.lib uuid.lib advapi32.lib
if ($LASTEXITCODE -ne 0) { throw 'Сборка защиты приложений завершилась ошибкой.' }
Write-Host "Собрано: $OutputDir\app-vpn-guard.exe"
